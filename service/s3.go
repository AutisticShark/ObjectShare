package service

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net/url"
	"strings"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Compatible implements ObjectStore and DirectUploader through the Amazon S3
// API. It is shared by S3, R2, B2, OSS, and COS while retaining provider names
// in operational errors.
type S3Compatible struct {
	provider        string
	bucket          string
	client          *s3.Client
	presign         *s3.PresignClient
	downloadTimeout config.Duration
	uploadTimeout   config.Duration
	connectSources  []string
}

func NewS3(settings *config.S3Config) (*S3Compatible, error) {
	if settings == nil {
		return nil, fmt.Errorf("S3 configuration is required")
	}
	return newS3Compatible("S3", &settings.S3CompatibleConfig, settings.SessionToken, settings.UsePathStyle)
}

func NewB2(settings *config.B2Config) (*S3Compatible, error) {
	if settings == nil {
		return nil, fmt.Errorf("B2 configuration is required")
	}
	settings = cloneS3Settings(settings)
	if settings.Endpoint == "" {
		settings.Endpoint = fmt.Sprintf("https://s3.%s.backblazeb2.com", settings.Region)
	}
	return newS3Compatible("B2", settings, "", false)
}

func NewOSS(settings *config.OSSConfig) (*S3Compatible, error) {
	if settings == nil {
		return nil, fmt.Errorf("OSS configuration is required")
	}
	settings = cloneS3Settings(settings)
	if settings.Endpoint == "" {
		settings.Endpoint = fmt.Sprintf("https://s3.oss-%s.aliyuncs.com", settings.Region)
	}
	return newS3Compatible("OSS", settings, "", false)
}

func NewCOS(settings *config.COSConfig) (*S3Compatible, error) {
	if settings == nil {
		return nil, fmt.Errorf("COS configuration is required")
	}
	settings = cloneS3Settings(settings)
	if settings.Endpoint == "" {
		settings.Endpoint = fmt.Sprintf("https://cos.%s.myqcloud.com", settings.Region)
	}
	return newS3Compatible("COS", settings, "", false)
}

func cloneS3Settings(settings *config.S3CompatibleConfig) *config.S3CompatibleConfig {
	copy := *settings
	return &copy
}

func newS3Compatible(provider string, settings *config.S3CompatibleConfig, sessionToken string, usePathStyle bool) (*S3Compatible, error) {
	loadOptions := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(settings.Region),
		// COS and OSS reject the optional streaming checksum trailer that newer
		// AWS SDK releases otherwise add to compatible PutObject requests.
		awsconfig.WithRequestChecksumCalculation(aws.RequestChecksumCalculationWhenRequired),
	}
	if settings.AccessKeyID != "" {
		loadOptions = append(loadOptions, awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			settings.AccessKeyID, settings.SecretAccessKey, sessionToken,
		)))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), loadOptions...)
	if err != nil {
		return nil, fmt.Errorf("load %s client config: %w", provider, err)
	}
	client := s3.NewFromConfig(awsCfg, func(options *s3.Options) {
		if settings.Endpoint != "" {
			options.BaseEndpoint = aws.String(settings.Endpoint)
		}
		options.UsePathStyle = usePathStyle
	})
	return &S3Compatible{
		provider: provider, bucket: settings.BucketName, client: client, presign: s3.NewPresignClient(client),
		downloadTimeout: settings.PresignLinkTimeout, uploadTimeout: settings.PresignUploadTimeout,
		connectSources: directUploadConnectSources(settings, usePathStyle),
	}, nil
}

func (store *S3Compatible) Put(ctx context.Context, key string, body io.Reader, size int64, contentType string) error {
	_, err := store.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(store.bucket), Key: aws.String(key), Body: body,
		ContentLength: aws.Int64(size), ContentType: aws.String(contentType),
	})
	if err != nil {
		return fmt.Errorf("put %s object: %w", store.provider, err)
	}
	return nil
}

func (store *S3Compatible) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	output, err := store.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(store.bucket), Key: aws.String(key)})
	if err != nil {
		return nil, fmt.Errorf("get %s object: %w", store.provider, err)
	}
	return output.Body, nil
}

func (store *S3Compatible) Delete(ctx context.Context, key string) error {
	_, err := store.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(store.bucket), Key: aws.String(key)})
	if err != nil {
		return fmt.Errorf("delete %s object: %w", store.provider, err)
	}
	return nil
}

func (store *S3Compatible) PresignGet(ctx context.Context, key, fileName string) (string, error) {
	disposition := mime.FormatMediaType("attachment", map[string]string{"filename": fileName})
	result, err := store.presign.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(store.bucket), Key: aws.String(key), ResponseContentDisposition: aws.String(disposition),
	}, func(options *s3.PresignOptions) { options.Expires = store.downloadTimeout.Duration() })
	if err != nil {
		return "", fmt.Errorf("presign %s object: %w", store.provider, err)
	}
	return result.URL, nil
}

func (store *S3Compatible) PresignPut(ctx context.Context, key string, size int64, contentType string) (string, error) {
	result, err := store.presign.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(store.bucket), Key: aws.String(key), ContentLength: aws.Int64(size), ContentType: aws.String(contentType),
	}, func(options *s3.PresignOptions) { options.Expires = store.uploadTimeout.Duration() })
	if err != nil {
		return "", fmt.Errorf("presign %s upload: %w", store.provider, err)
	}
	return result.URL, nil
}

func (store *S3Compatible) Stat(ctx context.Context, key string) (*ObjectInfo, error) {
	output, err := store.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(store.bucket), Key: aws.String(key)})
	if err != nil {
		return nil, fmt.Errorf("head %s object: %w", store.provider, err)
	}
	return &ObjectInfo{Size: aws.ToInt64(output.ContentLength), ContentType: aws.ToString(output.ContentType)}, nil
}

func (store *S3Compatible) DirectUploadPolicy() DirectUploadPolicy {
	return DirectUploadPolicy{Expires: store.uploadTimeout.Duration(), MaxSize: MaxSinglePartUploadSize, ConnectSources: store.connectSources}
}

func directUploadConnectSources(settings *config.S3CompatibleConfig, usePathStyle bool) []string {
	if settings.Endpoint == "" {
		return []string{fmt.Sprintf("https://s3.%s.amazonaws.com", settings.Region), fmt.Sprintf("https://*.s3.%s.amazonaws.com", settings.Region)}
	}
	endpoint, err := url.Parse(settings.Endpoint)
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return nil
	}
	origin := endpoint.Scheme + "://" + endpoint.Host
	if usePathStyle || strings.HasPrefix(endpoint.Hostname(), "*.") {
		return []string{origin}
	}
	wildcardHost := "*." + endpoint.Hostname()
	if port := endpoint.Port(); port != "" {
		wildcardHost += ":" + port
	}
	return []string{origin, endpoint.Scheme + "://" + wildcardHost}
}

var _ DirectUploader = (*S3Compatible)(nil)
