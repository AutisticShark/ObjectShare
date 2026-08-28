package service

import (
	"context"
	"fmt"
	"io"
	"mime"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type R2 struct {
	bucket          string
	client          *s3.Client
	presign         *s3.PresignClient
	downloadTimeout config.Duration
	uploadTimeout   config.Duration
}

func NewR2(settings *config.R2Config) (*R2, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(settings.AccessKeyID, settings.SecretAccessKey, "")),
		awsconfig.WithRegion(settings.Region),
	)
	if err != nil {
		return nil, fmt.Errorf("load R2 client config: %w", err)
	}
	endpoint := settings.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://%s.r2.cloudflarestorage.com", settings.AccountID)
	}
	client := s3.NewFromConfig(awsCfg, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(endpoint)
	})
	return &R2{
		bucket: settings.BucketName, client: client, presign: s3.NewPresignClient(client),
		downloadTimeout: settings.PresignLinkTimeout, uploadTimeout: settings.PresignUploadTimeout,
	}, nil
}

func (store *R2) Put(ctx context.Context, key string, body io.Reader, size int64, contentType string) error {
	_, err := store.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(store.bucket), Key: aws.String(key), Body: body,
		ContentLength: aws.Int64(size), ContentType: aws.String(contentType),
	})
	if err != nil {
		return fmt.Errorf("put R2 object: %w", err)
	}
	return nil
}

func (store *R2) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	output, err := store.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(store.bucket), Key: aws.String(key)})
	if err != nil {
		return nil, fmt.Errorf("get R2 object: %w", err)
	}
	return output.Body, nil
}

func (store *R2) Delete(ctx context.Context, key string) error {
	_, err := store.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(store.bucket), Key: aws.String(key)})
	if err != nil {
		return fmt.Errorf("delete R2 object: %w", err)
	}
	return nil
}

func (store *R2) PresignGet(ctx context.Context, key, fileName string) (string, error) {
	disposition := mime.FormatMediaType("attachment", map[string]string{"filename": fileName})
	result, err := store.presign.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(store.bucket), Key: aws.String(key), ResponseContentDisposition: aws.String(disposition),
	}, func(options *s3.PresignOptions) { options.Expires = store.downloadTimeout.Duration() })
	if err != nil {
		return "", fmt.Errorf("presign R2 object: %w", err)
	}
	return result.URL, nil
}

func (store *R2) PresignPut(ctx context.Context, key string, size int64, contentType string) (string, error) {
	result, err := store.presign.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(store.bucket), Key: aws.String(key), ContentLength: aws.Int64(size), ContentType: aws.String(contentType),
	}, func(options *s3.PresignOptions) { options.Expires = store.uploadTimeout.Duration() })
	if err != nil {
		return "", fmt.Errorf("presign R2 upload: %w", err)
	}
	return result.URL, nil
}

func (store *R2) Stat(ctx context.Context, key string) (*ObjectInfo, error) {
	output, err := store.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(store.bucket), Key: aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("head R2 object: %w", err)
	}
	return &ObjectInfo{Size: aws.ToInt64(output.ContentLength), ContentType: aws.ToString(output.ContentType)}, nil
}

var _ DirectUploader = (*R2)(nil)
