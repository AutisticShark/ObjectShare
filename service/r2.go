package service

import (
	"ObjectShare/config"
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"io"
	"mime/multipart"
	"os"
	"time"
)

func r2ClientGenerator() (*s3.Client, error) {
	bucketName := config.Config.R2.BucketName
	accountID := config.Config.R2.AccountID
	secretID := config.Config.R2.SecretID
	secretKey := config.Config.R2.SecretKey

	if bucketName == "" || accountID == "" || secretID == "" || secretKey == "" {
		return nil, errors.New("r2 config is not set")
	}

	r2Resolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{
			URL: fmt.Sprintf("https://%s.r2.cloudflarestorage.com", accountID),
		}, nil
	})

	r2Config, err := awsConfig.LoadDefaultConfig(
		context.TODO(),
		awsConfig.WithEndpointResolverWithOptions(r2Resolver),
		awsConfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(secretID, secretKey, "")),
		awsConfig.WithRegion("auto"))

	if err != nil {
		return nil, err
	}

	r2Client := s3.NewFromConfig(r2Config)

	return r2Client, nil
}

func UploadToR2(file multipart.File, fileId string, fileName string) error {
	r2Client, err := r2ClientGenerator()
	if err != nil {
		return err
	}

	_, err = r2Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(config.Config.R2.BucketName),
		Key:    aws.String(fileId + "/" + fileName),
		Body:   file,
	})
	if err != nil {
		return err
	}

	return nil
}

func DownloadFromR2(filePath string) (*os.File, error) {
	r2Client, err := r2ClientGenerator()
	if err != nil {
		return nil, err
	}

	fileObject := &os.File{}

	output, err := r2Client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(config.Config.R2.BucketName),
		Key:    aws.String(filePath),
	})
	if err != nil {
		return nil, err
	}
	defer output.Body.Close()

	fileObject, err = os.Create(filePath)
	if err != nil {
		return nil, err
	}
	defer fileObject.Close()

	_, err = io.Copy(fileObject, output.Body)
	if err != nil {
		return nil, err
	}

	return fileObject, err
}

func DeleteFromR2(filePath string) error {
	r2Client, err := r2ClientGenerator()
	if err != nil {
		return err
	}

	_, err = r2Client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket: aws.String(config.Config.R2.BucketName),
		Key:    aws.String(filePath),
	})

	return err
}

func GenerateR2PreSignedDownloadURL(fileId string, fileName string) (string, error) {
	r2Client, err := r2ClientGenerator()
	if err != nil {
		return "", err
	}

	presignR2Client := s3.NewPresignClient(r2Client)

	url, err := presignR2Client.PresignGetObject(
		context.TODO(),
		&s3.GetObjectInput{
			Bucket: aws.String(config.Config.R2.BucketName),
			Key:    aws.String(fileId + "/" + fileName),
		},
		func(opts *s3.PresignOptions) {
			opts.Expires = time.Duration(config.Config.R2.PresignLinkTimeout * int64(time.Second))
		})

	return url.URL, err
}
