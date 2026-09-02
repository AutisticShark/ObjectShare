package service

import (
	"fmt"

	"github.com/AutisticShark/ObjectShare/config"
)

type R2 = S3Compatible

func NewR2(settings *config.R2Config) (*R2, error) {
	if settings == nil {
		return nil, fmt.Errorf("R2 configuration is required")
	}
	endpoint := settings.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://%s.r2.cloudflarestorage.com", settings.AccountID)
	}
	return newS3Compatible("R2", &config.S3CompatibleConfig{
		BucketName: settings.BucketName, Endpoint: endpoint,
		AccessKeyID: settings.AccessKeyID, SecretAccessKey: settings.SecretAccessKey,
		Region: settings.Region, PresignLinkTimeout: settings.PresignLinkTimeout,
		PresignUploadTimeout: settings.PresignUploadTimeout,
	}, "", false)
}
