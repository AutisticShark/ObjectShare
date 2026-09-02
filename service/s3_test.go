package service

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
)

func TestS3CompatibleProvidersPresignBoundUploads(t *testing.T) {
	base := config.S3CompatibleConfig{
		BucketName: "objectshare-test", AccessKeyID: "access-key", SecretAccessKey: "secret-key",
		PresignLinkTimeout: config.Duration(10 * time.Minute), PresignUploadTimeout: config.Duration(time.Hour),
	}
	tests := []struct {
		name     string
		region   string
		newStore func(*config.S3CompatibleConfig) (*S3Compatible, error)
		wantHost string
	}{
		{"s3", "eu-west-1", func(settings *config.S3CompatibleConfig) (*S3Compatible, error) {
			return NewS3(&config.S3Config{S3CompatibleConfig: *settings})
		}, "objectshare-test.s3.eu-west-1.amazonaws.com"},
		{"b2", "us-west-004", NewB2, "objectshare-test.s3.us-west-004.backblazeb2.com"},
		{"oss", "cn-hangzhou", NewOSS, "objectshare-test.s3.oss-cn-hangzhou.aliyuncs.com"},
		{"cos", "ap-guangzhou", NewCOS, "objectshare-test.cos.ap-guangzhou.myqcloud.com"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			settings := base
			settings.Region = test.region
			store, err := test.newStore(&settings)
			if err != nil {
				t.Fatal(err)
			}
			value, err := store.PresignPut(context.Background(), "object-id", 1234, "text/plain")
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := url.Parse(value)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Host != test.wantHost {
				t.Fatalf("host = %q, want %q", parsed.Host, test.wantHost)
			}
			signedHeaders := strings.ToLower(parsed.Query().Get("X-Amz-SignedHeaders"))
			for _, header := range []string{"content-length", "content-type", "host"} {
				if !strings.Contains(signedHeaders, header) {
					t.Fatalf("%s is not bound by the presigned URL: %q", header, signedHeaders)
				}
			}
			policy := store.DirectUploadPolicy()
			if policy.Expires != time.Hour || policy.MaxSize != MaxSinglePartUploadSize || len(policy.ConnectSources) == 0 {
				t.Fatalf("unexpected direct upload policy: %#v", policy)
			}
		})
	}
}

func TestS3CustomEndpointSupportsPathStyle(t *testing.T) {
	store, err := NewS3(&config.S3Config{
		S3CompatibleConfig: config.S3CompatibleConfig{
			BucketName: "bucket", Endpoint: "https://storage.example.com:8443", Region: "us-east-1",
			AccessKeyID: "access-key", SecretAccessKey: "secret-key",
			PresignLinkTimeout: config.Duration(10 * time.Minute), PresignUploadTimeout: config.Duration(time.Hour),
		},
		UsePathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	value, err := store.PresignPut(context.Background(), "object-id", 1, "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Host != "storage.example.com:8443" || parsed.Path != "/bucket/object-id" {
		t.Fatalf("unexpected path-style URL: %s", value)
	}
	wantSource := "https://storage.example.com:8443"
	if sources := store.DirectUploadPolicy().ConnectSources; len(sources) != 1 || sources[0] != wantSource {
		t.Fatalf("connect sources = %#v, want %q", sources, wantSource)
	}
}
