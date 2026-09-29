package service

import (
	"context"
	"net/http"
	"net/http/httptest"
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

func TestCopySourceEscapesSegmentsAndKeepsSeparators(t *testing.T) {
	for _, test := range []struct{ bucket, key, want string }{
		{"bucket", "pending/0f8fad5b-d9cb-469f-a165-70867728950e", "bucket/pending/0f8fad5b-d9cb-469f-a165-70867728950e"},
		{"bucket", "plain", "bucket/plain"},
		{"my bucket", "a b/c?d", "my%20bucket/a%20b/c%3Fd"},
	} {
		if got := copySource(test.bucket, test.key); got != test.want {
			t.Errorf("copySource(%q, %q) = %q, want %q", test.bucket, test.key, got, test.want)
		}
	}
}

func TestS3CopyPublishesAStagedObjectServerSide(t *testing.T) {
	var method, path, source string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		method, path, source = request.Method, request.URL.Path, request.Header.Get("X-Amz-Copy-Source")
		writer.Header().Set("Content-Type", "application/xml")
		_, _ = writer.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><CopyObjectResult><ETag>"abc"</ETag></CopyObjectResult>`))
	}))
	defer server.Close()
	store, err := NewS3(&config.S3Config{UsePathStyle: true, S3CompatibleConfig: config.S3CompatibleConfig{
		BucketName: "objectshare-test", Region: "us-east-1", Endpoint: server.URL, AccessKeyID: "access-key", SecretAccessKey: "secret-key",
		PresignLinkTimeout: config.Duration(time.Minute), PresignUploadTimeout: config.Duration(time.Hour),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Copy(context.Background(), PendingUploadKey("file-id"), "file-id"); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPut || path != "/objectshare-test/file-id" || source != "objectshare-test/pending/file-id" {
		t.Fatalf("copy request = %s %s source %q", method, path, source)
	}
}

func TestPresignedDownloadsForceAttachmentAndNeutralContentType(t *testing.T) {
	store, err := NewS3(&config.S3Config{S3CompatibleConfig: config.S3CompatibleConfig{
		BucketName: "bucket", Region: "us-east-1", AccessKeyID: "access-key", SecretAccessKey: "secret-key",
		PresignLinkTimeout: config.Duration(10 * time.Minute), PresignUploadTimeout: config.Duration(time.Hour),
	}})
	if err != nil {
		t.Fatal(err)
	}
	value, err := store.PresignGet(context.Background(), "object-id", "report.html")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if got := query.Get("response-content-type"); got != "application/octet-stream" {
		t.Fatalf("response-content-type = %q, want application/octet-stream", got)
	}
	if got := query.Get("response-content-disposition"); !strings.HasPrefix(got, "attachment") {
		t.Fatalf("response-content-disposition = %q, want an attachment", got)
	}
}
