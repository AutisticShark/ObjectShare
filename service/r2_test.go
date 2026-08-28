package service

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
)

func TestR2PresignedPutBindsSizeAndContentType(t *testing.T) {
	store, err := NewR2(&config.R2Config{
		BucketName: "bucket", AccountID: "0123456789abcdef", AccessKeyID: "access-key",
		SecretAccessKey: "secret-key", Region: "auto",
		PresignLinkTimeout: config.Duration(10 * time.Minute), PresignUploadTimeout: config.Duration(time.Hour),
	})
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
	signedHeaders := strings.ToLower(parsed.Query().Get("X-Amz-SignedHeaders"))
	for _, header := range []string{"content-length", "content-type", "host"} {
		if !strings.Contains(signedHeaders, header) {
			t.Fatalf("%s is not bound by the presigned URL: %q", header, signedHeaders)
		}
	}
}
