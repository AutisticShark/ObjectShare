package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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

// fakeS3 is a minimal in-memory S3 endpoint: path-style PUT, GET, HEAD and DELETE.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string]fakeS3Object
	puts    []string
}

type fakeS3Object struct {
	body        []byte
	contentType string
}

func (server *fakeS3) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	server.mu.Lock()
	defer server.mu.Unlock()
	key := strings.TrimPrefix(request.URL.Path, "/objectshare-test/")
	switch request.Method {
	case http.MethodPut:
		body, _ := io.ReadAll(request.Body)
		server.objects[key] = fakeS3Object{body: body, contentType: request.Header.Get("Content-Type")}
		server.puts = append(server.puts, fmt.Sprintf("%s:%d:%s", key, request.ContentLength, request.Header.Get("Content-Type")))
		writer.Header().Set("ETag", `"etag"`)
	case http.MethodGet, http.MethodHead:
		object, ok := server.objects[key]
		if !ok {
			writer.Header().Set("Content-Type", "application/xml")
			writer.WriteHeader(http.StatusNotFound)
			if request.Method == http.MethodGet {
				_, _ = writer.Write([]byte(`<Error><Code>NoSuchKey</Code><Message>missing</Message></Error>`))
			}
			return
		}
		writer.Header().Set("Content-Type", object.contentType)
		writer.Header().Set("Content-Length", fmt.Sprint(len(object.body)))
		if request.Method == http.MethodGet {
			_, _ = writer.Write(object.body)
		}
	case http.MethodDelete:
		delete(server.objects, key)
		writer.WriteHeader(http.StatusNoContent)
	}
}

func TestS3CompatibleObjectLifecycleAgainstAnEndpoint(t *testing.T) {
	fake := &fakeS3{objects: map[string]fakeS3Object{}}
	server := httptest.NewServer(fake)
	defer server.Close()
	store, err := NewS3(&config.S3Config{UsePathStyle: true, S3CompatibleConfig: config.S3CompatibleConfig{
		BucketName: "objectshare-test", Region: "us-east-1", Endpoint: server.URL, AccessKeyID: "access-key", SecretAccessKey: "secret-key",
		PresignLinkTimeout: config.Duration(time.Minute), PresignUploadTimeout: config.Duration(time.Hour),
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	content := []byte("hello object storage")
	if err := store.Put(ctx, "object-1", bytes.NewReader(content), int64(len(content)), "text/plain"); err != nil {
		t.Fatal(err)
	}
	if len(fake.puts) != 1 || fake.puts[0] != fmt.Sprintf("object-1:%d:text/plain", len(content)) {
		t.Fatalf("PutObject request = %v, want an exact content length and the declared type", fake.puts)
	}
	info, err := store.Stat(ctx, "object-1")
	if err != nil || info.Size != int64(len(content)) || info.ContentType != "text/plain" {
		t.Fatalf("Stat = %#v, %v", info, err)
	}
	body, err := store.Open(ctx, "object-1")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(body)
	_ = body.Close()
	if !bytes.Equal(got, content) {
		t.Fatalf("Open returned %q", got)
	}
	if err := store.Delete(ctx, "object-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Stat(ctx, "object-1"); err == nil {
		t.Fatal("Stat of a deleted object succeeded")
	}
	if _, err := store.Open(ctx, "object-1"); err == nil || !strings.Contains(err.Error(), "S3") {
		t.Fatalf("Open of a deleted object = %v, want a provider-labelled error", err)
	}
	if err := store.Delete(ctx, "never-existed"); err != nil {
		t.Fatalf("deleting a missing object must be idempotent: %v", err)
	}
}

func TestOCIUsesPathStyleOnItsCompatibilityEndpoint(t *testing.T) {
	settings := &config.OCIConfig{
		BucketName: "objectshare-test", Region: "us-ashburn-1", Endpoint: "https://ns.compat.objectstorage.us-ashburn-1.oraclecloud.com",
		AccessKeyID: "access-key", SecretAccessKey: "secret-key",
		PresignLinkTimeout: config.Duration(10 * time.Minute), PresignUploadTimeout: config.Duration(time.Hour),
	}
	store, err := NewOCI(settings)
	if err != nil {
		t.Fatal(err)
	}
	upload, err := store.PresignPut(context.Background(), "pending/object-id", 1234, "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(upload)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Host != "ns.compat.objectstorage.us-ashburn-1.oraclecloud.com" || parsed.Path != "/objectshare-test/pending/object-id" {
		t.Fatalf("OCI must address the bucket in the path, got %s", upload)
	}
	if !strings.Contains(parsed.Query().Get("X-Amz-SignedHeaders"), "content-length") || !strings.Contains(parsed.Query().Get("X-Amz-Credential"), "/us-ashburn-1/s3/") {
		t.Fatalf("presigned upload is not bound to size and the OCI region: %s", upload)
	}
	if sources := store.DirectUploadPolicy().ConnectSources; len(sources) != 1 || sources[0] != "https://ns.compat.objectstorage.us-ashburn-1.oraclecloud.com" {
		t.Fatalf("OCI direct upload CSP sources = %v", sources)
	}
	download, err := store.PresignGet(context.Background(), "object-id", "report.txt")
	if err != nil || !strings.Contains(download, "/objectshare-test/object-id") {
		t.Fatalf("OCI presigned download = %q, %v", download, err)
	}
	if _, err := NewOCI(nil); err == nil {
		t.Fatal("a nil OCI configuration was accepted")
	}
	settings.Endpoint = ""
	if _, err := NewOCI(settings); err == nil || !strings.Contains(err.Error(), "endpoint") {
		t.Fatalf("OCI without an endpoint = %v", err)
	}
}

func TestStorageFactoryBuildsOCI(t *testing.T) {
	cfg := &config.ServiceConfig{StorageService: "OCI", OCI: &config.OCIConfig{
		BucketName: "objectshare-test", Region: "us-ashburn-1", Endpoint: "https://ns.compat.objectstorage.us-ashburn-1.oraclecloud.com",
		AccessKeyID: "access-key", SecretAccessKey: "secret-key",
		PresignLinkTimeout: config.Duration(time.Minute), PresignUploadTimeout: config.Duration(time.Hour),
	}}
	store, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if uploader, ok := store.(DirectUploader); !ok || uploader.DirectUploadPolicy().MaxSize != MaxSinglePartUploadSize {
		t.Fatalf("the OCI store does not support direct uploads: %T", store)
	}
}

func TestGCSDefaultsItsEndpointAndRegionAndUsesPathStyle(t *testing.T) {
	store, err := NewGCS(&config.GCSConfig{
		BucketName: "my.dotted.bucket", AccessKeyID: "GOOG1EXAMPLE", SecretAccessKey: "hmac-secret",
		PresignLinkTimeout: config.Duration(10 * time.Minute), PresignUploadTimeout: config.Duration(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	upload, err := store.PresignPut(context.Background(), "pending/object-id", 42, "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(upload)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Host != "storage.googleapis.com" || parsed.Path != "/my.dotted.bucket/pending/object-id" {
		t.Fatalf("GCS must default to https://storage.googleapis.com with the bucket in the path, got %s", upload)
	}
	if !strings.Contains(parsed.Query().Get("X-Amz-Credential"), "/auto/s3/") || !strings.Contains(parsed.Query().Get("X-Amz-SignedHeaders"), "content-length") {
		t.Fatalf("presigned upload is not signed for region auto and bound to its size: %s", upload)
	}
	if sources := store.DirectUploadPolicy().ConnectSources; len(sources) != 1 || sources[0] != "https://storage.googleapis.com" {
		t.Fatalf("GCS direct upload CSP sources = %v", sources)
	}
	custom, err := NewGCS(&config.GCSConfig{
		BucketName: "bucket", Region: "us", Endpoint: "https://private.googleapis.example", AccessKeyID: "GOOG1EXAMPLE", SecretAccessKey: "hmac-secret",
		PresignLinkTimeout: config.Duration(time.Minute), PresignUploadTimeout: config.Duration(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	download, err := custom.PresignGet(context.Background(), "object-id", "a.txt")
	if err != nil || !strings.HasPrefix(download, "https://private.googleapis.example/bucket/object-id") {
		t.Fatalf("a configured GCS endpoint was not honoured: %q %v", download, err)
	}
	if parsedDownload, parseErr := url.Parse(download); parseErr != nil || !strings.Contains(parsedDownload.Query().Get("X-Amz-Credential"), "/us/s3/") {
		t.Fatalf("a configured GCS region was not used for signing: %q %v", download, parseErr)
	}
	if _, err := NewGCS(nil); err == nil {
		t.Fatal("a nil GCS configuration was accepted")
	}
}

func TestStorageFactoryBuildsGCS(t *testing.T) {
	store, err := New(&config.ServiceConfig{StorageService: "gcs", GCS: &config.GCSConfig{
		BucketName: "bucket", AccessKeyID: "GOOG1EXAMPLE", SecretAccessKey: "hmac-secret",
		PresignLinkTimeout: config.Duration(time.Minute), PresignUploadTimeout: config.Duration(time.Hour),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if uploader, ok := store.(DirectUploader); !ok || uploader.DirectUploadPolicy().MaxSize != MaxSinglePartUploadSize {
		t.Fatalf("the GCS store does not support direct uploads: %T", store)
	}
}
