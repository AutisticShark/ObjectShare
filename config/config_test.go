package config

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDurationAcceptsStringAndLegacySeconds(t *testing.T) {
	for _, test := range []struct {
		input string
		want  time.Duration
	}{
		{`"15s"`, 15 * time.Second}, {`600`, 10 * time.Minute},
	} {
		var duration Duration
		if err := json.Unmarshal([]byte(test.input), &duration); err != nil {
			t.Fatal(err)
		}
		if duration.Duration() != test.want {
			t.Fatalf("%s: got %s, want %s", test.input, duration.Duration(), test.want)
		}
	}
}

func TestS3SessionTokenRequiresExplicitCredentials(t *testing.T) {
	cfg := defaults()
	cfg.StorageService = "s3"
	cfg.S3 = &S3Config{
		S3CompatibleConfig: S3CompatibleConfig{
			BucketName: "bucket", Region: "us-east-1",
			PresignLinkTimeout: Duration(time.Minute), PresignUploadTimeout: Duration(time.Minute),
		},
		SessionToken: "token",
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "session_token") {
		t.Fatalf("error = %v, want session_token validation", err)
	}
}

func TestSupportedObjectStorageConfigurations(t *testing.T) {
	for _, storage := range []string{"s3", "b2", "oss", "cos"} {
		t.Run(storage, func(t *testing.T) {
			cfg := defaults()
			cfg.StorageService = storage
			settings := &S3CompatibleConfig{
				BucketName: "bucket", Region: "region-1", AccessKeyID: "key", SecretAccessKey: "secret",
				PresignLinkTimeout: Duration(10 * time.Minute), PresignUploadTimeout: Duration(time.Hour),
			}
			switch storage {
			case "s3":
				cfg.S3 = &S3Config{S3CompatibleConfig: *settings}
			case "b2":
				cfg.B2 = settings
			case "oss":
				cfg.OSS = settings
			case "cos":
				cfg.COS = settings
			}
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestObjectStorageRejectsIncompleteCredentialsAndInsecureEndpoint(t *testing.T) {
	for _, test := range []struct {
		name     string
		settings *S3CompatibleConfig
		contains string
	}{
		{"partial credentials", &S3CompatibleConfig{BucketName: "bucket", Region: "region", AccessKeyID: "key", PresignLinkTimeout: Duration(time.Minute), PresignUploadTimeout: Duration(time.Minute)}, "provided together"},
		{"insecure endpoint", &S3CompatibleConfig{BucketName: "bucket", Region: "region", Endpoint: "http://storage.example.com", PresignLinkTimeout: Duration(time.Minute), PresignUploadTimeout: Duration(time.Minute)}, "absolute HTTPS URL"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := defaults()
			cfg.StorageService = "s3"
			cfg.S3 = &S3Config{S3CompatibleConfig: *test.settings}
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("error = %v, want text %q", err, test.contains)
			}
		})
	}
}

func TestObjectStorageEnvironmentOverrides(t *testing.T) {
	t.Setenv("OBJECTSHARE_STORAGE_SERVICE", "cos")
	t.Setenv("OBJECTSHARE_COS_BUCKET_NAME", "objectshare-1250000000")
	t.Setenv("OBJECTSHARE_COS_REGION", "ap-guangzhou")
	t.Setenv("OBJECTSHARE_COS_ENDPOINT", "https://cos.ap-guangzhou.myqcloud.com")
	t.Setenv("OBJECTSHARE_COS_ACCESS_KEY_ID", "secret-id")
	t.Setenv("OBJECTSHARE_COS_SECRET_ACCESS_KEY", "secret-key")
	t.Setenv("OBJECTSHARE_COS_PRESIGN_TIMEOUT", "15m")
	t.Setenv("OBJECTSHARE_COS_UPLOAD_PRESIGN_TIMEOUT", "45m")

	cfg := defaults()
	if err := applyEnvironment(cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.COS.BucketName != "objectshare-1250000000" || cfg.COS.Region != "ap-guangzhou" || cfg.COS.PresignLinkTimeout.Duration() != 15*time.Minute || cfg.COS.PresignUploadTimeout.Duration() != 45*time.Minute {
		t.Fatalf("COS environment was not applied: %#v", cfg.COS)
	}
}

func TestDefaultsValidate(t *testing.T) {
	cfg := defaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestExampleConfiguration(t *testing.T) {
	cfg, err := Load("../config.json.example")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Address != ":8080" || cfg.Db.Port != 5432 {
		t.Fatalf("unexpected example configuration: %#v", cfg)
	}
}

func TestEncryptionMemoryLimit(t *testing.T) {
	cfg := defaults()
	cfg.MaxFileSize = 129
	cfg.Encryption.Enabled = true
	cfg.Encryption.Key = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected encrypted upload limit error")
	}
}
