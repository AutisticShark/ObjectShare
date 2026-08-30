package config

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var Version = "dev"

func Load(path string) (*ServiceConfig, error) {
	cfg := defaults()

	if path != "" {
		if err := readJSON(path, cfg); err != nil {
			return nil, err
		}
	} else {
		for _, candidate := range []string{"config.json", "/etc/object-share/config.json"} {
			if _, err := os.Stat(candidate); err == nil {
				if err := readJSON(candidate, cfg); err != nil {
					return nil, err
				}
				break
			} else if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("inspect config %q: %w", candidate, err)
			}
		}
	}

	if err := applyEnvironment(cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func GetVersion() string { return Version }

func defaults() *ServiceConfig {
	return &ServiceConfig{
		Address:         ":8080",
		ReadTimeout:     Duration(5 * time.Minute),
		WriteTimeout:    Duration(5 * time.Minute),
		IdleTimeout:     Duration(60 * time.Second),
		ShutdownTimeout: Duration(15 * time.Second),
		MaxFileSize:     100,
		Auth: &AuthConfig{
			SignupEnabled: true, TokenLifetime: Duration(12 * time.Hour),
		},
		StorageService: "filesystem",
		StoragePath:    "data/objects",
		Db: &DatabaseConfig{
			Type:            "postgres",
			Host:            "127.0.0.1",
			Port:            5432,
			User:            "postgres",
			Database:        "object_share",
			SSLMode:         "require",
			TimeZone:        "UTC",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: Duration(30 * time.Minute),
		},
		Encryption: &EncryptionConfig{Method: "aes-256-gcm"},
		R2: &R2Config{
			Region:               "auto",
			PresignLinkTimeout:   Duration(10 * time.Minute),
			PresignUploadTimeout: Duration(time.Hour),
		},
		S3:  &S3Config{S3CompatibleConfig: *defaultS3CompatibleConfig("")},
		B2:  defaultS3CompatibleConfig(""),
		OSS: defaultS3CompatibleConfig(""),
		COS: defaultS3CompatibleConfig(""),
	}
}

func defaultS3CompatibleConfig(region string) *S3CompatibleConfig {
	return &S3CompatibleConfig{
		Region: region, PresignLinkTimeout: Duration(10 * time.Minute), PresignUploadTimeout: Duration(time.Hour),
	}
}

func readJSON(path string, cfg *ServiceConfig) error {
	clean := filepath.Clean(path)
	data, err := os.ReadFile(clean)
	if err != nil {
		return fmt.Errorf("read config %q: %w", clean, err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(cfg); err != nil {
		return fmt.Errorf("decode config %q: %w", clean, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode config %q: unexpected trailing data", clean)
	}
	return nil
}

func applyEnvironment(cfg *ServiceConfig) error {
	var problems []error
	setString("OBJECTSHARE_ADDRESS", &cfg.Address)
	problems = append(problems, setInt("OBJECTSHARE_PORT", &cfg.Port))
	problems = append(problems, setDuration("OBJECTSHARE_READ_TIMEOUT", &cfg.ReadTimeout))
	problems = append(problems, setDuration("OBJECTSHARE_WRITE_TIMEOUT", &cfg.WriteTimeout))
	problems = append(problems, setDuration("OBJECTSHARE_IDLE_TIMEOUT", &cfg.IdleTimeout))
	problems = append(problems, setDuration("OBJECTSHARE_SHUTDOWN_TIMEOUT", &cfg.ShutdownTimeout))
	problems = append(problems, setInt64("OBJECTSHARE_MAX_FILE_SIZE_MB", &cfg.MaxFileSize))
	problems = append(problems, setBool("OBJECTSHARE_SECURE_COOKIES", &cfg.SecureCookies))
	if cfg.Auth == nil {
		cfg.Auth = &AuthConfig{SignupEnabled: true, TokenLifetime: Duration(12 * time.Hour)}
	}
	problems = append(problems, setBool("OBJECTSHARE_SIGNUP_ENABLED", &cfg.Auth.SignupEnabled))
	setString("OBJECTSHARE_JWT_SECRET", &cfg.Auth.JWTSecret)
	problems = append(problems, setDuration("OBJECTSHARE_JWT_LIFETIME", &cfg.Auth.TokenLifetime))
	setString("OBJECTSHARE_STORAGE_SERVICE", &cfg.StorageService)
	setString("OBJECTSHARE_STORAGE_PATH", &cfg.StoragePath)

	if cfg.Db == nil {
		cfg.Db = &DatabaseConfig{}
	}
	setString("OBJECTSHARE_DB_HOST", &cfg.Db.Host)
	problems = append(problems, setInt("OBJECTSHARE_DB_PORT", &cfg.Db.Port))
	setString("OBJECTSHARE_DB_USER", &cfg.Db.User)
	setString("OBJECTSHARE_DB_PASSWORD", &cfg.Db.Password)
	setString("OBJECTSHARE_DB_DATABASE", &cfg.Db.Database)
	setString("OBJECTSHARE_DB_SSLMODE", &cfg.Db.SSLMode)
	setString("OBJECTSHARE_DB_TIMEZONE", &cfg.Db.TimeZone)
	problems = append(problems, setInt("OBJECTSHARE_DB_MAX_OPEN_CONNS", &cfg.Db.MaxOpenConns))
	problems = append(problems, setInt("OBJECTSHARE_DB_MAX_IDLE_CONNS", &cfg.Db.MaxIdleConns))
	problems = append(problems, setDuration("OBJECTSHARE_DB_CONN_MAX_LIFETIME", &cfg.Db.ConnMaxLifetime))

	if cfg.Encryption == nil {
		cfg.Encryption = &EncryptionConfig{}
	}
	problems = append(problems, setBool("OBJECTSHARE_ENCRYPTION_ENABLED", &cfg.Encryption.Enabled))
	setString("OBJECTSHARE_ENCRYPTION_METHOD", &cfg.Encryption.Method)
	setString("OBJECTSHARE_ENCRYPTION_KEY", &cfg.Encryption.Key)

	if cfg.R2 == nil {
		cfg.R2 = &R2Config{}
	}
	setString("OBJECTSHARE_R2_BUCKET_NAME", &cfg.R2.BucketName)
	setString("OBJECTSHARE_R2_ACCOUNT_ID", &cfg.R2.AccountID)
	setString("OBJECTSHARE_R2_ENDPOINT", &cfg.R2.Endpoint)
	setString("OBJECTSHARE_R2_ACCESS_KEY_ID", &cfg.R2.AccessKeyID)
	setString("OBJECTSHARE_R2_SECRET_ACCESS_KEY", &cfg.R2.SecretAccessKey)
	setString("OBJECTSHARE_R2_REGION", &cfg.R2.Region)
	problems = append(problems, setDuration("OBJECTSHARE_R2_PRESIGN_TIMEOUT", &cfg.R2.PresignLinkTimeout))
	problems = append(problems, setDuration("OBJECTSHARE_R2_UPLOAD_PRESIGN_TIMEOUT", &cfg.R2.PresignUploadTimeout))

	if cfg.S3 == nil {
		cfg.S3 = &S3Config{S3CompatibleConfig: *defaultS3CompatibleConfig("")}
	}
	applyS3Environment("S3", &cfg.S3.S3CompatibleConfig, &problems)
	setString("OBJECTSHARE_S3_SESSION_TOKEN", &cfg.S3.SessionToken)
	problems = append(problems, setBool("OBJECTSHARE_S3_USE_PATH_STYLE", &cfg.S3.UsePathStyle))
	if cfg.B2 == nil {
		cfg.B2 = defaultS3CompatibleConfig("")
	}
	applyS3Environment("B2", cfg.B2, &problems)
	if cfg.OSS == nil {
		cfg.OSS = defaultS3CompatibleConfig("")
	}
	applyS3Environment("OSS", cfg.OSS, &problems)
	if cfg.COS == nil {
		cfg.COS = defaultS3CompatibleConfig("")
	}
	applyS3Environment("COS", cfg.COS, &problems)
	return errors.Join(problems...)
}

func applyS3Environment(prefix string, settings *S3CompatibleConfig, problems *[]error) {
	base := "OBJECTSHARE_" + prefix + "_"
	setString(base+"BUCKET_NAME", &settings.BucketName)
	setString(base+"ENDPOINT", &settings.Endpoint)
	setString(base+"ACCESS_KEY_ID", &settings.AccessKeyID)
	setString(base+"SECRET_ACCESS_KEY", &settings.SecretAccessKey)
	setString(base+"REGION", &settings.Region)
	*problems = append(*problems, setDuration(base+"PRESIGN_TIMEOUT", &settings.PresignLinkTimeout))
	*problems = append(*problems, setDuration(base+"UPLOAD_PRESIGN_TIMEOUT", &settings.PresignUploadTimeout))
}

func (cfg *ServiceConfig) Validate() error {
	if cfg.Port > 0 {
		cfg.Address = ":" + strconv.Itoa(cfg.Port)
	} else if cfg.Address == "" {
		return errors.New("address or a valid port is required")
	}
	if cfg.MaxFileSize <= 0 || cfg.MaxFileSize > 10*1024 {
		return errors.New("max_file_size must be between 1 and 10240 MiB")
	}
	if cfg.Timeout > 0 && cfg.ReadTimeout == Duration(5*time.Minute) {
		cfg.ReadTimeout = Duration(time.Duration(cfg.Timeout) * time.Second)
		cfg.WriteTimeout = Duration(time.Duration(cfg.Timeout) * time.Second)
	}
	if cfg.ReadTimeout <= 0 || cfg.WriteTimeout <= 0 || cfg.IdleTimeout <= 0 || cfg.ShutdownTimeout <= 0 {
		return errors.New("all server timeouts must be positive")
	}
	if cfg.Auth == nil {
		cfg.Auth = &AuthConfig{SignupEnabled: true, TokenLifetime: Duration(12 * time.Hour)}
	}
	if len(cfg.Auth.JWTSecret) < 32 || cfg.Auth.JWTSecret == "replace-with-at-least-32-random-bytes" {
		return errors.New("auth jwt_secret must contain at least 32 non-placeholder bytes")
	}
	if cfg.Auth.TokenLifetime.Duration() < 5*time.Minute || cfg.Auth.TokenLifetime.Duration() > 24*time.Hour {
		return errors.New("auth token_lifetime must be between 5 minutes and 24 hours")
	}
	if cfg.Db == nil || cfg.Db.Host == "" || cfg.Db.Port <= 0 || cfg.Db.User == "" || cfg.Db.Database == "" {
		return errors.New("complete PostgreSQL configuration is required")
	}
	if cfg.Db.Type != "" && !strings.EqualFold(cfg.Db.Type, "postgres") {
		return fmt.Errorf("unsupported database type %q", cfg.Db.Type)
	}
	if cfg.Db.SSLMode == "" {
		cfg.Db.SSLMode = "require"
	}
	validSSLMode := map[string]bool{"disable": true, "allow": true, "prefer": true, "require": true, "verify-ca": true, "verify-full": true}
	if !validSSLMode[cfg.Db.SSLMode] {
		return fmt.Errorf("unsupported PostgreSQL ssl_mode %q", cfg.Db.SSLMode)
	}
	if cfg.Db.TimeZone == "" {
		cfg.Db.TimeZone = "UTC"
	}
	if cfg.Db.MaxOpenConns < 1 || cfg.Db.MaxIdleConns < 0 || cfg.Db.MaxIdleConns > cfg.Db.MaxOpenConns {
		return errors.New("invalid database connection pool limits")
	}

	switch strings.ToLower(cfg.StorageService) {
	case "filesystem":
		if cfg.StoragePath == "" {
			return errors.New("storage_path is required for filesystem storage")
		}
	case "r2":
		if cfg.R2 == nil {
			return errors.New("r2 configuration is required")
		}
		if cfg.R2.AccessKeyID == "" {
			cfg.R2.AccessKeyID = cfg.R2.SecretID
		}
		if cfg.R2.SecretAccessKey == "" {
			cfg.R2.SecretAccessKey = cfg.R2.SecretKey
		}
		if cfg.R2.BucketName == "" || (cfg.R2.AccountID == "" && cfg.R2.Endpoint == "") || cfg.R2.AccessKeyID == "" || cfg.R2.SecretAccessKey == "" {
			return errors.New("r2 bucket_name, account_id (or endpoint), access_key_id, and secret_access_key are required")
		}
		if cfg.R2.Endpoint != "" {
			endpoint, err := url.Parse(cfg.R2.Endpoint)
			if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
				return errors.New("r2 endpoint must be an absolute HTTPS URL without credentials, query, or fragment")
			}
		}
		if cfg.R2.PresignLinkTimeout.Duration() < time.Second || cfg.R2.PresignLinkTimeout.Duration() > 7*24*time.Hour {
			return errors.New("r2 presign timeout must be between 1 second and 7 days")
		}
		if cfg.R2.PresignUploadTimeout.Duration() < time.Minute || cfg.R2.PresignUploadTimeout.Duration() > 7*24*time.Hour {
			return errors.New("r2 upload presign timeout must be between 1 minute and 7 days")
		}
	case "s3":
		if cfg.S3 == nil {
			return errors.New("s3 configuration is required")
		}
		if err := validateS3Compatible("s3", &cfg.S3.S3CompatibleConfig, false); err != nil {
			return err
		}
		if cfg.S3.SessionToken != "" && cfg.S3.AccessKeyID == "" {
			return errors.New("s3 session_token requires access_key_id and secret_access_key")
		}
	case "b2":
		if err := validateS3Compatible("b2", cfg.B2, true); err != nil {
			return err
		}
	case "oss":
		if err := validateS3Compatible("oss", cfg.OSS, true); err != nil {
			return err
		}
	case "cos":
		if err := validateS3Compatible("cos", cfg.COS, true); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported storage service %q", cfg.StorageService)
	}

	if cfg.Encryption != nil && cfg.Encryption.Enabled {
		if cfg.Encryption.Method != "aes-256-gcm" {
			return fmt.Errorf("unsupported encryption method %q", cfg.Encryption.Method)
		}
		key, err := decodeKey(cfg.Encryption.Key)
		if err != nil || len(key) != 32 {
			return errors.New("encryption key must be a base64 or hex encoded 32-byte key")
		}
		if cfg.MaxFileSize > 128 {
			return errors.New("max_file_size cannot exceed 128 MiB when encryption is enabled")
		}
	}
	return nil
}

func validateS3Compatible(name string, settings *S3CompatibleConfig, requireCredentials bool) error {
	if settings == nil {
		return fmt.Errorf("%s configuration is required", name)
	}
	if settings.BucketName == "" || settings.Region == "" {
		return fmt.Errorf("%s bucket_name and region are required", name)
	}
	if (settings.AccessKeyID == "") != (settings.SecretAccessKey == "") {
		return fmt.Errorf("%s access_key_id and secret_access_key must be provided together", name)
	}
	if requireCredentials && settings.AccessKeyID == "" {
		return fmt.Errorf("%s access_key_id and secret_access_key are required", name)
	}
	if settings.Endpoint != "" {
		endpoint, err := url.Parse(settings.Endpoint)
		if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
			return fmt.Errorf("%s endpoint must be an absolute HTTPS URL without credentials, query, or fragment", name)
		}
	}
	if settings.PresignLinkTimeout.Duration() < time.Second || settings.PresignLinkTimeout.Duration() > 7*24*time.Hour {
		return fmt.Errorf("%s presign timeout must be between 1 second and 7 days", name)
	}
	if settings.PresignUploadTimeout.Duration() < time.Minute || settings.PresignUploadTimeout.Duration() > 7*24*time.Hour {
		return fmt.Errorf("%s upload presign timeout must be between 1 minute and 7 days", name)
	}
	return nil
}

func DecodeEncryptionKey(value string) ([]byte, error) { return decodeKey(value) }

func decodeKey(value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("empty key")
	}
	if key, err := base64.StdEncoding.DecodeString(value); err == nil {
		return key, nil
	}
	return hex.DecodeString(value)
}

func setString(name string, target *string) {
	if value, ok := os.LookupEnv(name); ok {
		*target = value
	}
}

func setInt(name string, target *int) error {
	if value, ok := os.LookupEnv(name); ok {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("%s must be an integer: %w", name, err)
		}
		*target = parsed
	}
	return nil
}

func setInt64(name string, target *int64) error {
	if value, ok := os.LookupEnv(name); ok {
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("%s must be an integer: %w", name, err)
		}
		*target = parsed
	}
	return nil
}

func setBool(name string, target *bool) error {
	if value, ok := os.LookupEnv(name); ok {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("%s must be a boolean: %w", name, err)
		}
		*target = parsed
	}
	return nil
}

func setDuration(name string, target *Duration) error {
	if value, ok := os.LookupEnv(name); ok {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("%s must be a duration: %w", name, err)
		}
		*target = Duration(parsed)
	}
	return nil
}
