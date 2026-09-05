package config

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var Version = "dev"

func Load(path string) (*ServiceConfig, error) {
	cfg, err := readUnvalidated(path)
	if err != nil {
		return nil, err
	}
	if err := applyEnvironment(cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadBootstrap reads all legacy seed inputs but validates only settings needed
// to connect to PostgreSQL and open its authoritative runtime document.
func LoadBootstrap(path string) (*ServiceConfig, error) {
	cfg, err := readUnvalidated(path)
	if err != nil {
		return nil, err
	}
	if err := applyEnvironment(cfg); err != nil {
		cfg.seedProblems = err
		if bootstrapErr := bootstrapEnvironmentProblems(err); bootstrapErr != nil {
			return nil, bootstrapErr
		}
	}
	if cfg.Auth == nil {
		cfg.Auth = &AuthConfig{}
	}
	bootstrap := defaults()
	bootstrap.Address, bootstrap.Port, bootstrap.Timeout = cfg.Address, cfg.Port, cfg.Timeout
	bootstrap.ReadTimeout, bootstrap.WriteTimeout = cfg.ReadTimeout, cfg.WriteTimeout
	bootstrap.IdleTimeout, bootstrap.ShutdownTimeout = cfg.IdleTimeout, cfg.ShutdownTimeout
	bootstrap.Db, bootstrap.SettingsKey = cfg.Db, cfg.SettingsKey
	bootstrap.Auth.JWTSecret, bootstrap.Auth.TokenLifetime = cfg.Auth.JWTSecret, cfg.Auth.TokenLifetime
	if err := bootstrap.Validate(); err != nil {
		return nil, err
	}
	cfg.Address, cfg.Port = bootstrap.Address, bootstrap.Port
	cfg.ReadTimeout, cfg.WriteTimeout = bootstrap.ReadTimeout, bootstrap.WriteTimeout
	cfg.IdleTimeout, cfg.ShutdownTimeout = bootstrap.IdleTimeout, bootstrap.ShutdownTimeout
	cfg.Db, cfg.SettingsKey = bootstrap.Db, bootstrap.SettingsKey
	cfg.Auth.JWTSecret, cfg.Auth.TokenLifetime = bootstrap.Auth.JWTSecret, bootstrap.Auth.TokenLifetime
	return cfg, nil
}

func readUnvalidated(path string) (*ServiceConfig, error) {
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

	return cfg, nil
}

// ValidateSeed reports environment compatibility/parsing failures that are
// relevant only when legacy values are about to become the first DB revision.
func (cfg *ServiceConfig) ValidateSeed() error { return cfg.seedProblems }

func bootstrapEnvironmentProblems(err error) error {
	bootstrapNames := []string{
		"OBJECTSHARE_PORT", "OBJECTSHARE_READ_TIMEOUT", "OBJECTSHARE_WRITE_TIMEOUT", "OBJECTSHARE_IDLE_TIMEOUT", "OBJECTSHARE_SHUTDOWN_TIMEOUT",
		"OBJECTSHARE_JWT_LIFETIME", "OBJECTSHARE_DB_PORT", "OBJECTSHARE_DB_MAX_OPEN_CONNS", "OBJECTSHARE_DB_MAX_IDLE_CONNS", "OBJECTSHARE_DB_CONN_MAX_LIFETIME",
	}
	var selected []error
	var visit func(error)
	visit = func(problem error) {
		if joined, ok := problem.(interface{ Unwrap() []error }); ok {
			for _, child := range joined.Unwrap() {
				visit(child)
			}
			return
		}
		for _, name := range bootstrapNames {
			if strings.Contains(problem.Error(), name) {
				selected = append(selected, problem)
				return
			}
		}
	}
	visit(err)
	return errors.Join(selected...)
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
		Upload:          &UploadConfig{GuestEnabled: true, MaxFilesPerBatch: 10},
		Retention:       &RetentionConfig{},
		Billing:         &BillingConfig{CreditCurrency: "USD", MinTopUpCredits: 5, MaxTopUpCredits: 1000, PayPal: PayPalBillingConfig{Environment: "sandbox"}},
		Auth: &AuthConfig{
			SignupEnabled: true, TokenLifetime: Duration(12 * time.Hour), OAuth: &OAuthConfig{},
		},
		Captcha: &CaptchaConfig{Provider: "none"},
		RateLimit: &RateLimitConfig{
			Enabled: true, Window: Duration(time.Minute), APILimit: 120,
			LoginLimit: 10, SignupLimit: 5, UploadLimit: 20, DownloadLimit: 60,
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
	if cfg.Email == nil {
		cfg.Email = &EmailConfig{}
	}
	problems = append(problems, applyEmailEnvironment(cfg.Email))
	setString("OBJECTSHARE_ADDRESS", &cfg.Address)
	problems = append(problems, setInt("OBJECTSHARE_PORT", &cfg.Port))
	problems = append(problems, setDuration("OBJECTSHARE_READ_TIMEOUT", &cfg.ReadTimeout))
	problems = append(problems, setDuration("OBJECTSHARE_WRITE_TIMEOUT", &cfg.WriteTimeout))
	problems = append(problems, setDuration("OBJECTSHARE_IDLE_TIMEOUT", &cfg.IdleTimeout))
	problems = append(problems, setDuration("OBJECTSHARE_SHUTDOWN_TIMEOUT", &cfg.ShutdownTimeout))
	problems = append(problems, setInt64("OBJECTSHARE_MAX_FILE_SIZE_MB", &cfg.MaxFileSize))
	problems = append(problems, setBool("OBJECTSHARE_SECURE_COOKIES", &cfg.SecureCookies))
	setString("OBJECTSHARE_SETTINGS_KEY", &cfg.SettingsKey)
	if cfg.Upload == nil {
		cfg.Upload = &UploadConfig{GuestEnabled: true, MaxFilesPerBatch: 10}
	}
	problems = append(problems, setBool("OBJECTSHARE_GUEST_UPLOAD_ENABLED", &cfg.Upload.GuestEnabled))
	problems = append(problems, setInt("OBJECTSHARE_MAX_FILES_PER_BATCH", &cfg.Upload.MaxFilesPerBatch))
	if cfg.Retention == nil {
		cfg.Retention = &RetentionConfig{}
	}
	problems = append(problems, setInt("OBJECTSHARE_GUEST_RETENTION_DAYS", &cfg.Retention.GuestDays))
	problems = append(problems, setInt("OBJECTSHARE_UNPAID_RETENTION_DAYS", &cfg.Retention.UnpaidDays))
	if cfg.Billing == nil {
		cfg.Billing = &BillingConfig{CreditCurrency: "USD", MinTopUpCredits: 5, MaxTopUpCredits: 1000, PayPal: PayPalBillingConfig{Environment: "sandbox"}}
	}
	problems = append(problems, setBool("OBJECTSHARE_STRIPE_ENABLED", &cfg.Billing.Stripe.Enabled))
	setString("OBJECTSHARE_BILLING_PUBLIC_URL", &cfg.Billing.PublicURL)
	setString("OBJECTSHARE_BILLING_CREDIT_CURRENCY", &cfg.Billing.CreditCurrency)
	problems = append(problems, setInt64("OBJECTSHARE_BILLING_MIN_TOP_UP_CREDITS", &cfg.Billing.MinTopUpCredits))
	problems = append(problems, setInt64("OBJECTSHARE_BILLING_MAX_TOP_UP_CREDITS", &cfg.Billing.MaxTopUpCredits))
	setString("OBJECTSHARE_STRIPE_SECRET_KEY", &cfg.Billing.Stripe.SecretKey)
	setString("OBJECTSHARE_STRIPE_WEBHOOK_SECRET", &cfg.Billing.Stripe.WebhookSecret)
	problems = append(problems, setBool("OBJECTSHARE_PAYPAL_ENABLED", &cfg.Billing.PayPal.Enabled))
	setString("OBJECTSHARE_PAYPAL_ENVIRONMENT", &cfg.Billing.PayPal.Environment)
	setString("OBJECTSHARE_PAYPAL_CLIENT_ID", &cfg.Billing.PayPal.ClientID)
	setString("OBJECTSHARE_PAYPAL_CLIENT_SECRET", &cfg.Billing.PayPal.ClientSecret)
	setString("OBJECTSHARE_PAYPAL_WEBHOOK_ID", &cfg.Billing.PayPal.WebhookID)
	for _, name := range []string{
		"OBJECTSHARE_GUEST_UPLOAD_QUOTA_MB",
		"OBJECTSHARE_USER_UPLOAD_QUOTA_MB",
		"OBJECTSHARE_ADMIN_UPLOAD_QUOTA_MB",
		"OBJECTSHARE_PANEL_UPLOAD_QUOTA_MB",
	} {
		if _, exists := os.LookupEnv(name); exists {
			problems = append(problems, fmt.Errorf("%s is no longer supported; manage each account's quota in PostgreSQL or /admin/users", name))
		}
	}
	if cfg.Auth == nil {
		cfg.Auth = &AuthConfig{SignupEnabled: true, TokenLifetime: Duration(12 * time.Hour), OAuth: &OAuthConfig{}}
	}
	problems = append(problems, setBool("OBJECTSHARE_SIGNUP_ENABLED", &cfg.Auth.SignupEnabled))
	setString("OBJECTSHARE_JWT_SECRET", &cfg.Auth.JWTSecret)
	problems = append(problems, setDuration("OBJECTSHARE_JWT_LIFETIME", &cfg.Auth.TokenLifetime))
	if cfg.Auth.OAuth == nil {
		cfg.Auth.OAuth = &OAuthConfig{}
	}
	setString("OBJECTSHARE_PUBLIC_URL", &cfg.Auth.OAuth.PublicURL)
	problems = append(problems, setBool("OBJECTSHARE_GOOGLE_OAUTH_ENABLED", &cfg.Auth.OAuth.Google.Enabled))
	setString("OBJECTSHARE_GOOGLE_OAUTH_CLIENT_ID", &cfg.Auth.OAuth.Google.ClientID)
	setString("OBJECTSHARE_GOOGLE_OAUTH_CLIENT_SECRET", &cfg.Auth.OAuth.Google.ClientSecret)
	problems = append(problems, setBool("OBJECTSHARE_GITHUB_OAUTH_ENABLED", &cfg.Auth.OAuth.GitHub.Enabled))
	setString("OBJECTSHARE_GITHUB_OAUTH_CLIENT_ID", &cfg.Auth.OAuth.GitHub.ClientID)
	setString("OBJECTSHARE_GITHUB_OAUTH_CLIENT_SECRET", &cfg.Auth.OAuth.GitHub.ClientSecret)
	problems = append(problems, setBool("OBJECTSHARE_DISCORD_OAUTH_ENABLED", &cfg.Auth.OAuth.Discord.Enabled))
	setString("OBJECTSHARE_DISCORD_OAUTH_CLIENT_ID", &cfg.Auth.OAuth.Discord.ClientID)
	setString("OBJECTSHARE_DISCORD_OAUTH_CLIENT_SECRET", &cfg.Auth.OAuth.Discord.ClientSecret)
	if cfg.Captcha == nil {
		cfg.Captcha = &CaptchaConfig{Provider: "none"}
	}
	setString("OBJECTSHARE_CAPTCHA_PROVIDER", &cfg.Captcha.Provider)
	setString("OBJECTSHARE_CAPTCHA_SITE_KEY", &cfg.Captcha.SiteKey)
	setString("OBJECTSHARE_CAPTCHA_SECRET_KEY", &cfg.Captcha.SecretKey)
	setString("OBJECTSHARE_CAPTCHA_EXPECTED_HOSTNAME", &cfg.Captcha.ExpectedHostname)
	problems = append(problems, setBool("OBJECTSHARE_CAPTCHA_PROTECT_LOGIN", &cfg.Captcha.ProtectLogin))
	problems = append(problems, setBool("OBJECTSHARE_CAPTCHA_PROTECT_SIGNUP", &cfg.Captcha.ProtectSignup))
	problems = append(problems, setBool("OBJECTSHARE_CAPTCHA_PROTECT_UPLOAD", &cfg.Captcha.ProtectUpload))
	problems = append(problems, setBool("OBJECTSHARE_CAPTCHA_PROTECT_DOWNLOAD", &cfg.Captcha.ProtectDownload))
	if cfg.RateLimit == nil {
		cfg.RateLimit = &RateLimitConfig{Enabled: true, Window: Duration(time.Minute), APILimit: 120, LoginLimit: 10, SignupLimit: 5, UploadLimit: 20, DownloadLimit: 60}
	}
	problems = append(problems, setBool("OBJECTSHARE_RATE_LIMIT_ENABLED", &cfg.RateLimit.Enabled))
	problems = append(problems, setDuration("OBJECTSHARE_RATE_LIMIT_WINDOW", &cfg.RateLimit.Window))
	problems = append(problems, setInt("OBJECTSHARE_RATE_LIMIT_API", &cfg.RateLimit.APILimit))
	problems = append(problems, setInt("OBJECTSHARE_RATE_LIMIT_LOGIN", &cfg.RateLimit.LoginLimit))
	problems = append(problems, setInt("OBJECTSHARE_RATE_LIMIT_SIGNUP", &cfg.RateLimit.SignupLimit))
	problems = append(problems, setInt("OBJECTSHARE_RATE_LIMIT_UPLOAD", &cfg.RateLimit.UploadLimit))
	problems = append(problems, setInt("OBJECTSHARE_RATE_LIMIT_DOWNLOAD", &cfg.RateLimit.DownloadLimit))
	if value, ok := os.LookupEnv("OBJECTSHARE_TRUSTED_PROXY_CIDRS"); ok {
		cfg.RateLimit.TrustedProxyCIDRs = splitCSV(value)
	}
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
	if cfg.Email == nil {
		cfg.Email = &EmailConfig{}
	}
	if err := cfg.Email.Validate(); err != nil {
		return err
	}
	if cfg.Port > 0 {
		cfg.Address = ":" + strconv.Itoa(cfg.Port)
	} else if cfg.Address == "" {
		return errors.New("address or a valid port is required")
	}
	if cfg.MaxFileSize <= 0 || cfg.MaxFileSize > 10*1024 {
		return errors.New("max_file_size must be between 1 and 10240 MiB")
	}
	if cfg.Upload == nil {
		cfg.Upload = &UploadConfig{GuestEnabled: true, MaxFilesPerBatch: 10}
	}
	if cfg.Upload.MaxFilesPerBatch == 0 {
		cfg.Upload.MaxFilesPerBatch = 10
	}
	if cfg.Upload.MaxFilesPerBatch < 1 || cfg.Upload.MaxFilesPerBatch > 100 {
		return errors.New("upload max_files_per_batch must be between 1 and 100")
	}
	if cfg.Retention == nil {
		cfg.Retention = &RetentionConfig{}
	}
	if cfg.Retention.GuestDays < 0 || cfg.Retention.GuestDays > 36500 {
		return errors.New("retention guest_days must be between 0 and 36500")
	}
	if cfg.Retention.UnpaidDays < 0 || cfg.Retention.UnpaidDays > 36500 {
		return errors.New("retention unpaid_days must be between 0 and 36500")
	}
	if cfg.Billing == nil {
		cfg.Billing = &BillingConfig{CreditCurrency: "USD", MinTopUpCredits: 5, MaxTopUpCredits: 1000, PayPal: PayPalBillingConfig{Environment: "sandbox"}}
	}
	if err := validateBilling(cfg.Billing, cfg.SecureCookies); err != nil {
		return err
	}
	if cfg.Timeout > 0 && cfg.ReadTimeout == Duration(5*time.Minute) {
		cfg.ReadTimeout = Duration(time.Duration(cfg.Timeout) * time.Second)
		cfg.WriteTimeout = Duration(time.Duration(cfg.Timeout) * time.Second)
	}
	if cfg.ReadTimeout <= 0 || cfg.WriteTimeout <= 0 || cfg.IdleTimeout <= 0 || cfg.ShutdownTimeout <= 0 {
		return errors.New("all server timeouts must be positive")
	}
	if cfg.Auth == nil {
		cfg.Auth = &AuthConfig{SignupEnabled: true, TokenLifetime: Duration(12 * time.Hour), OAuth: &OAuthConfig{}}
	}
	if len(cfg.Auth.JWTSecret) < 32 || cfg.Auth.JWTSecret == "replace-with-at-least-32-random-bytes" {
		return errors.New("auth jwt_secret must contain at least 32 non-placeholder bytes")
	}
	if cfg.SettingsKey == "" {
		// Compatibility for existing installations. New deployments should use
		// an independent stable settings key so JWT rotation is possible.
		cfg.SettingsKey = cfg.Auth.JWTSecret
	}
	if len(cfg.SettingsKey) < 32 || cfg.SettingsKey == "replace-with-at-least-32-random-bytes" || cfg.SettingsKey == "replace-with-a-different-32-byte-random-secret" {
		return errors.New("settings_key must contain at least 32 non-placeholder bytes")
	}
	if cfg.Auth.TokenLifetime.Duration() < 5*time.Minute || cfg.Auth.TokenLifetime.Duration() > 24*time.Hour {
		return errors.New("auth token_lifetime must be between 5 minutes and 24 hours")
	}
	if err := validateOAuth(cfg.Auth.OAuth, cfg.SecureCookies); err != nil {
		return err
	}
	if cfg.Captcha == nil {
		cfg.Captcha = &CaptchaConfig{Provider: "none"}
	}
	cfg.Captcha.Provider = strings.ToLower(strings.TrimSpace(cfg.Captcha.Provider))
	switch cfg.Captcha.Provider {
	case "", "none":
		cfg.Captcha.Provider = "none"
		if cfg.Captcha.ProtectLogin || cfg.Captcha.ProtectSignup || cfg.Captcha.ProtectUpload || cfg.Captcha.ProtectDownload {
			return errors.New("captcha protection requires provider turnstile")
		}
	case "turnstile":
		if strings.TrimSpace(cfg.Captcha.SiteKey) == "" || strings.TrimSpace(cfg.Captcha.SecretKey) == "" {
			return errors.New("captcha site_key and secret_key are required for turnstile")
		}
		if strings.TrimSpace(cfg.Captcha.ExpectedHostname) == "" {
			return errors.New("captcha expected_hostname is required for turnstile")
		}
		if strings.ContainsAny(cfg.Captcha.ExpectedHostname, "/:@?#") {
			return errors.New("captcha expected_hostname must be a hostname without scheme, port, path, query, or fragment")
		}
		hostURL, err := url.Parse("https://" + cfg.Captcha.ExpectedHostname)
		if err != nil || hostURL.Host != cfg.Captcha.ExpectedHostname || hostURL.Hostname() != cfg.Captcha.ExpectedHostname {
			return errors.New("captcha expected_hostname must be a valid hostname")
		}
	default:
		return fmt.Errorf("unsupported captcha provider %q", cfg.Captcha.Provider)
	}
	if cfg.RateLimit == nil {
		cfg.RateLimit = &RateLimitConfig{Enabled: true, Window: Duration(time.Minute), APILimit: 120, LoginLimit: 10, SignupLimit: 5, UploadLimit: 20, DownloadLimit: 60}
	}
	if cfg.RateLimit.Window.Duration() < time.Second || cfg.RateLimit.Window.Duration() > 24*time.Hour {
		return errors.New("rate_limit window must be between 1 second and 24 hours")
	}
	for _, limit := range []struct {
		name  string
		value int
	}{
		{"api_limit", cfg.RateLimit.APILimit}, {"login_limit", cfg.RateLimit.LoginLimit},
		{"signup_limit", cfg.RateLimit.SignupLimit}, {"upload_limit", cfg.RateLimit.UploadLimit},
		{"download_limit", cfg.RateLimit.DownloadLimit},
	} {
		if limit.value < 0 || limit.value > 1_000_000 {
			return fmt.Errorf("rate_limit %s must be between 0 and 1000000", limit.name)
		}
	}
	for _, value := range cfg.RateLimit.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(value); err != nil {
			return fmt.Errorf("rate_limit trusted_proxy_cidrs contains invalid CIDR %q", value)
		}
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

func validateBilling(settings *BillingConfig, secureCookies bool) error {
	if settings == nil {
		return nil
	}
	if settings.Enabled || settings.SecretKey != "" || settings.WebhookSecret != "" {
		if settings.Enabled {
			settings.Stripe.Enabled = true
		}
		if settings.Stripe.SecretKey == "" {
			settings.Stripe.SecretKey = settings.SecretKey
		}
		if settings.Stripe.WebhookSecret == "" {
			settings.Stripe.WebhookSecret = settings.WebhookSecret
		}
		settings.Enabled, settings.SecretKey, settings.WebhookSecret = false, "", ""
	}
	if settings.PayPal.Environment == "" {
		settings.PayPal.Environment = "sandbox"
	}
	settings.CreditCurrency = strings.ToUpper(strings.TrimSpace(settings.CreditCurrency))
	if settings.CreditCurrency == "" {
		settings.CreditCurrency = "USD"
	}
	if settings.MinTopUpCredits == 0 {
		settings.MinTopUpCredits = 5
	}
	if settings.MaxTopUpCredits == 0 {
		settings.MaxTopUpCredits = 1000
	}
	if !supportedCreditCurrency(settings.CreditCurrency) {
		return errors.New("billing credit_currency must be a supported two-decimal currency")
	}
	if settings.MinTopUpCredits < 1 || settings.MaxTopUpCredits < settings.MinTopUpCredits || settings.MaxTopUpCredits > 1_000_000 {
		return errors.New("billing credit top-up range must be between 1 and 1000000 credits")
	}
	if settings.Stripe.Enabled {
		validStripeKey := strings.HasPrefix(settings.Stripe.SecretKey, "sk_") || strings.HasPrefix(settings.Stripe.SecretKey, "rk_")
		if !validStripeKey || !strings.HasPrefix(settings.Stripe.WebhookSecret, "whsec_") {
			return errors.New("billing Stripe gateway requires secret_key and webhook_secret")
		}
	}
	settings.PayPal.Environment = strings.ToLower(strings.TrimSpace(settings.PayPal.Environment))
	settings.PayPal.ClientID = strings.TrimSpace(settings.PayPal.ClientID)
	settings.PayPal.WebhookID = strings.TrimSpace(settings.PayPal.WebhookID)
	if settings.PayPal.Environment != "sandbox" && settings.PayPal.Environment != "live" {
		return errors.New("billing PayPal environment must be sandbox or live")
	}
	if settings.PayPal.Enabled && (settings.PayPal.ClientID == "" || strings.TrimSpace(settings.PayPal.ClientSecret) == "" || settings.PayPal.WebhookID == "") {
		return errors.New("billing PayPal gateway requires client_id, client_secret, and webhook_id")
	}
	if !settings.Stripe.Enabled && !settings.PayPal.Enabled {
		return nil
	}
	if strings.TrimSpace(settings.PublicURL) == "" {
		return errors.New("billing public_url is required when a gateway is enabled")
	}
	publicURL, err := url.Parse(settings.PublicURL)
	if err != nil || publicURL.Host == "" || publicURL.User != nil || publicURL.RawQuery != "" || publicURL.Fragment != "" || (publicURL.Path != "" && publicURL.Path != "/") {
		return errors.New("billing public_url must be an absolute origin without credentials, path, query, or fragment")
	}
	hostname := strings.ToLower(publicURL.Hostname())
	localHTTP := publicURL.Scheme == "http" && (hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1")
	if publicURL.Scheme != "https" && !localHTTP {
		return errors.New("billing public_url must use HTTPS except on localhost")
	}
	if publicURL.Scheme == "https" && !secureCookies {
		return errors.New("secure_cookies must be true when billing uses an HTTPS public_url")
	}
	settings.PublicURL = strings.TrimSuffix(settings.PublicURL, "/")
	return nil
}

func supportedCreditCurrency(currency string) bool {
	switch currency {
	case "AUD", "BRL", "CAD", "CHF", "CNY", "CZK", "DKK", "EUR", "GBP", "HKD", "ILS", "MXN", "MYR", "NOK", "NZD", "PHP", "PLN", "SEK", "SGD", "THB", "USD":
		return true
	default:
		return false
	}
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func validateOAuth(settings *OAuthConfig, secureCookies bool) error {
	if settings == nil {
		return nil
	}
	providers := []struct {
		name     string
		settings OAuthProviderConfig
	}{
		{"google", settings.Google},
		{"github", settings.GitHub},
		{"discord", settings.Discord},
	}
	anyEnabled := false
	for _, provider := range providers {
		hasID := strings.TrimSpace(provider.settings.ClientID) != ""
		hasSecret := provider.settings.ClientSecret != ""
		if hasID != hasSecret {
			return fmt.Errorf("auth oauth %s client_id and client_secret must be provided together", provider.name)
		}
		if provider.settings.Enabled && !hasID {
			return fmt.Errorf("auth oauth %s requires client_id and client_secret when enabled", provider.name)
		}
		anyEnabled = anyEnabled || provider.settings.Enabled
	}
	if !anyEnabled {
		return nil
	}
	publicURL, err := url.Parse(settings.PublicURL)
	if err != nil || publicURL.Host == "" || publicURL.User != nil || publicURL.RawQuery != "" || publicURL.Fragment != "" || (publicURL.Path != "" && publicURL.Path != "/") {
		return errors.New("auth oauth public_url must be an absolute origin without credentials, path, query, or fragment")
	}
	hostname := strings.ToLower(publicURL.Hostname())
	localHTTP := publicURL.Scheme == "http" && (hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1")
	if publicURL.Scheme != "https" && !localHTTP {
		return errors.New("auth oauth public_url must use HTTPS except on localhost")
	}
	if publicURL.Scheme == "https" && !secureCookies {
		return errors.New("secure_cookies must be true when OAuth uses an HTTPS public_url")
	}
	settings.PublicURL = strings.TrimSuffix(settings.PublicURL, "/")
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
