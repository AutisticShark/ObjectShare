package config

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

const testJWTSecret = "test-only-jwt-secret-with-at-least-32-bytes"

func testDefaults() *ServiceConfig {
	cfg := defaults()
	cfg.Auth.JWTSecret = testJWTSecret
	return cfg
}

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
	cfg := testDefaults()
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
			cfg := testDefaults()
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
			cfg := testDefaults()
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

	cfg := testDefaults()
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
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "jwt_secret") {
		t.Fatalf("defaults without a deployment JWT secret should fail: %v", err)
	}
	if err := testDefaults().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticationEnvironmentAndLifetimeValidation(t *testing.T) {
	t.Setenv("OBJECTSHARE_SIGNUP_ENABLED", "false")
	t.Setenv("OBJECTSHARE_JWT_LIFETIME", "8h")
	cfg := testDefaults()
	if err := applyEnvironment(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Auth.SignupEnabled || cfg.Auth.TokenLifetime.Duration() != 8*time.Hour {
		t.Fatalf("authentication environment was not applied: %#v", cfg.Auth)
	}
	for _, lifetime := range []time.Duration{time.Minute, 31 * 24 * time.Hour} {
		cfg := testDefaults()
		cfg.Auth.TokenLifetime = Duration(lifetime)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "token_lifetime") {
			t.Fatalf("lifetime %s error = %v", lifetime, err)
		}
	}
}

func TestCaptchaEnvironmentAndValidation(t *testing.T) {
	t.Setenv("OBJECTSHARE_CAPTCHA_PROVIDER", "turnstile")
	t.Setenv("OBJECTSHARE_CAPTCHA_SITE_KEY", "public-site-key")
	t.Setenv("OBJECTSHARE_CAPTCHA_SECRET_KEY", "private-secret-key")
	t.Setenv("OBJECTSHARE_CAPTCHA_EXPECTED_HOSTNAME", "share.example.com")
	t.Setenv("OBJECTSHARE_CAPTCHA_PROTECT_LOGIN", "true")
	t.Setenv("OBJECTSHARE_CAPTCHA_PROTECT_SIGNUP", "true")
	t.Setenv("OBJECTSHARE_CAPTCHA_PROTECT_UPLOAD", "true")
	t.Setenv("OBJECTSHARE_CAPTCHA_PROTECT_DOWNLOAD", "true")
	cfg := testDefaults()
	if err := applyEnvironment(cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Captcha.Provider != "turnstile" || !cfg.Captcha.ProtectLogin || !cfg.Captcha.ProtectSignup || !cfg.Captcha.ProtectUpload || !cfg.Captcha.ProtectDownload {
		t.Fatalf("CAPTCHA environment was not applied: %#v", cfg.Captcha)
	}

	for _, test := range []struct {
		name     string
		settings *CaptchaConfig
		want     string
	}{
		{"missing keys", &CaptchaConfig{Provider: "turnstile", ProtectLogin: true}, "site_key and secret_key"},
		{"missing hostname", &CaptchaConfig{Provider: "turnstile", SiteKey: "site", SecretKey: "secret"}, "expected_hostname is required"},
		{"protection without provider", &CaptchaConfig{Provider: "none", ProtectUpload: true}, "requires provider turnstile"},
		{"unsafe hostname", &CaptchaConfig{Provider: "turnstile", SiteKey: "site", SecretKey: "secret", ExpectedHostname: "https://share.example.com"}, "expected_hostname"},
		{"unsupported provider", &CaptchaConfig{Provider: "recaptcha"}, "unsupported captcha provider"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := testDefaults()
			cfg.Captcha = test.settings
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestStripeBillingEnvironmentAndValidation(t *testing.T) {
	t.Setenv("OBJECTSHARE_STRIPE_ENABLED", "true")
	t.Setenv("OBJECTSHARE_BILLING_PUBLIC_URL", "https://share.example.com")
	t.Setenv("OBJECTSHARE_STRIPE_SECRET_KEY", "sk_test_example")
	t.Setenv("OBJECTSHARE_STRIPE_WEBHOOK_SECRET", "whsec_example")
	t.Setenv("OBJECTSHARE_BILLING_CREDIT_CURRENCY", "eur")
	t.Setenv("OBJECTSHARE_BILLING_MIN_TOP_UP_CREDITS", "10")
	t.Setenv("OBJECTSHARE_BILLING_MAX_TOP_UP_CREDITS", "500")
	cfg := testDefaults()
	cfg.SecureCookies = true
	if err := applyEnvironment(cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if !cfg.Billing.Stripe.Enabled || cfg.Billing.PublicURL != "https://share.example.com" || cfg.Billing.CreditCurrency != "EUR" || cfg.Billing.MinTopUpCredits != 10 || cfg.Billing.MaxTopUpCredits != 500 {
		t.Fatalf("billing environment was not applied: %#v", cfg.Billing)
	}

	for _, test := range []struct {
		name    string
		billing *BillingConfig
		secure  bool
		want    string
	}{
		{"missing secret", &BillingConfig{PublicURL: "https://share.example.com", Stripe: StripeBillingConfig{Enabled: true, SecretKey: "sk_test_example"}}, true, "webhook_secret"},
		{"unsafe origin", &BillingConfig{PublicURL: "http://share.example.com", Stripe: StripeBillingConfig{Enabled: true, SecretKey: "sk_test_example", WebhookSecret: "whsec_example"}}, false, "must use HTTPS"},
		{"insecure cookie", &BillingConfig{PublicURL: "https://share.example.com", Stripe: StripeBillingConfig{Enabled: true, SecretKey: "sk_test_example", WebhookSecret: "whsec_example"}}, false, "secure_cookies"},
		{"incomplete paypal", &BillingConfig{PublicURL: "https://share.example.com", PayPal: PayPalBillingConfig{Enabled: true, Environment: "live", ClientID: "client"}}, true, "client_secret"},
		{"invalid paypal environment", &BillingConfig{PayPal: PayPalBillingConfig{Environment: "staging"}}, true, "environment"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := testDefaults()
			candidate.Billing, candidate.SecureCookies = test.billing, test.secure
			if err := candidate.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want %q", err, test.want)
			}
		})
	}
}

func TestCreditBillingDefaultsAndValidation(t *testing.T) {
	cfg := testDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Billing.CreditCurrency != "USD" || cfg.Billing.MinTopUpCredits != 5 || cfg.Billing.MaxTopUpCredits != 1000 {
		t.Fatalf("credit defaults=%#v", cfg.Billing)
	}
	for _, test := range []struct {
		name, currency   string
		minimum, maximum int64
	}{
		{name: "unsupported currency", currency: "JPY", minimum: 5, maximum: 10},
		{name: "inverted bounds", currency: "USD", minimum: 20, maximum: 10},
		{name: "excessive maximum", currency: "USD", minimum: 1, maximum: 1_000_001},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := testDefaults()
			candidate.Billing.CreditCurrency, candidate.Billing.MinTopUpCredits, candidate.Billing.MaxTopUpCredits = test.currency, test.minimum, test.maximum
			if err := candidate.Validate(); err == nil || !strings.Contains(err.Error(), "billing") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestPayPalBillingEnvironmentAndLegacyStripeMigration(t *testing.T) {
	t.Setenv("OBJECTSHARE_PAYPAL_ENABLED", "true")
	t.Setenv("OBJECTSHARE_PAYPAL_ENVIRONMENT", "sandbox")
	t.Setenv("OBJECTSHARE_PAYPAL_CLIENT_ID", "paypal-client")
	t.Setenv("OBJECTSHARE_PAYPAL_CLIENT_SECRET", "paypal-secret")
	t.Setenv("OBJECTSHARE_PAYPAL_WEBHOOK_ID", "paypal-webhook")
	t.Setenv("OBJECTSHARE_BILLING_PUBLIC_URL", "http://localhost:8080")
	cfg := testDefaults()
	if err := applyEnvironment(cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if !cfg.Billing.PayPal.Enabled || cfg.Billing.PayPal.ClientID != "paypal-client" || cfg.Billing.PayPal.Environment != "sandbox" {
		t.Fatalf("PayPal environment was not applied: %#v", cfg.Billing.PayPal)
	}

	both := testDefaults()
	both.SecureCookies = true
	both.Billing = &BillingConfig{PublicURL: "https://share.example.com",
		Stripe: StripeBillingConfig{Enabled: true, SecretKey: "rk_live_example", WebhookSecret: "whsec_example"},
		PayPal: PayPalBillingConfig{Enabled: true, Environment: "live", ClientID: "client", ClientSecret: "secret", WebhookID: "webhook"},
	}
	if err := both.Validate(); err != nil {
		t.Fatalf("independently configured gateways were rejected: %v", err)
	}

	legacy := testDefaults()
	if err := json.Unmarshal([]byte(`{"billing":{"enabled":true,"public_url":"http://localhost:8080","secret_key":"sk_test_legacy","webhook_secret":"whsec_legacy"}}`), legacy); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Validate(); err != nil {
		t.Fatal(err)
	}
	if !legacy.Billing.Stripe.Enabled || legacy.Billing.Stripe.SecretKey != "sk_test_legacy" || legacy.Billing.Enabled || legacy.Billing.SecretKey != "" {
		t.Fatalf("legacy Stripe configuration was not migrated: %#v", legacy.Billing)
	}
}

func TestRateLimitEnvironmentDefaultsAndValidation(t *testing.T) {
	cfg := testDefaults()
	if err := json.Unmarshal([]byte(`{"rate_limit":{"upload_limit":7}}`), cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.RateLimit.Enabled || cfg.RateLimit.APILimit != 120 || cfg.RateLimit.UploadLimit != 7 {
		t.Fatalf("partial rate-limit JSON discarded defaults: %#v", cfg.RateLimit)
	}

	t.Setenv("OBJECTSHARE_RATE_LIMIT_ENABLED", "true")
	t.Setenv("OBJECTSHARE_RATE_LIMIT_WINDOW", "2m")
	t.Setenv("OBJECTSHARE_RATE_LIMIT_API", "200")
	t.Setenv("OBJECTSHARE_RATE_LIMIT_LOGIN", "8")
	t.Setenv("OBJECTSHARE_RATE_LIMIT_SIGNUP", "4")
	t.Setenv("OBJECTSHARE_RATE_LIMIT_UPLOAD", "12")
	t.Setenv("OBJECTSHARE_RATE_LIMIT_DOWNLOAD", "40")
	t.Setenv("OBJECTSHARE_TRUSTED_PROXY_CIDRS", "10.0.0.0/8, 2001:db8::/32")
	cfg = testDefaults()
	if err := applyEnvironment(cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.RateLimit.Window.Duration() != 2*time.Minute || cfg.RateLimit.APILimit != 200 || len(cfg.RateLimit.TrustedProxyCIDRs) != 2 {
		t.Fatalf("rate-limit environment was not applied: %#v", cfg.RateLimit)
	}

	for _, mutate := range []func(*RateLimitConfig){
		func(settings *RateLimitConfig) { settings.Window = Duration(500 * time.Millisecond) },
		func(settings *RateLimitConfig) { settings.DownloadLimit = -1 },
		func(settings *RateLimitConfig) { settings.TrustedProxyCIDRs = []string{"not-a-cidr"} },
	} {
		cfg := testDefaults()
		mutate(cfg.RateLimit)
		if err := cfg.Validate(); err == nil {
			t.Fatalf("invalid rate-limit configuration was accepted: %#v", cfg.RateLimit)
		}
	}
}

func TestGuestUploadPolicyAndQuotaConfigRejection(t *testing.T) {
	defaultsConfig := testDefaults()
	if defaultsConfig.Upload == nil || !defaultsConfig.Upload.GuestEnabled {
		t.Fatalf("guest uploads should remain enabled by default: %#v", defaultsConfig.Upload)
	}
	if err := json.Unmarshal([]byte(`{"upload":{"guest_enabled":false}}`), defaultsConfig); err != nil {
		t.Fatal(err)
	}
	if defaultsConfig.Upload.GuestEnabled {
		t.Fatalf("partial JSON upload settings discarded defaults: %#v", defaultsConfig.Upload)
	}

	t.Setenv("OBJECTSHARE_GUEST_UPLOAD_ENABLED", "false")
	cfg := testDefaults()
	if err := applyEnvironment(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Upload.GuestEnabled {
		t.Fatalf("guest upload environment was not applied: %#v", cfg.Upload)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OBJECTSHARE_USER_UPLOAD_QUOTA_MB", "25")
	if err := applyEnvironment(testDefaults()); err == nil || !strings.Contains(err.Error(), "OBJECTSHARE_USER_UPLOAD_QUOTA_MB is no longer supported") {
		t.Fatalf("legacy quota environment variable was silently accepted: %v", err)
	}

	path := t.TempDir() + "/legacy-quota.json"
	if err := os.WriteFile(path, []byte(`{"upload":{"guest_enabled":true,"user_quota_mib":25}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := readJSON(path, testDefaults()); err == nil || !strings.Contains(err.Error(), "unknown field \"user_quota_mib\"") {
		t.Fatalf("configuration-backed quota was accepted: %v", err)
	}
}

func TestRetentionDefaultsEnvironmentAndValidation(t *testing.T) {
	cfg := testDefaults()
	if cfg.Retention == nil || cfg.Retention.GuestDays != 0 || cfg.Retention.UnpaidDays != 0 {
		t.Fatalf("retention must default to non-destructive disabled values: %#v", cfg.Retention)
	}
	t.Setenv("OBJECTSHARE_GUEST_RETENTION_DAYS", "7")
	t.Setenv("OBJECTSHARE_UNPAID_RETENTION_DAYS", "30")
	if err := applyEnvironment(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Retention.GuestDays != 7 || cfg.Retention.UnpaidDays != 30 {
		t.Fatalf("retention environment was not applied: %#v", cfg.Retention)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, settings := range []*RetentionConfig{{GuestDays: -1}, {UnpaidDays: 36501}} {
		candidate := testDefaults()
		candidate.Retention = settings
		if err := candidate.Validate(); err == nil || !strings.Contains(err.Error(), "retention") {
			t.Fatalf("invalid retention configuration was accepted: %#v", settings)
		}
	}
}

func TestOAuthEnvironmentAndValidation(t *testing.T) {
	t.Setenv("OBJECTSHARE_PUBLIC_URL", "https://share.example.com")
	t.Setenv("OBJECTSHARE_SECURE_COOKIES", "true")
	t.Setenv("OBJECTSHARE_GOOGLE_OAUTH_ENABLED", "true")
	t.Setenv("OBJECTSHARE_GOOGLE_OAUTH_CLIENT_ID", "google-client")
	t.Setenv("OBJECTSHARE_GOOGLE_OAUTH_CLIENT_SECRET", "google-secret")
	t.Setenv("OBJECTSHARE_GITHUB_OAUTH_ENABLED", "true")
	t.Setenv("OBJECTSHARE_GITHUB_OAUTH_CLIENT_ID", "github-client")
	t.Setenv("OBJECTSHARE_GITHUB_OAUTH_CLIENT_SECRET", "github-secret")
	t.Setenv("OBJECTSHARE_DISCORD_OAUTH_ENABLED", "true")
	t.Setenv("OBJECTSHARE_DISCORD_OAUTH_CLIENT_ID", "discord-client")
	t.Setenv("OBJECTSHARE_DISCORD_OAUTH_CLIENT_SECRET", "discord-secret")
	cfg := testDefaults()
	if err := applyEnvironment(cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Auth.OAuth.PublicURL != "https://share.example.com" || !cfg.Auth.OAuth.Google.Enabled || !cfg.Auth.OAuth.GitHub.Enabled || !cfg.Auth.OAuth.Discord.Enabled {
		t.Fatalf("OAuth environment was not applied: %#v", cfg.Auth.OAuth)
	}
}

func TestOAuthRejectsPartialCredentialsAndUnsafePublicURL(t *testing.T) {
	for _, test := range []struct {
		name, publicURL, clientID, clientSecret, want string
	}{
		{"partial credentials", "https://share.example.com", "client", "", "provided together"},
		{"insecure public URL", "http://share.example.com", "client", "secret", "must use HTTPS"},
		{"public URL path", "https://share.example.com/objectshare", "client", "secret", "without credentials, path"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := testDefaults()
			cfg.SecureCookies = true
			cfg.Auth.OAuth = &OAuthConfig{PublicURL: test.publicURL, Google: OAuthProviderConfig{Enabled: true, ClientID: test.clientID, ClientSecret: test.clientSecret}}
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("OAuth validation error = %v, want %q", err, test.want)
			}
		})
	}
	cfg := testDefaults()
	cfg.Auth.OAuth = &OAuthConfig{PublicURL: "http://localhost:8080/", GitHub: OAuthProviderConfig{Enabled: true, ClientID: "client", ClientSecret: "secret"}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("localhost OAuth URL should be accepted: %v", err)
	}
	cfg = testDefaults()
	cfg.Auth.OAuth = &OAuthConfig{PublicURL: "https://share.example.com", Google: OAuthProviderConfig{Enabled: true, ClientID: "client", ClientSecret: "secret"}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "secure_cookies") {
		t.Fatalf("HTTPS OAuth without secure cookies error = %v", err)
	}
	cfg = testDefaults()
	cfg.SecureCookies = true
	cfg.Auth.OAuth = &OAuthConfig{PublicURL: "https://share.example.com", Discord: OAuthProviderConfig{Enabled: true, ClientID: "client"}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "auth oauth discord") {
		t.Fatalf("partial Discord OAuth credentials error = %v", err)
	}
}

func TestAuthenticationRejectsDocumentedPlaceholderSecret(t *testing.T) {
	cfg := testDefaults()
	cfg.Auth.JWTSecret = "replace-with-at-least-32-random-bytes"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "non-placeholder") {
		t.Fatalf("placeholder JWT secret error = %v", err)
	}
}

func TestExampleConfiguration(t *testing.T) {
	t.Setenv("OBJECTSHARE_JWT_SECRET", testJWTSecret)
	t.Setenv("OBJECTSHARE_SETTINGS_KEY", "a-separate-test-settings-key-with-at-least-32-bytes")
	cfg, err := Load("../config.json.example")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Address != ":8080" || cfg.Db.Port != 5432 {
		t.Fatalf("unexpected example configuration: %#v", cfg)
	}
}

func TestEncryptionMemoryLimit(t *testing.T) {
	cfg := testDefaults()
	cfg.MaxFileSize = 129
	cfg.Encryption.Enabled = true
	cfg.Encryption.Key = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected encrypted upload limit error")
	}
}
