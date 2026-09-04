package htmx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

func TestSettingsFormPreservesAndExplicitlyClearsWriteOnlySecrets(t *testing.T) {
	runtime := config.RuntimeConfig{
		Captcha: config.CaptchaConfig{SecretKey: "existing-captcha"},
		Billing: config.BillingConfig{PayPal: config.PayPalBillingConfig{ClientSecret: "existing-paypal"}},
		Auth: config.RuntimeAuthConfig{OAuth: config.OAuthConfig{
			Google:  config.OAuthProviderConfig{ClientSecret: "existing-google"},
			Discord: config.OAuthProviderConfig{ClientSecret: "existing-discord"},
		}},
		R2:         config.R2Config{AccessKeyID: "existing-access", SecretAccessKey: "existing-storage"},
		Encryption: config.EncryptionConfig{Key: "existing-encryption"},
	}
	request := httptest.NewRequest("POST", "/admin/settings", strings.NewReader(url.Values{
		"captcha_secret_key":          {""},
		"google_oauth_client_secret":  {""},
		"discord_oauth_client_secret": {""},
		"clear_discord_oauth_secret":  {"on"},
		"paypal_client_secret":        {""},
		"r2_access_key_id":            {"replacement-access"},
		"r2_secret_access_key":        {""},
		"encryption_key":              {""},
		"clear_encryption_key":        {"on"},
	}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := request.ParseForm(); err != nil {
		t.Fatal(err)
	}
	runtime.Captcha.SecretKey = updatedSecret(request, "captcha_secret_key", "clear_captcha_secret", runtime.Captcha.SecretKey)
	runtime.Auth.OAuth.Google.ClientSecret = updatedSecret(request, "google_oauth_client_secret", "clear_google_oauth_secret", runtime.Auth.OAuth.Google.ClientSecret)
	runtime.Auth.OAuth.Discord.ClientSecret = updatedSecret(request, "discord_oauth_client_secret", "clear_discord_oauth_secret", runtime.Auth.OAuth.Discord.ClientSecret)
	runtime.Billing.PayPal.ClientSecret = updatedSecret(request, "paypal_client_secret", "clear_paypal_client_secret", runtime.Billing.PayPal.ClientSecret)
	runtime.R2.AccessKeyID = updatedSecret(request, "r2_access_key_id", "clear_r2_access_key", runtime.R2.AccessKeyID)
	runtime.R2.SecretAccessKey = updatedSecret(request, "r2_secret_access_key", "clear_r2_secret_key", runtime.R2.SecretAccessKey)
	runtime.Encryption.Key = updatedSecret(request, "encryption_key", "clear_encryption_key", runtime.Encryption.Key)
	if runtime.Captcha.SecretKey != "existing-captcha" || runtime.Auth.OAuth.Google.ClientSecret != "existing-google" || runtime.Billing.PayPal.ClientSecret != "existing-paypal" || runtime.R2.SecretAccessKey != "existing-storage" {
		t.Fatal("blank write-only fields did not preserve stored secrets")
	}
	if runtime.R2.AccessKeyID != "replacement-access" || runtime.Auth.OAuth.Discord.ClientSecret != "" || runtime.Encryption.Key != "" {
		t.Fatal("secret replacement or explicit clearing failed")
	}
}

func TestSettingsConflictDoesNotOverwriteNewerRevision(t *testing.T) {
	repository := newAuthMemoryRepository()
	repository.setting = &db.ApplicationSetting{Value: "newer"}
	if err := repository.SaveApplicationSettings(t.Context(), "replacement", "admin@example.com", "stale"); !errors.Is(err, db.ErrConflict) {
		t.Fatalf("stale settings update returned %v", err)
	}
	if repository.setting.Value != "newer" {
		t.Fatal("stale settings update overwrote the newer revision")
	}
}

func TestDatabaseSettingsReaderMigratesLegacyStripeDocument(t *testing.T) {
	t.Setenv("OBJECTSHARE_JWT_SECRET", "settings-test-jwt-secret-with-at-least-32-bytes")
	t.Setenv("OBJECTSHARE_SETTINGS_KEY", "settings-test-settings-key-with-at-least-32-bytes")
	cfg, err := config.Load("../../config.json.example")
	if err != nil {
		t.Fatal(err)
	}
	legacy := config.RuntimeFromService(cfg)
	legacy.Billing = config.BillingConfig{Enabled: true, PublicURL: "http://localhost:8080", SecretKey: "sk_test_legacy", WebhookSecret: "whsec_legacy"}
	sealed, err := config.SealRuntime(legacy, cfg.SettingsKey)
	if err != nil {
		t.Fatal(err)
	}
	repository := newAuthMemoryRepository()
	repository.setting = &db.ApplicationSetting{Value: sealed}
	handler := &Handler{config: cfg, settings: repository, settingsKey: cfg.SettingsKey}
	request := httptest.NewRequest(http.MethodGet, "/admin/settings", nil)
	_, runtime, err := handler.readDatabaseSettings(request)
	if err != nil {
		t.Fatal(err)
	}
	if !runtime.Billing.Stripe.Enabled || runtime.Billing.Stripe.SecretKey != "sk_test_legacy" || runtime.Billing.Enabled {
		t.Fatalf("legacy settings were not normalized: %#v", runtime.Billing)
	}
}

func TestAdminConfigurationDashboardKeepsSecretsWriteOnlyAndSavesRevision(t *testing.T) {
	t.Setenv("OBJECTSHARE_JWT_SECRET", "dashboard-test-jwt-secret-with-at-least-32-bytes")
	t.Setenv("OBJECTSHARE_SETTINGS_KEY", "dashboard-test-settings-key-with-at-least-32-bytes")
	cfg, err := config.Load("../../config.json.example")
	if err != nil {
		t.Fatal(err)
	}
	cfg.RateLimit.Enabled = false
	runtime := config.RuntimeFromService(cfg)
	runtime.Captcha.SecretKey = "never-render-this-turnstile-secret"
	runtime.Auth.OAuth.Discord.ClientID = "discord-client"
	runtime.Auth.OAuth.Discord.ClientSecret = "never-render-this-discord-secret"
	runtime.Billing.PayPal.ClientSecret = "never-render-this-paypal-secret"
	runtime.R2.AccessKeyID = "never-render-this-storage-access-key"
	sealed, err := config.SealRuntime(runtime, cfg.SettingsKey)
	if err != nil {
		t.Fatal(err)
	}
	repository := newAuthMemoryRepository()
	repository.setting = &db.ApplicationSetting{Key: "runtime_config", Value: sealed, UpdatedBy: "bootstrap import", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	admin := &db.User{ID: "admin", Email: "admin@example.com", DisplayName: "Admin", Role: db.RoleAdmin, Active: true, TokenVersion: 1}
	repository.users[admin.ID] = admin
	handler, err := New(cfg, repository, &memoryStorage{objects: make(map[string][]byte)}, os.DirFS("../.."), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	claims := &appauth.Claims{CSRF: "signed-csrf"}

	getRequest := httptest.NewRequest(http.MethodGet, "/admin/settings", nil)
	getRequest = getRequest.WithContext(context.WithValue(getRequest.Context(), identityContextKey{}, &identity{User: admin, Claims: claims, Transport: transportCookie}))
	getResponse := httptest.NewRecorder()
	handler.AdminSettings(getResponse, getRequest)
	if getResponse.Code != http.StatusOK || !strings.Contains(getResponse.Body.String(), "Configuration dashboard") || !strings.Contains(getResponse.Body.String(), "configured") {
		t.Fatalf("dashboard response = %d, %q", getResponse.Code, getResponse.Body.String())
	}
	if strings.Contains(getResponse.Body.String(), runtime.Captcha.SecretKey) {
		t.Fatal("dashboard rendered a stored secret")
	}
	if strings.Contains(getResponse.Body.String(), runtime.R2.AccessKeyID) {
		t.Fatal("dashboard rendered a stored access key")
	}
	if strings.Contains(getResponse.Body.String(), runtime.Auth.OAuth.Discord.ClientSecret) {
		t.Fatal("dashboard rendered a stored Discord secret")
	}
	if strings.Contains(getResponse.Body.String(), runtime.Billing.PayPal.ClientSecret) {
		t.Fatal("dashboard rendered a stored PayPal secret")
	}

	values := runtimeFormValues(runtime)
	values.Set("csrf_token", claims.CSRF)
	values.Set("revision", settingsRevision(repository.setting.Value))
	values.Set("max_file_size", "77")
	values.Set("guest_retention_days", "7")
	values.Set("unpaid_retention_days", "30")
	values.Set("captcha_secret_key", "")
	postRequest := httptest.NewRequest(http.MethodPost, "/admin/settings", strings.NewReader(values.Encode()))
	postRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postRequest = postRequest.WithContext(context.WithValue(postRequest.Context(), identityContextKey{}, &identity{User: admin, Claims: claims, Transport: transportCookie}))
	postResponse := httptest.NewRecorder()
	handler.AdminSaveSettings(postResponse, postRequest)
	if postResponse.Code != http.StatusSeeOther {
		t.Fatalf("save response = %d, %q", postResponse.Code, postResponse.Body.String())
	}
	saved, err := config.OpenRuntime(repository.setting.Value, cfg.SettingsKey)
	if err != nil {
		t.Fatal(err)
	}
	if saved.MaxFileSize != 77 || saved.Retention.GuestDays != 7 || saved.Retention.UnpaidDays != 30 || saved.Captcha.SecretKey != runtime.Captcha.SecretKey || saved.Auth.OAuth.Discord.ClientSecret != runtime.Auth.OAuth.Discord.ClientSecret || saved.Billing.PayPal.ClientSecret != runtime.Billing.PayPal.ClientSecret {
		t.Fatalf("saved runtime lost values or secrets: %#v", saved)
	}
	if handler.config.MaxFileSize == 77 {
		t.Fatal("restart-required configuration was applied partially in process")
	}

	staleValues := runtimeFormValues(runtime)
	staleValues.Set("csrf_token", claims.CSRF)
	staleValues.Set("revision", settingsRevision(sealed))
	staleValues.Set("max_file_size", "88")
	staleRequest := httptest.NewRequest(http.MethodPost, "/admin/settings", strings.NewReader(staleValues.Encode()))
	staleRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	staleRequest = staleRequest.WithContext(context.WithValue(staleRequest.Context(), identityContextKey{}, &identity{User: admin, Claims: claims, Transport: transportCookie}))
	staleResponse := httptest.NewRecorder()
	handler.AdminSaveSettings(staleResponse, staleRequest)
	if staleResponse.Code != http.StatusOK || !strings.Contains(staleResponse.Body.String(), "changed in another administrator session") {
		t.Fatalf("stale save response = %d, %q", staleResponse.Code, staleResponse.Body.String())
	}
	stillSaved, err := config.OpenRuntime(repository.setting.Value, cfg.SettingsKey)
	if err != nil || stillSaved.MaxFileSize != 77 {
		t.Fatalf("stale form overwrote newer configuration: size=%d err=%v", stillSaved.MaxFileSize, err)
	}
}

func runtimeFormValues(runtime config.RuntimeConfig) url.Values {
	values := url.Values{
		"max_file_size": {fmt.Sprint(runtime.MaxFileSize)}, "guest_retention_days": {fmt.Sprint(runtime.Retention.GuestDays)}, "unpaid_retention_days": {fmt.Sprint(runtime.Retention.UnpaidDays)}, "oauth_public_url": {runtime.Auth.OAuth.PublicURL},
		"billing_public_url": {runtime.Billing.PublicURL}, "paypal_environment": {runtime.Billing.PayPal.Environment}, "paypal_client_id": {runtime.Billing.PayPal.ClientID}, "paypal_webhook_id": {runtime.Billing.PayPal.WebhookID},
		"google_oauth_client_id": {runtime.Auth.OAuth.Google.ClientID}, "github_oauth_client_id": {runtime.Auth.OAuth.GitHub.ClientID}, "discord_oauth_client_id": {runtime.Auth.OAuth.Discord.ClientID},
		"captcha_provider": {runtime.Captcha.Provider}, "captcha_site_key": {runtime.Captcha.SiteKey}, "captcha_expected_hostname": {runtime.Captcha.ExpectedHostname},
		"rate_limit_window": {runtime.RateLimit.Window.String()}, "rate_limit_api": {fmt.Sprint(runtime.RateLimit.APILimit)}, "rate_limit_login": {fmt.Sprint(runtime.RateLimit.LoginLimit)}, "rate_limit_signup": {fmt.Sprint(runtime.RateLimit.SignupLimit)}, "rate_limit_upload": {fmt.Sprint(runtime.RateLimit.UploadLimit)}, "rate_limit_download": {fmt.Sprint(runtime.RateLimit.DownloadLimit)}, "trusted_proxy_cidrs": {strings.Join(runtime.RateLimit.TrustedProxyCIDRs, ",")},
		"storage_service": {runtime.StorageService}, "storage_path": {runtime.StoragePath},
		"r2_bucket_name": {runtime.R2.BucketName}, "r2_account_id": {runtime.R2.AccountID}, "r2_endpoint": {runtime.R2.Endpoint}, "r2_region": {runtime.R2.Region}, "r2_presign_timeout": {runtime.R2.PresignLinkTimeout.String()}, "r2_upload_presign_timeout": {runtime.R2.PresignUploadTimeout.String()},
		"s3_bucket_name": {runtime.S3.BucketName}, "s3_endpoint": {runtime.S3.Endpoint}, "s3_region": {runtime.S3.Region}, "s3_presign_timeout": {runtime.S3.PresignLinkTimeout.String()}, "s3_upload_presign_timeout": {runtime.S3.PresignUploadTimeout.String()},
		"b2_bucket_name": {runtime.B2.BucketName}, "b2_endpoint": {runtime.B2.Endpoint}, "b2_region": {runtime.B2.Region}, "b2_presign_timeout": {runtime.B2.PresignLinkTimeout.String()}, "b2_upload_presign_timeout": {runtime.B2.PresignUploadTimeout.String()},
		"oss_bucket_name": {runtime.OSS.BucketName}, "oss_endpoint": {runtime.OSS.Endpoint}, "oss_region": {runtime.OSS.Region}, "oss_presign_timeout": {runtime.OSS.PresignLinkTimeout.String()}, "oss_upload_presign_timeout": {runtime.OSS.PresignUploadTimeout.String()},
		"cos_bucket_name": {runtime.COS.BucketName}, "cos_endpoint": {runtime.COS.Endpoint}, "cos_region": {runtime.COS.Region}, "cos_presign_timeout": {runtime.COS.PresignLinkTimeout.String()}, "cos_upload_presign_timeout": {runtime.COS.PresignUploadTimeout.String()},
		"encryption_method": {runtime.Encryption.Method},
	}
	for name, enabled := range map[string]bool{
		"secure_cookies": runtime.SecureCookies, "guest_enabled": runtime.Upload.GuestEnabled, "signup_enabled": runtime.Auth.SignupEnabled,
		"google_oauth_enabled": runtime.Auth.OAuth.Google.Enabled, "github_oauth_enabled": runtime.Auth.OAuth.GitHub.Enabled, "discord_oauth_enabled": runtime.Auth.OAuth.Discord.Enabled,
		"captcha_protect_login": runtime.Captcha.ProtectLogin, "captcha_protect_signup": runtime.Captcha.ProtectSignup, "captcha_protect_upload": runtime.Captcha.ProtectUpload, "captcha_protect_download": runtime.Captcha.ProtectDownload,
		"rate_limit_enabled": runtime.RateLimit.Enabled, "s3_use_path_style": runtime.S3.UsePathStyle, "encryption_enabled": runtime.Encryption.Enabled,
		"stripe_enabled": runtime.Billing.Stripe.Enabled, "paypal_enabled": runtime.Billing.PayPal.Enabled,
	} {
		if enabled {
			values.Set(name, "on")
		}
	}
	return values
}
