package htmx

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

type settingsSecretState struct {
	Captcha, Google, GitHub, Discord, Encryption bool
	StripeSecret, StripeWebhook                  bool
	PayPalSecret                                 bool
	R2Access, R2Secret                           bool
	S3Access, S3Secret, S3Session                bool
	B2Access, B2Secret                           bool
	OSSAccess, OSSSecret                         bool
	COSAccess, COSSecret                         bool
}

type adminSettingsPageData struct {
	Version, CSRF, Revision, Error, Message, UpdatedAt, UpdatedBy string
	TrustedProxyCIDRs                                             string
	User                                                          *db.User
	Config                                                        config.RuntimeConfig
	Secrets                                                       settingsSecretState
	RestartRequired                                               bool
}

func (handler *Handler) AdminSettings(writer http.ResponseWriter, request *http.Request) {
	identity := currentIdentity(request)
	if handler.settings == nil {
		http.Error(writer, "Database configuration storage is unavailable.", http.StatusServiceUnavailable)
		return
	}
	setting, runtime, err := handler.readDatabaseSettings(request)
	if err != nil {
		handler.internalError(writer, request, "load administrator configuration", err)
		return
	}
	handler.renderSettings(writer, identity, setting, runtime, "", settingsMessage(request.URL.Query().Get("message")))
}

func (handler *Handler) AdminSaveSettings(writer http.ResponseWriter, request *http.Request) {
	identity := currentIdentity(request)
	if handler.settings == nil {
		http.Error(writer, "Database configuration storage is unavailable.", http.StatusServiceUnavailable)
		return
	}
	if !handler.parseSettingsForm(writer, request) || !handler.verifyJWTCSRF(writer, request, identity) {
		return
	}
	setting, runtime, err := handler.readDatabaseSettings(request)
	if err != nil {
		handler.internalError(writer, request, "load configuration for update", err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(request.FormValue("revision")), []byte(settingsRevision(setting.Value))) != 1 {
		handler.renderSettings(writer, identity, setting, runtime, "Configuration changed in another administrator session. Review the current values and submit again.", "")
		return
	}
	if err := updateRuntimeFromForm(&runtime, request); err != nil {
		handler.renderSettings(writer, identity, setting, runtime, err.Error(), "")
		return
	}
	normalized, err := config.NormalizeRuntime(handler.config, runtime)
	if err != nil {
		handler.renderSettings(writer, identity, setting, runtime, strings.TrimPrefix(err.Error(), "validate database configuration: "), "")
		return
	}
	runtime = normalized
	sealed, err := config.SealRuntime(runtime, handler.settingsKey)
	if err != nil {
		handler.internalError(writer, request, "protect administrator configuration", err)
		return
	}
	if err := handler.settings.SaveApplicationSettings(request.Context(), sealed, identity.User.Email, setting.Value); err != nil {
		if errors.Is(err, db.ErrConflict) {
			latestSetting, latestRuntime, latestErr := handler.readDatabaseSettings(request)
			if latestErr != nil {
				handler.internalError(writer, request, "reload conflicting configuration", latestErr)
				return
			}
			handler.renderSettings(writer, identity, latestSetting, latestRuntime, "Configuration changed in another administrator session. Review the current values and submit again.", "")
			return
		}
		handler.internalError(writer, request, "save administrator configuration", err)
		return
	}
	handler.redirect(writer, request, "/admin/settings?message=saved")
}

func (handler *Handler) readDatabaseSettings(request *http.Request) (*db.ApplicationSetting, config.RuntimeConfig, error) {
	setting, err := handler.settings.ApplicationSettings(request.Context())
	if err != nil {
		return nil, config.RuntimeConfig{}, err
	}
	runtime, err := config.OpenRuntime(setting.Value, handler.settingsKey)
	if err != nil {
		return nil, config.RuntimeConfig{}, err
	}
	runtime, err = config.NormalizeRuntime(handler.config, runtime)
	return setting, runtime, err
}

func (handler *Handler) renderSettings(writer http.ResponseWriter, identity *identity, setting *db.ApplicationSetting, runtime config.RuntimeConfig, formError, message string) {
	pendingJSON, _ := json.Marshal(runtime)
	activeJSON, _ := json.Marshal(config.RuntimeFromService(handler.config))
	secrets := settingsSecretState{
		Captcha: runtime.Captcha.SecretKey != "", Google: runtime.Auth.OAuth.Google.ClientSecret != "", GitHub: runtime.Auth.OAuth.GitHub.ClientSecret != "", Discord: runtime.Auth.OAuth.Discord.ClientSecret != "", Encryption: runtime.Encryption.Key != "",
		StripeSecret: runtime.Billing.Stripe.SecretKey != "" || runtime.Billing.SecretKey != "", StripeWebhook: runtime.Billing.Stripe.WebhookSecret != "" || runtime.Billing.WebhookSecret != "", PayPalSecret: runtime.Billing.PayPal.ClientSecret != "",
		R2Access: runtime.R2.AccessKeyID != "", R2Secret: runtime.R2.SecretAccessKey != "",
		S3Access: runtime.S3.AccessKeyID != "", S3Secret: runtime.S3.SecretAccessKey != "", S3Session: runtime.S3.SessionToken != "",
		B2Access: runtime.B2.AccessKeyID != "", B2Secret: runtime.B2.SecretAccessKey != "",
		OSSAccess: runtime.OSS.AccessKeyID != "", OSSSecret: runtime.OSS.SecretAccessKey != "",
		COSAccess: runtime.COS.AccessKeyID != "", COSSecret: runtime.COS.SecretAccessKey != "",
	}
	redactRuntimeSecrets(&runtime)
	data := adminSettingsPageData{
		Version: config.GetVersion(), CSRF: identity.Claims.CSRF, Revision: settingsRevision(setting.Value), User: identity.User,
		Config: runtime, Error: formError, Message: message,
		UpdatedAt: setting.UpdatedAt.UTC().Format("2006-01-02 15:04:05 UTC"), UpdatedBy: setting.UpdatedBy,
		TrustedProxyCIDRs: strings.Join(runtime.RateLimit.TrustedProxyCIDRs, ", "),
		RestartRequired:   string(pendingJSON) != string(activeJSON),
		Secrets:           secrets,
	}
	handler.render(writer, "admin_settings.html", data)
}

func settingsRevision(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func redactRuntimeSecrets(runtime *config.RuntimeConfig) {
	runtime.Auth.OAuth.Google.ClientSecret = ""
	runtime.Auth.OAuth.GitHub.ClientSecret = ""
	runtime.Auth.OAuth.Discord.ClientSecret = ""
	runtime.Captcha.SecretKey = ""
	runtime.Billing.Stripe.SecretKey, runtime.Billing.Stripe.WebhookSecret = "", ""
	runtime.Billing.SecretKey, runtime.Billing.WebhookSecret = "", ""
	runtime.Billing.PayPal.ClientSecret = ""
	runtime.Encryption.Key = ""
	runtime.R2.AccessKeyID, runtime.R2.SecretAccessKey, runtime.R2.SecretID, runtime.R2.SecretKey = "", "", "", ""
	runtime.S3.AccessKeyID, runtime.S3.SecretAccessKey, runtime.S3.SessionToken = "", "", ""
	runtime.B2.AccessKeyID, runtime.B2.SecretAccessKey = "", ""
	runtime.OSS.AccessKeyID, runtime.OSS.SecretAccessKey = "", ""
	runtime.COS.AccessKeyID, runtime.COS.SecretAccessKey = "", ""
}

func (handler *Handler) parseSettingsForm(writer http.ResponseWriter, request *http.Request) bool {
	request.Body = http.MaxBytesReader(writer, request.Body, 128*1024)
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "Invalid configuration form.", http.StatusBadRequest)
		return false
	}
	return true
}

func updateRuntimeFromForm(runtime *config.RuntimeConfig, request *http.Request) error {
	var problems []error
	problems = append(problems, formInt64(request, "max_file_size", &runtime.MaxFileSize))
	runtime.SecureCookies = checked(request, "secure_cookies")
	runtime.Upload.GuestEnabled = checked(request, "guest_enabled")
	if request.FormValue("max_files_per_batch") != "" {
		problems = append(problems, formInt(request, "max_files_per_batch", &runtime.Upload.MaxFilesPerBatch))
	}
	problems = append(problems, formInt(request, "guest_retention_days", &runtime.Retention.GuestDays))
	problems = append(problems, formInt(request, "unpaid_retention_days", &runtime.Retention.UnpaidDays))
	runtime.Auth.SignupEnabled = checked(request, "signup_enabled")
	runtime.Billing.Stripe.Enabled = checked(request, "stripe_enabled")
	runtime.Billing.PublicURL = strings.TrimSpace(request.FormValue("billing_public_url"))
	if request.FormValue("billing_credit_currency") != "" {
		runtime.Billing.CreditCurrency = strings.ToUpper(strings.TrimSpace(request.FormValue("billing_credit_currency")))
	}
	if request.FormValue("billing_min_top_up_credits") != "" {
		problems = append(problems, formInt64(request, "billing_min_top_up_credits", &runtime.Billing.MinTopUpCredits))
	}
	if request.FormValue("billing_max_top_up_credits") != "" {
		problems = append(problems, formInt64(request, "billing_max_top_up_credits", &runtime.Billing.MaxTopUpCredits))
	}
	runtime.Billing.Stripe.SecretKey = updatedSecret(request, "stripe_secret_key", "clear_stripe_secret", runtime.Billing.Stripe.SecretKey)
	runtime.Billing.Stripe.WebhookSecret = updatedSecret(request, "stripe_webhook_secret", "clear_stripe_webhook_secret", runtime.Billing.Stripe.WebhookSecret)
	runtime.Billing.PayPal.Enabled = checked(request, "paypal_enabled")
	runtime.Billing.PayPal.Environment = strings.ToLower(strings.TrimSpace(request.FormValue("paypal_environment")))
	runtime.Billing.PayPal.ClientID = strings.TrimSpace(request.FormValue("paypal_client_id"))
	runtime.Billing.PayPal.ClientSecret = updatedSecret(request, "paypal_client_secret", "clear_paypal_client_secret", runtime.Billing.PayPal.ClientSecret)
	runtime.Billing.PayPal.WebhookID = strings.TrimSpace(request.FormValue("paypal_webhook_id"))

	runtime.Auth.OAuth.PublicURL = strings.TrimSpace(request.FormValue("oauth_public_url"))
	updateOAuthProvider(request, "google", &runtime.Auth.OAuth.Google)
	updateOAuthProvider(request, "github", &runtime.Auth.OAuth.GitHub)
	updateOAuthProvider(request, "discord", &runtime.Auth.OAuth.Discord)

	runtime.Captcha.Provider = strings.TrimSpace(request.FormValue("captcha_provider"))
	runtime.Captcha.SiteKey = strings.TrimSpace(request.FormValue("captcha_site_key"))
	runtime.Captcha.ExpectedHostname = strings.TrimSpace(request.FormValue("captcha_expected_hostname"))
	runtime.Captcha.SecretKey = updatedSecret(request, "captcha_secret_key", "clear_captcha_secret", runtime.Captcha.SecretKey)
	runtime.Captcha.ProtectLogin = checked(request, "captcha_protect_login")
	runtime.Captcha.ProtectSignup = checked(request, "captcha_protect_signup")
	runtime.Captcha.ProtectUpload = checked(request, "captcha_protect_upload")
	runtime.Captcha.ProtectDownload = checked(request, "captcha_protect_download")

	runtime.RateLimit.Enabled = checked(request, "rate_limit_enabled")
	problems = append(problems, formDuration(request, "rate_limit_window", &runtime.RateLimit.Window))
	problems = append(problems, formInt(request, "rate_limit_api", &runtime.RateLimit.APILimit))
	problems = append(problems, formInt(request, "rate_limit_login", &runtime.RateLimit.LoginLimit))
	problems = append(problems, formInt(request, "rate_limit_signup", &runtime.RateLimit.SignupLimit))
	problems = append(problems, formInt(request, "rate_limit_upload", &runtime.RateLimit.UploadLimit))
	problems = append(problems, formInt(request, "rate_limit_download", &runtime.RateLimit.DownloadLimit))
	runtime.RateLimit.TrustedProxyCIDRs = splitFormCSV(request.FormValue("trusted_proxy_cidrs"))

	runtime.StorageService = strings.ToLower(strings.TrimSpace(request.FormValue("storage_service")))
	runtime.StoragePath = strings.TrimSpace(request.FormValue("storage_path"))
	updateR2(request, &runtime.R2, &problems)
	updateS3(request, &runtime.S3, &problems)
	updateCompatible(request, "b2", &runtime.B2, &problems)
	updateCompatible(request, "oss", &runtime.OSS, &problems)
	updateCompatible(request, "cos", &runtime.COS, &problems)

	runtime.Encryption.Enabled = checked(request, "encryption_enabled")
	runtime.Encryption.Method = strings.TrimSpace(request.FormValue("encryption_method"))
	runtime.Encryption.Key = updatedSecret(request, "encryption_key", "clear_encryption_key", runtime.Encryption.Key)
	return errors.Join(problems...)
}

func updateOAuthProvider(request *http.Request, name string, provider *config.OAuthProviderConfig) {
	provider.Enabled = checked(request, name+"_oauth_enabled")
	provider.ClientID = strings.TrimSpace(request.FormValue(name + "_oauth_client_id"))
	provider.ClientSecret = updatedSecret(request, name+"_oauth_client_secret", "clear_"+name+"_oauth_secret", provider.ClientSecret)
}

func updateR2(request *http.Request, settings *config.R2Config, problems *[]error) {
	settings.BucketName = strings.TrimSpace(request.FormValue("r2_bucket_name"))
	settings.AccountID = strings.TrimSpace(request.FormValue("r2_account_id"))
	settings.Endpoint = strings.TrimSpace(request.FormValue("r2_endpoint"))
	settings.Region = strings.TrimSpace(request.FormValue("r2_region"))
	settings.AccessKeyID = updatedSecret(request, "r2_access_key_id", "clear_r2_access_key", settings.AccessKeyID)
	settings.SecretAccessKey = updatedSecret(request, "r2_secret_access_key", "clear_r2_secret_key", settings.SecretAccessKey)
	*problems = append(*problems, formDuration(request, "r2_presign_timeout", &settings.PresignLinkTimeout), formDuration(request, "r2_upload_presign_timeout", &settings.PresignUploadTimeout))
}

func updateS3(request *http.Request, settings *config.S3Config, problems *[]error) {
	updateCompatible(request, "s3", &settings.S3CompatibleConfig, problems)
	settings.SessionToken = updatedSecret(request, "s3_session_token", "clear_s3_session_token", settings.SessionToken)
	settings.UsePathStyle = checked(request, "s3_use_path_style")
}

func updateCompatible(request *http.Request, prefix string, settings *config.S3CompatibleConfig, problems *[]error) {
	settings.BucketName = strings.TrimSpace(request.FormValue(prefix + "_bucket_name"))
	settings.Endpoint = strings.TrimSpace(request.FormValue(prefix + "_endpoint"))
	settings.Region = strings.TrimSpace(request.FormValue(prefix + "_region"))
	settings.AccessKeyID = updatedSecret(request, prefix+"_access_key_id", "clear_"+prefix+"_access_key", settings.AccessKeyID)
	settings.SecretAccessKey = updatedSecret(request, prefix+"_secret_access_key", "clear_"+prefix+"_secret_key", settings.SecretAccessKey)
	*problems = append(*problems, formDuration(request, prefix+"_presign_timeout", &settings.PresignLinkTimeout), formDuration(request, prefix+"_upload_presign_timeout", &settings.PresignUploadTimeout))
}

func checked(request *http.Request, name string) bool { return request.FormValue(name) == "on" }

func updatedSecret(request *http.Request, field, clearField, current string) string {
	if checked(request, clearField) {
		return ""
	}
	if replacement := request.FormValue(field); replacement != "" {
		return replacement
	}
	return current
}

func splitFormCSV(value string) []string {
	var values []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			values = append(values, part)
		}
	}
	return values
}

func formInt(request *http.Request, name string, target *int) error {
	value, err := strconv.Atoi(strings.TrimSpace(request.FormValue(name)))
	if err != nil {
		return fmt.Errorf("%s must be a whole number", strings.ReplaceAll(name, "_", " "))
	}
	*target = value
	return nil
}

func formInt64(request *http.Request, name string, target *int64) error {
	value, err := strconv.ParseInt(strings.TrimSpace(request.FormValue(name)), 10, 64)
	if err != nil {
		return fmt.Errorf("%s must be a whole number", strings.ReplaceAll(name, "_", " "))
	}
	*target = value
	return nil
}

func formDuration(request *http.Request, name string, target *config.Duration) error {
	value, err := time.ParseDuration(strings.TrimSpace(request.FormValue(name)))
	if err != nil {
		return fmt.Errorf("%s must be a duration such as 1m or 12h", strings.ReplaceAll(name, "_", " "))
	}
	*target = config.Duration(value)
	return nil
}

func settingsMessage(value string) string {
	if value == "saved" {
		return "Configuration saved. Restart every ObjectShare application replica to activate it."
	}
	return ""
}
