package config

import (
	"encoding/json"
	"fmt"
	"time"
)

type Duration time.Duration

func (duration Duration) Duration() time.Duration { return time.Duration(duration) }

func (duration Duration) String() string { return time.Duration(duration).String() }

func (duration Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(duration).String())
}

func (duration *Duration) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err == nil {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", value, err)
		}
		*duration = Duration(parsed)
		return nil
	}
	var seconds int64
	if err := json.Unmarshal(data, &seconds); err != nil {
		return fmt.Errorf("duration must be a string or seconds: %w", err)
	}
	*duration = Duration(time.Duration(seconds) * time.Second)
	return nil
}

type ServiceConfig struct {
	seedProblems    error
	Address         string             `json:"address"`
	Port            int                `json:"port,omitempty"`
	Timeout         int                `json:"timeout,omitempty"`
	ReadTimeout     Duration           `json:"read_timeout"`
	WriteTimeout    Duration           `json:"write_timeout"`
	IdleTimeout     Duration           `json:"idle_timeout"`
	ShutdownTimeout Duration           `json:"shutdown_timeout"`
	MaxFileSize     int64              `json:"max_file_size"`
	SecureCookies   bool               `json:"secure_cookies"`
	SettingsKey     string             `json:"settings_key,omitempty"`
	Upload          *UploadConfig      `json:"upload,omitempty"`
	Auth            *AuthConfig        `json:"auth"`
	Captcha         *CaptchaConfig     `json:"captcha,omitempty"`
	RateLimit       *RateLimitConfig   `json:"rate_limit,omitempty"`
	StorageService  string             `json:"storage_service"`
	StoragePath     string             `json:"storage_path"`
	UploadCache     *UploadCacheConfig `json:"upload_cache,omitempty"`
	Db              *DatabaseConfig    `json:"db"`
	Encryption      *EncryptionConfig  `json:"encryption"`
	R2              *R2Config          `json:"r2,omitempty"`
	S3              *S3Config          `json:"s3,omitempty"`
	B2              *B2Config          `json:"b2,omitempty"`
	OSS             *OSSConfig         `json:"oss,omitempty"`
	COS             *COSConfig         `json:"cos,omitempty"`
}

// UploadConfig controls whether people without an account may upload. Account
// storage quotas are user data and therefore live in PostgreSQL, not config.
type UploadConfig struct {
	GuestEnabled bool `json:"guest_enabled"`
}

type AuthConfig struct {
	SignupEnabled bool         `json:"signup_enabled"`
	JWTSecret     string       `json:"jwt_secret"`
	TokenLifetime Duration     `json:"token_lifetime"`
	OAuth         *OAuthConfig `json:"oauth,omitempty"`
}

// CaptchaConfig controls server-verified Cloudflare Turnstile challenges. The
// provider "none" preserves existing installations until site-specific keys
// are configured. Protection switches are deliberately independent so an
// operator can roll the control out without changing unrelated routes.
type CaptchaConfig struct {
	Provider         string `json:"provider"`
	SiteKey          string `json:"site_key"`
	SecretKey        string `json:"secret_key"`
	ExpectedHostname string `json:"expected_hostname,omitempty"`
	ProtectLogin     bool   `json:"protect_login"`
	ProtectSignup    bool   `json:"protect_signup"`
	ProtectUpload    bool   `json:"protect_upload"`
	ProtectDownload  bool   `json:"protect_download"`
}

// RateLimitConfig applies shared, database-backed fixed-window request limits.
// Limits are requests per Window; zero disables only that scope. Proxy CIDRs
// identify reverse proxies whose forwarded client-address chain may be trusted.
type RateLimitConfig struct {
	Enabled           bool     `json:"enabled"`
	Window            Duration `json:"window"`
	APILimit          int      `json:"api_limit"`
	LoginLimit        int      `json:"login_limit"`
	SignupLimit       int      `json:"signup_limit"`
	UploadLimit       int      `json:"upload_limit"`
	DownloadLimit     int      `json:"download_limit"`
	TrustedProxyCIDRs []string `json:"trusted_proxy_cidrs,omitempty"`
}

type OAuthConfig struct {
	PublicURL string              `json:"public_url"`
	Google    OAuthProviderConfig `json:"google"`
	GitHub    OAuthProviderConfig `json:"github"`
}

type OAuthProviderConfig struct {
	Enabled      bool   `json:"enabled"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type UploadCacheConfig struct {
	Type     string `json:"type"`
	Path     string `json:"path"`
	MaxFiles int    `json:"max_files"`
}

type DatabaseConfig struct {
	Type            string   `json:"type,omitempty"`
	Host            string   `json:"host"`
	Port            int      `json:"port"`
	User            string   `json:"user"`
	Password        string   `json:"password"`
	Database        string   `json:"database"`
	SSLMode         string   `json:"ssl_mode"`
	TimeZone        string   `json:"timezone"`
	MaxOpenConns    int      `json:"max_open_conns"`
	MaxIdleConns    int      `json:"max_idle_conns"`
	ConnMaxLifetime Duration `json:"conn_max_lifetime"`
}

type EncryptionConfig struct {
	Enabled         bool                   `json:"enabled"`
	Mode            string                 `json:"mode,omitempty"`
	Method          string                 `json:"method"`
	Key             string                 `json:"key"`
	DecryptionCache *DecryptionCacheConfig `json:"decryption_cache,omitempty"`
}

type DecryptionCacheConfig struct {
	Type     string `json:"type"`
	Path     string `json:"path"`
	MaxFiles int    `json:"max_files"`
}

type R2Config struct {
	BucketName           string   `json:"bucket_name"`
	AccountID            string   `json:"account_id"`
	Endpoint             string   `json:"endpoint,omitempty"`
	AccessKeyID          string   `json:"access_key_id"`
	SecretAccessKey      string   `json:"secret_access_key"`
	SecretID             string   `json:"secret_id,omitempty"`
	SecretKey            string   `json:"secret_key,omitempty"`
	Region               string   `json:"region"`
	PresignLinkTimeout   Duration `json:"presign_link_timeout"`
	PresignUploadTimeout Duration `json:"presign_upload_timeout"`
}

// S3CompatibleConfig contains the settings shared by Amazon S3 and the
// S3-compatible APIs exposed by Backblaze B2, Alibaba Cloud OSS, and Tencent
// Cloud COS. Endpoint is optional for providers whose public endpoint can be
// derived from the region.
type S3CompatibleConfig struct {
	BucketName           string   `json:"bucket_name"`
	Endpoint             string   `json:"endpoint,omitempty"`
	AccessKeyID          string   `json:"access_key_id"`
	SecretAccessKey      string   `json:"secret_access_key"`
	Region               string   `json:"region"`
	PresignLinkTimeout   Duration `json:"presign_link_timeout"`
	PresignUploadTimeout Duration `json:"presign_upload_timeout"`
}

type S3Config struct {
	S3CompatibleConfig
	SessionToken string `json:"session_token,omitempty"`
	UsePathStyle bool   `json:"use_path_style,omitempty"`
}

type B2Config = S3CompatibleConfig
type OSSConfig = S3CompatibleConfig
type COSConfig = S3CompatibleConfig
