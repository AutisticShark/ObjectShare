package config

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const sealedRuntimePrefix = "enc:v1:"

// RuntimeConfig contains operational configuration that can be persisted in
// PostgreSQL. Listener, database, and JWT bootstrap settings deliberately stay
// in ServiceConfig because they are required before this document can be read.
type RuntimeConfig struct {
	MaxFileSize    int64             `json:"max_file_size"`
	SecureCookies  bool              `json:"secure_cookies"`
	Upload         UploadConfig      `json:"upload"`
	Auth           RuntimeAuthConfig `json:"auth"`
	Captcha        CaptchaConfig     `json:"captcha"`
	RateLimit      RateLimitConfig   `json:"rate_limit"`
	StorageService string            `json:"storage_service"`
	StoragePath    string            `json:"storage_path"`
	Encryption     EncryptionConfig  `json:"encryption"`
	R2             R2Config          `json:"r2"`
	S3             S3Config          `json:"s3"`
	B2             B2Config          `json:"b2"`
	OSS            OSSConfig         `json:"oss"`
	COS            COSConfig         `json:"cos"`
}

type RuntimeAuthConfig struct {
	SignupEnabled bool        `json:"signup_enabled"`
	OAuth         OAuthConfig `json:"oauth"`
}

func RuntimeFromService(cfg *ServiceConfig) RuntimeConfig {
	runtime := RuntimeConfig{
		MaxFileSize: cfg.MaxFileSize, SecureCookies: cfg.SecureCookies,
		StorageService: cfg.StorageService, StoragePath: cfg.StoragePath,
	}
	if cfg.Upload != nil {
		runtime.Upload = *cfg.Upload
	} else {
		runtime.Upload.GuestEnabled = true
	}
	if cfg.Auth != nil {
		runtime.Auth.SignupEnabled = cfg.Auth.SignupEnabled
		if cfg.Auth.OAuth != nil {
			runtime.Auth.OAuth = *cfg.Auth.OAuth
		}
	}
	if cfg.Captcha != nil {
		runtime.Captcha = *cfg.Captcha
	} else {
		runtime.Captcha.Provider = "none"
	}
	if cfg.RateLimit != nil {
		runtime.RateLimit = *cfg.RateLimit
		runtime.RateLimit.TrustedProxyCIDRs = append([]string(nil), cfg.RateLimit.TrustedProxyCIDRs...)
	}
	if cfg.Encryption != nil {
		runtime.Encryption = *cfg.Encryption
	}
	if cfg.R2 != nil {
		runtime.R2 = *cfg.R2
	}
	if cfg.S3 != nil {
		runtime.S3 = *cfg.S3
	}
	if cfg.B2 != nil {
		runtime.B2 = *cfg.B2
	}
	if cfg.OSS != nil {
		runtime.OSS = *cfg.OSS
	}
	if cfg.COS != nil {
		runtime.COS = *cfg.COS
	}
	return runtime
}

// ApplyRuntime validates a database document against the bootstrap settings
// and then replaces only the database-owned portion of cfg.
func ApplyRuntime(cfg *ServiceConfig, runtime RuntimeConfig) error {
	normalized, err := NormalizeRuntime(cfg, runtime)
	if err != nil {
		return err
	}
	applyRuntimeUnchecked(cfg, normalized)
	return nil
}

// NormalizeRuntime validates and normalizes a candidate without mutating the
// active bootstrap configuration. The admin dashboard uses this before commit.
func NormalizeRuntime(cfg *ServiceConfig, runtime RuntimeConfig) (RuntimeConfig, error) {
	if cfg == nil {
		return RuntimeConfig{}, errors.New("bootstrap configuration is required")
	}
	candidate, err := cloneService(cfg)
	if err != nil {
		return RuntimeConfig{}, err
	}
	applyRuntimeUnchecked(candidate, runtime)
	if err := candidate.Validate(); err != nil {
		return RuntimeConfig{}, fmt.Errorf("validate database configuration: %w", err)
	}
	return RuntimeFromService(candidate), nil
}

func applyRuntimeUnchecked(cfg *ServiceConfig, runtime RuntimeConfig) {
	cfg.MaxFileSize = runtime.MaxFileSize
	cfg.SecureCookies = runtime.SecureCookies
	cfg.Upload = &runtime.Upload
	if cfg.Auth == nil {
		cfg.Auth = &AuthConfig{}
	}
	cfg.Auth.SignupEnabled = runtime.Auth.SignupEnabled
	cfg.Auth.OAuth = &runtime.Auth.OAuth
	cfg.Captcha = &runtime.Captcha
	cfg.RateLimit = &runtime.RateLimit
	cfg.StorageService = runtime.StorageService
	cfg.StoragePath = runtime.StoragePath
	cfg.Encryption = &runtime.Encryption
	cfg.R2 = &runtime.R2
	cfg.S3 = &runtime.S3
	cfg.B2 = &runtime.B2
	cfg.OSS = &runtime.OSS
	cfg.COS = &runtime.COS
}

func cloneService(cfg *ServiceConfig) (*ServiceConfig, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("copy bootstrap configuration: %w", err)
	}
	var copy ServiceConfig
	if err := json.Unmarshal(data, &copy); err != nil {
		return nil, fmt.Errorf("copy bootstrap configuration: %w", err)
	}
	return &copy, nil
}

// SealRuntime encrypts the entire database-owned document, including provider
// credentials, using the stable bootstrap settings key.
func SealRuntime(runtime RuntimeConfig, settingsKey string) (string, error) {
	plaintext, err := json.Marshal(runtime)
	if err != nil {
		return "", fmt.Errorf("encode database configuration: %w", err)
	}
	aead, err := runtimeAEAD(settingsKey)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate database configuration nonce: %w", err)
	}
	sealed := aead.Seal(nonce, nonce, plaintext, []byte(sealedRuntimePrefix))
	return sealedRuntimePrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func OpenRuntime(value, settingsKey string) (RuntimeConfig, error) {
	var runtime RuntimeConfig
	if len(value) <= len(sealedRuntimePrefix) || value[:len(sealedRuntimePrefix)] != sealedRuntimePrefix {
		return runtime, errors.New("database configuration has an unsupported encryption format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(value[len(sealedRuntimePrefix):])
	if err != nil {
		return runtime, errors.New("database configuration is not valid base64")
	}
	aead, err := runtimeAEAD(settingsKey)
	if err != nil {
		return runtime, err
	}
	if len(payload) < aead.NonceSize() {
		return runtime, errors.New("database configuration is truncated")
	}
	nonce, ciphertext := payload[:aead.NonceSize()], payload[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(sealedRuntimePrefix))
	if err != nil {
		return runtime, errors.New("decrypt database configuration: bootstrap settings key does not match or the value was modified")
	}
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&runtime); err != nil {
		return runtime, fmt.Errorf("decode database configuration: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return runtime, errors.New("decode database configuration: unexpected trailing data")
	}
	return runtime, nil
}

func runtimeAEAD(settingsKey string) (cipher.AEAD, error) {
	if len(settingsKey) < 32 {
		return nil, errors.New("settings bootstrap key must contain at least 32 bytes")
	}
	key := sha256.Sum256([]byte("objectshare-database-config-v1\x00" + settingsKey))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("initialize database configuration encryption: %w", err)
	}
	return cipher.NewGCM(block)
}
