package config

import (
	"encoding/json"
	"fmt"
	"time"
)

type Duration time.Duration

func (duration Duration) Duration() time.Duration { return time.Duration(duration) }

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
	Address         string             `json:"address"`
	Port            int                `json:"port,omitempty"`
	Timeout         int                `json:"timeout,omitempty"`
	ReadTimeout     Duration           `json:"read_timeout"`
	WriteTimeout    Duration           `json:"write_timeout"`
	IdleTimeout     Duration           `json:"idle_timeout"`
	ShutdownTimeout Duration           `json:"shutdown_timeout"`
	MaxFileSize     int64              `json:"max_file_size"`
	SecureCookies   bool               `json:"secure_cookies"`
	StorageService  string             `json:"storage_service"`
	StoragePath     string             `json:"storage_path"`
	UploadCache     *UploadCacheConfig `json:"upload_cache,omitempty"`
	Db              *DatabaseConfig    `json:"db"`
	Encryption      *EncryptionConfig  `json:"encryption"`
	R2              *R2Config          `json:"r2,omitempty"`
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
