package config

type ServiceConfig struct {
	Port           int                `mapstructure:"port"`
	Timeout        int                `mapstructure:"timeout"`
	MaxFileSize    int64              `mapstructure:"max_file_size"`
	StorageService string             `mapstructure:"storage_service"`
	UploadCache    *UploadCacheConfig `mapstructure:"upload_cache"`
	Db             *DatabaseConfig    `mapstructure:"db"`
	Encryption     *EncryptionConfig  `mapstructure:"encryption"`
	R2             *R2Config          `mapstructure:"r2"`
}

type UploadCacheConfig struct {
	Type     string `mapstructure:"type"`
	Path     string `mapstructure:"path"`
	MaxFiles int    `mapstructure:"max_files"`
}

type DatabaseConfig struct {
	Type     string `mapstructure:"type"`
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	Database string `mapstructure:"database"`
}

type EncryptionConfig struct {
	Enabled         bool                   `mapstructure:"enabled"`
	Mode            string                 `mapstructure:"mode"`
	Method          string                 `mapstructure:"method"`
	Key             string                 `mapstructure:"key"`
	DecryptionCache *DecryptionCacheConfig `mapstructure:"decryption_cache"`
}

type DecryptionCacheConfig struct {
	Type     string `mapstructure:"type"`
	Path     string `mapstructure:"path"`
	MaxFiles int    `mapstructure:"max_files"`
}

type R2Config struct {
	BucketName         string `mapstructure:"bucket_name"`
	AccountID          string `mapstructure:"account_id"`
	SecretID           string `mapstructure:"secret_id"`
	SecretKey          string `mapstructure:"secret_key"`
	PresignLinkTimeout int64  `mapstructure:"presign_link_timeout"`
}
