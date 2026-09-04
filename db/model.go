package db

import "time"

type FileList struct {
	ID                    uint       `gorm:"primaryKey"`
	AnonymousSessionToken string     `gorm:"column:anonymous_session_token;type:varchar(64);not null"`
	FileID                string     `gorm:"column:file_id;type:uuid;uniqueIndex;not null"`
	FileOwner             *string    `gorm:"column:file_owner;type:uuid;index"`
	FileName              string     `gorm:"column:file_name;type:varchar(255);not null"`
	FileSize              int64      `gorm:"column:file_size;not null"`
	FileSHA256            string     `gorm:"column:file_sha256;type:varchar(64);not null"`
	FileSHA3              string     `gorm:"column:file_sha3;type:varchar(64);not null"`
	ContentType           string     `gorm:"column:content_type;type:varchar(255);not null;default:application/octet-stream"`
	IsAnonymousUpload     bool       `gorm:"column:is_anonymous_upload;not null;default:true"`
	IsEncrypted           bool       `gorm:"column:is_encrypted;not null;default:false"`
	EncryptionMethod      string     `gorm:"column:encryption_method;type:varchar(32)"`
	StorageService        string     `gorm:"column:storage_service;type:varchar(32);not null"`
	UploadStatus          string     `gorm:"column:upload_status;type:varchar(16);not null;default:complete;index"`
	ChecksumStatus        string     `gorm:"column:checksum_status;type:varchar(16);not null;default:verified"`
	UploadExpiresAt       *time.Time `gorm:"column:upload_expires_at;index"`
	RetentionClaimedAt    *time.Time `gorm:"column:retention_claimed_at;index"`
	CreatedAt             time.Time  `gorm:"column:created_at;not null"`
	UpdatedAt             time.Time  `gorm:"column:updated_at;not null"`
}

func (FileList) TableName() string { return "file_lists" }

const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

type User struct {
	ID               string     `gorm:"column:id;type:uuid;primaryKey"`
	Email            string     `gorm:"column:email;type:varchar(320);uniqueIndex;not null"`
	DisplayName      string     `gorm:"column:display_name;type:varchar(100);not null"`
	PasswordHash     string     `gorm:"column:password_hash;type:text;not null"`
	Role             string     `gorm:"column:role;type:varchar(16);not null;default:user;index"`
	Active           bool       `gorm:"column:active;not null;default:true;index"`
	TokenVersion     int        `gorm:"column:token_version;not null;default:1"`
	DarkMode         bool       `gorm:"column:dark_mode;not null;default:false"`
	IsPaid           bool       `gorm:"column:is_paid;not null;default:false;index"`
	UploadQuotaBytes int64      `gorm:"column:upload_quota_bytes;not null;default:0;check:chk_users_upload_quota_bytes_nonnegative,upload_quota_bytes >= 0"`
	LastLoginAt      *time.Time `gorm:"column:last_login_at"`
	CreatedAt        time.Time  `gorm:"column:created_at;not null"`
	UpdatedAt        time.Time  `gorm:"column:updated_at;not null"`
}

func (User) TableName() string { return "users" }

type OAuthIdentity struct {
	ID        uint      `gorm:"primaryKey"`
	UserID    string    `gorm:"column:user_id;type:uuid;not null;uniqueIndex:idx_oauth_user_provider"`
	Provider  string    `gorm:"column:provider;type:varchar(32);not null;uniqueIndex:idx_oauth_provider_subject;uniqueIndex:idx_oauth_user_provider"`
	Subject   string    `gorm:"column:subject;type:varchar(255);not null;uniqueIndex:idx_oauth_provider_subject"`
	Email     string    `gorm:"column:email;type:varchar(320);not null"`
	CreatedAt time.Time `gorm:"column:created_at;not null"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null"`
	User      User      `gorm:"foreignKey:UserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

func (OAuthIdentity) TableName() string { return "oauth_identities" }

type RevokedToken struct {
	JTIHash   string    `gorm:"column:jti_hash;type:char(64);primaryKey"`
	ExpiresAt time.Time `gorm:"column:expires_at;not null;index"`
	RevokedAt time.Time `gorm:"column:revoked_at;not null"`
}

func (RevokedToken) TableName() string { return "revoked_tokens" }

type LoginThrottle struct {
	Key           string     `gorm:"column:key;type:char(64);primaryKey"`
	Failures      int        `gorm:"column:failures;not null;default:0"`
	WindowStarted time.Time  `gorm:"column:window_started;not null"`
	LockedUntil   *time.Time `gorm:"column:locked_until;index"`
	UpdatedAt     time.Time  `gorm:"column:updated_at;not null;index"`
}

func (LoginThrottle) TableName() string { return "login_throttles" }

// RateLimitBucket stores hashed client identities only. Scope and KeyHash form
// the primary key so all application replicas enforce one shared counter.
type RateLimitBucket struct {
	Scope         string    `gorm:"column:scope;type:varchar(32);primaryKey"`
	KeyHash       string    `gorm:"column:key_hash;type:char(64);primaryKey"`
	WindowStarted time.Time `gorm:"column:window_started;not null"`
	Used          int       `gorm:"column:used;not null"`
	UpdatedAt     time.Time `gorm:"column:updated_at;not null;index"`
}

func (RateLimitBucket) TableName() string { return "rate_limit_buckets" }

// ApplicationSetting stores encrypted application configuration. Value is an
// authenticated ciphertext; provider credentials and encryption keys are never
// persisted as plaintext.
type ApplicationSetting struct {
	Key       string    `gorm:"column:key;type:varchar(64);primaryKey"`
	Value     string    `gorm:"column:value;type:text;not null"`
	UpdatedBy string    `gorm:"column:updated_by;type:varchar(320);not null"`
	CreatedAt time.Time `gorm:"column:created_at;not null"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null"`
}

func (ApplicationSetting) TableName() string { return "application_settings" }
