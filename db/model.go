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

// PaidPlan maps a Stripe recurring Price to the entitlements ObjectShare
// grants while the matching subscription is active.
type PaidPlan struct {
	ID                string    `gorm:"column:id;type:uuid;primaryKey"`
	Name              string    `gorm:"column:name;type:varchar(80);not null"`
	Description       string    `gorm:"column:description;type:varchar(500);not null"`
	StripePriceID     string    `gorm:"column:stripe_price_id;type:varchar(255);uniqueIndex;not null"`
	PriceLabel        string    `gorm:"column:price_label;type:varchar(80);not null"`
	StorageQuotaBytes int64     `gorm:"column:storage_quota_bytes;not null;check:chk_paid_plans_quota_positive,storage_quota_bytes > 0"`
	RetentionDays     int       `gorm:"column:retention_days;not null;check:chk_paid_plans_retention_nonnegative,retention_days >= 0"`
	DirectLinks       bool      `gorm:"column:direct_links;not null;default:false"`
	Active            bool      `gorm:"column:active;not null;default:true;index"`
	SortOrder         int       `gorm:"column:sort_order;not null;default:0;index"`
	CreatedAt         time.Time `gorm:"column:created_at;not null"`
	UpdatedAt         time.Time `gorm:"column:updated_at;not null"`
}

func (PaidPlan) TableName() string { return "paid_plans" }

type Subscription struct {
	ID                   string    `gorm:"column:id;type:uuid;primaryKey"`
	UserID               string    `gorm:"column:user_id;type:uuid;not null;uniqueIndex"`
	PlanID               string    `gorm:"column:plan_id;type:uuid;not null;index"`
	StripeCustomerID     string    `gorm:"column:stripe_customer_id;type:varchar(255);not null;index"`
	StripeSubscriptionID string    `gorm:"column:stripe_subscription_id;type:varchar(255);not null;uniqueIndex"`
	Status               string    `gorm:"column:status;type:varchar(32);not null;index"`
	CurrentPeriodEnd     time.Time `gorm:"column:current_period_end;not null;index"`
	CancelAtPeriodEnd    bool      `gorm:"column:cancel_at_period_end;not null;default:false"`
	LastEventCreated     int64     `gorm:"column:last_event_created;not null;default:0"`
	CreatedAt            time.Time `gorm:"column:created_at;not null"`
	UpdatedAt            time.Time `gorm:"column:updated_at;not null"`
	Plan                 PaidPlan  `gorm:"foreignKey:PlanID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	User                 User      `gorm:"foreignKey:UserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

func (Subscription) TableName() string { return "subscriptions" }

// BillingEvent makes webhook handling idempotent across retries and replicas.
type BillingEvent struct {
	EventID   string    `gorm:"column:event_id;type:varchar(255);primaryKey"`
	CreatedAt time.Time `gorm:"column:created_at;not null;index"`
}

func (BillingEvent) TableName() string { return "billing_events" }

// BillingCheckout prevents an account from opening overlapping subscription
// checkouts before Stripe's webhook has created the canonical subscription.
type BillingCheckout struct {
	UserID    string    `gorm:"column:user_id;type:uuid;primaryKey"`
	PlanID    string    `gorm:"column:plan_id;type:uuid;not null"`
	ExpiresAt time.Time `gorm:"column:expires_at;not null;index"`
	CreatedAt time.Time `gorm:"column:created_at;not null"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null"`
	User      User      `gorm:"foreignKey:UserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	Plan      PaidPlan  `gorm:"foreignKey:PlanID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

func (BillingCheckout) TableName() string { return "billing_checkouts" }
