package db

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/stdlib"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	ErrNotFound           = errors.New("record not found")
	ErrConflict           = errors.New("record already exists")
	ErrUploadQuota        = errors.New("upload quota exceeded")
	ErrInvalidQuota       = errors.New("upload quota must not be negative")
	ErrInsufficientCredit = errors.New("insufficient account credit")
	ErrInvalidCredit      = errors.New("invalid account credit operation")
	ErrAdminExists        = errors.New("an administrator already exists")
	ErrLastAdmin          = errors.New("the final active administrator must be preserved")
	ErrInvalidModeration  = errors.New("invalid moderation status")
	ErrModeratedUser      = errors.New("remove the ban or shadowban before deleting this account")
	ErrLastLoginMethod    = errors.New("the final login method must be preserved")
)

type UploadUsage struct {
	Used  int64
	Limit int64
}

type UploadQuotaError struct {
	Scope     string
	Used      int64
	Limit     int64
	Requested int64
}

func (err *UploadQuotaError) Error() string {
	return fmt.Sprintf("%s: %s scope uses %d of %d bytes and requested %d bytes", ErrUploadQuota, err.Scope, err.Used, err.Limit, err.Requested)
}

func (err *UploadQuotaError) Unwrap() error { return ErrUploadQuota }

// GuestUploadScope is the UploadQuotaError scope reported when the global cap
// on unfinished guest uploads is full.
const GuestUploadScope = "guests"

// GuestUploadLimiter is implemented by repositories that can reserve a guest
// upload while enforcing a cap on all unfinished guest reservations atomically.
type GuestUploadLimiter interface {
	ReserveGuestUpload(ctx context.Context, file *FileList, maxPendingBytes int64) error
}

type Repository interface {
	Create(context.Context, *FileList) error
	ReserveUpload(context.Context, *FileList) error
	UploadUsage(context.Context, string) (UploadUsage, error)
	Get(context.Context, string) (*FileList, error)
	CompleteUpload(context.Context, string) error
	ClaimUploadPublication(context.Context, string) error
	ReleaseUploadPublication(context.Context, string) error
	ExtendUploadReservation(context.Context, string, time.Time) error
	ClaimPendingUploadDeletion(context.Context, string) error
	FinalizeUpload(context.Context, string, string, string, bool, string) error
	ExpiredUploads(context.Context, time.Time, int) ([]FileList, error)
	Rename(context.Context, string, string) error
	Delete(context.Context, string) error
	Ping(context.Context) error
}

// RetentionRepository is kept separate from Repository so HTTP handlers do
// not receive background-maintenance capabilities they never use.
type RetentionRepository interface {
	ClaimFilesForRetention(context.Context, time.Time, time.Time, *time.Time, *time.Time, int) ([]FileList, error)
	ReleaseRetentionClaim(context.Context, string) error
	Delete(context.Context, string) error
}

// FileDeletionClaimer lets an owner-initiated delete follow the same safe order
// as retention: mark the file as being deleted, remove the object, then remove
// the row. A failure between the last two steps leaves a "deleting" row that the
// retention sweep retries, instead of a "complete" row whose object is gone.
type FileDeletionClaimer interface {
	ClaimFileDeletion(ctx context.Context, fileID string, now time.Time) error
	ReleaseRetentionClaim(context.Context, string) error
}

type AuthRepository interface {
	AdminCount(context.Context) (int64, error)
	BootstrapAdmin(context.Context, *User) error
	CreateUser(context.Context, *User) error
	CreateOAuthUser(context.Context, *User, *OAuthIdentity) error
	UserByEmail(context.Context, string) (*User, error)
	UserByID(context.Context, string) (*User, error)
	OAuthUser(context.Context, string, string) (*User, error)
	OAuthIdentities(context.Context, string) ([]OAuthIdentity, error)
	LinkOAuthIdentity(context.Context, *OAuthIdentity) error
	ClaimUnverifiedAccountForOAuth(context.Context, string, *OAuthIdentity, time.Time) (*User, error)
	UnlinkOAuthIdentity(context.Context, string, string) error
	ListUsers(context.Context) ([]User, error)
	AdminUserDirectory(context.Context, string, string, int) (AdminDirectory, error)
	StorageUsageByUser(context.Context) (map[string]int64, error)
	UpdateProfile(context.Context, string, string, string) error
	UpdateDarkMode(context.Context, string, bool) error
	UpdatePassword(context.Context, string, string) (*User, error)
	// RehashPassword replaces a password hash with an upgraded hash of the same
	// password, only if the stored hash is still the one that was verified. It
	// does not change the token version, so existing sessions stay valid.
	RehashPassword(ctx context.Context, id, oldHash, newHash string) error
	AdminUpdateUser(context.Context, string, string, bool) error
	AdminModerateUser(context.Context, string, string) error
	UpdateUploadQuota(context.Context, string, int64) error
	UpdatePaidStatus(context.Context, string, bool) error
	DeleteUser(context.Context, string) error
	ListFilesByOwner(context.Context, string) ([]FileList, error)
	RecordLogin(context.Context, string, time.Time) error
	RevokeToken(context.Context, string, time.Time, time.Time) error
	TokenRevoked(context.Context, string, time.Time) (bool, error)
	LoginAllowed(context.Context, string, time.Time) (bool, time.Time, error)
	RecordLoginFailure(context.Context, string, time.Time) error
	ReserveLoginAttempt(context.Context, string, time.Time) (bool, time.Time, error)
	ReserveAccountLoginAttempt(context.Context, string, time.Time) (bool, time.Time, error)
	ClearLoginFailures(context.Context, string) error
}

type SettingsRepository interface {
	ApplicationSettings(context.Context) (*ApplicationSetting, error)
	InitializeApplicationSettings(context.Context, string) error
	SaveApplicationSettings(context.Context, string, string, string) error
}

type RateLimitRepository interface {
	ConsumeRateLimit(context.Context, string, string, int, time.Duration, time.Time) (bool, time.Time, error)
}

type GormRepository struct {
	connection     *gorm.DB
	redis          *redisStore
	rateLimitCalls atomic.Uint64
}

func Open(ctx context.Context, cfg *config.DatabaseConfig) (*GormRepository, error) {
	pgxConfig, location, err := postgresConfig(cfg)
	if err != nil {
		return nil, err
	}
	return openPostgres(ctx, cfg, pgxConfig, location)
}

func openPostgres(ctx context.Context, cfg *config.DatabaseConfig, pgxConfig *pgx.ConnConfig, location *time.Location) (*GormRepository, error) {
	// AutoMigrate can inspect SELECT * repeatedly while changing a table's
	// columns. Neither pgx nor GORM may cache statements/result descriptions
	// across that DDL. DescribeExec preserves server-inferred parameter types
	// without caching; GORM's runtime statement cache is enabled after commit.
	pgxConfig = pgxConfig.Copy()
	pgxConfig.DefaultQueryExecMode = pgx.QueryExecModeDescribeExec
	sqlDB := stdlib.OpenDB(*pgxConfig, stdlib.OptionAfterConnect(func(_ context.Context, connection *pgx.Conn) error {
		connection.TypeMap().RegisterType(&pgtype.Type{
			Name: "timestamp", OID: pgtype.TimestampOID,
			Codec: &pgtype.TimestampCodec{ScanLocation: location},
		})
		return nil
	}))
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime.Duration())

	connection, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{
		SkipDefaultTransaction: true,
		DisableAutomaticPing:   true,
		Logger:                 queryLogger(),
	})
	if err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("open PostgreSQL: %w", err)
	}
	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("ping PostgreSQL: %w", err)
	}
	migration := connection.WithContext(ctx).Begin()
	if migration.Error != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("begin migration: %w", migration.Error)
	}
	if err := migration.Exec("SELECT pg_advisory_xact_lock(600165736419383690)").Error; err != nil {
		_ = migration.Rollback().Error
		_ = sqlDB.Close()
		return nil, fmt.Errorf("acquire migration lock: %w", err)
	}
	for _, statement := range []string{
		"ALTER TABLE IF EXISTS file_lists DROP CONSTRAINT IF EXISTS uni_file_lists_file_sha256",
		"ALTER TABLE IF EXISTS file_lists DROP CONSTRAINT IF EXISTS uni_file_lists_file_sha3",
		"ALTER TABLE IF EXISTS file_lists DROP CONSTRAINT IF EXISTS uni_file_lists_encryption_key",
		"DROP INDEX IF EXISTS idx_file_lists_file_sha256",
		"DROP INDEX IF EXISTS idx_file_lists_file_sha3",
		"DROP INDEX IF EXISTS idx_file_lists_encryption_key",
	} {
		if err := migration.Exec(statement).Error; err != nil {
			_ = migration.Rollback().Error
			_ = sqlDB.Close()
			return nil, fmt.Errorf("remove legacy uniqueness: %w", err)
		}
	}
	if migration.Migrator().HasTable(&PaidPlan{}) {
		statements := []string{
			"ALTER TABLE paid_plans ADD COLUMN IF NOT EXISTS gateway varchar(32)",
			"ALTER TABLE paid_plans ADD COLUMN IF NOT EXISTS gateway_plan_id varchar(255)",
			"UPDATE paid_plans SET gateway = 'stripe' WHERE gateway IS NULL OR gateway = ''",
		}
		if migration.Migrator().HasColumn(&legacyPaidPlan{}, "StripePriceID") {
			statements = append(statements,
				"UPDATE paid_plans SET gateway_plan_id = stripe_price_id WHERE gateway_plan_id IS NULL OR gateway_plan_id = ''",
				"ALTER TABLE paid_plans ALTER COLUMN stripe_price_id DROP NOT NULL",
			)
		}
		statements = append(statements,
			"ALTER TABLE paid_plans ALTER COLUMN gateway SET NOT NULL",
			"ALTER TABLE paid_plans ALTER COLUMN gateway_plan_id SET NOT NULL",
		)
		for _, statement := range statements {
			if err := migration.Exec(statement).Error; err != nil {
				_ = migration.Rollback().Error
				_ = sqlDB.Close()
				return nil, fmt.Errorf("migrate billing plans: %w", err)
			}
		}
	}
	if migration.Migrator().HasTable(&Subscription{}) {
		statements := []string{
			"ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS gateway varchar(32)",
			"ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS customer_id varchar(255)",
			"ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS gateway_subscription_id varchar(255)",
			"UPDATE subscriptions SET gateway = 'stripe' WHERE gateway IS NULL OR gateway = ''",
		}
		if migration.Migrator().HasColumn(&legacySubscription{}, "StripeSubscriptionID") {
			statements = append(statements,
				"UPDATE subscriptions SET customer_id = stripe_customer_id WHERE customer_id IS NULL",
				"UPDATE subscriptions SET gateway_subscription_id = stripe_subscription_id WHERE gateway_subscription_id IS NULL OR gateway_subscription_id = ''",
				"ALTER TABLE subscriptions ALTER COLUMN stripe_customer_id DROP NOT NULL",
				"ALTER TABLE subscriptions ALTER COLUMN stripe_subscription_id DROP NOT NULL",
			)
		}
		statements = append(statements,
			"UPDATE subscriptions SET customer_id = '' WHERE customer_id IS NULL",
			"ALTER TABLE subscriptions ALTER COLUMN gateway SET NOT NULL",
			"ALTER TABLE subscriptions ALTER COLUMN customer_id SET NOT NULL",
			"ALTER TABLE subscriptions ALTER COLUMN gateway_subscription_id SET NOT NULL",
		)
		for _, statement := range statements {
			if err := migration.Exec(statement).Error; err != nil {
				_ = migration.Rollback().Error
				_ = sqlDB.Close()
				return nil, fmt.Errorf("migrate billing subscriptions: %w", err)
			}
		}
	}
	if migration.Migrator().HasTable(&BillingEvent{}) {
		if err := migration.Exec("UPDATE billing_events SET event_id = 'stripe:' || event_id WHERE POSITION(':' IN event_id) = 0").Error; err != nil {
			_ = migration.Rollback().Error
			_ = sqlDB.Close()
			return nil, fmt.Errorf("migrate billing events: %w", err)
		}
	}
	if err := migration.AutoMigrate(&User{}, &ClientKeyVault{}, &OAuthIdentity{}, &RevokedToken{}, &LoginThrottle{}, &RateLimitBucket{}, &FileList{}, &ApplicationSetting{}, &PaidPlan{}, &Subscription{}, &BillingEvent{}, &BillingCheckout{}, &CreditTopUp{}, &CreditTransaction{}, &Invoice{}, &PaymentReconciliation{}); err != nil {
		_ = migration.Rollback().Error
		_ = sqlDB.Close()
		return nil, fmt.Errorf("migrate PostgreSQL: %w", err)
	}
	// Earlier releases declared is_anonymous_upload with a true default, which
	// made GORM replace an explicit false, so account uploads were stored as
	// anonymous. A file is anonymous exactly when it has no owner.
	if err := migration.Exec("UPDATE file_lists SET is_anonymous_upload = (file_owner IS NULL) WHERE is_anonymous_upload <> (file_owner IS NULL)").Error; err != nil {
		_ = migration.Rollback().Error
		_ = sqlDB.Close()
		return nil, fmt.Errorf("correct anonymous upload flags: %w", err)
	}
	// Every account that has a verified address has verified one at least
	// once. This backfills rows from before email_ever_verified existed and
	// rows verified by an older replica during a rolling upgrade; it changes
	// nothing once they agree.
	if err := migration.Exec("UPDATE users SET email_ever_verified = TRUE WHERE email_verified_at IS NOT NULL AND NOT email_ever_verified").Error; err != nil {
		_ = migration.Rollback().Error
		_ = sqlDB.Close()
		return nil, fmt.Errorf("backfill email verification history: %w", err)
	}
	for _, statement := range billingBackfillSQL {
		if err := migration.Exec(statement).Error; err != nil {
			_ = migration.Rollback().Error
			_ = sqlDB.Close()
			return nil, fmt.Errorf("backfill billing columns: %w", err)
		}
	}
	if err := migration.Exec(dropLegacySessionsSQL).Error; err != nil {
		_ = migration.Rollback().Error
		_ = sqlDB.Close()
		return nil, fmt.Errorf("remove legacy server sessions: %w", err)
	}
	if err := migration.Commit().Error; err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("commit migration: %w", err)
	}
	return &GormRepository{connection: connection.Session(&gorm.Session{PrepareStmt: true})}, nil
}

// dropLegacySessionsSQL removes the server-side login sessions table that
// earlier releases created (accounts now authenticate with JWTs only). It runs
// on every start, so it must never touch a different application's table: it
// looks only in the connection's current schema and only drops a table that has
// the session shape (user_id and expires_at columns). Once the legacy table is
// gone it does nothing.
const dropLegacySessionsSQL = `DO $$
BEGIN
  IF (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = 'sessions' AND column_name IN ('user_id', 'expires_at')) = 2 THEN
    EXECUTE format('DROP TABLE %I.sessions', current_schema());
  END IF;
END
$$`

type legacyPaidPlan struct {
	StripePriceID string `gorm:"column:stripe_price_id"`
}

func (legacyPaidPlan) TableName() string { return "paid_plans" }

type legacySubscription struct {
	StripeSubscriptionID string `gorm:"column:stripe_subscription_id"`
}

func (legacySubscription) TableName() string { return "subscriptions" }

func postgresConfig(cfg *config.DatabaseConfig) (*pgx.ConnConfig, *time.Location, error) {
	// Go resolves "Local" to the host's zone, but PostgreSQL has no such zone
	// name and would refuse every connection at start-up.
	if strings.EqualFold(cfg.TimeZone, "Local") {
		return nil, nil, fmt.Errorf("PostgreSQL time zone %q is not supported; use an IANA name such as UTC or Asia/Taipei", cfg.TimeZone)
	}
	location, err := time.LoadLocation(cfg.TimeZone)
	if err != nil {
		return nil, nil, fmt.Errorf("load PostgreSQL time zone %q: %w", cfg.TimeZone, err)
	}
	dsn := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(cfg.User, cfg.Password),
		// JoinHostPort brackets IPv6 literals; strip brackets the operator may
		// already have written so they are not doubled.
		Host: net.JoinHostPort(strings.TrimSuffix(strings.TrimPrefix(cfg.Host, "["), "]"), strconv.Itoa(cfg.Port)),
		Path: cfg.Database,
	}
	query := dsn.Query()
	query.Set("sslmode", cfg.SSLMode)
	dsn.RawQuery = query.Encode()

	pgxConfig, err := pgx.ParseConfig(dsn.String())
	if err != nil {
		return nil, nil, fmt.Errorf("parse PostgreSQL configuration: %w", err)
	}
	pgxConfig.RuntimeParams["timezone"] = cfg.TimeZone
	return pgxConfig, location, nil
}

func (repo *GormRepository) Close() error {
	var redisErr error
	if repo.redis != nil {
		redisErr = repo.redis.client.Close()
	}
	sqlDB, err := repo.connection.DB()
	if err != nil {
		return err
	}
	return errors.Join(redisErr, sqlDB.Close())
}

func (repo *GormRepository) Create(ctx context.Context, file *FileList) error {
	return repo.connection.WithContext(ctx).Create(file).Error
}

func (repo *GormRepository) ReserveUpload(ctx context.Context, file *FileList) error {
	connection := repo.connection.WithContext(ctx)
	if file.FileOwner == nil {
		return connection.Create(file).Error
	}
	return connection.Transaction(func(transaction *gorm.DB) error {
		// Lock only the owning account. Concurrent reservations for the same
		// account serialize, while unrelated users can continue uploading.
		var user User
		if err := transaction.Clauses(clause.Locking{Strength: "UPDATE"}).
			Select("id", "upload_quota_bytes").Where("id = ?", *file.FileOwner).First(&user).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		quota, err := effectiveUploadQuota(transaction, user.ID, user.UploadQuotaBytes, time.Now().UTC())
		if err != nil {
			return err
		}
		if quota > 0 {
			used, err := uploadBytesUsed(transaction, user.ID)
			if err != nil {
				return err
			}
			if exceedsQuota(used, file.FileSize, quota) {
				return &UploadQuotaError{Scope: "user", Used: used, Limit: quota, Requested: file.FileSize}
			}
		}
		return transaction.Create(file).Error
	})
}

// ReserveGuestUpload creates an anonymous reservation unless the bytes already
// reserved by unfinished guest uploads plus this file would exceed
// maxPendingBytes. The check and insert share one advisory-locked transaction so
// concurrent guests cannot each pass the check.
func (repo *GormRepository) ReserveGuestUpload(ctx context.Context, file *FileList, maxPendingBytes int64) error {
	if file.FileOwner != nil || maxPendingBytes <= 0 {
		return repo.ReserveUpload(ctx, file)
	}
	return repo.connection.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := transaction.Exec("SELECT pg_advisory_xact_lock(hashtextextended('objectshare-guest-pending-uploads', 0))").Error; err != nil {
			return err
		}
		var pending int64
		if err := transaction.Model(&FileList{}).Select("COALESCE(SUM(file_size), 0)").
			Where("file_owner IS NULL AND upload_status IN ?", []string{"pending", "publishing"}).Scan(&pending).Error; err != nil {
			return err
		}
		if exceedsQuota(pending, file.FileSize, maxPendingBytes) {
			return &UploadQuotaError{Scope: GuestUploadScope, Used: pending, Limit: maxPendingBytes, Requested: file.FileSize}
		}
		return transaction.Create(file).Error
	})
}

func (repo *GormRepository) UploadUsage(ctx context.Context, userID string) (UploadUsage, error) {
	connection := repo.connection.WithContext(ctx)
	var user User
	if err := connection.Select("id", "upload_quota_bytes").Where("id = ?", userID).First(&user).Error; errors.Is(err, gorm.ErrRecordNotFound) {
		return UploadUsage{}, ErrNotFound
	} else if err != nil {
		return UploadUsage{}, err
	}
	quota, err := effectiveUploadQuota(connection, user.ID, user.UploadQuotaBytes, time.Now().UTC())
	if err != nil {
		return UploadUsage{}, err
	}
	if quota == 0 {
		return UploadUsage{}, nil
	}
	used, err := uploadBytesUsed(connection, userID)
	return UploadUsage{Used: used, Limit: quota}, err
}

func effectiveUploadQuota(connection *gorm.DB, userID string, accountQuota int64, now time.Time) (int64, error) {
	// Zero has always meant an unlimited administrator-assigned account quota.
	// A paid plan must never reduce that existing entitlement.
	if accountQuota == 0 {
		return 0, nil
	}
	// Use the same terms as the account's entitlements: a settled invoice keeps
	// the quota it was sold with even if the plan is edited later.
	entitlements, err := entitlementsWithDB(connection, userID, now)
	if err != nil {
		return 0, err
	}
	if entitlements.Active && entitlements.StorageQuotaBytes > accountQuota {
		return entitlements.StorageQuotaBytes, nil
	}
	return accountQuota, nil
}

func uploadBytesUsed(connection *gorm.DB, userID string) (int64, error) {
	active := []string{"pending", "publishing", "complete", "deleting", "aborting"}
	var used int64
	if err := connection.Model(&FileList{}).Select("COALESCE(SUM(file_size), 0)").
		Where("upload_status IN ? AND file_owner = ?", active, userID).Scan(&used).Error; err != nil {
		return 0, err
	}
	return used, nil
}

func exceedsQuota(used, requested, limit int64) bool {
	return limit > 0 && (used >= limit || requested > limit-used)
}

func (repo *GormRepository) Get(ctx context.Context, fileID string) (*FileList, error) {
	var file FileList
	err := repo.connection.WithContext(ctx).Where("file_id = ?", fileID).First(&file).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &file, nil
}

// UploadPublicationLease is how long a "publishing" claim protects a direct
// upload while completion copies its staged object to the final key. A claim
// older than this is treated as abandoned (the process stopped mid-copy):
// completion may claim it again, and abort or expiry cleanup may delete it.
const UploadPublicationLease = 15 * time.Minute

// ClaimUploadPublication moves a pending upload (or an abandoned publishing
// claim) to "publishing" before completion creates its final object. Abort and
// expiry cleanup refuse a live claim, so they cannot delete the record while
// the copy runs and leave a final object that nothing references or counts.
func (repo *GormRepository) ClaimUploadPublication(ctx context.Context, fileID string) error {
	now := time.Now().UTC()
	result := repo.connection.WithContext(ctx).Model(&FileList{}).
		Where("file_id = ? AND (upload_status = ? OR (upload_status = ? AND updated_at < ?))", fileID, "pending", "publishing", now.Add(-UploadPublicationLease)).
		Updates(map[string]any{"upload_status": "publishing", "updated_at": now})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// ReleaseUploadPublication returns a publishing upload to pending after a
// failed copy, so the owner can retry completion and cleanup can expire it.
func (repo *GormRepository) ReleaseUploadPublication(ctx context.Context, fileID string) error {
	result := repo.connection.WithContext(ctx).Model(&FileList{}).
		Where("file_id = ? AND upload_status = ?", fileID, "publishing").
		Updates(map[string]any{"upload_status": "pending", "updated_at": time.Now().UTC()})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// ExtendUploadReservation moves a live pending upload's expiry out to until when a
// fresh upload URL is issued for it. An expired reservation is not revived, and
// an expiry is never shortened.
func (repo *GormRepository) ExtendUploadReservation(ctx context.Context, fileID string, until time.Time) error {
	result := repo.connection.WithContext(ctx).Model(&FileList{}).
		Where("file_id = ? AND upload_status = ? AND upload_expires_at >= ?", fileID, "pending", time.Now().UTC()).
		Update("upload_expires_at", gorm.Expr("GREATEST(upload_expires_at, ?)", until))
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (repo *GormRepository) CompleteUpload(ctx context.Context, fileID string) error {
	result := repo.connection.WithContext(ctx).Model(&FileList{}).
		Where("file_id = ? AND upload_status IN ?", fileID, []string{"pending", "publishing"}).
		Updates(map[string]any{"upload_status": "complete", "upload_expires_at": nil})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (repo *GormRepository) FinalizeUpload(ctx context.Context, fileID, sha256Sum, sha3Sum string, encrypted bool, encryptionMethod string) error {
	result := repo.connection.WithContext(ctx).Model(&FileList{}).
		Where("file_id = ? AND upload_status = ?", fileID, "pending").
		Updates(map[string]any{
			"file_sha256": sha256Sum, "file_sha3": sha3Sum, "is_encrypted": encrypted,
			"encryption_method": encryptionMethod, "upload_status": "complete",
			"checksum_status": "verified", "upload_expires_at": nil,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// ClaimPendingUploadDeletion prevents completion from racing with object deletion.
// An aborting upload cannot be completed. Keep that state until deletion succeeds
// so later cleanup can retry after an object-store failure or process restart.
// A live publishing claim is refused; an abandoned one may be deleted.
func (repo *GormRepository) ClaimPendingUploadDeletion(ctx context.Context, fileID string) error {
	result := repo.connection.WithContext(ctx).Model(&FileList{}).
		Where("file_id = ? AND (upload_status IN ? OR (upload_status = ? AND updated_at < ?))", fileID, []string{"pending", "aborting"},
			"publishing", time.Now().UTC().Add(-UploadPublicationLease)).
		Update("upload_status", "aborting")
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (repo *GormRepository) ExpiredUploads(ctx context.Context, before time.Time, limit int) ([]FileList, error) {
	var files []FileList
	err := repo.connection.WithContext(ctx).
		Where("(upload_status = ? AND upload_expires_at < ?) OR upload_status = ? OR (upload_status = ? AND upload_expires_at < ? AND updated_at < ?)",
			"pending", before, "aborting", "publishing", before, before.Add(-UploadPublicationLease)).
		Order("upload_expires_at ASC").Limit(limit).Find(&files).Error
	return files, err
}

func (repo *GormRepository) Rename(ctx context.Context, fileID, name string) error {
	result := repo.connection.WithContext(ctx).Model(&FileList{}).Where("file_id = ?", fileID).Update("file_name", name)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (repo *GormRepository) Delete(ctx context.Context, fileID string) error {
	result := repo.connection.WithContext(ctx).Where("file_id = ?", fileID).Delete(&FileList{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// ClaimFilesForRetention atomically marks a bounded batch before object-store
// deletion. SKIP LOCKED lets multiple replicas cooperate without deleting the
// same live row. Stale claims are reclaimed after an interrupted cleanup.
func (repo *GormRepository) ClaimFilesForRetention(ctx context.Context, now, staleBefore time.Time, guestBefore, unpaidBefore *time.Time, limit int) ([]FileList, error) {
	if limit <= 0 {
		return nil, nil
	}
	eligibleSQL, eligibilityArgs := retentionEligibilitySQLAt(now, guestBefore, unpaidBefore)
	var claimed []FileList
	err := repo.connection.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		args := append(eligibilityArgs, staleBefore)
		claimed = nil
		var claimedIDs, rejectedIDs []uint
		// The SQL pre-filter applies the same entitlement rule as the check done in
		// Go below, but it reads entitlements before they are locked, so it can
		// still select rows Go then rejects. Rejected rows stay in
		// place, and re-selecting them on every run would starve eligible rows
		// behind them; page past them instead, a bounded number of times.
		for pass := 0; pass < maxRetentionClaimPasses && len(claimedIDs) < limit; pass++ {
			want := limit - len(claimedIDs)
			query := transaction.Table("file_lists AS f").
				Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
				Where("(f.upload_status = 'complete' AND ("+eligibleSQL+")) OR (f.upload_status = 'deleting' AND f.retention_claimed_at <= ?)", args...)
			// Rows already accepted are only marked at the end, so exclude them too.
			if seen := append(append([]uint(nil), rejectedIDs...), claimedIDs...); len(seen) != 0 {
				query = query.Where("f.id NOT IN ?", seen)
			}
			var candidates []FileList
			if err := query.Order("COALESCE(f.retention_claimed_at, f.created_at), f.id").Limit(want).Find(&candidates).Error; err != nil {
				return err
			}
			accepted, rejected, err := retentionEligibleCandidates(transaction, candidates, now, unpaidBefore)
			if err != nil {
				return err
			}
			for _, file := range accepted {
				claimed = append(claimed, file)
				claimedIDs = append(claimedIDs, file.ID)
			}
			rejectedIDs = append(rejectedIDs, rejected...)
			if len(candidates) < want {
				break // nothing further matches
			}
		}
		if len(claimedIDs) == 0 {
			return nil
		}
		return transaction.Model(&FileList{}).Where("id IN ?", claimedIDs).
			Updates(map[string]any{"upload_status": "deleting", "retention_claimed_at": now, "updated_at": now}).Error
	})
	if err != nil {
		return nil, err
	}
	return claimed, nil
}

// maxRetentionClaimPasses bounds how many candidate pages one claim examines
// while skipping rows that the entitlement check rejects.
const maxRetentionClaimPasses = 10

// retentionEligibleCandidates applies the authoritative entitlement check to a
// page of SQL candidates and reports which rows to claim and which (by primary
// key) to skip.
func retentionEligibleCandidates(transaction *gorm.DB, candidates []FileList, now time.Time, unpaidBefore *time.Time) (accepted []FileList, rejected []uint, err error) {
	// Re-read each candidate's entitlement under a shared row lock. A
	// concurrent paid-status update must therefore commit before this
	// check or wait until the deletion claim commits.
	userIDs := make([]string, 0, len(candidates))
	seenUsers := make(map[string]bool)
	for _, file := range candidates {
		if file.UploadStatus == "complete" && file.FileOwner != nil && !seenUsers[*file.FileOwner] {
			seenUsers[*file.FileOwner] = true
			userIDs = append(userIDs, *file.FileOwner)
		}
	}
	usersByID := make(map[string]User, len(userIDs))
	if len(userIDs) != 0 {
		var users []User
		if err := transaction.Clauses(clause.Locking{Strength: "SHARE"}).
			Select("id", "is_paid").Where("id IN ?", userIDs).Order("id").Find(&users).Error; err != nil {
			return nil, nil, err
		}
		for _, user := range users {
			usersByID[user.ID] = user
		}
	}
	entitlementsByID := make(map[string]Entitlements, len(userIDs))
	for _, userID := range userIDs {
		entitlements, err := entitlementsWithDB(transaction, userID, now)
		if err != nil {
			return nil, nil, err
		}
		entitlementsByID[userID] = entitlements
	}
	for _, file := range candidates {
		eligible := file.UploadStatus == "deleting" || file.FileOwner == nil
		if file.UploadStatus == "complete" && file.FileOwner != nil {
			user, userExists := usersByID[*file.FileOwner]
			eligible = false
			if userExists && !user.IsPaid {
				entitlements := entitlementsByID[user.ID]
				if entitlements.Active {
					eligible = entitlements.RetentionDays > 0 && !file.CreatedAt.After(now.AddDate(0, 0, -entitlements.RetentionDays))
				} else if unpaidBefore != nil {
					eligible = !file.CreatedAt.After(*unpaidBefore)
				}
			}
		}
		if eligible {
			accepted = append(accepted, file)
		} else {
			rejected = append(rejected, file.ID)
		}
	}
	return accepted, rejected, nil
}

// subscriptionRetentionFromSQL is entitlementsWithDB's retention rule as a
// FROM clause over subscriptions s, exposing benefit.retention_days. Its two
// placeholders both take the evaluation time. Subscriptions without an invoice
// use the live plan; invoice-backed ones use currentPeriodInvoice's snapshot:
// for local purchases the most recently started paid plan invoice while its
// period lasts (so an early renewal waits for the earlier period to end),
// otherwise the invoice the subscription points to. Go's AddDate on a UTC time
// adds whole 24-hour days, hence INTERVAL '24 hours' rather than '1 day'.
const subscriptionRetentionFromSQL = `subscriptions AS s JOIN paid_plans AS p ON p.id = s.plan_id
	LEFT JOIN LATERAL (SELECT i.retention_days, i.period_start, i.duration_days FROM invoices AS i
		WHERE s.gateway = 'credit' AND i.user_id = s.user_id AND i.kind = 'plan' AND i.status = 'paid' AND i.period_start <= ?
		ORDER BY i.period_start DESC LIMIT 1) AS started ON TRUE
	LEFT JOIN invoices AS latest ON s.invoice_id <> '' AND CAST(latest.id AS text) = s.invoice_id AND latest.status = 'paid'
	CROSS JOIN LATERAL (SELECT CASE WHEN s.invoice_id = '' THEN p.retention_days
		WHEN started.period_start + started.duration_days * INTERVAL '24 hours' > ? THEN started.retention_days
		ELSE latest.retention_days END AS retention_days) AS benefit`

func retentionEligibilitySQLAt(now time.Time, guestBefore, unpaidBefore *time.Time) (string, []any) {
	var eligibility []string
	var eligibilityArgs []any
	if guestBefore != nil {
		eligibility = append(eligibility, "(f.file_owner IS NULL AND f.created_at <= ?)")
		eligibilityArgs = append(eligibilityArgs, *guestBefore)
	}
	if unpaidBefore != nil {
		eligibility = append(eligibility, `(f.file_owner IS NOT NULL AND EXISTS (SELECT 1 FROM users AS u WHERE u.id = f.file_owner AND u.is_paid = FALSE) AND ((EXISTS (SELECT 1 FROM `+subscriptionRetentionFromSQL+` WHERE s.user_id = f.file_owner AND s.status IN ('active','trialing') AND s.current_period_end > ? AND benefit.retention_days > 0 AND f.created_at <= CAST(? AS timestamptz) - (benefit.retention_days * INTERVAL '1 day'))) OR (NOT EXISTS (SELECT 1 FROM subscriptions AS s WHERE s.user_id = f.file_owner AND s.status IN ('active','trialing') AND s.current_period_end > ?) AND f.created_at <= ?)))`)
		eligibilityArgs = append(eligibilityArgs, now, now, now, now, now, *unpaidBefore)
	}
	eligibleSQL := "FALSE"
	if len(eligibility) != 0 {
		eligibleSQL = strings.Join(eligibility, " OR ")
	}
	return eligibleSQL, eligibilityArgs
}

// ClaimFileDeletion moves a complete file to the "deleting" state so it can no
// longer be served, using the same claim the retention sweep uses (and retries
// once the claim is stale).
func (repo *GormRepository) ClaimFileDeletion(ctx context.Context, fileID string, now time.Time) error {
	result := repo.connection.WithContext(ctx).Model(&FileList{}).
		Where("file_id = ? AND upload_status = ?", fileID, "complete").
		Updates(map[string]any{"upload_status": "deleting", "retention_claimed_at": now, "updated_at": now})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (repo *GormRepository) ReleaseRetentionClaim(ctx context.Context, fileID string) error {
	result := repo.connection.WithContext(ctx).Model(&FileList{}).
		Where("file_id = ? AND upload_status = ?", fileID, "deleting").
		Updates(map[string]any{"upload_status": "complete", "retention_claimed_at": nil})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (repo *GormRepository) Ping(ctx context.Context) error {
	if repo.redis != nil {
		if err := repo.redis.ping(ctx); err != nil {
			return err
		}
	}
	sqlDB, err := repo.connection.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}
