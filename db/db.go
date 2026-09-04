package db

import (
	"context"
	"errors"
	"fmt"
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
	ErrNotFound        = errors.New("record not found")
	ErrConflict        = errors.New("record already exists")
	ErrUploadQuota     = errors.New("upload quota exceeded")
	ErrInvalidQuota    = errors.New("upload quota must not be negative")
	ErrAdminExists     = errors.New("an administrator already exists")
	ErrLastAdmin       = errors.New("the final active administrator must be preserved")
	ErrLastLoginMethod = errors.New("the final login method must be preserved")
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

type Repository interface {
	Create(context.Context, *FileList) error
	ReserveUpload(context.Context, *FileList) error
	UploadUsage(context.Context, string) (UploadUsage, error)
	Get(context.Context, string) (*FileList, error)
	CompleteUpload(context.Context, string) error
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
	UnlinkOAuthIdentity(context.Context, string, string) error
	ListUsers(context.Context) ([]User, error)
	StorageUsageByUser(context.Context) (map[string]int64, error)
	UpdateProfile(context.Context, string, string, string) error
	UpdateDarkMode(context.Context, string, bool) error
	UpdatePassword(context.Context, string, string) (*User, error)
	AdminUpdateUser(context.Context, string, string, bool) error
	UpdateUploadQuota(context.Context, string, int64) error
	UpdatePaidStatus(context.Context, string, bool) error
	DeleteUser(context.Context, string) error
	ListFilesByOwner(context.Context, string) ([]FileList, error)
	RecordLogin(context.Context, string, time.Time) error
	RevokeToken(context.Context, string, time.Time, time.Time) error
	TokenRevoked(context.Context, string, time.Time) (bool, error)
	LoginAllowed(context.Context, string, time.Time) (bool, time.Time, error)
	RecordLoginFailure(context.Context, string, time.Time) error
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
	rateLimitCalls atomic.Uint64
}

func Open(ctx context.Context, cfg *config.DatabaseConfig) (*GormRepository, error) {
	pgxConfig, location, err := postgresConfig(cfg)
	if err != nil {
		return nil, err
	}
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
		PrepareStmt:            true,
		DisableAutomaticPing:   true,
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
	if err := migration.AutoMigrate(&User{}, &OAuthIdentity{}, &RevokedToken{}, &LoginThrottle{}, &RateLimitBucket{}, &FileList{}, &ApplicationSetting{}, &PaidPlan{}, &Subscription{}, &BillingEvent{}, &BillingCheckout{}); err != nil {
		_ = migration.Rollback().Error
		_ = sqlDB.Close()
		return nil, fmt.Errorf("migrate PostgreSQL: %w", err)
	}
	if err := migration.Exec("DROP TABLE IF EXISTS sessions").Error; err != nil {
		_ = migration.Rollback().Error
		_ = sqlDB.Close()
		return nil, fmt.Errorf("remove legacy server sessions: %w", err)
	}
	if err := migration.Commit().Error; err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("commit migration: %w", err)
	}
	return &GormRepository{connection: connection}, nil
}

func postgresConfig(cfg *config.DatabaseConfig) (*pgx.ConnConfig, *time.Location, error) {
	location, err := time.LoadLocation(cfg.TimeZone)
	if err != nil {
		return nil, nil, fmt.Errorf("load PostgreSQL time zone %q: %w", cfg.TimeZone, err)
	}
	dsn := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(cfg.User, cfg.Password),
		Host:   cfg.Host + ":" + strconv.Itoa(cfg.Port),
		Path:   cfg.Database,
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
	sqlDB, err := repo.connection.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
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
	var planQuota int64
	err := connection.Table("subscriptions AS s").Select("COALESCE(MAX(p.storage_quota_bytes), 0)").
		Joins("JOIN paid_plans AS p ON p.id = s.plan_id").
		Where("s.user_id = ? AND s.status IN ? AND s.current_period_end > ?", userID, []string{"active", "trialing"}, now).
		Scan(&planQuota).Error
	if err != nil {
		return 0, err
	}
	if planQuota > accountQuota {
		return planQuota, nil
	}
	return accountQuota, nil
}

func uploadBytesUsed(connection *gorm.DB, userID string) (int64, error) {
	active := []string{"pending", "complete", "deleting"}
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

func (repo *GormRepository) CompleteUpload(ctx context.Context, fileID string) error {
	result := repo.connection.WithContext(ctx).Model(&FileList{}).
		Where("file_id = ? AND upload_status = ?", fileID, "pending").
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

func (repo *GormRepository) ExpiredUploads(ctx context.Context, before time.Time, limit int) ([]FileList, error) {
	var files []FileList
	err := repo.connection.WithContext(ctx).
		Where("upload_status = ? AND upload_expires_at < ?", "pending", before).
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
		var candidates []FileList
		if err := transaction.Table("file_lists AS f").
			Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where("(f.upload_status = 'complete' AND ("+eligibleSQL+")) OR (f.upload_status = 'deleting' AND f.retention_claimed_at <= ?)", args...).
			Order("COALESCE(f.retention_claimed_at, f.created_at), f.id").Limit(limit).Find(&candidates).Error; err != nil {
			return err
		}

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
				return err
			}
			for _, user := range users {
				usersByID[user.ID] = user
			}
		}
		entitlementsByID := make(map[string]Entitlements, len(userIDs))
		for _, userID := range userIDs {
			entitlements, err := entitlementsWithDB(transaction, userID, now)
			if err != nil {
				return err
			}
			entitlementsByID[userID] = entitlements
		}

		claimed = candidates[:0]
		ids := make([]uint, 0, len(candidates))
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
				claimed = append(claimed, file)
				ids = append(ids, file.ID)
			}
		}
		if len(ids) == 0 {
			return nil
		}
		return transaction.Model(&FileList{}).Where("id IN ?", ids).
			Updates(map[string]any{"upload_status": "deleting", "retention_claimed_at": now, "updated_at": now}).Error
	})
	if err != nil {
		return nil, err
	}
	return claimed, nil
}

func retentionEligibilitySQLAt(now time.Time, guestBefore, unpaidBefore *time.Time) (string, []any) {
	var eligibility []string
	var eligibilityArgs []any
	if guestBefore != nil {
		eligibility = append(eligibility, "(f.file_owner IS NULL AND f.created_at <= ?)")
		eligibilityArgs = append(eligibilityArgs, *guestBefore)
	}
	if unpaidBefore != nil {
		eligibility = append(eligibility, `(f.file_owner IS NOT NULL AND EXISTS (SELECT 1 FROM users AS u WHERE u.id = f.file_owner AND u.is_paid = FALSE) AND ((EXISTS (SELECT 1 FROM subscriptions AS s JOIN paid_plans AS p ON p.id = s.plan_id WHERE s.user_id = f.file_owner AND s.status IN ('active','trialing') AND s.current_period_end > ? AND p.retention_days > 0 AND f.created_at <= ? - (p.retention_days * INTERVAL '1 day'))) OR (NOT EXISTS (SELECT 1 FROM subscriptions AS s WHERE s.user_id = f.file_owner AND s.status IN ('active','trialing') AND s.current_period_end > ?) AND f.created_at <= ?)))`)
		eligibilityArgs = append(eligibilityArgs, now, now, now, *unpaidBefore)
	}
	eligibleSQL := "FALSE"
	if len(eligibility) != 0 {
		eligibleSQL = strings.Join(eligibility, " OR ")
	}
	return eligibleSQL, eligibilityArgs
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
	sqlDB, err := repo.connection.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}
