package db

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
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
	if err := migration.AutoMigrate(&User{}, &OAuthIdentity{}, &RevokedToken{}, &LoginThrottle{}, &RateLimitBucket{}, &FileList{}, &ApplicationSetting{}); err != nil {
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
		if user.UploadQuotaBytes > 0 {
			used, err := uploadBytesUsed(transaction, user.ID)
			if err != nil {
				return err
			}
			if exceedsQuota(used, file.FileSize, user.UploadQuotaBytes) {
				return &UploadQuotaError{Scope: "user", Used: used, Limit: user.UploadQuotaBytes, Requested: file.FileSize}
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
	if user.UploadQuotaBytes == 0 {
		return UploadUsage{}, nil
	}
	used, err := uploadBytesUsed(connection, userID)
	return UploadUsage{Used: used, Limit: user.UploadQuotaBytes}, err
}

func uploadBytesUsed(connection *gorm.DB, userID string) (int64, error) {
	active := []string{"pending", "complete"}
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

func (repo *GormRepository) Ping(ctx context.Context) error {
	sqlDB, err := repo.connection.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}
