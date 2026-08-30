package db

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/stdlib"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	ErrNotFound    = errors.New("record not found")
	ErrConflict    = errors.New("record already exists")
	ErrAdminExists = errors.New("an administrator already exists")
	ErrLastAdmin   = errors.New("the final active administrator must be preserved")
)

type Repository interface {
	Create(context.Context, *FileList) error
	Get(context.Context, string) (*FileList, error)
	CompleteUpload(context.Context, string) error
	ExpiredUploads(context.Context, time.Time, int) ([]FileList, error)
	Rename(context.Context, string, string) error
	Delete(context.Context, string) error
	Ping(context.Context) error
}

type AuthRepository interface {
	AdminCount(context.Context) (int64, error)
	BootstrapAdmin(context.Context, *User) error
	CreateUser(context.Context, *User) error
	UserByEmail(context.Context, string) (*User, error)
	UserByID(context.Context, string) (*User, error)
	ListUsers(context.Context) ([]User, error)
	UpdateProfile(context.Context, string, string, string) error
	UpdatePassword(context.Context, string, string) (*User, error)
	AdminUpdateUser(context.Context, string, string, bool) error
	DeleteUser(context.Context, string) error
	ListFilesByOwner(context.Context, string) ([]FileList, error)
	RecordLogin(context.Context, string, time.Time) error
	RevokeToken(context.Context, string, time.Time, time.Time) error
	TokenRevoked(context.Context, string, time.Time) (bool, error)
	LoginAllowed(context.Context, string, time.Time) (bool, time.Time, error)
	RecordLoginFailure(context.Context, string, time.Time) error
	ClearLoginFailures(context.Context, string) error
}

type GormRepository struct{ connection *gorm.DB }

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
	if err := migration.AutoMigrate(&User{}, &RevokedToken{}, &LoginThrottle{}, &FileList{}); err != nil {
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
