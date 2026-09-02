package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	loginWindow      = 15 * time.Minute
	loginLockout     = 15 * time.Minute
	maxLoginFailures = 5
)

func translateConflict(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) && pgError.Code == "23505" {
		return ErrConflict
	}
	return err
}

func (repo *GormRepository) AdminCount(ctx context.Context) (int64, error) {
	var count int64
	err := repo.connection.WithContext(ctx).Model(&User{}).Where("role = ?", RoleAdmin).Count(&count).Error
	return count, err
}

func (repo *GormRepository) BootstrapAdmin(ctx context.Context, user *User) error {
	return repo.connection.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := transaction.Exec("LOCK TABLE users IN EXCLUSIVE MODE").Error; err != nil {
			return err
		}
		var count int64
		if err := transaction.Model(&User{}).Where("role = ?", RoleAdmin).Count(&count).Error; err != nil {
			return err
		}
		if count != 0 {
			return ErrAdminExists
		}
		user.Role = RoleAdmin
		user.Active = true
		return translateConflict(transaction.Create(user).Error)
	})
}

func (repo *GormRepository) CreateUser(ctx context.Context, user *User) error {
	return translateConflict(repo.connection.WithContext(ctx).Create(user).Error)
}

func (repo *GormRepository) CreateOAuthUser(ctx context.Context, user *User, identity *OAuthIdentity) error {
	return repo.connection.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := translateConflict(transaction.Create(user).Error); err != nil {
			return err
		}
		identity.UserID = user.ID
		return translateConflict(transaction.Create(identity).Error)
	})
}

func (repo *GormRepository) UserByEmail(ctx context.Context, email string) (*User, error) {
	var user User
	err := repo.connection.WithContext(ctx).Where("email = ?", email).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return &user, err
}

func (repo *GormRepository) UserByID(ctx context.Context, id string) (*User, error) {
	var user User
	err := repo.connection.WithContext(ctx).Where("id = ?", id).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return &user, err
}

func (repo *GormRepository) OAuthUser(ctx context.Context, provider, subject string) (*User, error) {
	var identity OAuthIdentity
	err := repo.connection.WithContext(ctx).Preload("User").Where("provider = ? AND subject = ?", provider, subject).First(&identity).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &identity.User, nil
}

func (repo *GormRepository) OAuthIdentities(ctx context.Context, userID string) ([]OAuthIdentity, error) {
	var identities []OAuthIdentity
	err := repo.connection.WithContext(ctx).Where("user_id = ?", userID).Order("provider ASC").Find(&identities).Error
	return identities, err
}

func (repo *GormRepository) LinkOAuthIdentity(ctx context.Context, identity *OAuthIdentity) error {
	return translateConflict(repo.connection.WithContext(ctx).Create(identity).Error)
}

func (repo *GormRepository) UnlinkOAuthIdentity(ctx context.Context, userID, provider string) error {
	return repo.connection.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		var user User
		if err := transaction.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", userID).First(&user).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		var count int64
		if err := transaction.Model(&OAuthIdentity{}).Where("user_id = ?", userID).Count(&count).Error; err != nil {
			return err
		}
		var identity OAuthIdentity
		if err := transaction.Clauses(clause.Locking{Strength: "UPDATE"}).Where("user_id = ? AND provider = ?", userID, provider).First(&identity).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if user.PasswordHash == "" && count <= 1 {
			return ErrLastLoginMethod
		}
		return transaction.Delete(&identity).Error
	})
}

func (repo *GormRepository) ListUsers(ctx context.Context) ([]User, error) {
	var users []User
	err := repo.connection.WithContext(ctx).Order("role ASC, display_name ASC, email ASC").Find(&users).Error
	return users, err
}

func (repo *GormRepository) StorageUsageByUser(ctx context.Context) (map[string]int64, error) {
	type usageRow struct {
		FileOwner string `gorm:"column:file_owner"`
		Used      int64  `gorm:"column:used"`
	}
	var rows []usageRow
	err := repo.connection.WithContext(ctx).Model(&FileList{}).
		Select("file_owner, COALESCE(SUM(file_size), 0) AS used").
		Where("file_owner IS NOT NULL AND upload_status IN ?", []string{"pending", "complete"}).
		Group("file_owner").Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	usage := make(map[string]int64, len(rows))
	for _, row := range rows {
		usage[row.FileOwner] = row.Used
	}
	return usage, nil
}

func (repo *GormRepository) UpdateProfile(ctx context.Context, id, email, displayName string) error {
	result := repo.connection.WithContext(ctx).Model(&User{}).Where("id = ?", id).
		Updates(map[string]any{"email": email, "display_name": displayName})
	if result.Error != nil {
		return translateConflict(result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (repo *GormRepository) UpdateDarkMode(ctx context.Context, id string, enabled bool) error {
	result := repo.connection.WithContext(ctx).Model(&User{}).Where("id = ?", id).
		Update("dark_mode", enabled)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (repo *GormRepository) UpdatePassword(ctx context.Context, id, passwordHash string) (*User, error) {
	var updated User
	err := repo.connection.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		result := transaction.Model(&User{}).Where("id = ?", id).Updates(map[string]any{
			"password_hash": passwordHash, "token_version": gorm.Expr("token_version + 1"),
		})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return ErrNotFound
		}
		return transaction.Where("id = ?", id).First(&updated).Error
	})
	return &updated, err
}

func (repo *GormRepository) AdminUpdateUser(ctx context.Context, id, role string, active bool) error {
	return repo.connection.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := transaction.Exec("LOCK TABLE users IN EXCLUSIVE MODE").Error; err != nil {
			return err
		}
		var user User
		if err := transaction.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", id).First(&user).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if user.Role == RoleAdmin && user.Active && (role != RoleAdmin || !active) {
			var count int64
			if err := transaction.Model(&User{}).Where("role = ? AND active = ?", RoleAdmin, true).Count(&count).Error; err != nil {
				return err
			}
			if count <= 1 {
				return ErrLastAdmin
			}
		}
		roleChanged := role != user.Role
		activeChanged := active != user.Active
		updates := map[string]any{"role": role, "active": active}
		if roleChanged || activeChanged {
			updates["token_version"] = gorm.Expr("token_version + 1")
		}
		if err := transaction.Model(&user).Updates(updates).Error; err != nil {
			return err
		}
		return nil
	})
}

func (repo *GormRepository) UpdateUploadQuota(ctx context.Context, id string, quotaBytes int64) error {
	if quotaBytes < 0 {
		return ErrInvalidQuota
	}
	result := repo.connection.WithContext(ctx).Model(&User{}).Where("id = ?", id).
		Update("upload_quota_bytes", quotaBytes)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (repo *GormRepository) DeleteUser(ctx context.Context, id string) error {
	return repo.connection.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := transaction.Exec("LOCK TABLE users IN EXCLUSIVE MODE").Error; err != nil {
			return err
		}
		var user User
		if err := transaction.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", id).First(&user).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if user.Role == RoleAdmin && user.Active {
			var count int64
			if err := transaction.Model(&User{}).Where("role = ? AND active = ?", RoleAdmin, true).Count(&count).Error; err != nil {
				return err
			}
			if count <= 1 {
				return ErrLastAdmin
			}
		}
		if err := transaction.Model(&FileList{}).Where("file_owner = ?", id).
			Updates(map[string]any{"file_owner": nil, "is_anonymous_upload": true}).Error; err != nil {
			return err
		}
		return transaction.Delete(&user).Error
	})
}

func (repo *GormRepository) ListFilesByOwner(ctx context.Context, userID string) ([]FileList, error) {
	var files []FileList
	err := repo.connection.WithContext(ctx).Where("file_owner = ? AND upload_status = ?", userID, "complete").
		Order("created_at DESC").Find(&files).Error
	return files, err
}

func (repo *GormRepository) RecordLogin(ctx context.Context, userID string, now time.Time) error {
	result := repo.connection.WithContext(ctx).Model(&User{}).Where("id = ?", userID).Update("last_login_at", now)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (repo *GormRepository) RevokeToken(ctx context.Context, jtiHash string, expiresAt, now time.Time) error {
	return repo.connection.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := transaction.Where("expires_at <= ?", now).Delete(&RevokedToken{}).Error; err != nil {
			return err
		}
		return transaction.Clauses(clause.OnConflict{DoNothing: true}).Create(&RevokedToken{
			JTIHash: jtiHash, ExpiresAt: expiresAt, RevokedAt: now,
		}).Error
	})
}

func (repo *GormRepository) TokenRevoked(ctx context.Context, jtiHash string, now time.Time) (bool, error) {
	var count int64
	err := repo.connection.WithContext(ctx).Model(&RevokedToken{}).
		Where("jti_hash = ? AND expires_at > ?", jtiHash, now).Count(&count).Error
	return count != 0, err
}

func (repo *GormRepository) LoginAllowed(ctx context.Context, key string, now time.Time) (bool, time.Time, error) {
	var throttle LoginThrottle
	err := repo.connection.WithContext(ctx).Where("key = ?", key).First(&throttle).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return true, time.Time{}, nil
	}
	if err != nil {
		return false, time.Time{}, err
	}
	if throttle.LockedUntil != nil && throttle.LockedUntil.After(now) {
		return false, *throttle.LockedUntil, nil
	}
	return true, time.Time{}, nil
}

func (repo *GormRepository) RecordLoginFailure(ctx context.Context, key string, now time.Time) error {
	return repo.connection.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := transaction.Where("updated_at < ?", now.Add(-24*time.Hour)).Delete(&LoginThrottle{}).Error; err != nil {
			return err
		}
		if err := transaction.Exec("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", key).Error; err != nil {
			return err
		}
		var throttle LoginThrottle
		err := transaction.Clauses(clause.Locking{Strength: "UPDATE"}).Where("key = ?", key).First(&throttle).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return transaction.Create(&LoginThrottle{Key: key, Failures: 1, WindowStarted: now, UpdatedAt: now}).Error
		}
		if err != nil {
			return err
		}
		if now.Sub(throttle.WindowStarted) >= loginWindow {
			throttle.Failures = 0
			throttle.WindowStarted = now
			throttle.LockedUntil = nil
		}
		throttle.Failures++
		if throttle.Failures >= maxLoginFailures {
			lockedUntil := now.Add(loginLockout)
			throttle.LockedUntil = &lockedUntil
		}
		throttle.UpdatedAt = now
		return transaction.Save(&throttle).Error
	})
}

func (repo *GormRepository) ClearLoginFailures(ctx context.Context, key string) error {
	return repo.connection.WithContext(ctx).Where("key = ?", key).Delete(&LoginThrottle{}).Error
}
