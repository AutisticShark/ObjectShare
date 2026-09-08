package db

import (
	"context"
	"errors"

	"gorm.io/gorm"
)

func ValidModerationStatus(status string) bool {
	return status == ModerationNone || status == ModerationBanned || status == ModerationShadowbanned
}

// Serialize with access changes and deletion so concurrent moderation cannot
// remove the last available administrator.
func (repo *GormRepository) AdminModerateUser(ctx context.Context, id, status string) error {
	if !ValidModerationStatus(status) {
		return ErrInvalidModeration
	}
	return repo.connection.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("LOCK TABLE users IN EXCLUSIVE MODE").Error; err != nil {
			return err
		}
		var user User
		if err := tx.Where("id = ?", id).First(&user).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if user.ModerationStatus == status {
			return nil
		}
		if user.IsAvailableAdmin() && status != ModerationNone {
			var count int64
			if err := tx.Model(&User{}).Where("role = ? AND active = ? AND moderation_status = ?", RoleAdmin, true, ModerationNone).Count(&count).Error; err != nil {
				return err
			}
			if count <= 1 {
				return ErrLastAdmin
			}
		}
		updates := map[string]any{"moderation_status": status}
		// Shadowbans on ordinary accounts must not sign the user out. Ban
		// transitions invalidate tokens, as do changes to administrator access.
		if status == ModerationBanned || user.ModerationStatus == ModerationBanned || user.Role == RoleAdmin {
			updates["token_version"] = gorm.Expr("token_version + 1")
		}
		return tx.Model(&user).Updates(updates).Error
	})
}
