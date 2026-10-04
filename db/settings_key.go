package db

import (
	"context"
	"errors"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// PreviousKeyRecoveryPrefix marks an MFA recovery-code hash computed with the
// settings key replaced by the most recent rotation. Only keyed hashes of
// recovery codes are stored, so they cannot be re-keyed; a marked code keeps
// working only while that previous key stays configured.
const PreviousKeyRecoveryPrefix = "previous-key:"

// SettingsKeyRotation reports what RotateSettingsKey changed.
type SettingsKeyRotation struct {
	// Rotated is false when the stored configuration already used the new key.
	Rotated bool
	// Accounts counts accounts whose MFA state was rewritten.
	Accounts int
	// Unreadable counts accounts with an MFA secret neither key could open.
	Unreadable int
	// PreviousKeyRecoveryAccounts counts accounts that still hold recovery
	// codes usable only with the previous key.
	PreviousKeyRecoveryAccounts int64
}

// RotateSettingsKey re-protects every value sealed with the settings key in one
// transaction. reseal converts the runtime configuration document and reports
// whether it was still sealed with the previous key; only then are accounts'
// MFA states passed to resealMFA, so a completed rotation is never repeated.
// The configuration row stays locked throughout, which serializes replicas
// starting at the same time and makes a concurrent dashboard save retry.
func (repo *GormRepository) RotateSettingsKey(ctx context.Context, reseal func(string) (string, bool, error), resealMFA func(*User) (changed, unreadable bool, err error)) (SettingsKeyRotation, error) {
	var result SettingsKeyRotation
	err := repo.connection.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var setting ApplicationSetting
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("key = ?", runtimeSettingsKey).First(&setting).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil // Nothing has been sealed yet; the first import uses the new key.
		}
		if err != nil {
			return err
		}
		value, changed, err := reseal(setting.Value)
		if err != nil || !changed {
			return err
		}
		if err := tx.Model(&ApplicationSetting{}).Where("key = ?", runtimeSettingsKey).
			Updates(map[string]any{"value": value, "updated_by": "settings key rotation", "updated_at": gorm.Expr("CURRENT_TIMESTAMP")}).Error; err != nil {
			return err
		}
		result.Rotated = true
		var users []User
		return tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("mfa <> '{}'::jsonb").FindInBatches(&users, 200, func(*gorm.DB, int) error {
			for index := range users {
				changed, unreadable, err := resealMFA(&users[index])
				if err != nil {
					return err
				}
				if unreadable {
					result.Unreadable++
				}
				if !changed {
					continue
				}
				if err := tx.Model(&users[index]).Select("MFA").Updates(&users[index]).Error; err != nil {
					return err
				}
				result.Accounts++
			}
			return nil
		}).Error
	})
	if err != nil {
		return SettingsKeyRotation{}, err
	}
	err = repo.connection.WithContext(ctx).Model(&User{}).
		Where(`EXISTS (SELECT 1 FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(mfa->'recovery') = 'array' THEN mfa->'recovery' ELSE '[]'::jsonb END) AS code WHERE starts_with(code, ?))`, PreviousKeyRecoveryPrefix).
		Count(&result.PreviousKeyRecoveryAccounts).Error
	return result, err
}
