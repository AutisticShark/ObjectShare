package db

import (
	"context"
	"errors"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const runtimeSettingsKey = "runtime_config"

func (repo *GormRepository) ApplicationSettings(ctx context.Context) (*ApplicationSetting, error) {
	var setting ApplicationSetting
	err := repo.connection.WithContext(ctx).Where("key = ?", runtimeSettingsKey).First(&setting).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return &setting, err
}

// InitializeApplicationSettings imports legacy file/environment configuration
// once. ON CONFLICT preserves the database as the authority across restarts and
// is safe when multiple replicas start for the first time concurrently.
func (repo *GormRepository) InitializeApplicationSettings(ctx context.Context, value string) error {
	setting := &ApplicationSetting{Key: runtimeSettingsKey, Value: value, UpdatedBy: "bootstrap import"}
	return repo.connection.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(setting).Error
}

func (repo *GormRepository) SaveApplicationSettings(ctx context.Context, value, updatedBy, previousValue string) error {
	result := repo.connection.WithContext(ctx).Model(&ApplicationSetting{}).
		Where("key = ? AND value = ?", runtimeSettingsKey, previousValue).
		Updates(map[string]any{"value": value, "updated_by": updatedBy, "updated_at": gorm.Expr("CURRENT_TIMESTAMP")})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrConflict
	}
	return nil
}

var _ SettingsRepository = (*GormRepository)(nil)
