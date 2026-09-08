package db

import (
	"context"
	"errors"

	"gorm.io/gorm"
)

// ClientKeyVault contains only a browser-encrypted account key. There is no
// server-side recovery key and no endpoint that replaces an existing vault.
type ClientKeyVault struct {
	UserID     string `gorm:"type:uuid;primaryKey" json:"user_id"`
	KeyID      string `gorm:"type:varchar(43);not null" json:"key_id"`
	Salt       string `gorm:"type:varchar(22);not null" json:"salt"`
	IV         string `gorm:"type:varchar(16);not null" json:"iv"`
	WrappedKey string `gorm:"type:varchar(64);not null" json:"wrapped_key"`
	Version    int    `gorm:"not null" json:"version"`
	User       User   `gorm:"foreignKey:UserID;references:ID;constraint:OnDelete:CASCADE" json:"-"`
}

type ClientKeyRepository interface {
	ClientKey(context.Context, string) (*ClientKeyVault, error)
	CreateClientKey(context.Context, *ClientKeyVault) error
}

func (repo *GormRepository) ClientKey(ctx context.Context, userID string) (*ClientKeyVault, error) {
	var vault ClientKeyVault
	err := repo.connection.WithContext(ctx).Where("user_id = ?", userID).First(&vault).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return &vault, err
}

func (repo *GormRepository) CreateClientKey(ctx context.Context, vault *ClientKeyVault) error {
	// Serializing against upload reservations ensures encryption cannot be
	// enabled concurrently with a new plaintext reservation for this account.
	return repo.connection.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT id FROM users WHERE id = ? FOR UPDATE", vault.UserID).Error; err != nil {
			return err
		}
		result := tx.Exec("INSERT INTO client_key_vaults (user_id, key_id, salt, iv, wrapped_key, version) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (user_id) DO NOTHING", vault.UserID, vault.KeyID, vault.Salt, vault.IV, vault.WrappedKey, vault.Version)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrConflict
		}
		return nil
	})
}
