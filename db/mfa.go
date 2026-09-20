package db

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// MFAState is private account state. Seeds are encrypted; codes and JWT IDs are
// hashed. One active challenge per account makes superseded flows unusable.
type MFAState struct {
	Method        string    `json:"method,omitempty"`
	Secret        string    `json:"secret,omitempty"`
	LastStep      int64     `json:"last_step,omitempty"`
	Recovery      []string  `json:"recovery,omitempty"`
	Challenge     string    `json:"challenge,omitempty"`
	Action        string    `json:"action,omitempty"`
	AuthHash      string    `json:"auth_hash,omitempty"`
	PendingMethod string    `json:"pending_method,omitempty"`
	PendingSecret string    `json:"pending_secret,omitempty"`
	EmailHash     string    `json:"email_hash,omitempty"`
	Email         string    `json:"email,omitempty"`
	Expires       time.Time `json:"expires,omitempty"`
	SentAt        time.Time `json:"sent_at,omitempty"`
	Failures      int       `json:"failures,omitempty"`
	LockedUntil   time.Time `json:"locked_until,omitempty"`
}

var ErrMFAEmailChange = errors.New("disable email MFA before changing the email address")

type MFARepository interface {
	MutateMFA(context.Context, string, int, func(*User) error) (*User, error)
}

// Serialize validation, attempt accounting and consumption across replicas.
// Callbacks return nil to commit failed-attempt counters, errors to roll back.
func (repo *GormRepository) MutateMFA(ctx context.Context, id string, version int, mutate func(*User) error) (*User, error) {
	var user User
	err := repo.connection.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", id).First(&user).Error; err != nil {
			return err
		}
		if !user.CanAuthenticate() || user.TokenVersion != version {
			return ErrConflict
		}
		if err := mutate(&user); err != nil {
			return err
		}
		return tx.Model(&user).Select("MFA", "TokenVersion").Updates(&user).Error
	})
	return &user, err
}
