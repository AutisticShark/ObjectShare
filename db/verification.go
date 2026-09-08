package db

import (
	"context"
	"time"
)

// Verification tokens prove email ownership only; they never authenticate a user.
type EmailVerificationRepository interface {
	ReserveEmailVerification(context.Context, string, string, string, time.Time, time.Time) (bool, error)
	VerifyEmail(context.Context, string, string, time.Time) (bool, error)
}

// The conditional update serializes concurrent sends across replicas. Preserve
// the reservation on provider errors because the email may have been accepted.
func (repo *GormRepository) ReserveEmailVerification(ctx context.Context, id, email, hash string, now, expires time.Time) (bool, error) {
	result := repo.connection.WithContext(ctx).Model(&User{}).
		Where("id = ? AND email = ? AND active = ? AND email_verified_at IS NULL AND (email_verification_sent_at IS NULL OR email_verification_sent_at <= ?)", id, email, true, now.Add(-time.Minute)).
		Updates(map[string]any{"email_verification_hash": hash, "email_verification_expires_at": expires, "email_verification_sent_at": now})
	return result.RowsAffected == 1, result.Error
}

func (repo *GormRepository) VerifyEmail(ctx context.Context, id, hash string, now time.Time) (bool, error) {
	if hash == "" {
		return false, nil
	}
	result := repo.connection.WithContext(ctx).Model(&User{}).
		Where("id = ? AND active = ? AND email_verified_at IS NULL AND email_verification_hash = ? AND email_verification_expires_at > ?", id, true, hash, now).
		Updates(map[string]any{"email_verified_at": now, "email_verification_hash": "", "email_verification_expires_at": nil})
	return result.RowsAffected == 1, result.Error
}
