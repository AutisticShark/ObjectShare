package db

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresEmailVerificationUpgradePreservesExistingUsers(t *testing.T) {
	settings := creditTestSettings(t)
	cfg := &config.DatabaseConfig{MaxOpenConns: 1, MaxIdleConns: 1}
	open := func() *GormRepository {
		t.Helper()
		repo, err := openPostgres(t.Context(), cfg, settings, time.UTC)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = repo.Close() })
		return repo
	}
	repo := open()
	user := creditTestUser(t, repo, 37)
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	// Simulate a populated pre-verification user schema, then use the real
	// startup migration twice to cover compatibility and idempotence.
	pool := stdlib.OpenDB(*settings)
	_, err := pool.ExecContext(t.Context(), "ALTER TABLE users DROP COLUMN email_verified_at, DROP COLUMN email_verification_hash, DROP COLUMN email_verification_sent_at, DROP COLUMN email_verification_expires_at")
	_ = pool.Close()
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		repo = open()
		current, err := repo.UserByID(t.Context(), user.ID)
		if err != nil {
			t.Fatal(err)
		}
		if current.Email != user.Email || current.PasswordHash != user.PasswordHash || current.Role != user.Role || current.CreditBalance != 37 || current.EmailVerifiedAt != nil || current.EmailVerificationHash != "" || current.EmailVerificationExpiresAt != nil || current.EmailVerificationSentAt != nil {
			t.Fatal("upgrade changed account values or verified an existing user")
		}
		if err := repo.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPostgresEmailVerificationLifecycleAndConcurrency(t *testing.T) {
	repo := creditTestRepository(t)
	user := creditTestUser(t, repo, 0)
	now := time.Now().UTC().Truncate(time.Second)
	hash := strings.Repeat("a", 64)
	var sends atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			ok, err := repo.ReserveEmailVerification(t.Context(), user.ID, user.Email, hash, now, now.Add(time.Hour))
			if err != nil {
				t.Error(err)
			}
			if ok {
				sends.Add(1)
			}
		})
	}
	wg.Wait()
	if sends.Load() != 1 {
		t.Fatalf("concurrent send reservations=%d", sends.Load())
	}
	if ok, err := repo.VerifyEmail(t.Context(), user.ID, strings.Repeat("b", 64), now); err != nil || ok {
		t.Fatal("accepted wrong token", err)
	}
	if ok, err := repo.VerifyEmail(t.Context(), user.ID, hash, now.Add(time.Hour)); err != nil || ok {
		t.Fatal("accepted expired token", err)
	}
	if err := repo.UpdateProfile(t.Context(), user.ID, "changed@example.com", "Changed"); err != nil {
		t.Fatal(err)
	}
	if ok, err := repo.VerifyEmail(t.Context(), user.ID, hash, now); err != nil || ok {
		t.Fatal("accepted previous email token", err)
	}
	if ok, err := repo.ReserveEmailVerification(t.Context(), user.ID, user.Email, hash, now.Add(time.Minute), now.Add(time.Hour)); err != nil || ok {
		t.Fatal("reserved against stale email", err)
	}
	if ok, err := repo.ReserveEmailVerification(t.Context(), user.ID, "changed@example.com", hash, now, now.Add(time.Hour)); err != nil || ok {
		t.Fatal("email change bypassed cooldown", err)
	}
	if ok, err := repo.ReserveEmailVerification(t.Context(), user.ID, "changed@example.com", hash, now.Add(time.Minute), now.Add(time.Hour)); err != nil || !ok {
		t.Fatal("could not resend", err)
	}
	var verified atomic.Int32
	for range 8 {
		wg.Go(func() {
			ok, err := repo.VerifyEmail(t.Context(), user.ID, hash, now.Add(2*time.Minute))
			if err != nil {
				t.Error(err)
			}
			if ok {
				verified.Add(1)
			}
		})
	}
	wg.Wait()
	if verified.Load() != 1 {
		t.Fatalf("concurrent token consumptions=%d", verified.Load())
	}
	if err := repo.UpdateProfile(t.Context(), user.ID, "changed@example.com", "Name only"); err != nil {
		t.Fatal(err)
	}
	current, err := repo.UserByID(t.Context(), user.ID)
	if err != nil || current.EmailVerifiedAt == nil || current.EmailVerificationHash != "" || current.EmailVerificationExpiresAt != nil {
		t.Fatal("verification not persisted or token not cleared", err)
	}
	if err := repo.UpdateProfile(t.Context(), user.ID, "another@example.com", "Changed again"); err != nil {
		t.Fatal(err)
	}
	current, err = repo.UserByID(t.Context(), user.ID)
	if err != nil || current.EmailVerifiedAt != nil {
		t.Fatal("email change retained verification", err)
	}
	// Resending invalidates the previous token; disabled accounts cannot consume it.
	for i, value := range []string{hash, strings.Repeat("c", 64)} {
		if ok, err := repo.ReserveEmailVerification(t.Context(), user.ID, current.Email, value, now.Add(time.Duration(i+3)*time.Minute), now.Add(time.Hour)); err != nil || !ok {
			t.Fatal("reserve replacement", err)
		}
	}
	if ok, err := repo.VerifyEmail(t.Context(), user.ID, hash, now.Add(5*time.Minute)); err != nil || ok {
		t.Fatal("accepted superseded token", err)
	}
	if err := repo.AdminUpdateUser(t.Context(), user.ID, RoleUser, false); err != nil {
		t.Fatal(err)
	}
	if ok, err := repo.VerifyEmail(t.Context(), user.ID, strings.Repeat("c", 64), now.Add(5*time.Minute)); err != nil || ok {
		t.Fatal("verified disabled account", err)
	}
}
