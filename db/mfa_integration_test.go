package db

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
)

func TestPostgresMFAMigrationPreservesAccounts(t *testing.T) {
	settings := creditTestSettings(t)
	cfg := &config.DatabaseConfig{MaxOpenConns: 2, MaxIdleConns: 1}
	repo, err := openPostgres(t.Context(), cfg, settings, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	user := creditTestUser(t, repo, 37)
	if err := repo.connection.Exec("ALTER TABLE users DROP COLUMN mfa").Error; err != nil {
		t.Fatal(err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		repo, err = openPostgres(t.Context(), cfg, settings, time.UTC)
		if err != nil {
			t.Fatal(err)
		}
		current, err := repo.UserByID(t.Context(), user.ID)
		if err != nil || current.Email != user.Email || current.CreditBalance != 37 || current.MFA.Method != "" || current.TokenVersion != user.TokenVersion {
			t.Fatal("migration changed account", err)
		}
		if err := repo.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPostgresMFAAtomicConsumptionAndAccountChecks(t *testing.T) {
	repo := creditTestRepository(t)
	user := creditTestUser(t, repo, 0)
	secret, _ := appauth.NewTOTPSecret()
	now := time.Now().UTC()
	code, _ := appauth.TOTPCode(secret, now.Unix()/30)
	_, err := repo.MutateMFA(t.Context(), user.ID, user.TokenVersion, func(u *User) error { u.MFA = MFAState{Method: "totp", Recovery: []string{"recovery-hash"}}; return nil })
	if err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			_, err := repo.MutateMFA(t.Context(), user.ID, user.TokenVersion, func(u *User) error {
				if step, ok := appauth.VerifyTOTP(secret, code, now, u.MFA.LastStep); ok {
					u.MFA.LastStep = step
					successes.Add(1)
				}
				return nil
			})
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("concurrent TOTP successes=%d", successes.Load())
	}
	successes.Store(0)
	for range 12 {
		wg.Go(func() {
			_, err := repo.MutateMFA(t.Context(), user.ID, user.TokenVersion, func(u *User) error {
				if len(u.MFA.Recovery) > 0 {
					u.MFA.Recovery = nil
					successes.Add(1)
				}
				u.MFA.Failures++
				return nil
			})
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	current, err := repo.UserByID(t.Context(), user.ID)
	if err != nil || successes.Load() != 1 || current.MFA.Failures != 12 {
		t.Fatal("lost atomic consumption or attempt accounting", err)
	}
	if _, err := repo.MutateMFA(t.Context(), user.ID, user.TokenVersion+1, func(*User) error { t.Fatal("accepted stale version"); return nil }); !errors.Is(err, ErrConflict) {
		t.Fatal("version check failed", err)
	}
	_, err = repo.MutateMFA(t.Context(), user.ID, user.TokenVersion, func(u *User) error { u.TokenVersion++; u.MFA = MFAState{}; return nil })
	if err != nil {
		t.Fatal(err)
	}
	current, err = repo.UserByID(t.Context(), user.ID)
	if err != nil || current.TokenVersion != user.TokenVersion+1 || current.MFA.Method != "" || current.MFA.LastStep != 0 {
		t.Fatal("reset did not persist zero values", err)
	}
	if err := repo.connection.Model(&User{}).Where("id = ?", user.ID).Update("moderation_status", ModerationBanned).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := repo.MutateMFA(t.Context(), user.ID, current.TokenVersion, func(*User) error { t.Fatal("accepted banned account"); return nil }); !errors.Is(err, ErrConflict) {
		t.Fatal("ban check failed", err)
	}
}

// Stored rows keep the sign-in challenge at the top level of the JSON; the
// management slot is stored separately and changing it leaves sign-in alone.
func TestPostgresMFAChallengeSlotsAreStoredSeparately(t *testing.T) {
	repo := creditTestRepository(t)
	user := creditTestUser(t, repo, 0)
	legacy := `{"method":"totp","challenge":"login-challenge","action":"login","failures":2}`
	if err := repo.connection.Exec("UPDATE users SET mfa = ?::jsonb WHERE id = ?", legacy, user.ID).Error; err != nil {
		t.Fatal(err)
	}
	_, err := repo.MutateMFA(t.Context(), user.ID, user.TokenVersion, func(u *User) error {
		if slot := u.MFA.ChallengeSlot("login"); slot.Challenge != "login-challenge" || slot.Failures != 2 {
			t.Errorf("stored sign-in challenge was not read into the sign-in slot: %+v", slot)
		}
		manage := u.MFA.ChallengeSlot("disable")
		manage.Challenge, manage.Action, manage.Failures = "manage-challenge", "disable", 5
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	current, err := repo.UserByID(t.Context(), user.ID)
	if err != nil || current.MFA.Challenge != "login-challenge" || current.MFA.Failures != 2 || current.MFA.Manage.Challenge != "manage-challenge" || current.MFA.Manage.Failures != 5 {
		t.Fatalf("challenge slots were not stored separately: %+v %v", current.MFA, err)
	}
	var stored string
	if err := repo.connection.Raw("SELECT mfa->>'challenge' FROM users WHERE id = ?", user.ID).Scan(&stored).Error; err != nil || stored != "login-challenge" {
		t.Fatalf("sign-in challenge moved within the stored JSON: %q %v", stored, err)
	}
}

func TestPostgresMFAEmailChangeGuardAndRollback(t *testing.T) {
	repo := creditTestRepository(t)
	user := creditTestUser(t, repo, 0)
	_, err := repo.MutateMFA(t.Context(), user.ID, user.TokenVersion, func(u *User) error { u.MFA.Method = "email"; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateProfile(t.Context(), user.ID, "changed@example.com", "Changed"); !errors.Is(err, ErrMFAEmailChange) {
		t.Fatal("email factor redirected", err)
	}
	if err := repo.UpdateProfile(t.Context(), user.ID, user.Email, "Changed"); err != nil {
		t.Fatal("same-email change blocked", err)
	}
	_, err = repo.MutateMFA(t.Context(), user.ID, user.TokenVersion, func(u *User) error { u.MFA.Method = ""; u.TokenVersion++; return ErrConflict })
	if !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	current, err := repo.UserByID(t.Context(), user.ID)
	if err != nil || current.MFA.Method != "email" || current.TokenVersion != user.TokenVersion {
		t.Fatal("failed mutation committed", err)
	}
	if _, err := repo.UpdatePassword(t.Context(), user.ID, "new-password-hash"); err != nil {
		t.Fatal(err)
	}
	current, _ = repo.UserByID(t.Context(), user.ID)
	if current.MFA.Method != "email" {
		t.Fatal("password reset removed MFA")
	}
}
