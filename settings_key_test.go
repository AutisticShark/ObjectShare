package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

// memoryRotator mirrors GormRepository.RotateSettingsKey over in-memory state.
type memoryRotator struct {
	settings *memorySettingsRepository
	users    []db.User
	runs     int
}

func (rotator *memoryRotator) RotateSettingsKey(_ context.Context, reseal func(string) (string, bool, error), resealMFA func(*db.User) (bool, bool, error)) (db.SettingsKeyRotation, error) {
	var result db.SettingsKeyRotation
	if rotator.settings.setting != nil {
		value, changed, err := reseal(rotator.settings.setting.Value)
		if err != nil {
			return result, err
		}
		if changed {
			rotator.runs++
			rotator.settings.setting.Value, result.Rotated = value, true
			for index := range rotator.users {
				changed, unreadable, err := resealMFA(&rotator.users[index])
				if err != nil {
					return result, err
				}
				if changed {
					result.Accounts++
				}
				if unreadable {
					result.Unreadable++
				}
			}
		}
	}
	for _, user := range rotator.users {
		for _, hash := range user.MFA.Recovery {
			if strings.HasPrefix(hash, db.PreviousKeyRecoveryPrefix) {
				result.PreviousKeyRecoveryAccounts++
				break
			}
		}
	}
	return result, nil
}

// Following the start-up warning on a deployment that used the JWT-derived
// settings key must re-key the stored configuration and MFA secrets instead
// of failing with "bootstrap settings key does not match".
func TestSettingsKeyRotationAtStartup(t *testing.T) {
	const jwtSecret = "main-test-jwt-secret-with-at-least-32-bytes"
	const newKey = "main-test-independent-settings-key-32-bytes"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("OBJECTSHARE_JWT_SECRET", jwtSecret)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"db": {"password": "x"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	legacy, err := config.LoadBootstrap(path)
	if err != nil || !legacy.SettingsKeyDerived {
		t.Fatalf("expected the derived legacy key: %v", err)
	}
	legacy.MaxFileSize = 42
	settings := &memorySettingsRepository{}
	if err := loadDatabaseConfiguration(t.Context(), settings, legacy, logger); err != nil {
		t.Fatal(err)
	}
	const totp = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	enrolled := db.User{ID: "11111111-1111-4111-8111-111111111111"}
	enrolled.MFA.Method = "totp"
	enrolled.MFA.Secret, _ = appauth.SealMFASecret(jwtSecret, enrolled.ID, totp)
	enrolled.MFA.PendingSecret, _ = appauth.SealMFASecret(jwtSecret, enrolled.ID, totp)
	enrolled.MFA.Manage.PendingSecret, _ = appauth.SealMFASecret(jwtSecret, enrolled.ID, totp)
	recoveryHash := appauth.MFAHash(jwtSecret, enrolled.ID+":recovery", strings.Repeat("a", 32))
	enrolled.MFA.Recovery = []string{recoveryHash, db.PreviousKeyRecoveryPrefix + "made-with-an-even-older-key"}
	broken := db.User{ID: "22222222-2222-4222-8222-222222222222"}
	broken.MFA.Method, broken.MFA.Secret = "totp", "mfa:v1:not-a-valid-ciphertext"
	rotator := &memoryRotator{settings: settings, users: []db.User{enrolled, broken}}

	// Setting only the new key fails closed with a hint, changing nothing.
	t.Setenv("OBJECTSHARE_SETTINGS_KEY", newKey)
	withoutPrevious, err := config.LoadBootstrap(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := loadDatabaseConfiguration(t.Context(), settings, withoutPrevious, logger); err == nil || !strings.Contains(err.Error(), "OBJECTSHARE_SETTINGS_KEY_PREVIOUS") {
		t.Fatalf("a changed key without the previous key must fail with guidance: %v", err)
	}

	t.Setenv("OBJECTSHARE_SETTINGS_KEY_PREVIOUS", jwtSecret)
	for range 2 {
		cfg, err := config.LoadBootstrap(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := rotateSettingsKey(t.Context(), rotator, cfg, logger); err != nil {
			t.Fatal(err)
		}
		if err := loadDatabaseConfiguration(t.Context(), settings, cfg, logger); err != nil || cfg.MaxFileSize != 42 {
			t.Fatalf("rotated configuration did not open with the new key: max=%d err=%v", cfg.MaxFileSize, err)
		}
	}
	if rotator.runs != 1 {
		t.Fatalf("a completed rotation was repeated %d times", rotator.runs)
	}
	user := rotator.users[0].MFA
	for _, sealed := range []string{user.Secret, user.PendingSecret, user.Manage.PendingSecret} {
		if secret, err := appauth.OpenMFASecret(newKey, enrolled.ID, sealed); err != nil || secret != totp {
			t.Fatalf("TOTP secret was not re-sealed with the new key: %v", err)
		}
	}
	if len(user.Recovery) != 1 || user.Recovery[0] != db.PreviousKeyRecoveryPrefix+recoveryHash {
		t.Fatalf("recovery hashes = %q, want only the marked previous-key hash", user.Recovery)
	}
	if rotator.users[1].MFA.Secret != "mfa:v1:not-a-valid-ciphertext" {
		t.Fatal("an unreadable secret must be left as it was")
	}
}
