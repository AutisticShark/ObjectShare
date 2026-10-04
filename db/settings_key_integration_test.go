package db

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/google/uuid"
)

// A settings-key rotation rewrites the configuration row and every MFA state
// in one transaction, exactly once even when replicas start together.
func TestPostgresSettingsKeyRotationIsTransactionalAndRunsOnce(t *testing.T) {
	settings := creditTestSettings(t)
	repo, err := openPostgres(t.Context(), &config.DatabaseConfig{MaxOpenConns: 4, MaxIdleConns: 1}, settings, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	if err := repo.InitializeApplicationSettings(t.Context(), "sealed-with-old-key"); err != nil {
		t.Fatal(err)
	}
	enrolled := User{ID: uuid.NewString(), Email: uuid.NewString() + "@example.com", Active: true, TokenVersion: 1,
		MFA: MFAState{Method: "totp", Secret: "old-secret", Recovery: []string{"old-hash"}}}
	plain := User{ID: uuid.NewString(), Email: uuid.NewString() + "@example.com", Active: true, TokenVersion: 1}
	for _, user := range []*User{&enrolled, &plain} {
		if err := repo.connection.Create(user).Error; err != nil {
			t.Fatal(err)
		}
	}
	reseal := func(value string) (string, bool, error) {
		if value == "sealed-with-new-key" {
			return value, false, nil
		}
		return "sealed-with-new-key", true, nil
	}
	var visited atomic.Int32
	resealMFA := func(user *User) (bool, bool, error) {
		visited.Add(1)
		user.MFA.Secret = strings.Replace(user.MFA.Secret, "old", "new", 1)
		user.MFA.Recovery = []string{PreviousKeyRecoveryPrefix + user.MFA.Recovery[0]}
		return true, false, nil
	}

	var wait sync.WaitGroup
	results := make([]SettingsKeyRotation, 3)
	errs := make([]error, 3)
	for index := range results {
		wait.Go(func() { results[index], errs[index] = repo.RotateSettingsKey(t.Context(), reseal, resealMFA) })
	}
	wait.Wait()
	rotated := 0
	for index, result := range results {
		if errs[index] != nil {
			t.Fatal(errs[index])
		}
		if result.Rotated {
			rotated++
			if result.Accounts != 1 {
				t.Fatalf("accounts updated = %d, want only the MFA-enabled account", result.Accounts)
			}
		}
		if result.PreviousKeyRecoveryAccounts != 1 {
			t.Fatalf("previous-key recovery accounts = %d, want 1", result.PreviousKeyRecoveryAccounts)
		}
	}
	if rotated != 1 || visited.Load() != 1 {
		t.Fatalf("rotation ran %d times and visited %d accounts; want exactly once", rotated, visited.Load())
	}
	setting, err := repo.ApplicationSettings(t.Context())
	if err != nil || setting.Value != "sealed-with-new-key" || setting.UpdatedBy != "settings key rotation" {
		t.Fatalf("configuration row not rotated: %+v %v", setting, err)
	}
	stored, err := repo.UserByID(t.Context(), enrolled.ID)
	if err != nil || stored.MFA.Secret != "new-secret" || len(stored.MFA.Recovery) != 1 || stored.MFA.Recovery[0] != PreviousKeyRecoveryPrefix+"old-hash" || stored.MFA.Method != "totp" {
		t.Fatalf("MFA state not rewritten: %+v %v", stored.MFA, err)
	}

	// A failing account rolls the whole rotation back.
	if err := repo.SaveApplicationSettings(t.Context(), "sealed-with-old-key", "test", "sealed-with-new-key"); err != nil {
		t.Fatal(err)
	}
	failing := func(*User) (bool, bool, error) { return false, false, errTestRotation }
	if _, err := repo.RotateSettingsKey(t.Context(), reseal, failing); err == nil {
		t.Fatal("a failing account did not abort the rotation")
	}
	if setting, _ := repo.ApplicationSettings(t.Context()); setting.Value != "sealed-with-old-key" {
		t.Fatalf("a failed rotation left the configuration row at %q", setting.Value)
	}
}

var errTestRotation = &rotationTestError{}

type rotationTestError struct{}

func (*rotationTestError) Error() string { return "test rotation failure" }
