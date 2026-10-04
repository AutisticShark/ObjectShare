package config

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRuntimeConfigurationRoundTripIsEncrypted(t *testing.T) {
	cfg := testDefaults()
	cfg.Auth.OAuth.Google.ClientSecret = "google-plaintext-secret"
	cfg.Auth.OAuth.Discord.ClientSecret = "discord-plaintext-secret"
	cfg.Captcha.SecretKey = "turnstile-plaintext-secret"
	cfg.Billing.PayPal.ClientSecret = "paypal-plaintext-secret"
	cfg.R2.SecretAccessKey = "storage-plaintext-secret"
	runtime := RuntimeFromService(cfg)
	sealed, err := SealRuntime(runtime, testJWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{runtime.Auth.OAuth.Google.ClientSecret, runtime.Auth.OAuth.Discord.ClientSecret, runtime.Captcha.SecretKey, runtime.Billing.PayPal.ClientSecret, runtime.R2.SecretAccessKey} {
		if strings.Contains(sealed, secret) {
			t.Fatalf("sealed configuration exposed %q", secret)
		}
	}
	opened, err := OpenRuntime(sealed, testJWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Auth.OAuth.Google.ClientSecret != runtime.Auth.OAuth.Google.ClientSecret || opened.Auth.OAuth.Discord.ClientSecret != runtime.Auth.OAuth.Discord.ClientSecret || opened.Captcha.SecretKey != runtime.Captcha.SecretKey || opened.Billing.PayPal.ClientSecret != runtime.Billing.PayPal.ClientSecret || opened.R2.SecretAccessKey != runtime.R2.SecretAccessKey {
		t.Fatal("sealed configuration did not round-trip secrets")
	}
	if _, err := OpenRuntime(sealed, "a-different-bootstrap-secret-that-is-long-enough"); err == nil {
		t.Fatal("configuration opened with a different bootstrap key")
	}
}

func TestApplyRuntimePreservesBootstrapBoundary(t *testing.T) {
	cfg := testDefaults()
	wantAddress, wantDB, wantJWT, wantLifetime, wantSettingsKey := cfg.Address, *cfg.Db, cfg.Auth.JWTSecret, cfg.Auth.TokenLifetime, cfg.SettingsKey
	runtime := RuntimeFromService(cfg)
	runtime.MaxFileSize = 42
	runtime.Upload.GuestEnabled = false
	runtime.Retention.GuestDays = 7
	runtime.Retention.UnpaidDays = 30
	runtime.Auth.SignupEnabled = false
	runtime.RateLimit.Window = Duration(2 * time.Minute)
	if err := ApplyRuntime(cfg, runtime); err != nil {
		t.Fatal(err)
	}
	if cfg.MaxFileSize != 42 || cfg.Upload.GuestEnabled || cfg.Retention.GuestDays != 7 || cfg.Retention.UnpaidDays != 30 || cfg.Auth.SignupEnabled || cfg.RateLimit.Window != Duration(2*time.Minute) {
		t.Fatalf("runtime fields were not applied: %#v", cfg)
	}
	if cfg.Address != wantAddress || *cfg.Db != wantDB || cfg.Auth.JWTSecret != wantJWT || cfg.Auth.TokenLifetime != wantLifetime || cfg.SettingsKey != wantSettingsKey {
		t.Fatal("database configuration crossed the bootstrap boundary")
	}
}

func TestApplyRuntimeRejectsInvalidDocumentWithoutMutation(t *testing.T) {
	cfg := testDefaults()
	runtime := RuntimeFromService(cfg)
	runtime.MaxFileSize = 0
	if err := ApplyRuntime(cfg, runtime); err == nil {
		t.Fatal("invalid database configuration was accepted")
	}
	if cfg.MaxFileSize == 0 {
		t.Fatal("invalid database configuration partially mutated active settings")
	}
}

func TestSettingsKeyDefaultsForUpgradeButRejectsDocumentedPlaceholder(t *testing.T) {
	cfg := testDefaults()
	cfg.SettingsKey = ""
	if err := cfg.Validate(); err != nil || cfg.SettingsKey != cfg.Auth.JWTSecret {
		t.Fatalf("upgrade fallback did not use the JWT secret: key=%q err=%v", cfg.SettingsKey, err)
	}
	cfg = testDefaults()
	cfg.SettingsKey = "replace-with-a-different-32-byte-random-secret"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "settings_key") {
		t.Fatalf("documented settings placeholder was accepted: %v", err)
	}
}

func TestWithRuntimeBuildsSnapshotsFromAnUnchangedBootstrap(t *testing.T) {
	cfg := testDefaults()
	cfg.MaxFileSize = 100
	runtime := RuntimeFromService(cfg)
	runtime.MaxFileSize = 42
	runtime.Branding.SiteName = "Cat Cloud"
	first, err := WithRuntime(cfg, runtime)
	if err != nil {
		t.Fatal(err)
	}
	if first.MaxFileSize != 42 || first.Branding.SiteName != "Cat Cloud" {
		t.Fatalf("the snapshot did not carry the database document: %#v", first)
	}
	if cfg.MaxFileSize != 100 || cfg.Branding.SiteName == "Cat Cloud" {
		t.Fatal("building a snapshot mutated the bootstrap configuration")
	}
	// A later revision must not inherit anything from the one it replaces.
	runtime.MaxFileSize = 7
	// An empty site name normalizes back to the default, which also shows the
	// second snapshot inherited nothing from the first.
	runtime.Branding.SiteName = ""
	second, err := WithRuntime(cfg, runtime)
	if err != nil {
		t.Fatal(err)
	}
	if second.MaxFileSize != 7 || second.Branding.SiteName != "ObjectShare" || first.MaxFileSize != 42 || first.Branding.SiteName != "Cat Cloud" {
		t.Fatalf("snapshots shared state: first=%d/%q second=%d/%q", first.MaxFileSize, first.Branding.SiteName, second.MaxFileSize, second.Branding.SiteName)
	}
	// Re-applying a document to a configuration already carrying it must be a
	// no-op, so the dashboard does not report a pending activation after one.
	reapplied, err := WithRuntime(first, RuntimeFromService(first))
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(RuntimeFromService(first))
	after, _ := json.Marshal(RuntimeFromService(reapplied))
	if string(before) != string(after) {
		t.Fatalf("activating a document was not idempotent: %s and %s", before, after)
	}
	invalid := RuntimeFromService(cfg)
	invalid.MaxFileSize = 0
	if _, err := WithRuntime(cfg, invalid); err == nil {
		t.Fatal("an invalid database document produced a snapshot")
	}
	if cfg.MaxFileSize != 100 {
		t.Fatal("a rejected document mutated the bootstrap configuration")
	}
}

// A deployment that used the JWT-derived settings key moves to an independent
// key by setting settings_key to the new key and settings_key_previous to the
// old one. The stored document must re-seal without losing a byte.
func TestSettingsKeyRotationResealsTheStoredDocument(t *testing.T) {
	path := t.TempDir() + "/config.json"
	if err := os.WriteFile(path, []byte(`{"auth": {"jwt_secret": "`+testJWTSecret+`"}, "db": {"password": "x"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OBJECTSHARE_SETTINGS_KEY", "")
	legacy, err := LoadBootstrap(path)
	if err != nil || !legacy.SettingsKeyDerived {
		t.Fatalf("expected the derived legacy key: %v", err)
	}
	legacy.R2.SecretAccessKey = "storage-secret-kept-across-rotation"
	if err := legacy.Validate(); err != nil {
		t.Fatal(err)
	}
	sealed, err := SealRuntime(RuntimeFromService(legacy), legacy.SettingsKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("OBJECTSHARE_SETTINGS_KEY", "an-independent-settings-key-of-32-bytes-or-more")
	t.Setenv("OBJECTSHARE_SETTINGS_KEY_PREVIOUS", testJWTSecret)
	upgraded, err := LoadBootstrap(path)
	if err != nil || upgraded.SettingsKeyDerived || upgraded.SettingsKeyPrevious != testJWTSecret {
		t.Fatalf("rotation bootstrap: derived=%v previous set=%v err=%v", upgraded.SettingsKeyDerived, upgraded.SettingsKeyPrevious != "", err)
	}
	if _, err := OpenRuntime(sealed, upgraded.SettingsKey); err == nil {
		t.Fatal("the new key opened a document sealed with the old key")
	}
	resealed, changed, err := ResealRuntime(sealed, upgraded.SettingsKey, upgraded.SettingsKeyPrevious)
	if err != nil || !changed {
		t.Fatalf("reseal: changed=%v err=%v", changed, err)
	}
	before, _ := openRuntimePlaintext(sealed, legacy.SettingsKey)
	after, err := openRuntimePlaintext(resealed, upgraded.SettingsKey)
	if err != nil || string(after) != string(before) {
		t.Fatalf("re-sealed document differs or does not open with the new key: %v", err)
	}
	if again, changed, err := ResealRuntime(resealed, upgraded.SettingsKey, upgraded.SettingsKeyPrevious); err != nil || changed || again != resealed {
		t.Fatalf("a repeated rotation must be a no-op: changed=%v err=%v", changed, err)
	}
	if _, _, err := ResealRuntime(sealed, upgraded.SettingsKey, "a-wrong-previous-settings-key-with-32-bytes"); err == nil {
		t.Fatal("a wrong previous key re-sealed the document")
	}
}

func TestSettingsKeyPreviousValidation(t *testing.T) {
	for name, test := range map[string]struct {
		settingsKey, previous, contains string
	}{
		"requires an explicit settings key": {"", "previous-settings-key-with-at-least-32-bytes", "requires settings_key"},
		"too short":                         {"current-settings-key-with-at-least-32-bytes", "short", "at least 32"},
		"same as the current key":           {"current-settings-key-with-at-least-32-bytes", "current-settings-key-with-at-least-32-bytes", "must differ"},
	} {
		cfg := testDefaults()
		cfg.SettingsKey, cfg.SettingsKeyPrevious = test.settingsKey, test.previous
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), test.contains) {
			t.Errorf("%s: %v", name, err)
		}
	}
	cfg := testDefaults()
	cfg.SettingsKey, cfg.SettingsKeyPrevious = "current-settings-key-with-at-least-32-bytes", testJWTSecret
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a valid rotation was rejected: %v", err)
	}
}
