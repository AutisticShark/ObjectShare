package config

import (
	"strings"
	"testing"
	"time"
)

func TestRuntimeConfigurationRoundTripIsEncrypted(t *testing.T) {
	cfg := testDefaults()
	cfg.Auth.OAuth.Google.ClientSecret = "google-plaintext-secret"
	cfg.Auth.OAuth.Discord.ClientSecret = "discord-plaintext-secret"
	cfg.Captcha.SecretKey = "turnstile-plaintext-secret"
	cfg.R2.SecretAccessKey = "storage-plaintext-secret"
	runtime := RuntimeFromService(cfg)
	sealed, err := SealRuntime(runtime, testJWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{runtime.Auth.OAuth.Google.ClientSecret, runtime.Auth.OAuth.Discord.ClientSecret, runtime.Captcha.SecretKey, runtime.R2.SecretAccessKey} {
		if strings.Contains(sealed, secret) {
			t.Fatalf("sealed configuration exposed %q", secret)
		}
	}
	opened, err := OpenRuntime(sealed, testJWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Auth.OAuth.Google.ClientSecret != runtime.Auth.OAuth.Google.ClientSecret || opened.Auth.OAuth.Discord.ClientSecret != runtime.Auth.OAuth.Discord.ClientSecret || opened.Captcha.SecretKey != runtime.Captcha.SecretKey || opened.R2.SecretAccessKey != runtime.R2.SecretAccessKey {
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
	runtime.Auth.SignupEnabled = false
	runtime.RateLimit.Window = Duration(2 * time.Minute)
	if err := ApplyRuntime(cfg, runtime); err != nil {
		t.Fatal(err)
	}
	if cfg.MaxFileSize != 42 || cfg.Upload.GuestEnabled || cfg.Auth.SignupEnabled || cfg.RateLimit.Window != Duration(2*time.Minute) {
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
