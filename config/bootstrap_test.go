package config

import (
	"os"
	"strings"
	"testing"
)

func TestLoadBootstrapAllowsDatabaseToOverrideInvalidLegacyRuntime(t *testing.T) {
	path := t.TempDir() + "/config.json"
	document := `{
  "address": ":8080",
  "max_file_size": 0,
  "auth": {"jwt_secret":"test-only-jwt-secret-with-at-least-32-bytes","token_lifetime":"12h"},
  "db": {"host":"127.0.0.1","port":5432,"user":"objectshare","database":"objectshare","ssl_mode":"disable","timezone":"UTC","max_open_conns":5,"max_idle_conns":1,"conn_max_lifetime":"30m"}
}`
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "max_file_size") {
		t.Fatalf("full load accepted invalid runtime seed: %v", err)
	}
	cfg, err := LoadBootstrap(path)
	if err != nil {
		t.Fatalf("bootstrap load rejected an overridable runtime seed: %v", err)
	}
	valid := RuntimeFromService(defaults())
	if err := ApplyRuntime(cfg, valid); err != nil {
		t.Fatalf("database runtime did not replace invalid seed: %v", err)
	}
}

func TestLoadBootstrapDefersOnlyOperationalEnvironmentErrors(t *testing.T) {
	t.Setenv("OBJECTSHARE_JWT_SECRET", testJWTSecret)
	t.Setenv("OBJECTSHARE_MAX_FILE_SIZE_MB", "not-a-number")
	cfg, err := LoadBootstrap("")
	if err != nil {
		t.Fatalf("runtime environment problem blocked database bootstrap: %v", err)
	}
	if cfg.ValidateSeed() == nil {
		t.Fatal("first-time import lost deferred runtime environment error")
	}
	t.Setenv("OBJECTSHARE_DB_PORT", "not-a-number")
	if _, err := LoadBootstrap(""); err == nil || !strings.Contains(err.Error(), "OBJECTSHARE_DB_PORT") {
		t.Fatalf("invalid database bootstrap environment was deferred: %v", err)
	}
}
