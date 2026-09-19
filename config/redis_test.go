package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRedisConfigurationValidation(t *testing.T) {
	for _, value := range []string{"", "redis://localhost:6379/0", "rediss://user:password@cache.example:6380/1"} {
		cfg := testDefaults()
		cfg.Redis.URL = value
		if err := cfg.Validate(); err != nil {
			t.Fatalf("valid URL rejected: %v", err)
		}
	}
	for _, mutate := range []func(*RedisConfig){
		func(c *RedisConfig) { c.URL = "https://private-secret@localhost" },
		func(c *RedisConfig) { c.URL = "redis://localhost/-1" },
		func(c *RedisConfig) { c.URL = "redis://localhost?unknown=private-secret" },
		func(c *RedisConfig) { c.KeyPrefix = "" },
		func(c *RedisConfig) { c.KeyPrefix = "{other}" },
		func(c *RedisConfig) { c.Timeout = 0 },
		func(c *RedisConfig) { c.Timeout = Duration(time.Minute) },
		func(c *RedisConfig) { c.PublicPlansTTL = -1 },
		func(c *RedisConfig) { c.PublicPlansTTL = Duration(6 * time.Minute) },
	} {
		cfg := testDefaults()
		mutate(&cfg.Redis)
		if err := cfg.Validate(); err == nil || strings.Contains(err.Error(), "private-secret") {
			t.Fatalf("expected sanitized validation error, got %v", err)
		}
	}
	cfg := testDefaults()
	cfg.Redis.PublicPlansTTL = 0
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRedisBootstrapEnvironmentAndRuntimeBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"auth":{"jwt_secret":"`+testJWTSecret+`"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OBJECTSHARE_REDIS_URL", "rediss://cache.example:6380/2")
	t.Setenv("OBJECTSHARE_REDIS_PASSWORD", "bootstrap-redis-secret")
	t.Setenv("OBJECTSHARE_REDIS_KEY_PREFIX", "separate-install:")
	t.Setenv("OBJECTSHARE_REDIS_TIMEOUT", "250ms")
	t.Setenv("OBJECTSHARE_REDIS_PUBLIC_PLANS_TTL", "15s")
	// Invalid legacy seed policy must not prevent loading current DB settings.
	t.Setenv("OBJECTSHARE_RATE_LIMIT_API", "invalid-seed")
	cfg, err := LoadBootstrap(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Redis.Password != "bootstrap-redis-secret" || cfg.Redis.Timeout.Duration() != 250*time.Millisecond || cfg.Redis.PublicPlansTTL.Duration() != 15*time.Second || cfg.Redis.KeyPrefix != "separate-install:" {
		t.Fatal("bootstrap environment not applied")
	}
	runtime := RuntimeFromService(testDefaults())
	payload, err := json.Marshal(runtime)
	if err != nil || strings.Contains(string(payload), "redis") {
		t.Fatal("Redis leaked into runtime settings")
	}
	reloaded, err := WithRuntime(cfg, runtime)
	if err != nil || reloaded.Redis != cfg.Redis {
		t.Fatalf("runtime reload changed bootstrap Redis: %v", err)
	}
	t.Setenv("OBJECTSHARE_REDIS_TIMEOUT", "invalid")
	if _, err := LoadBootstrap(path); err == nil {
		t.Fatal("invalid Redis duration treated as optional seed")
	}
	t.Setenv("OBJECTSHARE_REDIS_TIMEOUT", "1s")
	t.Setenv("OBJECTSHARE_REDIS_PUBLIC_PLANS_TTL", "invalid")
	if _, err := LoadBootstrap(path); err == nil {
		t.Fatal("invalid Redis TTL treated as optional seed")
	}
}
