package config

import (
	"errors"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisConfig is bootstrap infrastructure, never part of the runtime document.
// An empty URL preserves the PostgreSQL-only deployment.
type RedisConfig struct {
	URL            string   `json:"url"`
	Password       string   `json:"password,omitempty"`
	KeyPrefix      string   `json:"key_prefix"`
	Timeout        Duration `json:"timeout"`
	PublicPlansTTL Duration `json:"public_plans_ttl"`
}

func defaultRedisConfig() RedisConfig {
	return RedisConfig{KeyPrefix: "objectshare:", Timeout: Duration(time.Second), PublicPlansTTL: Duration(30 * time.Second)}
}

func (cfg RedisConfig) Validate() error {
	if cfg.URL != "" {
		options, err := redis.ParseURL(cfg.URL)
		if err != nil || !(strings.HasPrefix(cfg.URL, "redis://") || strings.HasPrefix(cfg.URL, "rediss://")) {
			// Parse errors can include the URL, password, or query parameters.
			return errors.New("redis.url must be a valid redis:// or rediss:// URL")
		}
		if options.DB < 0 {
			return errors.New("redis.url database must not be negative")
		}
	}
	if cfg.KeyPrefix == "" || len(cfg.KeyPrefix) > 128 || strings.ContainsAny(cfg.KeyPrefix, "{}\r\n\t ") {
		return errors.New("redis.key_prefix must contain 1-128 characters without whitespace or braces")
	}
	if cfg.Timeout.Duration() < time.Millisecond || cfg.Timeout.Duration() > 30*time.Second {
		return errors.New("redis.timeout must be between 1ms and 30s")
	}
	if cfg.PublicPlansTTL.Duration() < 0 || cfg.PublicPlansTTL.Duration() > 5*time.Minute || (cfg.PublicPlansTTL != 0 && cfg.PublicPlansTTL.Duration() < time.Millisecond) {
		return errors.New("redis.public_plans_ttl must be 0 (disabled) or between 1ms and 5m")
	}
	return nil
}
