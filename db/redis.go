package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type redisStore struct {
	client            *redis.Client
	prefix            string
	timeout, plansTTL time.Duration
}

// EnableRedis is called once before serving requests. The repository owns the
// client and closes it with its database connection. Never switch backends live:
// replicas must share one rate-limit authority for the entire deployment.
func (repo *GormRepository) EnableRedis(ctx context.Context, cfg config.RedisConfig) error {
	if cfg.URL == "" {
		return nil
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	options, err := redis.ParseURL(cfg.URL)
	if err != nil {
		return errors.New("invalid Redis configuration")
	}
	if cfg.Password != "" {
		options.Password = cfg.Password
	}
	// A timed-out mutation may already have executed. Do not retry it and
	// double-charge a request. Context and socket timeouts bound every operation.
	options.MaxRetries = -1
	options.DialerRetries = 1
	options.DialTimeout = cfg.Timeout.Duration()
	options.ReadTimeout = cfg.Timeout.Duration()
	options.WriteTimeout = cfg.Timeout.Duration()
	options.PoolTimeout = cfg.Timeout.Duration()
	options.ContextTimeoutEnabled = true
	store := &redisStore{client: redis.NewClient(options), prefix: cfg.KeyPrefix,
		timeout: cfg.Timeout.Duration(), plansTTL: cfg.PublicPlansTTL.Duration()}
	if err := store.ping(ctx); err != nil {
		_ = store.client.Close()
		return errors.New("Redis startup health check failed; check connectivity and credentials")
	}
	repo.redis = store
	return nil
}

func (store *redisStore) ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, store.timeout)
	defer cancel()
	if err := store.client.Ping(ctx).Err(); err != nil {
		return errors.New("Redis unavailable")
	}
	return nil
}

// Redis time prevents application clock skew from granting extra requests.
// Count, decision, and expiry are one atomic operation; denied requests never
// extend the fixed window. A changed limit applies to the existing count.
const consumeRateLimitScript = `
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local window = tonumber(ARGV[2])
local bucket = redis.call('HMGET', KEYS[1], 'started', 'used')
local started = tonumber(bucket[1])
local used = tonumber(bucket[2])
if not started or now >= started + window then
  started = now
  used = 0
end
local remaining = math.max(1, started + window - now)
local allowed = 0
if used < tonumber(ARGV[1]) then
  used = used + 1
  allowed = 1
end
redis.call('HSET', KEYS[1], 'started', started, 'used', used)
redis.call('PEXPIRE', KEYS[1], remaining)
return {allowed, remaining}
`

func (store *redisStore) consume(ctx context.Context, scope, keyHash string, limit int, window time.Duration) (bool, time.Time, error) {
	if window < time.Millisecond || window > 24*time.Hour {
		return false, time.Time{}, errors.New("invalid rate-limit window")
	}
	ctx, cancel := context.WithTimeout(ctx, store.timeout)
	defer cancel()
	// Hash the tuple to avoid separator collisions and raw identities in keys.
	digest := sha256.Sum256([]byte(scope + "\x00" + keyHash))
	key := store.prefix + "v1:rate:" + hex.EncodeToString(digest[:])
	result, err := store.client.Eval(ctx, consumeRateLimitScript, []string{key}, limit, window.Milliseconds()).Int64Slice()
	if err != nil || len(result) != 2 {
		return false, time.Time{}, errors.New("Redis rate limiter unavailable")
	}
	return result[0] == 1, time.Now().Add(time.Duration(result[1]) * time.Millisecond), nil
}

// Reserve a unique fill token on a miss. Invalidation deletes this token too,
// so a query started before a committed edit cannot refill the newer cache.
// Keep the original TTL on fill to bound staleness even for a slow DB query.
const readPlansScript = `
local value = redis.call('GET', KEYS[1])
if value and redis.call('PTTL', KEYS[1]) > 0 then return value end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
return ARGV[1]
`
const fillPlansScript = `
if redis.call('GET', KEYS[1]) == ARGV[1] then
  redis.call('SET', KEYS[1], ARGV[2], 'KEEPTTL')
  return 1
end
return 0
`

func (store *redisStore) plansKey() string { return store.prefix + "v1:public-plans" }

func (store *redisStore) readPlans(ctx context.Context) ([]PaidPlan, string, bool) {
	if store.plansTTL == 0 {
		return nil, "", false
	}
	ctx, cancel := context.WithTimeout(ctx, store.timeout)
	defer cancel()
	token := "pending:" + uuid.NewString()
	value, err := store.client.Eval(ctx, readPlansScript, []string{store.plansKey()}, token, store.plansTTL.Milliseconds()).Text()
	if err != nil {
		return nil, "", false
	}
	if strings.HasPrefix(value, "pending:") {
		return nil, value, false
	}
	var plans []PaidPlan
	if json.Unmarshal([]byte(value), &plans) != nil {
		return nil, value, false
	}
	return plans, "", true
}

func (store *redisStore) fillPlans(ctx context.Context, token string, plans []PaidPlan) {
	if token == "" {
		return
	}
	payload, err := json.Marshal(plans)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, store.timeout)
	defer cancel()
	// Cache failure never turns a successful database read into an error.
	_ = store.client.Eval(ctx, fillPlansScript, []string{store.plansKey()}, token, payload).Err()
}

func (repo *GormRepository) invalidatePublicPlans(ctx context.Context) {
	if repo.redis == nil || repo.redis.plansTTL == 0 {
		return
	}
	// A committed write still invalidates if the HTTP caller disconnected.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), repo.redis.timeout)
	defer cancel()
	if err := repo.redis.client.Del(ctx, repo.redis.plansKey()).Err(); err != nil {
		slog.Warn("public plan cache invalidation failed; cached display expires at its existing TTL")
	}
}
