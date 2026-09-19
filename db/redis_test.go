package db

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
)

func testRedisConfig(address string) config.RedisConfig {
	return config.RedisConfig{URL: "redis://" + address, Password: "test-redis-secret", KeyPrefix: "test:", Timeout: config.Duration(time.Second), PublicPlansTTL: config.Duration(30 * time.Second)}
}

func attachTestRedis(t *testing.T, repo *GormRepository, server *miniredis.Miniredis) {
	t.Helper()
	if err := repo.EnableRedis(t.Context(), testRedisConfig(server.Addr())); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.redis.client.Close() })
}

func testRedisServer(t *testing.T) *miniredis.Miniredis {
	t.Helper()
	server := miniredis.RunT(t)
	server.RequireAuth("test-redis-secret")
	return server
}

func TestRedisRateLimitSharedAtomicExpiryAndIsolation(t *testing.T) {
	server := testRedisServer(t)
	now := time.Now().UTC()
	server.SetTime(now)
	repos := []*GormRepository{{}, {}}
	for _, repo := range repos {
		attachTestRedis(t, repo, server)
	}
	var allowed, failures atomic.Int64
	var wg sync.WaitGroup
	for i := range 60 {
		wg.Go(func() {
			ok, _, err := repos[i%2].ConsumeRateLimit(t.Context(), "login", "identity", 10, time.Minute, now.Add(24*time.Hour))
			if err != nil {
				failures.Add(1)
			}
			if ok {
				allowed.Add(1)
			}
		})
	}
	wg.Wait()
	if failures.Load() != 0 || allowed.Load() != 10 {
		t.Fatalf("allowed=%d errors=%d", allowed.Load(), failures.Load())
	}
	ok, retryAt, err := repos[0].ConsumeRateLimit(t.Context(), "login", "identity", 10, time.Minute, now)
	if err != nil || ok || time.Until(retryAt) < 58*time.Second {
		t.Fatalf("denied result: %v %v %v", ok, retryAt, err)
	}
	for _, tuple := range [][2]string{{"upload", "identity"}, {"login", "another"}} {
		ok, _, err := repos[1].ConsumeRateLimit(t.Context(), tuple[0], tuple[1], 1, time.Minute, now)
		if err != nil || !ok {
			t.Fatalf("scope/identity isolation: %v %v", ok, err)
		}
	}
	for _, key := range server.Keys() {
		if strings.Contains(key, "identity") || server.TTL(key) != time.Minute {
			t.Fatalf("key privacy/expiry: %s %s", key, server.TTL(key))
		}
	}
	server.FastForward(time.Minute)
	server.SetTime(now.Add(time.Minute))
	ok, _, err = repos[0].ConsumeRateLimit(t.Context(), "login", "identity", 10, time.Minute, now)
	if err != nil || !ok {
		t.Fatalf("expired bucket: %v %v", ok, err)
	}
	// A lower policy limit applies to the current count without resetting it.
	ok, _, err = repos[0].ConsumeRateLimit(t.Context(), "login", "identity", 1, time.Minute, now)
	if err != nil || ok {
		t.Fatalf("lowered limit: %v %v", ok, err)
	}
}

func TestRedisRateLimitFailsClosedAndDisabledScopesBypass(t *testing.T) {
	server := testRedisServer(t)
	repo := &GormRepository{}
	attachTestRedis(t, repo, server)
	server.Close()
	ok, _, err := repo.ConsumeRateLimit(t.Context(), "api", "identity", 1, time.Minute, time.Now())
	if err == nil || ok {
		t.Fatal("Redis outage must fail closed without consulting PostgreSQL")
	}
	ok, _, err = repo.ConsumeRateLimit(t.Context(), "api", "identity", 0, time.Minute, time.Now())
	if err != nil || !ok {
		t.Fatal("disabled scope should not need Redis")
	}
}

func TestRedisPlansCacheInvalidationRaceExpiryAndCorruption(t *testing.T) {
	server := testRedisServer(t)
	repo := &GormRepository{}
	attachTestRedis(t, repo, server)
	store := repo.redis
	ctx := t.Context()
	_, oldToken, hit := store.readPlans(ctx)
	if hit || oldToken == "" {
		t.Fatal("expected cold miss")
	}
	repo.invalidatePublicPlans(ctx)
	_, newToken, _ := store.readPlans(ctx)
	store.fillPlans(ctx, oldToken, []PaidPlan{{Name: "stale"}})
	if _, _, hit := store.readPlans(ctx); hit {
		t.Fatal("old query resurrected invalidated cache")
	}
	server.FastForward(10 * time.Second)
	store.fillPlans(ctx, newToken, []PaidPlan{{Name: "current"}})
	plans, _, hit := store.readPlans(ctx)
	if !hit || len(plans) != 1 || plans[0].Name != "current" {
		t.Fatalf("cache hit = %v %v", plans, hit)
	}
	if server.TTL(store.plansKey()) != 20*time.Second {
		t.Fatal("fill extended original expiry")
	}
	server.FastForward(20 * time.Second)
	if _, _, hit := store.readPlans(ctx); hit {
		t.Fatal("expired cache was served")
	}
	if err := server.Set(store.plansKey(), "broken-json"); err != nil {
		t.Fatal(err)
	}
	server.SetTTL(store.plansKey(), 10*time.Second)
	_, token, hit := store.readPlans(ctx)
	if hit {
		t.Fatal("malformed cache must be a miss")
	}
	store.fillPlans(ctx, token, []PaidPlan{})
	if plans, _, hit := store.readPlans(ctx); !hit || len(plans) != 0 {
		t.Fatal("empty catalog must be cached")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	repo.invalidatePublicPlans(canceled)
	if server.Exists(store.plansKey()) {
		t.Fatal("canceled caller prevented post-commit invalidation")
	}
	store.plansTTL = 0
	if _, token, hit := store.readPlans(ctx); hit || token != "" || server.Exists(store.plansKey()) {
		t.Fatal("disabled cache contacted Redis")
	}
}

func TestRedisStartupAuthenticationAndDisabledConfiguration(t *testing.T) {
	server := testRedisServer(t)
	cfg := testRedisConfig(server.Addr())
	cfg.Password = "wrong-password"
	repo := &GormRepository{}
	if err := repo.EnableRedis(t.Context(), cfg); err == nil || strings.Contains(err.Error(), cfg.Password) {
		t.Fatal("expected sanitized startup error")
	}
	if repo.redis != nil {
		t.Fatal("failed client attached")
	}
	cfg.URL = ""
	if err := repo.EnableRedis(t.Context(), cfg); err != nil || repo.redis != nil {
		t.Fatal("empty URL should retain PostgreSQL")
	}
}

func TestPostgresRedisPublicPlansFallbackAndAuthoritativePrice(t *testing.T) {
	repo := creditTestRepository(t)
	server := testRedisServer(t)
	attachTestRedis(t, repo, server)
	ctx := t.Context()
	plan := &PaidPlan{Name: "cached plan", Price: 10, DurationDays: 30, StorageQuotaBytes: 1024, Active: true}
	if err := repo.CreatePlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	plans, err := repo.PublicPlans(ctx)
	if err != nil || len(plans) != 1 || plans[0].Price != 10 {
		t.Fatalf("initial plans: %v %v", plans, err)
	}
	// Simulate an external SQL edit which cannot invalidate Redis. Display may
	// remain stale, but invoice creation must use the authoritative current price.
	if err := repo.connection.Model(plan).Update("credit_price", 20).Error; err != nil {
		t.Fatal(err)
	}
	plans, err = repo.PublicPlans(ctx)
	if err != nil || plans[0].Price != 10 {
		t.Fatal("expected cached display")
	}
	user := creditTestUser(t, repo, 100)
	invoice, err := repo.CreatePlanInvoice(ctx, user.ID, plan.ID, uuid.NewString(), "USD", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if invoice.Credits != 20 {
		t.Fatalf("invoice used stale price: %+v", invoice)
	}
	plan.Price = 30
	if err := repo.UpdatePlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	plans, err = repo.PublicPlans(ctx)
	if err != nil || plans[0].Price != 30 {
		t.Fatal("edit did not invalidate cache")
	}
	plan.Active = false
	if err := repo.UpdatePlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	plans, err = repo.PublicPlans(ctx)
	if err != nil || len(plans) != 0 {
		t.Fatal("disabled plan still visible after invalidation")
	}
	second := &PaidPlan{Name: "new plan", Price: 5, DurationDays: 1, StorageQuotaBytes: 1024, Active: true}
	if err := repo.CreatePlan(ctx, second); err != nil {
		t.Fatal(err)
	}
	plans, err = repo.PublicPlans(ctx)
	if err != nil || len(plans) != 1 || plans[0].ID != second.ID {
		t.Fatal("creation did not invalidate empty catalog")
	}
	server.Close()
	plans, err = repo.PublicPlans(ctx)
	if err != nil || len(plans) != 1 {
		t.Fatalf("outage fallback: %v %v", plans, err)
	}
	second.Price = 8
	if err := repo.UpdatePlan(ctx, second); err != nil {
		t.Fatal("cache outage turned committed edit into failure", err)
	}
}
