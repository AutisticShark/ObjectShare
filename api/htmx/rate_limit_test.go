package htmx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

func TestLocalRateLimiterEnforcesAndResetsWindow(t *testing.T) {
	limiter := newLocalRateLimiter()
	now := time.Unix(1000, 0)
	for attempt := 0; attempt < 2; attempt++ {
		if allowed, _ := limiter.consume("upload:key", 2, time.Minute, now); !allowed {
			t.Fatalf("attempt %d was rejected", attempt+1)
		}
	}
	if allowed, retryAt := limiter.consume("upload:key", 2, time.Minute, now); allowed || !retryAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("third attempt allowed=%v retryAt=%v", allowed, retryAt)
	}
	if allowed, _ := limiter.consume("upload:key", 2, time.Minute, now.Add(time.Minute)); !allowed {
		t.Fatal("new window was rejected")
	}
}

func TestRateLimitReturns429AndRetryAfter(t *testing.T) {
	handler := &Handler{config: &config.ServiceConfig{RateLimit: &config.RateLimitConfig{Enabled: true, Window: config.Duration(time.Minute), APILimit: 1}}, localRateLimits: newLocalRateLimiter()}
	next := handler.RateLimitAPI(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) }))
	for attempt := 0; attempt < 2; attempt++ {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/download/id", nil)
		request.RemoteAddr = "198.51.100.4:1234"
		response := httptest.NewRecorder()
		next.ServeHTTP(response, request)
		if attempt == 0 && response.Code != http.StatusNoContent {
			t.Fatalf("first status = %d", response.Code)
		}
		if attempt == 1 && (response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" || response.Header().Get("X-RateLimit-Scope") != "api") {
			t.Fatalf("limited response = %d headers=%v", response.Code, response.Header())
		}
	}
}

func TestClientIPTrustsOnlyConfiguredProxyChain(t *testing.T) {
	networks, err := parseTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	handler := &Handler{trustedProxies: networks}
	trusted := httptest.NewRequest(http.MethodGet, "/", nil)
	trusted.RemoteAddr = "10.0.0.2:8080"
	trusted.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.3")
	if got := handler.clientIP(trusted); got != "203.0.113.9" {
		t.Fatalf("trusted proxy client IP = %q", got)
	}
	untrusted := httptest.NewRequest(http.MethodGet, "/", nil)
	untrusted.RemoteAddr = "198.51.100.2:8080"
	untrusted.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := handler.clientIP(untrusted); got != "198.51.100.2" {
		t.Fatalf("untrusted proxy spoofed client IP = %q", got)
	}
}

type recordingRateLimitRepository struct {
	scope, keyHash string
	allowed        bool
}

func (repository *recordingRateLimitRepository) ConsumeRateLimit(_ context.Context, scope, keyHash string, _ int, _ time.Duration, _ time.Time) (bool, time.Time, error) {
	repository.scope, repository.keyHash = scope, keyHash
	return repository.allowed, time.Now().Add(time.Minute), nil
}

func TestRateLimiterUsesSharedRepositoryAndHashesIdentity(t *testing.T) {
	repository := &recordingRateLimitRepository{allowed: true}
	handler := &Handler{
		config:     &config.ServiceConfig{RateLimit: &config.RateLimitConfig{Enabled: true, Window: config.Duration(time.Minute), APILimit: 10}},
		rateLimits: repository, localRateLimits: newLocalRateLimiter(),
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1", nil)
	request.RemoteAddr = "203.0.113.22:8080"
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: &db.User{ID: "sensitive-user-id"}}))
	response := httptest.NewRecorder()
	handler.RateLimitAPI(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) })).ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || repository.scope != "api" || len(repository.keyHash) != 64 || repository.keyHash == "sensitive-user-id" {
		t.Fatalf("status=%d scope=%q key=%q", response.Code, repository.scope, repository.keyHash)
	}
}
