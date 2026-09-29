package htmx

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestLoginThrottleKeySeparatesClientsBehindTrustedProxy(t *testing.T) {
	networks, err := parseTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	handler := &Handler{trustedProxies: networks}
	request := func(remote, forwarded string) *http.Request {
		request := httptest.NewRequest(http.MethodPost, "/login", nil)
		request.RemoteAddr = remote
		if forwarded != "" {
			request.Header.Set("X-Forwarded-For", forwarded)
		}
		return request
	}
	victim := handler.loginThrottleKey(request("10.0.0.2:8080", "203.0.113.9"), "victim@example.com")
	attacker := handler.loginThrottleKey(request("10.0.0.2:8080", "198.51.100.7"), "victim@example.com")
	if victim == attacker {
		t.Fatal("clients behind the same trusted proxy share a login throttle bucket")
	}
	if victim != handler.loginThrottleKey(request("10.0.0.3:9090", "203.0.113.9"), " Victim@Example.com ") {
		t.Fatal("the same client and email must map to one bucket across proxies and letter case")
	}
	spoofed := handler.loginThrottleKey(request("198.51.100.2:1", "203.0.113.9"), "victim@example.com")
	if spoofed == victim {
		t.Fatal("X-Forwarded-For from an untrusted peer must not select the throttle bucket")
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

func TestLocalRateLimiterPrunesExpiredBuckets(t *testing.T) {
	limiter := newLocalRateLimiter()
	start := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for i := range 500 {
		if allowed, _ := limiter.consume(fmt.Sprintf("api:client-%d", i), 5, time.Minute, start); !allowed {
			t.Fatal("first request was refused")
		}
	}
	if len(limiter.buckets) != 500 {
		t.Fatalf("buckets = %d", len(limiter.buckets))
	}
	// Two windows later a single new client triggers the sweep.
	limiter.consume("api:fresh", 5, time.Minute, start.Add(3*time.Minute))
	if len(limiter.buckets) != 1 {
		t.Fatalf("expired buckets were never pruned: %d left", len(limiter.buckets))
	}
	// A bucket still inside its window survives a later sweep and keeps counting.
	long := 5 * time.Minute
	limiter.consume("api:live", 2, long, start.Add(3*time.Minute+50*time.Second))
	limiter.consume("api:live", 2, long, start.Add(3*time.Minute+55*time.Second))           // used 2 of 2
	limiter.consume("api:trigger", 5, time.Minute, start.Add(4*time.Minute+20*time.Second)) // sweeps; "live" is still in its window
	if allowed, _ := limiter.consume("api:live", 2, long, start.Add(4*time.Minute+30*time.Second)); allowed {
		t.Fatal("pruning reset a live bucket")
	}
}

func TestBillingAndWebhookRoutesAreRateLimited(t *testing.T) {
	repository := &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}}
	handler := newTestHandler(t, repository, &memoryStorage{objects: make(map[string][]byte)})
	handler.config.RateLimit = &config.RateLimitConfig{Enabled: true, Window: config.Duration(time.Minute), APILimit: 1000}
	handler.config.Billing = &config.BillingConfig{}
	handler.billingGateways = map[string]billingGateway{db.BillingGatewayPayPal: &paypalGatewayStub{}}
	for name, test := range map[string]struct {
		limit int
		call  func() *httptest.ResponseRecorder
	}{
		"paypal webhook": {120, func() *httptest.ResponseRecorder {
			response := httptest.NewRecorder()
			handler.PayPalWebhook(response, httptest.NewRequest(http.MethodPost, "/api/v1/billing/paypal/webhook", strings.NewReader("{}")))
			return response
		}},
		"billing top-up": {10, func() *httptest.ResponseRecorder {
			response := httptest.NewRecorder()
			handler.BillingTopUp(response, httptest.NewRequest(http.MethodPost, "/billing/top-up/stripe", strings.NewReader("")))
			return response
		}},
	} {
		t.Run(name, func(t *testing.T) {
			handler.localRateLimits = newLocalRateLimiter()
			for attempt := 1; attempt <= test.limit; attempt++ {
				if response := test.call(); response.Code == http.StatusTooManyRequests {
					t.Fatalf("request %d of %d was limited", attempt, test.limit)
				}
			}
			if response := test.call(); response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" {
				t.Fatalf("request %d was not limited: %d", test.limit+1, response.Code)
			}
		})
	}
}
