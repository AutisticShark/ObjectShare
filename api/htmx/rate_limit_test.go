package htmx

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
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

// Proxies such as HAProxy ("option forwardfor") append their own
// X-Forwarded-For line after any the client sent. Reading only the first line
// would let the client choose its rate-limit and login-throttle identity.
func TestClientIPReadsEveryForwardedForLine(t *testing.T) {
	networks, err := parseTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	handler := &Handler{trustedProxies: networks}
	request := httptest.NewRequest(http.MethodPost, "/login", nil)
	request.RemoteAddr = "10.0.0.5:4000"
	request.Header.Add("X-Forwarded-For", "198.51.100.77")         // spoofed by the client
	request.Header.Add("X-Forwarded-For", "203.0.113.9, 10.0.0.6") // appended by trusted proxies
	if got := handler.clientIP(request); got != "203.0.113.9" {
		t.Fatalf("clientIP = %q, want the proxy-reported client 203.0.113.9", got)
	}
}

func TestClientNetworkBucketsIPv6By64(t *testing.T) {
	handler := &Handler{}
	network := func(remote string) string {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.RemoteAddr = remote
		return handler.clientNetwork(request)
	}
	if got := network("198.51.100.4:1234"); got != "198.51.100.4" {
		t.Fatalf("IPv4 network = %q", got)
	}
	if got := network("[::ffff:198.51.100.4]:1234"); got != "198.51.100.4" {
		t.Fatalf("IPv4-mapped IPv6 network = %q, want the IPv4 address", got)
	}
	first, rotated := network("[2001:db8:1:2::1]:1234"), network("[2001:db8:1:2:ffff:ffff:ffff:fffe]:1234")
	if first != "2001:db8:1:2::/64" || rotated != first {
		t.Fatalf("addresses in one /64 map to %q and %q", first, rotated)
	}
	if other := network("[2001:db8:1:3::1]:1234"); other == first {
		t.Fatal("a different /64 shares the bucket")
	}
}

func loginTestHandler(t *testing.T) *Handler {
	t.Helper()
	repository := newAuthMemoryRepository()
	hash, _ := appauth.HashPassword("the correct password")
	repository.users["60c628c1-85cb-4463-b895-a629c31bfa55"] = &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "victim@example.com", DisplayName: "Victim", PasswordHash: hash, Role: db.RoleUser, Active: true, TokenVersion: 1}
	return newAuthTestHandler(t, repository, false)
}

func apiLoginFrom(handler *Handler, remote, password string) int {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(fmt.Sprintf(`{"email":"victim@example.com","password":%q}`, password)))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = remote
	response := httptest.NewRecorder()
	handler.APILogin(response, request)
	return response.Code
}

// Rotating addresses inside one IPv6 /64 must not reset the per-client lockout.
func TestLoginLockoutCoversWholeIPv6Slash64(t *testing.T) {
	handler := loginTestHandler(t)
	page := httptest.NewRecorder()
	handler.LoginPage(page, httptest.NewRequest(http.MethodGet, "/login", nil))
	csrf, preAuthCookie := strings.TrimSpace(page.Body.String()), page.Result().Cookies()[0]
	login := func(remote, password string) *httptest.ResponseRecorder {
		request := formRequest("/login", url.Values{"csrf_token": {csrf}, "email": {"victim@example.com"}, "password": {password}})
		request.AddCookie(preAuthCookie)
		request.RemoteAddr = remote
		response := httptest.NewRecorder()
		handler.Login(response, request)
		return response
	}
	for range 5 {
		login("[2001:db8:1:2::1]:4000", "wrong guess")
	}
	for host := 2; host <= 40; host++ {
		if response := login(fmt.Sprintf("[2001:db8:1:2::%x]:4000", host), "wrong guess"); response.Code != http.StatusTooManyRequests {
			t.Fatalf("guess from a rotated address in the locked /64 returned %d", response.Code)
		}
	}
	if response := login("[2001:db8:1:2::ffff]:4000", "the correct password"); response.Code != http.StatusTooManyRequests {
		t.Fatalf("correct password from the locked /64 returned %d", response.Code)
	}
	if response := login("[2001:db8:1:3::1]:4000", "the correct password"); response.Code != http.StatusSeeOther {
		t.Fatalf("correct password from another /64 returned %d", response.Code)
	}
}

// Guesses spread across many networks are capped per account.
func TestLoginAccountLimitSpansClientNetworks(t *testing.T) {
	handler := loginTestHandler(t)
	for network := range 5 {
		for range 4 {
			if code := apiLoginFrom(handler, fmt.Sprintf("198.51.100.%d:4000", network+1), "wrong guess"); code != http.StatusUnauthorized {
				t.Fatalf("guess below the account limit returned %d", code)
			}
		}
	}
	if code := apiLoginFrom(handler, "203.0.113.1:4000", "wrong guess"); code != http.StatusTooManyRequests {
		t.Fatalf("guess past the account limit from a fresh network returned %d", code)
	}
	if code := apiLoginFrom(handler, "203.0.113.2:4000", "the correct password"); code != http.StatusTooManyRequests {
		t.Fatalf("correct password on a locked account returned %d", code)
	}
}

func TestSuccessfulLoginClearsTheAccountLimit(t *testing.T) {
	handler := loginTestHandler(t)
	guess := func(round int) {
		for network := range 19 {
			if code := apiLoginFrom(handler, fmt.Sprintf("198.51.%d.%d:4000", round, network+1), "wrong guess"); code != http.StatusUnauthorized {
				t.Fatalf("round %d guess %d returned %d", round, network+1, code)
			}
		}
	}
	guess(100)
	if code := apiLoginFrom(handler, "203.0.113.1:4000", "the correct password"); code != http.StatusOK {
		t.Fatalf("owner login below the account limit returned %d", code)
	}
	guess(101)
}

// With login CAPTCHA each guess already costs a solved challenge, so the
// account-wide lock is not applied and cannot be used to keep the owner out.
func TestLoginCaptchaReplacesTheAccountLock(t *testing.T) {
	handler := loginTestHandler(t)
	handler.config.Captcha = &config.CaptchaConfig{Provider: "turnstile", SiteKey: "site", SecretKey: "secret", ProtectLogin: true}
	handler.captcha = captchaVerifierFunc(func(context.Context, string, string, string) error { return nil })
	for network := range 30 {
		if code := apiLoginFrom(handler, fmt.Sprintf("198.51.100.%d:4000", network+1), "wrong guess"); code != http.StatusUnauthorized {
			t.Fatalf("CAPTCHA-verified guess %d returned %d", network+1, code)
		}
	}
	if code := apiLoginFrom(handler, "203.0.113.1:4000", "the correct password"); code != http.StatusOK {
		t.Fatalf("owner login after CAPTCHA-verified guesses returned %d", code)
	}
}
