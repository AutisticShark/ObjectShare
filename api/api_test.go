package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/go-chi/chi/v5/middleware"
)

func TestSecurityHeaders(t *testing.T) {
	handler := securityHeaders(false, nil)(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) }))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	for _, name := range []string{"Content-Security-Policy", "Permissions-Policy", "Referrer-Policy", "X-Content-Type-Options", "X-Frame-Options"} {
		if response.Header().Get(name) == "" {
			t.Errorf("%s is missing", name)
		}
	}
}

func TestBrandingCSPAllowsOnlyConfiguredImageOrigins(t *testing.T) {
	for _, branding := range []config.BrandingConfig{
		{},
		{LogoURL: "https://cdn.example.com/logo.png", HeaderImageURL: "/branding/header.png", FaviconURL: "https://icons.example.com/icon.png", FooterLinkURL: "https://legal.example.com/privacy"},
	} {
		handler := securityHeaders(true, branding.ImageSources(), "https://storage.example.com")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
		policy := response.Header().Get("Content-Security-Policy")
		want := "img-src 'self' data:"
		if branding.LogoURL != "" {
			want += " https://cdn.example.com https://icons.example.com"
		}
		if !strings.Contains(policy, want+";") {
			t.Fatalf("image CSP: %s", policy)
		}
		for _, expected := range []string{"connect-src 'self' https://storage.example.com https://challenges.cloudflare.com;", "script-src 'self' https://cdn.jsdelivr.net https://challenges.cloudflare.com;", "style-src 'self' https://cdn.jsdelivr.net;", "form-action 'self';"} {
			if !strings.Contains(policy, expected) {
				t.Fatalf("branding changed other policy: %s", policy)
			}
		}
		if strings.Contains(policy, "legal.example.com") || strings.Contains(policy, "img-src https:") || strings.Contains(policy, "unsafe-inline") {
			t.Fatalf("overbroad CSP: %s", policy)
		}
	}
}

func TestSecurityHeadersIncludeConfiguredObjectStorageOrigin(t *testing.T) {
	handler := securityHeaders(false, nil, "https://bucket.s3.example.com")(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	policy := response.Header().Get("Content-Security-Policy")
	if !strings.Contains(policy, "connect-src 'self' https://bucket.s3.example.com;") {
		t.Fatalf("unexpected CSP: %s", policy)
	}
}

func TestSecurityHeadersAllowTurnstileOnlyWhenConfigured(t *testing.T) {
	handler := securityHeaders(true, nil)(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) }))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/login", nil))
	policy := response.Header().Get("Content-Security-Policy")
	if !strings.Contains(policy, "script-src 'self' https://cdn.jsdelivr.net https://challenges.cloudflare.com") ||
		!strings.Contains(policy, "frame-src https://challenges.cloudflare.com") {
		t.Fatalf("Turnstile is not allowed by CSP: %s", policy)
	}
}

func TestSameOriginRejectsCrossSiteRequest(t *testing.T) {
	handler := sameOrigin(func(*http.Request) string { return "" }, slog.New(slog.DiscardHandler))(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) }))
	request := httptest.NewRequest(http.MethodPost, "https://objectshare.example/delete", nil)
	request.Header.Set("Origin", "https://attacker.example")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestSameOriginComparesSchemeWhenKnown(t *testing.T) {
	for _, test := range []struct {
		name, scheme, origin, site string
		want                       int
	}{
		{"https origin on an http site", "http", "https://objectshare.example", "", http.StatusForbidden},
		{"http origin on an https site", "https", "http://objectshare.example", "", http.StatusForbidden},
		{"matching https", "https", "https://objectshare.example", "same-origin", http.StatusNoContent},
		{"matching http", "http", "http://objectshare.example", "", http.StatusNoContent},
		{"scheme case is ignored", "https", "HTTPS://objectshare.example", "", http.StatusNoContent},
		// Without TLS or a trusted X-Forwarded-Proto the scheme is unknown, so a
		// TLS-terminating proxy that is not configured as trusted keeps working.
		{"unknown scheme", "", "https://objectshare.example", "", http.StatusNoContent},
		{"unknown scheme still checks host", "", "https://attacker.example", "", http.StatusForbidden},
		{"no origin", "https", "", "", http.StatusNoContent},
		{"cross-site fetch metadata", "https", "https://objectshare.example", "cross-site", http.StatusForbidden},
		{"opaque origin", "", "null", "", http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := sameOrigin(func(*http.Request) string { return test.scheme }, slog.New(slog.DiscardHandler))(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) }))
			request := httptest.NewRequest(http.MethodPost, "http://objectshare.example/login", nil)
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			if test.site != "" {
				request.Header.Set("Sec-Fetch-Site", test.site)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
		})
	}
}

func TestSameOriginLogsLikelyHostRewrite(t *testing.T) {
	var logs bytes.Buffer
	handler := sameOrigin(func(*http.Request) string { return "" }, slog.New(slog.NewJSONHandler(&logs, nil)))(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) }))
	// nginx's default proxy_pass sends the upstream address as Host.
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/login", nil)
	request.Header.Set("Origin", "https://share.example.com")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d", response.Code)
	}
	if !strings.Contains(logs.String(), "proxy_set_header Host $host") || !strings.Contains(logs.String(), `"origin_host":"share.example.com"`) || !strings.Contains(logs.String(), `"host":"127.0.0.1:8080"`) {
		t.Fatalf("host rewrite was not diagnosed: %s", logs.String())
	}

	logs.Reset()
	request = httptest.NewRequest(http.MethodPost, "http://share.example.com/login", nil)
	request.Header.Set("Origin", "https://attacker.example")
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if logs.Len() != 0 {
		t.Fatalf("an ordinary cross-site request was logged as a proxy problem: %s", logs.String())
	}
}

func TestRequestIDIsEchoedAndRecordedByErrorLogs(t *testing.T) {
	chain := requestID(requestIDHeader(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if middleware.GetReqID(request.Context()) == "" {
			t.Error("no request id in the context")
		}
		writer.WriteHeader(http.StatusNoContent)
	})))
	response := httptest.NewRecorder()
	chain.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	generated := response.Header().Get("X-Request-Id")
	if generated == "" {
		t.Fatal("responses do not carry X-Request-Id")
	}
	hostname, _ := os.Hostname()
	if hostname != "" && strings.Contains(generated, hostname) || strings.Contains(generated, "/") {
		t.Fatalf("request id reveals the host: %q", generated)
	}
	response = httptest.NewRecorder()
	chain.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if second := response.Header().Get("X-Request-Id"); second == generated || len(second) < 20 {
		t.Fatalf("request ids are not unique random values: %q then %q", generated, second)
	}
}

func TestRequestIDIgnoresClientSuppliedValue(t *testing.T) {
	var logs bytes.Buffer
	var contextID string
	chain := requestID(requestIDHeader(accessLog(slog.New(slog.NewJSONHandler(&logs, nil)))(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		contextID = middleware.GetReqID(request.Context())
		writer.WriteHeader(http.StatusNoContent)
	}))))
	for _, supplied := range []string{"proxy-assigned-42", "forged\"\nrequest_id=victim", strings.Repeat("a", 200)} {
		logs.Reset()
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set("X-Request-Id", supplied)
		response := httptest.NewRecorder()
		chain.ServeHTTP(response, request)
		echoed := response.Header().Get("X-Request-Id")
		if echoed == supplied || contextID != echoed || echoed == "" {
			t.Fatalf("client request id was adopted: header %q, context %q", echoed, contextID)
		}
		var entry map[string]any
		if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
			t.Fatal(err)
		}
		if entry["request_id"] != echoed {
			t.Fatalf("access log request_id = %v, want %q", entry["request_id"], echoed)
		}
		// A well-formed proxy value is kept only as a separate, labelled field.
		if want := supplied == "proxy-assigned-42"; (entry["upstream_request_id"] == supplied) != want || (!want && entry["upstream_request_id"] != nil) {
			t.Fatalf("upstream_request_id = %v for %q", entry["upstream_request_id"], supplied)
		}
	}
}
