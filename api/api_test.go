package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AutisticShark/ObjectShare/config"
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
	handler := requireSameOrigin(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) }))
	request := httptest.NewRequest(http.MethodPost, "https://objectshare.example/delete", nil)
	request.Header.Set("Origin", "https://attacker.example")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d", response.Code)
	}
}
