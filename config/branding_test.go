package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBrandingURLValidation(t *testing.T) {
	for _, value := range []string{
		"https://assets.example.com/logo.png", "https://assets.example.com:8443/a%20b.png?v=2&size=32",
		"/branding/logo.png", "https://[2001:db8::1]/icon.png",
	} {
		if !validBrandingURL(value) {
			t.Errorf("rejected %q", value)
		}
	}
	for _, value := range []string{
		"javascript:alert(1)", "data:image/svg+xml,<svg></svg>", "http://assets.example.com/a.png",
		"//evil.example/logo", "/%2fevil.example/logo", `/\evil.example/logo`, "/%5cevil/logo",
		"relative.png", "https://user:password@example.com/logo", "https://example.com/a#fragment",
		"https://example.com/a\n", "https://example.com/%0d%0a", "https://example.com/%00",
		"https://*.example.com/a", "https://example.com;script-src/a", "https://example.com/'/a",
		"https://example.com:99999/a", "https://example.com:/a", "https:///a", "/bad%zz",
		"https://example.com/" + strings.Repeat("a", 2048),
	} {
		if validBrandingURL(value) {
			t.Errorf("accepted unsafe URL %q", value)
		}
	}
	// Every configurable URL goes through the same validation, including links.
	for _, field := range []string{"logo_url", "header_image_url", "favicon_url", "footer_link_url"} {
		var c BrandingConfig
		if err := json.Unmarshal([]byte(`{"`+field+`":"javascript:alert(1)"}`), &c); err != nil {
			t.Fatal(err)
		}
		if c.Validate() == nil {
			t.Errorf("%s bypassed validation", field)
		}
	}
}

func TestBrandingDefaultsLimitsAndImageSources(t *testing.T) {
	c := BrandingConfig{}
	if err := c.Validate(); err != nil || c.SiteName != "ObjectShare" || len(c.ImageSources()) != 0 {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	for _, c := range []BrandingConfig{
		{SiteName: strings.Repeat("x", 81)}, {Tagline: strings.Repeat("x", 241)},
		{FooterMessage: strings.Repeat("x", 2001)}, {FooterLinkText: strings.Repeat("x", 81), FooterLinkURL: "/privacy"},
		{SiteName: "bad\x00name"}, {Tagline: "two\nlines"}, {SiteName: "\xff"},
		{FooterLinkText: "Privacy"}, {FooterLinkURL: "/privacy"},
	} {
		if c.Validate() == nil {
			t.Errorf("accepted invalid branding: %+v", c)
		}
	}
	c = BrandingConfig{SiteName: strings.Repeat("貓", 80), FooterMessage: "First line\nSecond line",
		LogoURL: "https://cdn.example.com/logo", HeaderImageURL: "https://cdn.example.com/banner",
		FaviconURL: "https://icons.example.com/icon", FooterLinkText: "Privacy", FooterLinkURL: "https://legal.example.com/privacy"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"https://cdn.example.com", "https://icons.example.com"}; !reflect.DeepEqual(c.ImageSources(), want) {
		t.Fatalf("image sources: %v", c.ImageSources())
	}
	c.LogoURL = "https://*.example.com/unsafe"
	if strings.Contains(strings.Join(c.ImageSources(), " "), "*") {
		t.Fatal("unsafe CSP source")
	}
}

func TestBrandingSeedRuntimeRoundTripAndLegacyDefaults(t *testing.T) {
	want := BrandingConfig{SiteName: "Cat's files", Tagline: "Share with friends", LogoURL: "https://cdn.example/logo.png",
		HeaderImageURL: "/branding/header.png", FaviconURL: "/branding/icon.png", FooterMessage: "Hello\nWelcome",
		FooterLinkText: "Help", FooterLinkURL: "https://example.com/help"}
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]string
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	for key, value := range fields {
		t.Setenv("OBJECTSHARE_BRANDING_"+strings.ToUpper(key), value)
	}
	cfg := testDefaults()
	if err := applyEnvironment(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Branding != want {
		t.Fatalf("seed not applied: %+v", cfg.Branding)
	}
	sealed, err := SealRuntime(RuntimeFromService(cfg), testJWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenRuntime(sealed, testJWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	fresh := testDefaults()
	if err := ApplyRuntime(fresh, runtime); err != nil {
		t.Fatal(err)
	}
	if fresh.Branding != want {
		t.Fatalf("round trip changed branding: %+v", fresh.Branding)
	}
	runtime.Branding.LogoURL = "javascript:alert(1)"
	if err := ApplyRuntime(fresh, runtime); err == nil || fresh.Branding != want {
		t.Fatal("invalid revision mutated active branding")
	}
	// Old encrypted documents contain no branding object.
	legacy, _ := json.Marshal(RuntimeFromService(testDefaults()))
	var document map[string]json.RawMessage
	if err := json.Unmarshal(legacy, &document); err != nil {
		t.Fatal(err)
	}
	delete(document, "branding")
	legacy, _ = json.Marshal(document)
	var old RuntimeConfig
	if err := json.Unmarshal(legacy, &old); err != nil {
		t.Fatal(err)
	}
	if err := ApplyRuntime(fresh, old); err != nil {
		t.Fatal(err)
	}
	if fresh.Branding.SiteName != "ObjectShare" || fresh.Branding.LogoURL != "" {
		t.Fatal("legacy defaults not applied")
	}
}

func TestBrandingJSONSeedAndStaleEnvironment(t *testing.T) {
	t.Setenv("OBJECTSHARE_JWT_SECRET", testJWTSecret)
	path := filepath.Join(t.TempDir(), "seed.json")
	if err := os.WriteFile(path, []byte(`{"branding":{"site_name":"JSON site","logo_url":"/branding/logo.png"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Branding.SiteName != "JSON site" || cfg.Branding.LogoURL != "/branding/logo.png" {
		t.Fatal("JSON seed lost")
	}
	t.Setenv("OBJECTSHARE_BRANDING_LOGO_URL", "javascript:alert(1)")
	if _, err := Load(path); err == nil {
		t.Fatal("invalid first import accepted")
	}
	cfg, err = LoadBootstrap(path)
	if err != nil {
		t.Fatal("stale branding blocked bootstrap:", err)
	}
	if err := ApplyRuntime(cfg, RuntimeFromService(testDefaults())); err != nil {
		t.Fatal("database settings did not replace stale branding:", err)
	}
}
