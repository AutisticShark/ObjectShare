package htmx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

func TestBrandingRendersAcrossFullPagesAndEscapesText(t *testing.T) {
	branding := config.BrandingConfig{SiteName: `Cat <script>alert(1)</script>`, Tagline: `Share "safely" <img src=x onerror=alert(1)>`,
		LogoURL: "https://cdn.example.com/logo.png", HeaderImageURL: "https://cdn.example.com/banner.png",
		FaviconURL: "https://cdn.example.com/icon.png", FooterMessage: "Welcome\n<script>alert(2)</script>",
		FooterLinkText: `<b>Privacy</b>`, FooterLinkURL: "https://example.com/privacy"}
	if err := branding.Validate(); err != nil {
		t.Fatal(err)
	}
	parsed, err := parseTemplates(os.DirFS("../.."), branding)
	if err != nil {
		t.Fatal(err)
	}
	user := &db.User{ID: "admin", Role: db.RoleAdmin, DisplayName: "Cat"}
	for _, dark := range []bool{false, true} {
		user.DarkMode = dark
		for _, test := range []struct {
			name string
			data any
		}{
			{"index.html", map[string]any{"User": user}}, {"file_view.html", map[string]any{"User": user, "FileName": "report.pdf"}},
			{"login.html", authPageData{}}, {"signup.html", authPageData{}}, {"setup.html", authPageData{}},
			{"oauth_error.html", oauthErrorData{}}, {"account.html", accountPageData{User: user}},
			{"admin_users.html", adminPageData{User: user}}, {"admin_settings.html", adminSettingsPageData{User: user}},
			{"admin_plans.html", adminPlansPageData{User: user}}, {"plans.html", plansPageData{User: user}},
			{"upload_results.html", map[string]any{"User": user, "Files": []any{}}},
		} {
			var output strings.Builder
			if err := parsed.ExecuteTemplate(&output, test.name, test.data); err != nil {
				t.Fatalf("%s: %v", test.name, err)
			}
			page := output.String()
			for _, want := range []string{"Cat &lt;script&gt;alert(1)&lt;/script&gt;", `rel="icon" href="https://cdn.example.com/icon.png"`,
				`src="https://cdn.example.com/logo.png"`, `href="/assets/branding.css"`, "Welcome\n&lt;script&gt;alert(2)&lt;/script&gt;",
				`href="https://example.com/privacy"`, "&lt;b&gt;Privacy&lt;/b&gt;", "Made with", "by Cat", `aria-label="love"`,
			} {
				if !strings.Contains(page, want) {
					t.Errorf("%s missing %q", test.name, want)
				}
			}
			for _, bad := range []string{"<script>alert(", "<img src=x", "<b>Privacy</b>", "ZgotmplZ"} {
				if strings.Contains(page, bad) {
					t.Errorf("%s unsafe rendering: %q", test.name, bad)
				}
			}
			if test.name == "index.html" && !strings.Contains(page, `src="https://cdn.example.com/banner.png"`) {
				t.Fatal("banner missing")
			}
		}
	}
	// Guest pages use the same branding without requiring an account.
	for _, name := range []string{"index.html", "file_view.html", "plans.html"} {
		var output strings.Builder
		if err := parsed.ExecuteTemplate(&output, name, map[string]any{}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output.String(), branding.LogoURL) {
			t.Errorf("guest %s missing logo", name)
		}
	}
}

func TestBrandingAdminRejectsInvalidSaveAndAllowsClearing(t *testing.T) {
	repository := newAuthMemoryRepository()
	handler := newAuthTestHandler(t, repository, false)
	t.Setenv("OBJECTSHARE_JWT_SECRET", "branding-test-secret-with-at-least-32-bytes")
	t.Setenv("OBJECTSHARE_SETTINGS_KEY", "branding-settings-key-with-at-least-32-bytes")
	cfg, err := config.Load("../../config.json.example")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Branding = config.BrandingConfig{SiteName: "Configured site", LogoURL: "/branding/logo.png", FooterMessage: "Hello"}
	handler.config, handler.settings, handler.settingsKey = cfg, repository, cfg.SettingsKey
	handler.templates, err = parseTemplates(os.DirFS("../.."), cfg.Branding)
	if err != nil {
		t.Fatal(err)
	}
	runtime := config.RuntimeFromService(cfg)
	sealed, err := config.SealRuntime(runtime, cfg.SettingsKey)
	if err != nil {
		t.Fatal(err)
	}
	repository.setting = &db.ApplicationSetting{Value: sealed}
	admin := &db.User{ID: "admin", Email: "admin@example.com", Role: db.RoleAdmin, Active: true, TokenVersion: 1}
	_, claims := issueTestJWT(t, handler, admin)
	for _, test := range []struct {
		name, logo, csrf string
		role             string
		save             bool
	}{
		{"unsafe URL", "javascript:alert(1)", claims.CSRF, db.RoleAdmin, false},
		{"missing CSRF", "", "", db.RoleAdmin, false},
		{"normal user", "", claims.CSRF, db.RoleUser, false},
		{"clear optional fields", "", claims.CSRF, db.RoleAdmin, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := runtimeFormValues(runtime)
			values.Set("revision", settingsRevision(sealed))
			values.Set("csrf_token", test.csrf)
			values.Set("branding_logo_url", test.logo)
			request := formRequest("/admin/settings", values)
			user := *admin
			user.Role = test.role
			request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: &user, Claims: claims, Transport: transportCookie}))
			response := httptest.NewRecorder()
			handler.RequireAdmin(http.HandlerFunc(handler.AdminSaveSettings)).ServeHTTP(response, request)
			if !test.save {
				if repository.setting.Value != sealed {
					t.Fatal("rejected request changed stored settings")
				}
				return
			}
			if response.Code != http.StatusSeeOther {
				t.Fatalf("clear failed: %d %s", response.Code, response.Body.String())
			}
			saved, err := config.OpenRuntime(repository.setting.Value, cfg.SettingsKey)
			if err != nil {
				t.Fatal(err)
			}
			if saved.Branding != (config.BrandingConfig{SiteName: "ObjectShare"}) {
				t.Fatalf("clear: %+v", saved.Branding)
			}
			if cfg.Branding.SiteName != "Configured site" {
				t.Fatal("save activated before restart")
			}
			if err := config.ApplyRuntime(cfg, saved); err != nil {
				t.Fatal(err)
			}
			if cfg.Branding.SiteName != "ObjectShare" {
				t.Fatal("restart did not apply saved branding")
			}
		})
	}
}
