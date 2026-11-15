package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

func TestBrandingReachesEveryPageAndIsEscaped(t *testing.T) {
	branding := config.BrandingConfig{SiteName: `Cat <script>alert(1)</script>`, Tagline: `Share "safely" <img src=x onerror=alert(1)>`,
		LogoURL: "https://cdn.example.com/logo.png", HeaderImageURL: "https://cdn.example.com/banner.png",
		FaviconURL: "https://cdn.example.com/icon.png", FooterMessage: "Welcome\n<script>alert(2)</script>",
		FooterLinkText: `<b>Privacy</b>`, FooterLinkURL: "https://example.com/privacy"}
	if err := branding.Validate(); err != nil {
		t.Fatal(err)
	}
	handler := &Handler{config: &config.ServiceConfig{Branding: branding}}
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
			{"files.html", workspacePageData{User: user, Page: 1}},
			{"billing.html", accountPageData{User: user}},
			{"invoices.html", invoicePageData{User: user}},
			{"invoices.html", invoicePageData{User: user, Page: 1}},
			{"invoices.html", invoicePageData{User: user, Invoices: []db.Invoice{{ID: "invoice", Name: "Plan", Currency: "USD", AmountMinor: 1000, Status: "paid"}}}},
			{"billing_problem.html", billingProblemPageData{User: user, Message: "Payment needs attention"}},
			{"admin_dashboard.html", overviewPageData{User: user}},
			{"admin_invoices.html", workspacePageData{User: user, Page: 1}},
			{"upload_results.html", map[string]any{"User": user, "Files": []any{}}},
			// Guest pages use the same branding without requiring an account.
			{"index.html", map[string]any{}}, {"file_view.html", map[string]any{}}, {"plans.html", map[string]any{}},
		} {
			output, err := handler.frontendPage(test.name, test.data)
			if err != nil {
				t.Fatalf("%s: %v", test.name, err)
			}
			page := string(output)
			for _, want := range []string{"<title>Cat &lt;script&gt;alert(1)&lt;/script&gt;</title>", `<link rel="icon" href="https://cdn.example.com/icon.png">`,
				`<meta name="description" content="Share &#34;safely&#34; &lt;img src=x onerror=alert(1)&gt;">`,
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
			shown := bootBranding(t, page)
			for key, want := range map[string]string{"SiteName": branding.SiteName, "Tagline": branding.Tagline, "LogoURL": branding.LogoURL,
				"HeaderImageURL": branding.HeaderImageURL, "FaviconURL": branding.FaviconURL, "FooterMessage": branding.FooterMessage,
				"FooterLinkText": branding.FooterLinkText, "FooterLinkURL": branding.FooterLinkURL} {
				if shown[key] != want {
					t.Errorf("%s: branding %s = %q, want %q", test.name, key, shown[key], want)
				}
			}
		}
	}
}

// bootBranding decodes the branding a rendered page hands to the frontend.
func bootBranding(t *testing.T, body string) map[string]any {
	t.Helper()
	const open = `<script id="objectshare-page" type="application/json">`
	start := strings.Index(body, open)
	end := strings.LastIndex(body, "</script>")
	if start < 0 || end < start {
		t.Fatalf("response carries no page data: %.300s", body)
	}
	var boot struct{ Branding map[string]any }
	if err := json.Unmarshal([]byte(body[start+len(open):end]), &boot); err != nil {
		t.Fatalf("decode page data: %v", err)
	}
	return boot.Branding
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
