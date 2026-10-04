package htmx

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

// Forms whose response is a whole page must select and replace .page, like
// login and the user directory. Without it htmx swaps the full HTML document
// into the form (a nested page) and silently drops 4xx/5xx responses.
func TestPageFormsReplaceThePageAndLoadTheErrorHandler(t *testing.T) {
	parsed, err := parseTemplates(os.DirFS("../.."), config.BrandingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	admin := &db.User{ID: "admin", Role: db.RoleAdmin}
	for _, test := range []struct {
		name, action string
		data         any
	}{
		{"setup.html", "/setup", authPageData{CSRF: "csrf", Setup: true, SetupTokenRequired: true}},
		{"signup.html", "/signup", authPageData{CSRF: "csrf"}},
		{"login.html", "/login", authPageData{CSRF: "csrf"}},
		{"admin_settings.html", "/admin/settings", adminSettingsPageData{CSRF: "csrf", User: admin}},
	} {
		var output bytes.Buffer
		if err := parsed.ExecuteTemplate(&output, test.name, test.data); err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		page := output.String()
		form := regexp.MustCompile(`<form[^>]*hx-post="` + regexp.QuoteMeta(test.action) + `"[^>]*>`).FindString(page)
		if form == "" {
			t.Fatalf("%s has no HTMX form for %s", test.name, test.action)
		}
		for _, attribute := range []string{`hx-select=".page"`, `hx-target=".page"`, `hx-swap="outerHTML"`} {
			if !strings.Contains(form, attribute) {
				t.Errorf("%s form is missing %s: %s", test.name, attribute, form)
			}
		}
		if !regexp.MustCompile(`class="page[ "]`).MatchString(page) {
			t.Errorf("%s has no .page element to replace", test.name)
		}
		if !strings.Contains(page, `<script defer src="/assets/htmx-errors.js?v=`) {
			t.Errorf("%s does not load the HTMX error handler", test.name)
		}
	}
}

// A rejected setup token must come back as a complete page, so the error
// handler can swap it in with the message.
func TestRejectedSetupTokenRendersASwappablePage(t *testing.T) {
	repository := newAuthMemoryRepository()
	handler := newAuthTestHandler(t, repository, false)
	handler.config.Auth.SetupToken = "a-sufficiently-long-setup-token"
	page := httptest.NewRecorder()
	handler.SetupPage(page, httptest.NewRequest(http.MethodGet, "/setup", nil))
	csrf, cookie := strings.TrimSpace(page.Body.String()), page.Result().Cookies()[0]
	parsed, err := parseTemplates(os.DirFS("../.."), config.BrandingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	handler.templates = parsed
	request := formRequest("/setup", url.Values{"csrf_token": {csrf}, "setup_token": {"wrong"}, "display_name": {"Admin"}, "email": {"admin@example.com"}, "password": {"a sufficiently long password"}, "password_confirm": {"a sufficiently long password"}})
	request.Header.Set("HX-Request", "true")
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.Setup(response, request)
	body := response.Body.String()
	if response.Code != http.StatusForbidden || !strings.HasPrefix(response.Header().Get("Content-Type"), "text/html") ||
		!strings.Contains(body, `class="page page-center"`) || !strings.Contains(body, "The setup token is incorrect.") {
		t.Fatalf("setup token rejection: %d %q %s", response.Code, response.Header().Get("Content-Type"), body)
	}
}
