package htmx

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
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
	member := &db.User{ID: "member", Email: "member@example.com", Role: db.RoleUser, PasswordHash: "hash"}
	account := accountPageData{CSRF: "csrf", User: member, HasPassword: true, VerificationEnabled: true,
		OAuthProviders: []oauthAccountProvider{{Key: "github", Label: "GitHub", Configured: true, Linked: true}}}
	file := map[string]any{"FileID": "file-id", "FileName": "file.txt", "CanManage": true, "User": member, "CSRF": "csrf"}
	sharing := sharingPageData{CSRF: "csrf", FileID: "file-id", FileName: "file.txt", Mode: db.ShareLink, User: member}
	for _, test := range []struct {
		name, action string
		data         any
	}{
		{"setup.html", "/setup", authPageData{CSRF: "csrf", Setup: true, SetupTokenRequired: true}},
		{"signup.html", "/signup", authPageData{CSRF: "csrf"}},
		{"login.html", "/login", authPageData{CSRF: "csrf"}},
		{"admin_settings.html", "/admin/settings", adminSettingsPageData{CSRF: "csrf", User: admin}},
		{"account.html", "/account/email/resend", account},
		{"account.html", "/account/profile", account},
		{"account.html", "/account/password", account},
		{"account.html", "/account/theme", account},
		{"account.html", "/account/oauth/github/unlink", account},
		{"account.html", "/logout", account},
		{"file_view.html", "/api/v1/update/file-id", file},
		{"file_view.html", "/api/v1/delete/file-id", file},
		{"sharing.html", "/file/file-id/sharing", sharing},
	} {
		var output bytes.Buffer
		if err := parsed.ExecuteTemplate(&output, test.name, test.data); err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		page := output.String()
		var forms []string
		for _, form := range regexp.MustCompile(`<form[^>]*hx-post="`+regexp.QuoteMeta(test.action)+`"[^>]*>`).FindAllString(page, -1) {
			// The navigation theme toggle saves without swapping anything and
			// reports its own failures (theme.js).
			if !strings.Contains(form, "data-theme-toggle") {
				forms = append(forms, form)
			}
		}
		if len(forms) == 0 {
			t.Fatalf("%s has no HTMX form for %s", test.name, test.action)
		}
		for _, form := range forms {
			for _, attribute := range []string{`hx-select=".page"`, `hx-target=".page"`, `hx-swap="outerHTML"`} {
				if !strings.Contains(form, attribute) {
					t.Errorf("%s form is missing %s: %s", test.name, attribute, form)
				}
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

// The account forms replace .page, so each handler's answer to an HTMX request
// must be a complete account page (swapped normally, or by htmx-errors.js for
// 4xx) or a short plain-text message that htmx-errors.js shows in the form.
func TestAccountFormResponsesAreSwappable(t *testing.T) {
	repository := newAuthMemoryRepository()
	hash, _ := appauth.HashPassword("the current password")
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "user@example.com", DisplayName: "User", PasswordHash: hash, Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[user.ID] = user
	repository.identities["discord|subject"] = &db.OAuthIdentity{Provider: "discord", Subject: "subject", UserID: user.ID}
	handler := newAuthTestHandler(t, repository, false)
	parsed, err := parseTemplates(os.DirFS("../.."), config.BrandingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	handler.templates = parsed
	_, claims := issueTestJWT(t, handler, user)
	claims.AuthTime = jwt.NewNumericDate(time.Now().Add(-time.Hour)) // not a fresh sign-in
	post := func(serve http.HandlerFunc, path string, values url.Values, provider string) *httptest.ResponseRecorder {
		if _, ok := values["csrf_token"]; !ok {
			values.Set("csrf_token", claims.CSRF)
		}
		request := formRequest(path, values)
		if provider != "" {
			route := chi.NewRouteContext()
			route.URLParams.Add("provider", provider)
			request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, route))
		}
		request.Header.Set("HX-Request", "true")
		request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: user, Claims: claims, Transport: transportCookie}))
		response := httptest.NewRecorder()
		serve(response, request)
		return response
	}
	page := func(name string, response *httptest.ResponseRecorder, status int, message string) {
		t.Helper()
		body := response.Body.String()
		if response.Code != status || !strings.HasPrefix(response.Header().Get("Content-Type"), "text/html") ||
			!strings.Contains(body, `<div class="page">`) || !strings.Contains(body, `<div class="alert alert-danger" role="alert">`+message+`</div>`) {
			t.Errorf("%s: %d %q, want a %d account page showing %q: %s", name, response.Code, response.Header().Get("Content-Type"), status, message, body)
		}
	}
	page("profile validation", post(handler.UpdateProfile, "/account/profile", url.Values{"display_name": {"User"}, "email": {"not an email"}}, ""), http.StatusOK, "Enter a valid email address.")
	page("theme validation", post(handler.UpdateTheme, "/account/theme", url.Values{"theme": {"purple"}}, ""), http.StatusOK, "Choose either the light or dark theme.")
	page("stale unlink", post(handler.OAuthUnlink, "/account/oauth/discord/unlink", url.Values{}, "discord"), http.StatusOK,
		"To remove a login provider, sign out and sign in again, then remove it within five minutes.")
	wrongPassword := url.Values{"current_password": {"a wrong password"}, "password": {"a brand new password"}, "password_confirm": {"a brand new password"}}
	for range 5 {
		page("wrong current password", post(handler.UpdateOwnPassword, "/account/password", wrongPassword, ""), http.StatusOK, "Current password is incorrect.")
	}
	page("password lockout", post(handler.UpdateOwnPassword, "/account/password", wrongPassword, ""), http.StatusTooManyRequests, "Too many incorrect password attempts. Try again later.")
	forged := post(handler.UpdateOwnPassword, "/account/password", url.Values{"csrf_token": {"forged"}}, "")
	if forged.Code != http.StatusForbidden || !strings.HasPrefix(forged.Header().Get("Content-Type"), "text/plain") || strings.TrimSpace(forged.Body.String()) != "Invalid CSRF token." {
		t.Errorf("CSRF failure: %d %q %q", forged.Code, forged.Header().Get("Content-Type"), forged.Body.String())
	}
}
