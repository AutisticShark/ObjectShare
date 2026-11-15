package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

// A rejected setup token must come back as a complete setup page carrying the
// message, so the frontend can show it.
func TestRejectedSetupTokenRendersTheSetupPageWithTheError(t *testing.T) {
	repository := newAuthMemoryRepository()
	handler := newAuthTestHandler(t, repository, false)
	handler.config.Auth.SetupToken = "a-sufficiently-long-setup-token"
	page := httptest.NewRecorder()
	handler.SetupPage(page, httptest.NewRequest(http.MethodGet, "/setup", nil))
	_, pageData := pageOf(t, page.Body.String())
	csrf, _ := pageData["CSRF"].(string)
	cookie := page.Result().Cookies()[0]
	if csrf == "" {
		t.Fatal("the setup page carries no CSRF token")
	}
	request := formRequest("/setup", url.Values{"csrf_token": {csrf}, "setup_token": {"wrong"}, "display_name": {"Admin"}, "email": {"admin@example.com"}, "password": {"a sufficiently long password"}, "password_confirm": {"a sufficiently long password"}})
	request.Header.Set(fetchRequestHeader, "true")
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.Setup(response, request)
	body := response.Body.String()
	if response.Code != http.StatusForbidden || !strings.HasPrefix(response.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("setup token rejection: %d %q %s", response.Code, response.Header().Get("Content-Type"), body)
	}
	if name, data := pageOf(t, body); name != "setup" || data["Error"] != "The setup token is incorrect." || data["SetupTokenRequired"] != true {
		t.Fatalf("setup token rejection page: %s %v", name, data)
	}
}

// Each account handler's answer to a fetch form submission must be a complete account
// page carrying the error, or a short plain-text message.
func TestAccountFormResponsesCarryTheErrorOrPlainText(t *testing.T) {
	repository := newAuthMemoryRepository()
	hash, _ := appauth.HashPassword("the current password")
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "user@example.com", DisplayName: "User", PasswordHash: hash, Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[user.ID] = user
	repository.identities["discord|subject"] = &db.OAuthIdentity{Provider: "discord", Subject: "subject", UserID: user.ID}
	handler := newAuthTestHandler(t, repository, false)
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
		request.Header.Set(fetchRequestHeader, "true")
		request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: user, Claims: claims, Transport: transportCookie}))
		response := httptest.NewRecorder()
		serve(response, request)
		return response
	}
	page := func(name string, response *httptest.ResponseRecorder, status int, message string) {
		t.Helper()
		body := response.Body.String()
		if response.Code != status || !strings.HasPrefix(response.Header().Get("Content-Type"), "text/html") {
			t.Errorf("%s: %d %q, want a %d account page showing %q: %s", name, response.Code, response.Header().Get("Content-Type"), status, message, body)
			return
		}
		if pageName, data := pageOf(t, body); pageName != "account" || data["Error"] != message {
			t.Errorf("%s: page %q error %v, want an account page showing %q", name, pageName, data["Error"], message)
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
