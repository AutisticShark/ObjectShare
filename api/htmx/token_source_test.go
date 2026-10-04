package htmx

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/db"
)

// Secrets in a URL leak through access logs, browser history, and Referer, so
// CSRF and setup tokens are accepted only from the POST body (or, for CSRF, the
// X-CSRF-Token header the scripts send).
func TestSetupAndPreAuthCSRFTokensAreNotReadFromTheQueryString(t *testing.T) {
	repository := newAuthMemoryRepository()
	handler := newAuthTestHandler(t, repository, false)
	handler.config.Auth.SetupToken = "a-sufficiently-long-setup-token"
	page := httptest.NewRecorder()
	handler.SetupPage(page, httptest.NewRequest(http.MethodGet, "/setup", nil))
	csrf, cookie := strings.TrimSpace(page.Body.String()), page.Result().Cookies()[0]
	registration := url.Values{"display_name": {"Admin"}, "email": {"admin@example.com"}, "password": {"a sufficiently long password"}, "password_confirm": {"a sufficiently long password"}}
	submit := func(query, body url.Values) *httptest.ResponseRecorder {
		values := url.Values{}
		for key, value := range registration {
			values[key] = value
		}
		for key, value := range body {
			values[key] = value
		}
		request := formRequest("/setup?"+query.Encode(), values)
		request.AddCookie(cookie)
		response := httptest.NewRecorder()
		handler.Setup(response, request)
		return response
	}

	if response := submit(url.Values{"setup_token": {"a-sufficiently-long-setup-token"}}, url.Values{"csrf_token": {csrf}}); response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "setup token is incorrect") {
		t.Fatalf("setup token from the query string: status=%d body=%q", response.Code, response.Body.String())
	}
	if response := submit(url.Values{"csrf_token": {csrf}}, url.Values{"setup_token": {"a-sufficiently-long-setup-token"}}); response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "Invalid CSRF token") {
		t.Fatalf("CSRF token from the query string: status=%d body=%q", response.Code, response.Body.String())
	}
	if len(repository.users) != 0 {
		t.Fatal("setup accepted a token from the query string")
	}
	if response := submit(url.Values{}, url.Values{"csrf_token": {csrf}, "setup_token": {"a-sufficiently-long-setup-token"}}); response.Code != http.StatusSeeOther || len(repository.users) != 1 {
		t.Fatalf("setup with body tokens: status=%d users=%d body=%q", response.Code, len(repository.users), response.Body.String())
	}
}

func TestSessionCSRFTokenIsNotReadFromTheQueryString(t *testing.T) {
	repository := newAuthMemoryRepository()
	hash, _ := appauth.HashPassword("a sufficiently long password")
	user := &db.User{ID: "1f0b7d7e-3c1a-4f4e-9a52-6a0c5c7f1d11", Email: "user@example.com", DisplayName: "User", PasswordHash: hash, Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[user.ID] = user
	handler := newAuthTestHandler(t, repository, false)
	logout := handler.Authenticate(handler.RequireUser(http.HandlerFunc(handler.Logout)))
	token, claims := issueTestJWT(t, handler, user)

	request := formRequest("/logout?csrf_token="+url.QueryEscape(claims.CSRF), url.Values{})
	request.AddCookie(&http.Cookie{Name: "objectshare_jwt", Value: token})
	response := httptest.NewRecorder()
	logout.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || len(repository.revoked) != 0 {
		t.Fatalf("query-string CSRF status=%d revoked=%d", response.Code, len(repository.revoked))
	}

	request = formRequest("/logout", url.Values{})
	request.Header.Set("X-CSRF-Token", claims.CSRF)
	request.AddCookie(&http.Cookie{Name: "objectshare_jwt", Value: token})
	response = httptest.NewRecorder()
	logout.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || len(repository.revoked) != 1 {
		t.Fatalf("header CSRF status=%d revoked=%d", response.Code, len(repository.revoked))
	}
}
