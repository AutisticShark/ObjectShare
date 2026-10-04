package htmx

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

// serveAuthenticated runs request through Authenticate and reports the
// identity, if any, that reached the next handler.
func serveAuthenticated(handler *Handler, request *http.Request) (*httptest.ResponseRecorder, *identity, bool) {
	var served *identity
	reached := false
	response := httptest.NewRecorder()
	handler.Authenticate(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		reached, served = true, currentIdentity(request)
		writer.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(response, request)
	return response, served, reached
}

// A reverse proxy protected with HTTP Basic authentication forwards its own
// Authorization header; that must not hide the ObjectShare JWT cookie.
func TestNonBearerAuthorizationFallsBackToJWTCookie(t *testing.T) {
	repository := newAuthMemoryRepository()
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "user@example.com", DisplayName: "User", Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[user.ID] = user
	handler := newAuthTestHandler(t, repository, false)
	token, _ := issueTestJWT(t, handler, user)
	for _, authorization := range []string{"Basic dXNlcjpwYXNz", `Digest username="user", realm="proxy"`, "Negotiate abc", "Bearertoken"} {
		request := httptest.NewRequest(http.MethodGet, "/account", nil)
		request.Header.Set("Authorization", authorization)
		request.AddCookie(&http.Cookie{Name: handler.jwtCookieName(), Value: token})
		response, served, _ := serveAuthenticated(handler, request)
		if served == nil || served.User.ID != user.ID || served.Transport != transportCookie {
			t.Fatalf("Authorization %q hid the JWT cookie: identity=%v", authorization, served)
		}
		if len(response.Result().Cookies()) != 0 {
			t.Fatalf("Authorization %q cleared a valid JWT cookie", authorization)
		}

		anonymous := httptest.NewRequest(http.MethodGet, "/", nil)
		anonymous.Header.Set("Authorization", authorization)
		if response, served, reached := serveAuthenticated(handler, anonymous); !reached || served != nil || response.Code != http.StatusNoContent {
			t.Fatalf("Authorization %q without a cookie: reached=%v identity=%v status=%d", authorization, reached, served, response.Code)
		}
	}
}

// A client that presents a bearer token which fails validation must receive
// 401 rather than continue as a guest, e.g. turning an account upload into an
// anonymous one.
func TestInvalidBearerTokenIsRejectedInsteadOfAnonymous(t *testing.T) {
	repository := newAuthMemoryRepository()
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "user@example.com", DisplayName: "User", Role: db.RoleUser, Active: true, TokenVersion: 1}
	stale := &db.User{ID: "4d754f93-6968-4dea-a5f8-87cb074375f1", Email: "stale@example.com", DisplayName: "Stale", Role: db.RoleUser, Active: true, TokenVersion: 1}
	disabled := &db.User{ID: "b0f1f0a4-3f39-4a8c-9a43-3a7b8f5d2c11", Email: "disabled@example.com", DisplayName: "Disabled", Role: db.RoleUser, Active: true, TokenVersion: 1}
	deleted := &db.User{ID: "9a1c2e4b-7d3f-4b5a-8c6d-0e1f2a3b4c5d", Role: db.RoleUser, TokenVersion: 1}
	repository.users[user.ID], repository.users[stale.ID], repository.users[disabled.ID] = user, stale, disabled
	handler := newAuthTestHandler(t, repository, false)

	valid, _ := issueTestJWT(t, handler, user)
	revoked, revokedClaims := issueTestJWT(t, handler, user)
	if err := repository.RevokeToken(context.Background(), appauth.TokenHash(revokedClaims.ID), revokedClaims.ExpiresAt.Time, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	expired, _, err := handler.jwt.Issue(user.ID, user.Role, user.TokenVersion, time.Now().UTC().Add(-13*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	staleToken, _ := issueTestJWT(t, handler, stale)
	stale.TokenVersion++
	disabledToken, _ := issueTestJWT(t, handler, disabled)
	disabled.Active = false
	deletedToken, _ := issueTestJWT(t, handler, deleted)
	wrongRole, _, err := handler.jwt.Issue(user.ID, db.RoleAdmin, user.TokenVersion, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	for name, authorization := range map[string]string{
		"malformed":             "Bearer garbage",
		"tampered":              "Bearer " + valid + "x",
		"missing token":         "Bearer",
		"extra fields":          "Bearer " + valid + " extra",
		"expired":               "Bearer " + expired,
		"revoked jti":           "Bearer " + revoked,
		"token version":         "Bearer " + staleToken,
		"disabled user":         "Bearer " + disabledToken,
		"deleted user":          "Bearer " + deletedToken,
		"role mismatch":         "Bearer " + wrongRole,
		"lowercase scheme":      "bearer garbage",
		"cookie does not apply": "Bearer garbage",
	} {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/upload", nil)
		request.Header.Set("Authorization", authorization)
		if name == "cookie does not apply" {
			request.AddCookie(&http.Cookie{Name: handler.jwtCookieName(), Value: valid})
		}
		response, _, reached := serveAuthenticated(handler, request)
		if reached || response.Code != http.StatusUnauthorized {
			t.Fatalf("%s bearer token: reached=%v status=%d", name, reached, response.Code)
		}
		if got := response.Header().Get("WWW-Authenticate"); got != `Bearer error="invalid_token"` {
			t.Fatalf("%s bearer token WWW-Authenticate=%q", name, got)
		}
		if len(response.Result().Cookies()) != 0 {
			t.Fatalf("%s bearer token changed browser cookies", name)
		}
	}

	request := httptest.NewRequest(http.MethodGet, "/account", nil)
	request.Header.Set("Authorization", "Bearer "+valid)
	if _, served, _ := serveAuthenticated(handler, request); served == nil || served.Transport != transportBearer {
		t.Fatalf("valid bearer token was not authenticated: %v", served)
	}

	// An invalid cookie is still cleared and the request continues anonymously.
	cookieRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	cookieRequest.AddCookie(&http.Cookie{Name: handler.jwtCookieName(), Value: revoked})
	response, served, reached := serveAuthenticated(handler, cookieRequest)
	if !reached || served != nil || response.Code != http.StatusNoContent {
		t.Fatalf("invalid cookie: reached=%v identity=%v status=%d", reached, served, response.Code)
	}
	cleared := false
	for _, cookie := range response.Result().Cookies() {
		cleared = cleared || (cookie.Name == handler.jwtCookieName() && cookie.MaxAge < 0)
	}
	if !cleared {
		t.Fatal("invalid JWT cookie was not cleared")
	}
}

func TestInvalidBearerTokenDoesNotBecomeGuestUpload(t *testing.T) {
	repository := newAuthMemoryRepository()
	handler := newAuthTestHandler(t, repository, false)
	handler.config.Upload = &config.UploadConfig{GuestEnabled: true}
	body := new(bytes.Buffer)
	form := multipart.NewWriter(body)
	_ = form.WriteField("share_mode", "private")
	part, _ := form.CreateFormFile("file", "hello.txt")
	_, _ = part.Write([]byte("x"))
	_ = form.Close()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/upload", body)
	request.Header.Set("Content-Type", form.FormDataContentType())
	request.Header.Set("Authorization", "Bearer garbage")
	response := httptest.NewRecorder()
	handler.Authenticate(http.HandlerFunc(handler.Upload)).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || len(repository.files) != 0 {
		t.Fatalf("invalid bearer upload status=%d files=%d", response.Code, len(repository.files))
	}
}

// The parser accepts a JWT until exp+JWTLeeway, so a logged-out token must
// stay revoked for that whole window.
func TestRevokedJWTStaysRevokedThroughExpiryLeeway(t *testing.T) {
	repository := newAuthMemoryRepository()
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "user@example.com", DisplayName: "User", Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[user.ID] = user
	handler := newAuthTestHandler(t, repository, false)
	// Issued so that exp was 10s ago: still inside the parser leeway.
	token, claims, err := handler.jwt.Issue(user.ID, user.Role, user.TokenVersion, time.Now().UTC().Add(-12*time.Hour-10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handler.jwt.Parse(token); err != nil {
		t.Fatalf("token inside the leeway should still parse: %v", err)
	}
	// The user logged out an hour before the token expired.
	if err := repository.RevokeToken(context.Background(), appauth.TokenHash(claims.ID), claims.ExpiresAt.Time, claims.ExpiresAt.Time.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/account", nil)
	request.AddCookie(&http.Cookie{Name: handler.jwtCookieName(), Value: token})
	if _, served, _ := serveAuthenticated(handler, request); served != nil {
		t.Fatal("a revoked JWT authenticated again inside the expiry leeway")
	}
}
