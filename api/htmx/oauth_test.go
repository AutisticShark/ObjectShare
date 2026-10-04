package htmx

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/go-chi/chi/v5"
)

type fakeOAuthProvider struct {
	key, label      string
	profile         *appauth.OAuthProfile
	err             error
	state, verifier string
}

func (provider *fakeOAuthProvider) Key() string   { return provider.key }
func (provider *fakeOAuthProvider) Label() string { return provider.label }
func (provider *fakeOAuthProvider) AuthorizationURL(state, verifier string) string {
	provider.state, provider.verifier = state, verifier
	return "https://provider.example/authorize?state=" + url.QueryEscape(state)
}
func (provider *fakeOAuthProvider) Profile(_ context.Context, _, verifier string) (*appauth.OAuthProfile, error) {
	if verifier != provider.verifier {
		return nil, errors.New("PKCE verifier changed")
	}
	return provider.profile, provider.err
}

func TestOAuthLoginCreatesJWTAccountWithoutPersistingProviderToken(t *testing.T) {
	repository := newAuthMemoryRepository()
	handler := newAuthTestHandler(t, repository, true)
	provider := &fakeOAuthProvider{key: "google", label: "Google", profile: &appauth.OAuthProfile{Subject: "google-subject", Email: "USER@example.com", EmailVerified: true, DisplayName: "OAuth User"}}
	handler.oauthProviders = map[string]appauth.OAuthProvider{"google": provider}

	startResponse, flowCookie := startOAuth(t, handler, "google", loginDestinationAdminUsers, nil)
	if startResponse.Code != http.StatusSeeOther || provider.state == "" || provider.verifier == "" || flowCookie.SameSite != http.SameSiteLaxMode || !flowCookie.HttpOnly || !flowCookie.Secure {
		t.Fatalf("OAuth start was not hardened: status=%d cookie=%#v", startResponse.Code, flowCookie)
	}
	callback := oauthRouteRequest(http.MethodGet, "/oauth/google/callback?code=code&state="+url.QueryEscape(provider.state), "google")
	callback.AddCookie(flowCookie)
	response := httptest.NewRecorder()
	handler.OAuthCallback(response, callback)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/admin/users" || len(repository.users) != 1 || len(repository.identities) != 1 {
		t.Fatalf("OAuth callback status=%d location=%q users=%d identities=%d body=%q", response.Code, response.Header().Get("Location"), len(repository.users), len(repository.identities), response.Body.String())
	}
	user, err := repository.UserByEmail(context.Background(), "user@example.com")
	if err != nil || user.PasswordHash != "" || user.Role != db.RoleUser || user.EmailVerifiedAt == nil {
		t.Fatalf("OAuth-created user = %#v err=%v", user, err)
	}
	var rawJWT string
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == "__Host-objectshare_jwt" {
			rawJWT = cookie.Value
		}
	}
	claims, err := handler.jwt.Parse(rawJWT)
	if err != nil || claims.Subject != user.ID {
		t.Fatalf("OAuth JWT claims=%#v err=%v", claims, err)
	}

	_, forgedFlowCookie := startOAuth(t, handler, "google", "https://attacker.example/phishing", nil)
	forgedCallback := oauthRouteRequest(http.MethodGet, "/oauth/google/callback?code=code&state="+url.QueryEscape(provider.state), "google")
	forgedCallback.AddCookie(forgedFlowCookie)
	forgedResponse := httptest.NewRecorder()
	handler.OAuthCallback(forgedResponse, forgedCallback)
	if forgedResponse.Code != http.StatusSeeOther || forgedResponse.Header().Get("Location") != "/account" {
		t.Fatalf("forged OAuth destination status=%d location=%q", forgedResponse.Code, forgedResponse.Header().Get("Location"))
	}
}

func TestOAuthRejectsStateTamperingAndAutomaticEmailLinking(t *testing.T) {
	repository := newAuthMemoryRepository()
	hash, _ := appauth.HashPassword("a sufficiently long password")
	verifiedAt := time.Now().Add(-time.Hour)
	existing := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "user@example.com", DisplayName: "Existing", PasswordHash: hash, Role: db.RoleUser, Active: true, TokenVersion: 1, EmailVerifiedAt: &verifiedAt}
	repository.users[existing.ID] = existing
	handler := newAuthTestHandler(t, repository, false)
	provider := &fakeOAuthProvider{key: "github", label: "GitHub", profile: &appauth.OAuthProfile{Subject: "12345", Email: existing.Email, EmailVerified: true, DisplayName: "GitHub User"}}
	handler.oauthProviders = map[string]appauth.OAuthProvider{"github": provider}

	_, cookie := startOAuth(t, handler, "github", "", nil)
	tamperedCookie := *cookie
	signatureStart := strings.LastIndex(tamperedCookie.Value, ".") + 1
	if tamperedCookie.Value[signatureStart] == 'A' {
		tamperedCookie.Value = tamperedCookie.Value[:signatureStart] + "B" + tamperedCookie.Value[signatureStart+1:]
	} else {
		tamperedCookie.Value = tamperedCookie.Value[:signatureStart] + "A" + tamperedCookie.Value[signatureStart+1:]
	}
	tamperedFlow := oauthRouteRequest(http.MethodGet, "/oauth/github/callback?code=code&state="+url.QueryEscape(provider.state), "github")
	tamperedFlow.AddCookie(&tamperedCookie)
	tamperedFlowResponse := httptest.NewRecorder()
	handler.OAuthCallback(tamperedFlowResponse, tamperedFlow)
	if len(repository.identities) != 0 || !strings.Contains(tamperedFlowResponse.Body.String(), "invalid or expired") {
		t.Fatalf("tampered flow cookie identities=%d body=%q", len(repository.identities), tamperedFlowResponse.Body.String())
	}

	_, cookie = startOAuth(t, handler, "github", "", nil)
	tampered := oauthRouteRequest(http.MethodGet, "/oauth/github/callback?code=code&state=attacker-state", "github")
	tampered.AddCookie(cookie)
	tamperedResponse := httptest.NewRecorder()
	handler.OAuthCallback(tamperedResponse, tampered)
	if len(repository.identities) != 0 || !strings.Contains(tamperedResponse.Body.String(), "invalid or expired") {
		t.Fatalf("tampered state identities=%d body=%q", len(repository.identities), tamperedResponse.Body.String())
	}

	_, cookie = startOAuth(t, handler, "github", "", nil)
	callback := oauthRouteRequest(http.MethodGet, "/oauth/github/callback?code=code&state="+url.QueryEscape(provider.state), "github")
	callback.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.OAuthCallback(response, callback)
	if len(repository.users) != 1 || len(repository.identities) != 0 || !strings.Contains(response.Body.String(), "already uses this email") {
		t.Fatalf("email collision users=%d identities=%d body=%q", len(repository.users), len(repository.identities), response.Body.String())
	}
}

func TestOAuthRejectsUnverifiedProviderEmail(t *testing.T) {
	repository := newAuthMemoryRepository()
	handler := newAuthTestHandler(t, repository, false)
	provider := &fakeOAuthProvider{key: "google", label: "Google", profile: &appauth.OAuthProfile{Subject: "subject", Email: "user@example.com", EmailVerified: false, DisplayName: "User"}}
	handler.oauthProviders = map[string]appauth.OAuthProvider{"google": provider}
	_, cookie := startOAuth(t, handler, "google", "", nil)
	callback := oauthRouteRequest(http.MethodGet, "/oauth/google/callback?code=code&state="+url.QueryEscape(provider.state), "google")
	callback.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.OAuthCallback(response, callback)
	if len(repository.users) != 0 || len(repository.identities) != 0 || !strings.Contains(response.Body.String(), "verified email address") {
		t.Fatalf("unverified email users=%d identities=%d body=%q", len(repository.users), len(repository.identities), response.Body.String())
	}
}

func TestOAuthLinkIsBoundToLiveJWTAndFinalLoginMethodIsPreserved(t *testing.T) {
	repository := newAuthMemoryRepository()
	hash, _ := appauth.HashPassword("a sufficiently long password")
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "user@example.com", DisplayName: "User", PasswordHash: hash, Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[user.ID] = user
	handler := newAuthTestHandler(t, repository, false)
	provider := &fakeOAuthProvider{key: "google", label: "Google", profile: &appauth.OAuthProfile{Subject: "subject", Email: user.Email, EmailVerified: true, DisplayName: "User"}}
	handler.oauthProviders = map[string]appauth.OAuthProvider{"google": provider}
	_, claims := issueTestJWT(t, handler, user)
	identity := &identity{User: user, Claims: claims, Transport: transportCookie}

	_, cookie := startOAuth(t, handler, "google", "", identity)
	repository.revoked[appauth.TokenHash(claims.ID)] = time.Now().Add(time.Hour)
	callback := oauthRouteRequest(http.MethodGet, "/oauth/google/callback?code=code&state="+url.QueryEscape(provider.state), "google")
	callback.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.OAuthCallback(response, callback)
	if len(repository.identities) != 0 || !strings.Contains(response.Body.String(), "login ended") {
		t.Fatalf("revoked linking flow identities=%d body=%q", len(repository.identities), response.Body.String())
	}

	delete(repository.revoked, appauth.TokenHash(claims.ID))
	_, cookie = startOAuth(t, handler, "google", "", identity)
	callback = oauthRouteRequest(http.MethodGet, "/oauth/google/callback?code=code&state="+url.QueryEscape(provider.state), "google")
	callback.AddCookie(cookie)
	response = httptest.NewRecorder()
	handler.OAuthCallback(response, callback)
	if response.Code != http.StatusSeeOther || len(repository.identities) != 1 {
		t.Fatalf("linked callback status=%d identities=%d body=%q", response.Code, len(repository.identities), response.Body.String())
	}

	user.PasswordHash = ""
	if err := repository.UnlinkOAuthIdentity(context.Background(), user.ID, "google"); !errors.Is(err, db.ErrLastLoginMethod) {
		t.Fatalf("removing final login method returned %v", err)
	}
}

func TestOAuthSignupDisabledStillAllowsLinkedIdentity(t *testing.T) {
	repository := newAuthMemoryRepository()
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "user@example.com", DisplayName: "User", Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[user.ID] = user
	repository.identities["google\x00subject"] = &db.OAuthIdentity{UserID: user.ID, Provider: "google", Subject: "subject", Email: user.Email}
	handler := newAuthTestHandler(t, repository, false)
	handler.config.Auth.SignupEnabled = false
	provider := &fakeOAuthProvider{key: "google", label: "Google", profile: &appauth.OAuthProfile{Subject: "subject", Email: user.Email, EmailVerified: true, DisplayName: "User"}}
	handler.oauthProviders = map[string]appauth.OAuthProvider{"google": provider}
	_, cookie := startOAuth(t, handler, "google", "", nil)
	callback := oauthRouteRequest(http.MethodGet, "/oauth/google/callback?code=code&state="+url.QueryEscape(provider.state), "google")
	callback.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.OAuthCallback(response, callback)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/account" {
		t.Fatalf("linked OAuth login with signup disabled status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestDiscordOAuthIsPresentedAndCanBeUnlinked(t *testing.T) {
	repository := newAuthMemoryRepository()
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "user@example.com", DisplayName: "User", PasswordHash: "configured", Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[user.ID] = user
	repository.identities["discord\x0080351110224678912"] = &db.OAuthIdentity{UserID: user.ID, Provider: "discord", Subject: "80351110224678912", Email: user.Email}
	handler := newAuthTestHandler(t, repository, false)
	handler.oauthProviders = map[string]appauth.OAuthProvider{
		"google":  &fakeOAuthProvider{key: "google", label: "Google"},
		"github":  &fakeOAuthProvider{key: "github", label: "GitHub"},
		"discord": &fakeOAuthProvider{key: "discord", label: "Discord"},
	}

	buttons := handler.oauthLoginButtons(loginDestinationAdminUsers)
	if len(buttons) != 3 || buttons[2].Key != "discord" || buttons[2].Label != "Discord" || buttons[2].URL != "/oauth/discord/start?next=admin-users" {
		t.Fatalf("Discord OAuth login button missing or out of order: %#v", buttons)
	}
	providers, err := handler.oauthAccountProviders(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) != 3 || providers[2].Key != "discord" || !providers[2].Configured || !providers[2].Linked {
		t.Fatalf("Discord account provider missing: %#v", providers)
	}

	request := oauthRouteRequest(http.MethodPost, "/account/oauth/discord/unlink", "discord")
	request.Body = io.NopCloser(strings.NewReader(url.Values{"csrf_token": {"signed-csrf"}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: user, Claims: &appauth.Claims{CSRF: "signed-csrf", AuthTime: jwt.NewNumericDate(time.Now()), RegisteredClaims: jwt.RegisteredClaims{IssuedAt: jwt.NewNumericDate(time.Now())}}, Transport: transportCookie}))
	response := httptest.NewRecorder()
	handler.OAuthUnlink(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/account?message=oauth-unlinked" || len(repository.identities) != 0 {
		t.Fatalf("Discord unlink status=%d location=%q identities=%d body=%q", response.Code, response.Header().Get("Location"), len(repository.identities), response.Body.String())
	}
}

func TestOAuthOnlyUserCanSetPasswordWithoutCurrentPassword(t *testing.T) {
	repository := newAuthMemoryRepository()
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "user@example.com", DisplayName: "User", PasswordHash: "", Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[user.ID] = user
	handler := newAuthTestHandler(t, repository, false)
	_, claims := issueTestJWT(t, handler, user)
	request := formRequest("/account/password", url.Values{
		"csrf_token":       {claims.CSRF},
		"password":         {"a newly configured password"},
		"password_confirm": {"a newly configured password"},
	})
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: user, Claims: claims, Transport: transportCookie}))
	response := httptest.NewRecorder()
	handler.UpdateOwnPassword(response, request)
	if response.Code != http.StatusSeeOther || !appauth.VerifyPassword("a newly configured password", repository.users[user.ID].PasswordHash) || repository.users[user.ID].TokenVersion != 2 {
		t.Fatalf("set password status=%d user=%#v body=%q", response.Code, repository.users[user.ID], response.Body.String())
	}
}

// responseJWT returns the session JWT a response set, or "" when it set none.
func responseJWT(response *httptest.ResponseRecorder) string {
	for _, cookie := range response.Result().Cookies() {
		if strings.HasSuffix(cookie.Name, "objectshare_jwt") && cookie.Value != "" {
			return cookie.Value
		}
	}
	return ""
}

// A session older than recentAuthWindow must not set the first password of a
// passwordless account: that would need no proof at all, and the JWT it
// re-issues would then pass for a fresh sign-in.
func TestSettingAFirstPasswordRequiresARecentSignIn(t *testing.T) {
	repository := newAuthMemoryRepository()
	verifiedAt := time.Now().Add(-24 * time.Hour)
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "owner@example.com", DisplayName: "Owner", Role: db.RoleUser, Active: true, TokenVersion: 1, EmailVerifiedAt: &verifiedAt}
	repository.users[user.ID] = user
	repository.identities["google\x00owner-google"] = &db.OAuthIdentity{UserID: user.ID, Provider: "google", Subject: "owner-google", Email: user.Email}
	handler := newAuthTestHandler(t, repository, false)
	serve := func(next http.HandlerFunc, request *http.Request, token string) *httptest.ResponseRecorder {
		request.AddCookie(&http.Cookie{Name: "objectshare_jwt", Value: token})
		response := httptest.NewRecorder()
		handler.Authenticate(handler.RequireUser(next)).ServeHTTP(response, request)
		return response
	}
	setPassword := func(token, csrf string) *httptest.ResponseRecorder {
		return serve(handler.UpdateOwnPassword, formRequest("/account/password", url.Values{"csrf_token": {csrf}, "password": {"an attacker chosen password"}, "password_confirm": {"an attacker chosen password"}}), token)
	}
	unlink := func(token, csrf string) *httptest.ResponseRecorder {
		request := formRequest("/account/oauth/google/unlink", url.Values{"csrf_token": {csrf}})
		routeContext := chi.NewRouteContext()
		routeContext.URLParams.Add("provider", "google")
		return serve(handler.OAuthUnlink, request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext)), token)
	}

	stale, staleClaims, err := handler.jwt.Issue(user.ID, user.Role, user.TokenVersion, time.Now().UTC().Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	response := setPassword(stale, staleClaims.CSRF)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "sign in again") || responseJWT(response) != "" || user.PasswordHash != "" || user.TokenVersion != 1 {
		t.Fatalf("a stale session set the first password: status=%d jwt=%v body=%q", response.Code, responseJWT(response) != "", response.Body.String())
	}
	if unlink(stale, staleClaims.CSRF); len(repository.identities) != 1 {
		t.Fatal("a stale session removed the only OAuth login")
	}

	// A recent sign-in may set it, and the replacement JWT keeps the original
	// sign-in time rather than starting a new one.
	signedIn := time.Now().UTC().Add(-4 * time.Minute).Truncate(time.Second)
	recent, recentClaims, err := handler.jwt.Issue(user.ID, user.Role, user.TokenVersion, signedIn)
	if err != nil {
		t.Fatal(err)
	}
	response = setPassword(recent, recentClaims.CSRF)
	replacement, err := handler.jwt.Parse(responseJWT(response))
	if response.Code != http.StatusSeeOther || err != nil || user.PasswordHash == "" || user.TokenVersion != 2 {
		t.Fatalf("a recent session could not set a password: status=%d err=%v body=%q", response.Code, err, response.Body.String())
	}
	if replacement.AuthTime == nil || !replacement.AuthTime.Time.Equal(signedIn) || !replacement.IssuedAt.Time.After(signedIn) {
		t.Fatalf("replacement JWT auth_time=%v iat=%v, want auth_time %v carried forward", replacement.AuthTime, replacement.IssuedAt, signedIn)
	}
}

// Changing a password re-issues the JWT. The replacement must keep the old
// sign-in time, so an old session cannot launder itself into a recent one.
func TestPasswordChangeDoesNotRefreshTheSignInTime(t *testing.T) {
	repository := newAuthMemoryRepository()
	hash, _ := appauth.HashPassword("the current password")
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "owner@example.com", DisplayName: "Owner", PasswordHash: hash, Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[user.ID] = user
	handler := newAuthTestHandler(t, repository, false)
	signedIn := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	stale, claims, err := handler.jwt.Issue(user.ID, user.Role, user.TokenVersion, signedIn)
	if err != nil {
		t.Fatal(err)
	}
	request := formRequest("/account/password", url.Values{"csrf_token": {claims.CSRF}, "current_password": {"the current password"}, "password": {"a brand new password"}, "password_confirm": {"a brand new password"}})
	request.AddCookie(&http.Cookie{Name: "objectshare_jwt", Value: stale})
	response := httptest.NewRecorder()
	handler.Authenticate(handler.RequireUser(http.HandlerFunc(handler.UpdateOwnPassword))).ServeHTTP(response, request)
	replacement, err := handler.jwt.Parse(responseJWT(response))
	if response.Code != http.StatusSeeOther || err != nil {
		t.Fatalf("password change status=%d err=%v body=%q", response.Code, err, response.Body.String())
	}
	if replacement.AuthTime == nil || !replacement.AuthTime.Time.Equal(signedIn) || recentlyAuthenticated(&identity{User: user, Claims: replacement}) {
		t.Fatalf("password change refreshed the sign-in time: auth_time=%v", replacement.AuthTime)
	}
}

// A bearer client's token stops working when its password changes, so the
// replacement must come back in the response body, not only as a cookie.
func TestBearerPasswordChangeReturnsTheReplacementToken(t *testing.T) {
	repository := newAuthMemoryRepository()
	hash, _ := appauth.HashPassword("the current password")
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "user@example.com", DisplayName: "User", PasswordHash: hash, Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[user.ID] = user
	handler := newAuthTestHandler(t, repository, false)
	token, original := issueTestJWT(t, handler, user)
	request := formRequest("/account/password", url.Values{"current_password": {"the current password"}, "password": {"a brand new password"}, "password_confirm": {"a brand new password"}})
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.Authenticate(handler.RequireUser(http.HandlerFunc(handler.UpdateOwnPassword))).ServeHTTP(response, request)
	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || response.Code != http.StatusOK || body.TokenType != "Bearer" || body.ExpiresIn <= 0 || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("bearer password change status=%d body=%q", response.Code, response.Body.String())
	}
	if responseJWT(response) != "" {
		t.Fatal("a bearer client was sent a session cookie")
	}
	claims, err := handler.jwt.Parse(body.AccessToken)
	if err != nil || claims.TokenVersion != 2 || claims.AuthTime == nil || !claims.AuthTime.Time.Equal(original.AuthTime.Time) {
		t.Fatalf("replacement token claims=%#v err=%v", claims, err)
	}
	check := httptest.NewRequest(http.MethodGet, "/api/v1/private", nil)
	check.Header.Set("Authorization", "Bearer "+body.AccessToken)
	var served *identity
	handler.Authenticate(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { served = currentIdentity(r) })).ServeHTTP(httptest.NewRecorder(), check)
	if served == nil || served.User.ID != user.ID {
		t.Fatal("the replacement bearer token does not authenticate")
	}
}

func startOAuth(t *testing.T, handler *Handler, provider, next string, current *identity) (*httptest.ResponseRecorder, *http.Cookie) {
	t.Helper()
	path := "/oauth/" + provider + "/start"
	if next != "" {
		path += "?next=" + url.QueryEscape(next)
	}
	request := oauthRouteRequest(http.MethodGet, path, provider)
	if current != nil {
		request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, current))
	}
	response := httptest.NewRecorder()
	handler.OAuthStart(response, request)
	for _, cookie := range response.Result().Cookies() {
		if strings.Contains(cookie.Name, "objectshare_oauth") {
			return response, cookie
		}
	}
	t.Fatalf("OAuth start did not set a flow cookie: status=%d body=%q", response.Code, response.Body.String())
	return nil, nil
}

func oauthRouteRequest(method, target, provider string) *http.Request {
	request := httptest.NewRequest(method, target, nil)
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("provider", provider)
	return request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
}

func TestPasswordReverificationIsThrottledPerAccount(t *testing.T) {
	repository := newAuthMemoryRepository()
	hash, _ := appauth.HashPassword("the current password")
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "user@example.com", DisplayName: "User", PasswordHash: hash, Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[user.ID] = user
	handler := newAuthTestHandler(t, repository, false)
	_, claims := issueTestJWT(t, handler, user)
	change := func(current string) *httptest.ResponseRecorder {
		request := formRequest("/account/password", url.Values{
			"csrf_token": {claims.CSRF}, "current_password": {current},
			"password": {"a brand new password"}, "password_confirm": {"a brand new password"},
		})
		request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: user, Claims: claims, Transport: transportCookie}))
		response := httptest.NewRecorder()
		handler.UpdateOwnPassword(response, request)
		return response
	}
	for attempt := 1; attempt <= 5; attempt++ {
		if response := change("a wrong password"); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Current password is incorrect.") {
			t.Fatalf("guess %d: status=%d body=%q", attempt, response.Code, response.Body.String())
		}
	}
	locked := change("the current password")
	if locked.Code != http.StatusTooManyRequests || locked.Header().Get("Retry-After") == "" || repository.users[user.ID].TokenVersion != 1 {
		t.Fatalf("a locked account accepted a password change: status=%d retry=%q", locked.Code, locked.Header().Get("Retry-After"))
	}

	// A different account is unaffected, and success clears the counter.
	other := &db.User{ID: "b8a2e2a4-7a68-4b35-8d3c-2a4c8a1d5e71", Email: "other@example.com", DisplayName: "Other", PasswordHash: hash, Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[other.ID] = other
	_, otherClaims := issueTestJWT(t, handler, other)
	request := formRequest("/account/password", url.Values{
		"csrf_token": {otherClaims.CSRF}, "current_password": {"the current password"},
		"password": {"another brand new password"}, "password_confirm": {"another brand new password"},
	})
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: other, Claims: otherClaims, Transport: transportCookie}))
	response := httptest.NewRecorder()
	handler.UpdateOwnPassword(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("another account was throttled: %d %q", response.Code, response.Body.String())
	}
}

func TestOAuthLinkChangesRequireAFreshSignIn(t *testing.T) {
	repository := newAuthMemoryRepository()
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "user@example.com", DisplayName: "User", Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[user.ID] = user
	repository.identities["discord|subject"] = &db.OAuthIdentity{Provider: "discord", Subject: "subject", UserID: user.ID}
	handler := newAuthTestHandler(t, repository, false)
	stale := &identity{User: user, Transport: transportCookie, Claims: &appauth.Claims{CSRF: "signed-csrf", RegisteredClaims: jwt.RegisteredClaims{
		IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)), ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}}}
	if recentlyAuthenticated(stale) || recentlyAuthenticated(nil) || recentlyAuthenticated(&identity{User: user}) {
		t.Fatal("stale or claim-less sessions must not count as recently authenticated")
	}

	request := oauthRouteRequest(http.MethodPost, "/account/oauth/discord/unlink", "discord")
	request.Body = io.NopCloser(strings.NewReader(url.Values{"csrf_token": {"signed-csrf"}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, stale))
	response := httptest.NewRecorder()
	handler.OAuthUnlink(response, request)
	if len(repository.identities) != 1 || !strings.Contains(response.Body.String(), "sign in again") {
		t.Fatalf("a stale session unlinked a provider: identities=%d body=%q", len(repository.identities), response.Body.String())
	}

	handler.oauthProviders = map[string]appauth.OAuthProvider{"google": &fakeOAuthProvider{key: "google", label: "Google"}}
	startRequest := oauthRouteRequest(http.MethodGet, "/oauth/google/start", "google")
	startRequest = startRequest.WithContext(context.WithValue(startRequest.Context(), identityContextKey{}, stale))
	start := httptest.NewRecorder()
	handler.OAuthStart(start, startRequest)
	for _, cookie := range start.Result().Cookies() {
		if strings.Contains(cookie.Name, "objectshare_oauth") {
			t.Fatal("a stale session was given an OAuth link flow cookie")
		}
	}
	if !strings.Contains(start.Body.String(), "sign in again") {
		t.Fatalf("a stale session started a provider link: status=%d body=%q", start.Code, start.Body.String())
	}
}

func TestVerifiedOAuthEmailReclaimsAnUnverifiedSquattedAccount(t *testing.T) {
	repository := newAuthMemoryRepository()
	squatterHash, _ := appauth.HashPassword("the squatter's password")
	squatted := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "owner@example.com", DisplayName: "Squatter", PasswordHash: squatterHash, Role: db.RoleUser, Active: true, TokenVersion: 3}
	repository.users[squatted.ID] = squatted
	repository.identities["github\x00attackers-account"] = &db.OAuthIdentity{UserID: squatted.ID, Provider: "github", Subject: "attackers-account", Email: "attacker@example.net"}
	handler := newAuthTestHandler(t, repository, false)
	oldToken, _ := issueTestJWT(t, handler, squatted)
	provider := &fakeOAuthProvider{key: "google", label: "Google", profile: &appauth.OAuthProfile{Subject: "real-owner", Email: squatted.Email, EmailVerified: true, DisplayName: "Real Owner"}}
	handler.oauthProviders = map[string]appauth.OAuthProvider{"google": provider}

	_, cookie := startOAuth(t, handler, "google", "", nil)
	callback := oauthRouteRequest(http.MethodGet, "/oauth/google/callback?code=code&state="+url.QueryEscape(provider.state), "google")
	callback.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.OAuthCallback(response, callback)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/account" {
		t.Fatalf("verified owner was not signed in: status=%d location=%q body=%q", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	claimed := repository.users[squatted.ID]
	if len(repository.users) != 1 || claimed.EmailVerifiedAt == nil || claimed.PasswordHash != "" || claimed.MFA.Method != "" || claimed.TokenVersion != 4 {
		t.Fatalf("squatter kept access: %#v", claimed)
	}
	if len(repository.identities) != 1 || repository.identities["google\x00real-owner"] == nil {
		t.Fatalf("the squatter's linked identity survived: %#v", repository.identities)
	}
	if appauth.VerifyPassword("the squatter's password", claimed.PasswordHash) {
		t.Fatal("the squatter's password still works")
	}
	if _, err := handler.jwt.Parse(oldToken); err != nil {
		t.Fatalf("test setup: %v", err)
	}
	// The squatter's outstanding JWT now carries a stale token version and is refused.
	request := httptest.NewRequest(http.MethodGet, "/account", nil)
	request.AddCookie(&http.Cookie{Name: "objectshare_jwt", Value: oldToken})
	var served *identity
	handler.Authenticate(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { served = currentIdentity(r) })).ServeHTTP(httptest.NewRecorder(), request)
	if served != nil {
		t.Fatal("a JWT issued before the takeover still authenticates")
	}
}

// oauthLoginAs completes an OAuth login whose provider vouches for email and
// returns the account the session JWT it set belongs to ("" when none).
func oauthLoginAs(t *testing.T, handler *Handler, subject, email string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	provider := &fakeOAuthProvider{key: "google", label: "Google", profile: &appauth.OAuthProfile{Subject: subject, Email: email, EmailVerified: true, DisplayName: "Google User"}}
	handler.oauthProviders = map[string]appauth.OAuthProvider{"google": provider}
	_, flowCookie := startOAuth(t, handler, "google", "", nil)
	callback := oauthRouteRequest(http.MethodGet, "/oauth/google/callback?code=code&state="+url.QueryEscape(provider.state), "google")
	callback.AddCookie(flowCookie)
	response := httptest.NewRecorder()
	handler.OAuthCallback(response, callback)
	subjectID := ""
	if raw := responseJWT(response); raw != "" {
		if claims, err := handler.jwt.Parse(raw); err == nil {
			subjectID = claims.Subject
		}
	}
	return response, subjectID
}

// A session alone (here one signed in two hours ago) must not repoint an
// established account's email, and even a legitimate email change must not
// let an OAuth login for the new address claim the account and wipe its
// password, MFA, and linked logins.
func TestEmailChangeRequiresReauthenticationAndNeverMakesAnAccountClaimable(t *testing.T) {
	repository := newAuthMemoryRepository()
	hash, _ := appauth.HashPassword("the owner's real password")
	verifiedAt := time.Now().Add(-30 * 24 * time.Hour)
	owner := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "owner@example.com", DisplayName: "Owner", PasswordHash: hash,
		Role: db.RoleUser, Active: true, TokenVersion: 1, EmailVerifiedAt: &verifiedAt}
	if err := repository.CreateUser(t.Context(), owner); err != nil {
		t.Fatal(err)
	}
	owner = repository.users[owner.ID]
	handler := newAuthTestHandler(t, repository, false)
	stale, claims, err := handler.jwt.Issue(owner.ID, owner.Role, owner.TokenVersion, time.Now().UTC().Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	updateProfile := func(values url.Values) *httptest.ResponseRecorder {
		values.Set("csrf_token", claims.CSRF)
		request := formRequest("/account/profile", values)
		request.AddCookie(&http.Cookie{Name: "objectshare_jwt", Value: stale})
		response := httptest.NewRecorder()
		handler.Authenticate(handler.RequireUser(http.HandlerFunc(handler.UpdateProfile))).ServeHTTP(response, request)
		return response
	}

	for _, password := range []string{"", "a wrong password"} {
		response := updateProfile(url.Values{"email": {"attacker@evil.test"}, "display_name": {"Owner"}, "current_password": {password}})
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "current password") || owner.Email != "owner@example.com" || owner.EmailVerifiedAt == nil {
			t.Fatalf("email changed without the current password %q: status=%d email=%q body=%q", password, response.Code, owner.Email, response.Body.String())
		}
	}
	if response, subject := oauthLoginAs(t, handler, "attacker-google", "attacker@evil.test"); subject == owner.ID || owner.PasswordHash != hash {
		t.Fatalf("an OAuth login for an unrelated address took over the account: status=%d", response.Code)
	}
	// Display-name edits stay password-free.
	if response := updateProfile(url.Values{"email": {"owner@example.com"}, "display_name": {"Renamed"}}); response.Code != http.StatusSeeOther || owner.DisplayName != "Renamed" {
		t.Fatalf("display-name change status=%d body=%q", response.Code, response.Body.String())
	}

	// With the password the change succeeds and clears the current verification,
	// but the account has verified an address before, so it stays established.
	if response := updateProfile(url.Values{"email": {"new@example.net"}, "display_name": {"Renamed"}, "current_password": {"the owner's real password"}}); response.Code != http.StatusSeeOther || owner.Email != "new@example.net" || owner.EmailVerifiedAt != nil {
		t.Fatalf("email change with the password status=%d email=%q body=%q", response.Code, owner.Email, response.Body.String())
	}
	response, subject := oauthLoginAs(t, handler, "someone-google", "new@example.net")
	if subject == owner.ID || response.Code != http.StatusBadRequest || owner.PasswordHash != hash || owner.TokenVersion != 1 || repository.identities["google\x00someone-google"] != nil {
		t.Fatalf("an OAuth login claimed an account that had verified an email: status=%d subject=%q password kept=%v", response.Code, subject, owner.PasswordHash == hash)
	}
}

func TestPasswordlessEmailChangeRequiresARecentSignIn(t *testing.T) {
	repository := newAuthMemoryRepository()
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "owner@example.com", DisplayName: "Owner", Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[user.ID] = user
	handler := newAuthTestHandler(t, repository, false)
	change := func(issued time.Time, email string) *httptest.ResponseRecorder {
		token, claims, err := handler.jwt.Issue(user.ID, user.Role, user.TokenVersion, issued)
		if err != nil {
			t.Fatal(err)
		}
		request := formRequest("/account/profile", url.Values{"csrf_token": {claims.CSRF}, "email": {email}, "display_name": {"Owner"}})
		request.AddCookie(&http.Cookie{Name: "objectshare_jwt", Value: token})
		response := httptest.NewRecorder()
		handler.Authenticate(handler.RequireUser(http.HandlerFunc(handler.UpdateProfile))).ServeHTTP(response, request)
		return response
	}
	if response := change(time.Now().UTC().Add(-time.Hour), "attacker@evil.test"); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "sign in again") || user.Email != "owner@example.com" {
		t.Fatalf("a stale passwordless session changed the email: status=%d body=%q", response.Code, response.Body.String())
	}
	if response := change(time.Now().UTC(), "new@example.com"); response.Code != http.StatusSeeOther || user.Email != "new@example.com" {
		t.Fatalf("a recent passwordless session could not change the email: status=%d body=%q", response.Code, response.Body.String())
	}
}

// Only accounts that never verified any address and have no MFA are handed to
// a verified OAuth email; an MFA-enrolled squatter is refused.
func TestOAuthEmailDoesNotReclaimAccountsWithMFA(t *testing.T) {
	repository := newAuthMemoryRepository()
	hash, _ := appauth.HashPassword("a sufficiently long password")
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "owner@example.com", DisplayName: "Holder", PasswordHash: hash, Role: db.RoleUser, Active: true, TokenVersion: 1, MFA: db.MFAState{Method: "totp"}}
	repository.users[user.ID] = user
	handler := newAuthTestHandler(t, repository, false)
	response, subject := oauthLoginAs(t, handler, "google-owner", user.Email)
	if response.Code != http.StatusBadRequest || subject != "" || user.PasswordHash != hash || user.MFA.Method != "totp" || user.TokenVersion != 1 || len(repository.identities) != 0 {
		t.Fatalf("an MFA account was claimed: status=%d user=%#v", response.Code, user)
	}
}
