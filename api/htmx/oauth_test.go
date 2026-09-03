package htmx

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

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
	if err != nil || user.PasswordHash != "" || user.Role != db.RoleUser {
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
	existing := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "user@example.com", DisplayName: "Existing", PasswordHash: hash, Role: db.RoleUser, Active: true, TokenVersion: 1}
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
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: user, Claims: &appauth.Claims{CSRF: "signed-csrf"}, Transport: transportCookie}))
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
