package htmx

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const oauthFlowLifetime = 10 * time.Minute

var oauthProviderKeys = [...]string{"google", "github", "discord"}

type oauthButton struct {
	Key, Label, URL string
}

type oauthAccountProvider struct {
	Key, Label string
	Configured bool
	Linked     bool
}

type oauthErrorData struct {
	Version, Error, Back, BackLabel string
	User                            *db.User
}

type oauthFlow struct {
	State            string `json:"state"`
	Verifier         string `json:"verifier"`
	Provider         string `json:"provider"`
	Next             string `json:"next,omitempty"`
	LinkUserID       string `json:"link_user_id,omitempty"`
	LinkTokenVersion int    `json:"link_token_version,omitempty"`
	LinkJTIHash      string `json:"link_jti_hash,omitempty"`
	LinkJWTExpiresAt int64  `json:"link_jwt_expires_at,omitempty"`
	ExpiresAt        int64  `json:"expires_at"`
}

func (handler *Handler) OAuthStart(writer http.ResponseWriter, request *http.Request) {
	provider := handler.oauthProvider(chi.URLParam(request, "provider"))
	if provider == nil {
		http.NotFound(writer, request)
		return
	}
	if currentIdentity(request) == nil {
		if !handler.allowRequest(writer, request, "login", handler.rateLimitSettings().LoginLimit) {
			return
		}
		if handler.captchaEnabled("login") && request.Method != http.MethodPost {
			http.Error(writer, "CAPTCHA-protected login must start from the login page.", http.StatusMethodNotAllowed)
			return
		}
		if request.Method == http.MethodPost {
			if !handler.parseAuthForm(writer, request) || !handler.verifyPreAuthCSRF(writer, request) || !handler.verifyCaptcha(writer, request, "login", "") {
				return
			}
		}
	}
	state, _, err := appauth.NewToken()
	if err != nil {
		handler.internalError(writer, request, "generate OAuth state", err)
		return
	}
	verifier, _, err := appauth.NewToken()
	if err != nil {
		handler.internalError(writer, request, "generate OAuth PKCE verifier", err)
		return
	}
	flow := oauthFlow{State: state, Verifier: verifier, Provider: provider.Key(), Next: safeLoginDestination(request.URL.Query().Get("next")), ExpiresAt: time.Now().Add(oauthFlowLifetime).Unix()}
	if identity := currentIdentity(request); identity != nil {
		if identity.Claims == nil || identity.Claims.ExpiresAt == nil {
			handler.renderOAuthError(writer, request, "Your login cannot be used to link an OAuth provider. Log in again and retry.", true)
			return
		}
		flow.LinkUserID = identity.User.ID
		flow.LinkTokenVersion = identity.User.TokenVersion
		flow.LinkJTIHash = appauth.TokenHash(identity.Claims.ID)
		flow.LinkJWTExpiresAt = identity.Claims.ExpiresAt.Time.Unix()
		flow.Next = ""
	}
	cookieValue, err := handler.signOAuthFlow(flow)
	if err != nil {
		handler.internalError(writer, request, "encode OAuth state", err)
		return
	}
	http.SetCookie(writer, &http.Cookie{
		Name: handler.oauthCookieName(), Value: cookieValue, Path: "/", HttpOnly: true,
		Secure: handler.config.SecureCookies, SameSite: http.SameSiteLaxMode,
		Expires: time.Unix(flow.ExpiresAt, 0).UTC(), MaxAge: int(oauthFlowLifetime.Seconds()),
	})
	writer.Header().Set("Cache-Control", "no-store")
	handler.redirect(writer, request, provider.AuthorizationURL(state, verifier))
}

func (handler *Handler) OAuthCallback(writer http.ResponseWriter, request *http.Request) {
	provider := handler.oauthProvider(chi.URLParam(request, "provider"))
	if provider == nil {
		http.NotFound(writer, request)
		return
	}
	flow, err := handler.readOAuthFlow(request)
	handler.clearOAuthCookie(writer)
	if err != nil || flow.Provider != provider.Key() {
		handler.renderOAuthError(writer, request, "This OAuth login request is invalid or expired.", false)
		return
	}
	stateValues := request.URL.Query()["state"]
	if len(stateValues) != 1 || subtle.ConstantTimeCompare([]byte(stateValues[0]), []byte(flow.State)) != 1 {
		handler.renderOAuthError(writer, request, "This OAuth login request is invalid or expired.", flow.LinkUserID != "")
		return
	}
	if providerErrors := request.URL.Query()["error"]; len(providerErrors) != 0 {
		message := "The OAuth provider did not complete sign-in."
		if len(providerErrors) == 1 && providerErrors[0] == "access_denied" {
			message = "OAuth sign-in was canceled."
		}
		handler.renderOAuthError(writer, request, message, flow.LinkUserID != "")
		return
	}
	codeValues := request.URL.Query()["code"]
	if len(codeValues) != 1 || codeValues[0] == "" || len(codeValues[0]) > 4096 {
		handler.renderOAuthError(writer, request, "The OAuth provider returned an invalid authorization code.", flow.LinkUserID != "")
		return
	}
	profile, err := provider.Profile(request.Context(), codeValues[0], flow.Verifier)
	if err != nil {
		handler.logger.Warn("OAuth provider verification failed", "provider", provider.Key(), "error", err)
		handler.renderOAuthError(writer, request, "The OAuth provider could not verify this login. Please try again.", flow.LinkUserID != "")
		return
	}
	if profile == nil {
		handler.renderOAuthError(writer, request, "The OAuth provider returned an invalid identity response.", flow.LinkUserID != "")
		return
	}
	email, err := appauth.NormalizeEmail(profile.Email)
	if err != nil || !profile.EmailVerified || !validOAuthSubject(profile.Subject) {
		handler.renderOAuthError(writer, request, "The OAuth provider did not return a verified email address and stable account identifier.", flow.LinkUserID != "")
		return
	}
	displayName := oauthDisplayName(profile.DisplayName, provider.Label())
	identity := &db.OAuthIdentity{Provider: provider.Key(), Subject: profile.Subject, Email: email}
	if flow.LinkUserID != "" {
		handler.finishOAuthLink(writer, request, flow, identity, provider.Label())
		return
	}
	handler.finishOAuthLogin(writer, request, flow, identity, email, displayName)
}

func (handler *Handler) finishOAuthLink(writer http.ResponseWriter, request *http.Request, flow oauthFlow, identity *db.OAuthIdentity, label string) {
	user, err := handler.users.UserByID(request.Context(), flow.LinkUserID)
	if err != nil || !user.Active || user.TokenVersion != flow.LinkTokenVersion || flow.LinkJWTExpiresAt <= time.Now().Unix() || flow.LinkJTIHash == "" {
		handler.renderOAuthError(writer, request, "Your ObjectShare account changed while OAuth was in progress. Log in and try linking again.", true)
		return
	}
	revoked, err := handler.users.TokenRevoked(request.Context(), flow.LinkJTIHash, time.Now().UTC())
	if err != nil {
		handler.internalError(writer, request, "check OAuth link JWT revocation", err)
		return
	}
	if revoked {
		handler.renderOAuthError(writer, request, "Your ObjectShare login ended while OAuth was in progress. Log in and try linking again.", true)
		return
	}
	existing, lookupErr := handler.users.OAuthUser(request.Context(), identity.Provider, identity.Subject)
	if lookupErr == nil {
		if existing.ID != user.ID {
			handler.renderOAuthError(writer, request, "That OAuth account is already linked to another ObjectShare account.", true)
			return
		}
	} else if !errors.Is(lookupErr, db.ErrNotFound) {
		handler.internalError(writer, request, "look up linked OAuth identity", lookupErr)
		return
	} else {
		identity.UserID = user.ID
		if err := handler.users.LinkOAuthIdentity(request.Context(), identity); err != nil {
			if errors.Is(err, db.ErrConflict) {
				handler.renderOAuthError(writer, request, "Only one "+label+" account can be linked to an ObjectShare account.", true)
				return
			}
			handler.internalError(writer, request, "link OAuth identity", err)
			return
		}
	}
	if err := handler.startJWT(writer, request, user, true); err != nil {
		handler.internalError(writer, request, "issue JWT after OAuth link", err)
		return
	}
	handler.redirect(writer, request, "/account?message=oauth-linked")
}

func (handler *Handler) finishOAuthLogin(writer http.ResponseWriter, request *http.Request, flow oauthFlow, identity *db.OAuthIdentity, email, displayName string) {
	user, err := handler.users.OAuthUser(request.Context(), identity.Provider, identity.Subject)
	if errors.Is(err, db.ErrNotFound) {
		if !handler.config.Auth.SignupEnabled {
			handler.renderOAuthError(writer, request, "This OAuth account is not linked, and new account registration is disabled.", false)
			return
		}
		if _, emailErr := handler.users.UserByEmail(request.Context(), email); emailErr == nil {
			handler.renderOAuthError(writer, request, "An ObjectShare account already uses this email. Log in with its password, then link this provider from My account.", false)
			return
		} else if !errors.Is(emailErr, db.ErrNotFound) {
			handler.internalError(writer, request, "check OAuth email", emailErr)
			return
		}
		user = &db.User{ID: uuid.NewString(), Email: email, DisplayName: displayName, PasswordHash: "", Role: db.RoleUser, Active: true, TokenVersion: 1}
		identity.UserID = user.ID
		if createErr := handler.users.CreateOAuthUser(request.Context(), user, identity); createErr != nil {
			if !errors.Is(createErr, db.ErrConflict) {
				handler.internalError(writer, request, "create OAuth user", createErr)
				return
			}
			user, err = handler.users.OAuthUser(request.Context(), identity.Provider, identity.Subject)
			if err != nil {
				handler.renderOAuthError(writer, request, "An ObjectShare account already uses this email. Log in with its password, then link this provider from My account.", false)
				return
			}
		}
	} else if err != nil {
		handler.internalError(writer, request, "look up OAuth identity", err)
		return
	}
	if !user.Active {
		handler.renderOAuthError(writer, request, "This ObjectShare account is disabled.", false)
		return
	}
	if err := handler.startJWT(writer, request, user, true); err != nil {
		handler.internalError(writer, request, "issue OAuth login JWT", err)
		return
	}
	handler.redirectAfterLogin(writer, request, flow.Next)
}

func (handler *Handler) OAuthUnlink(writer http.ResponseWriter, request *http.Request) {
	provider := strings.ToLower(chi.URLParam(request, "provider"))
	if oauthProviderLabel(provider) == "" {
		http.NotFound(writer, request)
		return
	}
	identity := currentIdentity(request)
	if !handler.parseAuthForm(writer, request) || !handler.verifyJWTCSRF(writer, request, identity) {
		return
	}
	err := handler.users.UnlinkOAuthIdentity(request.Context(), identity.User.ID, provider)
	if errors.Is(err, db.ErrLastLoginMethod) {
		handler.renderAccount(writer, request, identity, "Set a password or link another provider before removing your only login method.", "")
		return
	}
	if errors.Is(err, db.ErrNotFound) {
		http.NotFound(writer, request)
		return
	}
	if err != nil {
		handler.internalError(writer, request, "unlink OAuth identity", err)
		return
	}
	handler.redirect(writer, request, "/account?message=oauth-unlinked")
}

func (handler *Handler) oauthProvider(key string) appauth.OAuthProvider {
	return handler.oauthProviders[strings.ToLower(key)]
}

func (handler *Handler) oauthLoginButtons(next string) []oauthButton {
	buttons := make([]oauthButton, 0, len(handler.oauthProviders))
	for _, key := range oauthProviderKeys {
		if provider := handler.oauthProviders[key]; provider != nil {
			endpoint := "/oauth/" + key + "/start"
			if safe := safeLoginDestination(next); safe != "" {
				endpoint += "?next=" + url.QueryEscape(safe)
			}
			buttons = append(buttons, oauthButton{Key: key, Label: provider.Label(), URL: endpoint})
		}
	}
	return buttons
}

func (handler *Handler) oauthAccountProviders(ctx context.Context, userID string) ([]oauthAccountProvider, error) {
	identities, err := handler.users.OAuthIdentities(ctx, userID)
	if err != nil {
		return nil, err
	}
	linked := make(map[string]bool, len(identities))
	for _, identity := range identities {
		linked[identity.Provider] = true
	}
	rows := make([]oauthAccountProvider, 0, len(oauthProviderKeys))
	for _, key := range oauthProviderKeys {
		configured := handler.oauthProviders[key] != nil
		if configured || linked[key] {
			rows = append(rows, oauthAccountProvider{Key: key, Label: oauthProviderLabel(key), Configured: configured, Linked: linked[key]})
		}
	}
	return rows, nil
}

func (handler *Handler) signOAuthFlow(flow oauthFlow) (string, error) {
	payload, err := json.Marshal(flow)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, handler.oauthSecret)
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (handler *Handler) readOAuthFlow(request *http.Request) (oauthFlow, error) {
	var flow oauthFlow
	cookie, err := request.Cookie(handler.oauthCookieName())
	if err != nil || len(cookie.Value) > 4096 {
		return flow, errors.New("missing OAuth flow cookie")
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		return flow, errors.New("invalid OAuth flow cookie")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return flow, errors.New("invalid OAuth flow signature")
	}
	mac := hmac.New(sha256.New, handler.oauthSecret)
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return flow, errors.New("invalid OAuth flow signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) > 2048 || json.Unmarshal(payload, &flow) != nil {
		return oauthFlow{}, errors.New("invalid OAuth flow payload")
	}
	now := time.Now().Unix()
	if flow.State == "" || flow.Verifier == "" || flow.Provider == "" || flow.ExpiresAt < now || flow.ExpiresAt > now+int64(oauthFlowLifetime.Seconds())+30 {
		return oauthFlow{}, errors.New("expired OAuth flow payload")
	}
	return flow, nil
}

func (handler *Handler) oauthCookieName() string {
	if handler.config.SecureCookies {
		return "__Host-objectshare_oauth"
	}
	return "objectshare_oauth"
}

func (handler *Handler) clearOAuthCookie(writer http.ResponseWriter) {
	for _, name := range []string{"objectshare_oauth", "__Host-objectshare_oauth"} {
		http.SetCookie(writer, &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: true, Secure: handler.config.SecureCookies || strings.HasPrefix(name, "__Host-"), SameSite: http.SameSiteLaxMode, MaxAge: -1})
	}
}

func (handler *Handler) renderOAuthError(writer http.ResponseWriter, request *http.Request, message string, linking bool) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	back, label := "/login", "Back to login"
	if linking {
		back, label = "/account", "Back to My account"
	}
	writer.WriteHeader(http.StatusBadRequest)
	handler.render(writer, "oauth_error.html", oauthErrorData{Version: config.GetVersion(), Error: message, Back: back, BackLabel: label, User: identityUser(request)})
}

func validOAuthSubject(subject string) bool {
	if subject == "" || len(subject) > 255 || !utf8.ValidString(subject) {
		return false
	}
	for _, character := range subject {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func oauthDisplayName(value, providerLabel string) string {
	value = strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return -1
		}
		return character
	}, value)
	runes := []rune(strings.TrimSpace(value))
	if len(runes) > 100 {
		runes = runes[:100]
	}
	if name, err := appauth.ValidateDisplayName(string(runes)); err == nil {
		return name
	}
	return providerLabel + " user"
}

func oauthProviderLabel(key string) string {
	return map[string]string{"google": "Google", "github": "GitHub", "discord": "Discord"}[key]
}
