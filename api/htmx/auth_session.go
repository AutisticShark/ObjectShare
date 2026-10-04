package htmx

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/db"
)

// startJWT signs user in after they proved a login factor (password, OAuth,
// completed login MFA, signup). The cookie JWT's auth_time is now.
func (handler *Handler) startJWT(writer http.ResponseWriter, request *http.Request, user *db.User, recordLogin bool) error {
	token, _, err := handler.issueJWT(request, user, recordLogin)
	if err != nil {
		return err
	}
	handler.setJWTCookie(writer, token)
	return nil
}

// replaceJWT re-issues the cookie JWT (for example after a token version bump)
// without counting as a sign-in: authTime is carried forward unchanged.
func (handler *Handler) replaceJWT(writer http.ResponseWriter, request *http.Request, user *db.User, authTime time.Time, recordLogin bool) error {
	token, _, err := handler.issueReplacementJWT(request, user, authTime, recordLogin)
	if err != nil {
		return err
	}
	handler.setJWTCookie(writer, token)
	return nil
}

func (handler *Handler) setJWTCookie(writer http.ResponseWriter, token string) {
	http.SetCookie(writer, &http.Cookie{Name: handler.jwtCookieName(), Value: token, Path: "/", HttpOnly: true, Secure: handler.config.SecureCookies, SameSite: http.SameSiteStrictMode})
}

// writeAccessToken returns a JWT to a bearer-token client as JSON, in the same
// shape as the API login response, plus any extra fields.
func writeAccessToken(writer http.ResponseWriter, token string, claims *appauth.Claims, extra map[string]any) {
	body := map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": int(time.Until(claims.ExpiresAt.Time).Seconds())}
	for key, value := range extra {
		body[key] = value
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(writer).Encode(body)
}

// issueJWT signs a token for a user who has just authenticated.
func (handler *Handler) issueJWT(request *http.Request, user *db.User, recordLogin bool) (string, *appauth.Claims, error) {
	return handler.signJWT(request, user, true, time.Time{}, recordLogin)
}

// issueReplacementJWT signs a token that keeps an earlier sign-in time. A zero
// authTime yields a token that never counts as a recent sign-in.
func (handler *Handler) issueReplacementJWT(request *http.Request, user *db.User, authTime time.Time, recordLogin bool) (string, *appauth.Claims, error) {
	return handler.signJWT(request, user, false, authTime, recordLogin)
}

func (handler *Handler) signJWT(request *http.Request, user *db.User, fresh bool, authTime time.Time, recordLogin bool) (string, *appauth.Claims, error) {
	if user.TokenVersion < 1 {
		user.TokenVersion = 1
	}
	now := time.Now().UTC()
	if fresh {
		authTime = now
	}
	token, claims, err := handler.jwt.Reissue(user.ID, user.Role, user.TokenVersion, now, authTime)
	if err != nil {
		return "", nil, err
	}
	if recordLogin {
		if err := handler.users.RecordLogin(request.Context(), user.ID, now); err != nil {
			return "", nil, err
		}
	}
	return token, claims, nil
}

func (handler *Handler) jwtCookieName() string {
	if handler.config.SecureCookies {
		return "__Host-objectshare_jwt"
	}
	return "objectshare_jwt"
}

func (handler *Handler) clearJWTCookie(writer http.ResponseWriter) {
	for _, name := range []string{"objectshare_jwt", "__Host-objectshare_jwt"} {
		http.SetCookie(writer, &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: true, Secure: handler.config.SecureCookies || strings.HasPrefix(name, "__Host-"), SameSite: http.SameSiteStrictMode, MaxAge: -1})
	}
}

func (handler *Handler) verifyJWTCSRF(writer http.ResponseWriter, request *http.Request, identity *identity) bool {
	if identity != nil && identity.Transport == transportBearer {
		return true
	}
	provided := request.Header.Get("X-CSRF-Token")
	if provided == "" {
		provided = request.PostFormValue("csrf_token")
	}
	if identity == nil || subtle.ConstantTimeCompare([]byte(provided), []byte(identity.Claims.CSRF)) != 1 {
		http.Error(writer, "Invalid CSRF token.", http.StatusForbidden)
		return false
	}
	return true
}

func (handler *Handler) verifyAuthenticatedMutationCSRF(writer http.ResponseWriter, request *http.Request) bool {
	identity := currentIdentity(request)
	if identity == nil {
		return true
	}
	return handler.verifyJWTCSRF(writer, request, identity)
}

func (handler *Handler) preAuthCSRF(writer http.ResponseWriter, request *http.Request) string {
	return handler.preAuthCSRFWithSecret(writer, request, handler.csrfSecret)
}

func (handler *Handler) preAuthCSRFWithSecret(writer http.ResponseWriter, request *http.Request, secret []byte) string {
	name := handler.preAuthCookieName()
	value := ""
	if cookie, err := request.Cookie(name); err == nil {
		if decoded, decodeErr := base64.RawURLEncoding.DecodeString(cookie.Value); decodeErr == nil && len(decoded) == 32 {
			value = cookie.Value
		}
	}
	if value == "" {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			handler.internalError(writer, request, "generate pre-authentication CSRF token", err)
			return ""
		}
		value = base64.RawURLEncoding.EncodeToString(raw)
		http.SetCookie(writer, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: handler.config.SecureCookies, SameSite: http.SameSiteStrictMode})
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (handler *Handler) verifyPreAuthCSRF(writer http.ResponseWriter, request *http.Request) bool {
	return handler.verifyPreAuthCSRFWithSecret(writer, request, handler.csrfSecret)
}

func (handler *Handler) verifyPreAuthCSRFWithSecret(writer http.ResponseWriter, request *http.Request, secret []byte) bool {
	cookie, err := request.Cookie(handler.preAuthCookieName())
	if err != nil {
		http.Error(writer, "Invalid CSRF token.", http.StatusForbidden)
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || len(decoded) != 32 {
		http.Error(writer, "Invalid CSRF token.", http.StatusForbidden)
		return false
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(cookie.Value))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(request.PostFormValue("csrf_token")), []byte(want)) != 1 {
		http.Error(writer, "Invalid CSRF token.", http.StatusForbidden)
		return false
	}
	return true
}

func (handler *Handler) preAuthCookieName() string {
	if handler.config.SecureCookies {
		return "__Host-objectshare_preauth"
	}
	return "objectshare_preauth"
}

func (handler *Handler) loginThrottleKey(request *http.Request, email string) string {
	// clientNetwork honours the trusted-proxy list, so clients behind Cloudflare
	// or a reverse proxy are throttled individually instead of sharing the proxy
	// IP, and buckets IPv6 by /64 so address rotation does not reset the lockout.
	return appauth.TokenHash(strings.ToLower(strings.TrimSpace(email)) + "|" + handler.clientNetwork(request))
}

// loginAccountThrottleKey counts password attempts against one account from
// every client, capping guesses spread across many networks.
func loginAccountThrottleKey(email string) string {
	return appauth.TokenHash("login-account|" + strings.ToLower(strings.TrimSpace(email)))
}

// loginDestinations is the single allow-list of pages a login may return to.
// key is the `next` query value, path the page it maps to.
var loginDestinations = []struct{ key, path string }{
	{loginDestinationAdminUsers, "/admin/users"},
	{loginDestinationAdminSettings, "/admin/settings"},
	{"files", "/files"},
	{"billing", "/billing"},
	{"plans", "/plans"},
	{"invoices", "/invoices"},
	{"admin", "/admin"},
	{"admin-invoices", "/admin/invoices"},
	{"admin-plans", "/admin/plans"},
}

func safeLoginDestination(value string) string {
	for _, destination := range loginDestinations {
		if value == destination.key {
			return destination.key
		}
	}
	return ""
}

func (handler *Handler) redirectToLogin(writer http.ResponseWriter, request *http.Request) {
	for _, destination := range loginDestinations {
		if request.URL.Path == destination.path {
			handler.redirect(writer, request, "/login?next="+destination.key)
			return
		}
	}
	handler.redirect(writer, request, "/login")
}

func (handler *Handler) redirectAfterLogin(writer http.ResponseWriter, request *http.Request, destination string) {
	for _, candidate := range loginDestinations {
		if destination == candidate.key {
			handler.redirect(writer, request, candidate.path)
			return
		}
	}
	handler.redirect(writer, request, "/account")
}

// verifyCurrentPassword re-checks a signed-in user's password for a sensitive
// account change. Attempts share the login lockout, keyed per account, so a
// hijacked session cannot be used to guess the password without limit. It
// reports whether the password matched and, when the account is locked out, the
// time it may try again.
func (handler *Handler) verifyCurrentPassword(request *http.Request, user *db.User, password string) (ok bool, lockedUntil time.Time, err error) {
	key := appauth.TokenHash("account-password|" + user.ID)
	allowed, retryAt, err := handler.users.ReserveLoginAttempt(request.Context(), key, time.Now().UTC())
	if err != nil {
		return false, time.Time{}, err
	}
	if !allowed {
		return false, retryAt, nil
	}
	if user.PasswordHash == "" || !appauth.VerifyPassword(password, user.PasswordHash) {
		return false, time.Time{}, nil
	}
	if err := handler.users.ClearLoginFailures(request.Context(), key); err != nil {
		handler.logger.Error("clear password verification failures", "error", err)
	}
	return true, time.Time{}, nil
}

// recentAuthWindow is how long after signing in a session may still change its
// login methods (linked providers, MFA enrolment for passwordless accounts).
const recentAuthWindow = 5 * time.Minute

// recentlyAuthenticated reports whether the user behind identity proved a login
// factor recently. It uses the auth_time claim, which only a real sign-in sets
// and every re-issued token carries forward, so refreshing a token (iat) never
// turns an old session into a recent one. Tokens without auth_time are not
// recent.
func recentlyAuthenticated(identity *identity) bool {
	return identity != nil && identity.Claims != nil && identity.Claims.AuthTime != nil &&
		time.Since(identity.Claims.AuthTime.Time) < recentAuthWindow
}

// identityAuthTime is the sign-in time a replacement for identity's JWT keeps,
// or zero when the JWT has none.
func identityAuthTime(identity *identity) time.Time {
	if identity == nil || identity.Claims == nil || identity.Claims.AuthTime == nil {
		return time.Time{}
	}
	return identity.Claims.AuthTime.Time
}
