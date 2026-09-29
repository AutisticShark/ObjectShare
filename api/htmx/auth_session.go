package htmx

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/db"
)

func (handler *Handler) startJWT(writer http.ResponseWriter, request *http.Request, user *db.User, recordLogin bool) error {
	token, _, err := handler.issueJWT(request, user, recordLogin)
	if err != nil {
		return err
	}
	http.SetCookie(writer, &http.Cookie{Name: handler.jwtCookieName(), Value: token, Path: "/", HttpOnly: true, Secure: handler.config.SecureCookies, SameSite: http.SameSiteStrictMode})
	return nil
}

func (handler *Handler) issueJWT(request *http.Request, user *db.User, recordLogin bool) (string, *appauth.Claims, error) {
	if user.TokenVersion < 1 {
		user.TokenVersion = 1
	}
	now := time.Now().UTC()
	token, claims, err := handler.jwt.Issue(user.ID, user.Role, user.TokenVersion, now)
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
		provided = request.FormValue("csrf_token")
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
	if subtle.ConstantTimeCompare([]byte(request.FormValue("csrf_token")), []byte(want)) != 1 {
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
	// clientIP honours the trusted-proxy list, so clients behind Cloudflare or a
	// reverse proxy are throttled individually instead of sharing the proxy IP.
	return appauth.TokenHash(strings.ToLower(strings.TrimSpace(email)) + "|" + handler.clientIP(request))
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
