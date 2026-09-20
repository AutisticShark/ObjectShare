package htmx

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/AutisticShark/ObjectShare/email"
)

type mfaPageData struct {
	Version, CSRF, Action, Method, Secret, Error, Message string
	User                                                  *db.User
	Codes                                                 []string
	EmailAvailable                                        bool
}

var errMFAInvalid = errors.New("invalid or expired MFA challenge")
var errMFACooldown = errors.New("Wait one minute before starting another verification. After five failed codes, wait 15 minutes.")

func (handler *Handler) mfaRepository() db.MFARepository {
	repo, _ := handler.users.(db.MFARepository)
	return repo
}

func (handler *Handler) mfaEmailAvailable() bool {
	return handler.emailSender != nil && handler.config.Email != nil && handler.config.Email.Provider != "" && handler.config.Email.Provider != "none"
}

func (handler *Handler) renderMFA(writer http.ResponseWriter, data mfaPageData) {
	writer.Header().Set("Cache-Control", "private, no-store")
	writer.Header().Set("Pragma", "no-cache")
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	data.Version = config.GetVersion()
	handler.render(writer, "mfa.html", data)
}

func (handler *Handler) MFASettings(writer http.ResponseWriter, request *http.Request) {
	id := currentIdentity(request)
	handler.renderMFA(writer, mfaPageData{User: id.User, CSRF: id.Claims.CSRF, EmailAvailable: handler.mfaEmailAvailable()})
}

// BeginMFAChange requires an authenticated account and CSRF protection. Initial
// enrollment reauthenticates a password, or requires a recent OAuth-only login.
// Disabling or replacing recovery codes always proves the existing factor.
func (handler *Handler) BeginMFAChange(writer http.ResponseWriter, request *http.Request) {
	id := currentIdentity(request)
	if !handler.parseAuthForm(writer, request) || !handler.verifyJWTCSRF(writer, request, id) {
		return
	}
	if !handler.allowRequest(writer, request, "mfa-manage", 10) {
		return
	}
	action := request.FormValue("action")
	if action != "setup-totp" && action != "setup-email" && action != "disable" && action != "recovery" {
		http.Error(writer, "Invalid MFA action.", http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(action, "setup-") {
		valid := id.User.PasswordHash != "" && appauth.VerifyPassword(request.FormValue("current_password"), id.User.PasswordHash)
		if id.User.PasswordHash == "" {
			valid = id.Claims.IssuedAt != nil && time.Since(id.Claims.IssuedAt.Time) < 5*time.Minute
		}
		if !valid {
			handler.renderMFA(writer, mfaPageData{User: id.User, CSRF: id.Claims.CSRF, EmailAvailable: handler.mfaEmailAvailable(), Error: "Confirm your current password. For an OAuth-only account, sign out and sign in again, then enroll within five minutes."})
			return
		}
	}
	handler.beginMFA(writer, request, id.User, action, "", transportCookie)
}

func (handler *Handler) beginMFA(writer http.ResponseWriter, request *http.Request, user *db.User, action, next, transport string) {
	writer.Header().Set("Cache-Control", "no-store")
	repo := handler.mfaRepository()
	if repo == nil {
		http.Error(writer, "MFA storage is unavailable.", http.StatusServiceUnavailable)
		return
	}
	now := time.Now().UTC()
	token, claims, err := handler.jwt.IssueMFA(user.ID, user.Role, user.TokenVersion, action, safeLoginDestination(next), transport, now)
	if err != nil {
		handler.internalError(writer, request, "create MFA JWT", err)
		return
	}
	var secret, sealed, code, method string
	var retryAt time.Time
	if action == "setup-totp" {
		secret, err = appauth.NewTOTPSecret()
		if err == nil {
			sealed, err = appauth.SealMFASecret(handler.settingsKey, user.ID, secret)
		}
		if err != nil {
			handler.internalError(writer, request, "create MFA secret", err)
			return
		}
	}
	code, err = appauth.NewEmailOTP()
	if err != nil {
		handler.internalError(writer, request, "create MFA code", err)
		return
	}
	updated, err := repo.MutateMFA(request.Context(), user.ID, user.TokenVersion, func(current *db.User) error {
		now := time.Now().UTC()
		if !now.Before(claims.ExpiresAt.Time) {
			return errMFAInvalid
		}
		state := &current.MFA
		if now.Before(state.LockedUntil) {
			retryAt = state.LockedUntil
			return errMFACooldown
		}
		if now.Before(state.SentAt.Add(time.Minute)) {
			retryAt = state.SentAt.Add(time.Minute)
			return errMFACooldown
		}
		method = state.Method
		if strings.HasPrefix(action, "setup-") {
			if method != "" {
				return errMFAInvalid
			}
			method = strings.TrimPrefix(action, "setup-")
		} else if method != "email" && method != "totp" {
			return errMFAInvalid
		}
		if method == "email" && action == "setup-email" && (!handler.mfaEmailAvailable() || current.EmailVerifiedAt == nil) {
			return errors.New("Email MFA needs a verified address and configured email delivery.")
		}
		state.Challenge, state.Action = appauth.TokenHash(claims.ID), action
		state.PendingMethod, state.PendingSecret = method, sealed
		state.Email, state.EmailHash = current.Email, ""
		state.Expires, state.SentAt = claims.ExpiresAt.Time, now
		// Starting a new challenge does not reset failed attempts. Only a
		// successful proof or the end of a lockout resets the account budget.
		if !state.LockedUntil.IsZero() {
			state.Failures = 0
			state.LockedUntil = time.Time{}
		}
		state.AuthHash = ""
		if action != "login" {
			state.AuthHash = appauth.TokenHash(currentIdentity(request).Claims.ID)
		}
		if method == "email" {
			state.EmailHash = appauth.MFAHash(handler.settingsKey, current.ID+":"+state.Challenge, code)
		}
		return nil
	})
	if err != nil {
		status := http.StatusBadRequest
		message := "Could not start verification. Reload account settings or sign in again."
		if errors.Is(err, errMFACooldown) {
			status = http.StatusTooManyRequests
			message = errMFACooldown.Error()
			writer.Header().Set("Retry-After", strconv.Itoa(max(1, int(time.Until(retryAt).Seconds())+1)))
		}
		if action == "setup-email" && !errors.Is(err, errMFACooldown) {
			message = "Email MFA needs a verified address, configured email delivery, and no existing MFA method."
		}
		if transport == transportCookie {
			data := mfaPageData{Error: message}
			if id := currentIdentity(request); action != "login" && id != nil {
				data.User, data.CSRF, data.EmailAvailable = id.User, id.Claims.CSRF, handler.mfaEmailAvailable()
			}
			handler.renderMFA(writer, data)
			return
		}
		http.Error(writer, message, status)
		return
	}
	message := ""
	if method == "email" {
		message = handler.sendMFACode(request, updated.Email, code)
	}
	if transport == transportBearer {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(writer).Encode(map[string]any{"mfa_required": true, "challenge_token": token, "method": method, "expires_in": 300, "message": message})
		return
	}
	http.SetCookie(writer, &http.Cookie{Name: handler.mfaCookieName(), Value: token, Path: "/", HttpOnly: true, Secure: handler.config.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: 300})
	if action == "login" {
		handler.clearJWTCookie(writer)
	}
	handler.renderMFA(writer, mfaPageData{Action: action, Method: method, Secret: secret, CSRF: claims.CSRF, Message: message})
}

func (handler *Handler) sendMFACode(request *http.Request, address, code string) string {
	if handler.mfaEmailAvailable() {
		err := handler.emailSender.Send(request.Context(), email.Message{To: address, Subject: "ObjectShare verification code", Text: "Your ObjectShare verification code is: " + code + "\n\nIt expires when this verification ends (within five minutes). Do not share this code. If you did not request it, ignore this email."})
		if err == nil {
			return "A verification code was sent to your verified email address."
		}
	}
	return "The email provider could not confirm delivery. Check your inbox, wait one minute before resending, or use a recovery code for an existing MFA method."
}

func (handler *Handler) mfaCookieName() string {
	if handler.config.SecureCookies {
		return "__Host-objectshare_mfa"
	}
	return "objectshare_mfa"
}

func (handler *Handler) readMFA(request *http.Request) (*appauth.Claims, error) {
	cookie, err := request.Cookie(handler.mfaCookieName())
	if err != nil {
		return nil, err
	}
	claims, err := handler.jwt.ParseMFA(cookie.Value)
	if err == nil && claims.Transport != transportCookie {
		err = errMFAInvalid
	}
	return claims, err
}

func validMFAState(user *db.User, claims *appauth.Claims, now time.Time) bool {
	s := &user.MFA
	return user.CanAuthenticate() && user.TokenVersion == claims.TokenVersion && s.Challenge == appauth.TokenHash(claims.ID) && s.Action == claims.Action && now.Before(s.Expires) && now.Before(claims.ExpiresAt.Time) && !now.Before(s.LockedUntil) && user.Email == s.Email
}

func (handler *Handler) MFAChallenge(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "private, no-store")
	claims, err := handler.readMFA(request)
	if err != nil {
		http.Error(writer, "Sign in again to start verification.", http.StatusUnauthorized)
		return
	}
	user, err := handler.users.UserByID(request.Context(), claims.Subject)
	if err != nil || !validMFAState(user, claims, time.Now()) {
		http.Error(writer, "Verification expired. Sign in again.", http.StatusUnauthorized)
		return
	}
	// Setup keys are shown only in the initial authenticated POST response.
	handler.renderMFA(writer, mfaPageData{Action: claims.Action, Method: user.MFA.PendingMethod, CSRF: claims.CSRF})
}

func (handler *Handler) VerifyMFA(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "private, no-store")
	if !handler.parseAuthForm(writer, request) {
		return
	}
	claims, err := handler.readMFA(request)
	if err != nil || subtle.ConstantTimeCompare([]byte(claims.CSRF), []byte(request.FormValue("csrf_token"))) != 1 {
		http.Error(writer, "Invalid verification request.", http.StatusForbidden)
		return
	}
	handler.completeMFA(writer, request, claims, request.FormValue("code"))
}

func (handler *Handler) completeMFA(writer http.ResponseWriter, request *http.Request, claims *appauth.Claims, code string) {
	writer.Header().Set("Cache-Control", "no-store")
	if !handler.allowRequest(writer, request, "mfa-verify", 10) {
		return
	}
	repo := handler.mfaRepository()
	if repo == nil {
		http.Error(writer, "MFA storage is unavailable.", http.StatusServiceUnavailable)
		return
	}
	code = strings.TrimSpace(code)
	var success bool
	var codes []string
	var method string
	user, err := repo.MutateMFA(request.Context(), claims.Subject, claims.TokenVersion, func(user *db.User) error {
		now := time.Now().UTC()
		if !validMFAState(user, claims, now) {
			return errMFAInvalid
		}
		s := &user.MFA
		if claims.Action != "login" {
			id := currentIdentity(request)
			if id == nil || id.User.ID != user.ID || appauth.TokenHash(id.Claims.ID) != s.AuthHash {
				return errMFAInvalid
			}
		}
		method = s.PendingMethod
		setup := strings.HasPrefix(claims.Action, "setup-")
		// Recovery codes cannot confirm a new factor.
		if !setup {
			hash := appauth.MFAHash(handler.settingsKey, user.ID+":recovery", code)
			for i, saved := range s.Recovery {
				if subtle.ConstantTimeCompare([]byte(hash), []byte(saved)) == 1 {
					s.Recovery = append(s.Recovery[:i:i], s.Recovery[i+1:]...)
					success = true
					break
				}
			}
		}
		if !success && method == "email" && s.EmailHash != "" {
			hash := appauth.MFAHash(handler.settingsKey, user.ID+":"+s.Challenge, code)
			success = subtle.ConstantTimeCompare([]byte(hash), []byte(s.EmailHash)) == 1
		}
		if !success && method == "totp" {
			sealed, last := s.Secret, s.LastStep
			if setup {
				sealed, last = s.PendingSecret, 0
			}
			secret, openErr := appauth.OpenMFASecret(handler.settingsKey, user.ID, sealed)
			if openErr != nil {
				return openErr
			}
			if step, ok := appauth.VerifyTOTP(secret, code, now, last); ok {
				s.LastStep, success = step, true
			}
		}
		if !success {
			s.Failures++
			if s.Failures >= 5 {
				s.LockedUntil = now.Add(15 * time.Minute)
				s.Challenge = ""
			}
			return nil
		}
		if setup || claims.Action == "recovery" {
			var genErr error
			codes, genErr = appauth.NewRecoveryCodes()
			if genErr != nil {
				return genErr
			}
			s.Recovery = nil
			for _, value := range codes {
				s.Recovery = append(s.Recovery, appauth.MFAHash(handler.settingsKey, user.ID+":recovery", value))
			}
		}
		if setup {
			s.Method, s.Secret = method, s.PendingSecret
		}
		if claims.Action == "disable" {
			*s = db.MFAState{}
		}
		if claims.Action != "login" {
			user.TokenVersion++
		}
		s.Challenge, s.EmailHash, s.PendingSecret, s.AuthHash = "", "", "", ""
		s.Failures, s.LockedUntil = 0, time.Time{}
		return nil
	})
	if err != nil || !success {
		if claims.Transport == transportBearer {
			http.Error(writer, "Invalid, expired, or already used code or challenge.", http.StatusUnauthorized)
			return
		}
		handler.renderMFA(writer, mfaPageData{Action: claims.Action, Method: method, CSRF: claims.CSRF, Error: "Invalid, expired, or already used code. After five failures, wait 15 minutes and sign in again. Authenticator codes change every 30 seconds."})
		return
	}
	if claims.Transport == transportBearer {
		token, issued, issueErr := handler.issueJWT(request, user, true)
		if issueErr != nil {
			handler.internalError(writer, request, "issue MFA API JWT", issueErr)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": int(time.Until(issued.ExpiresAt.Time).Seconds())})
		return
	}
	http.SetCookie(writer, &http.Cookie{Name: handler.mfaCookieName(), Path: "/", MaxAge: -1, HttpOnly: true, Secure: handler.config.SecureCookies, SameSite: http.SameSiteStrictMode})
	if err := handler.startJWT(writer, request, user, claims.Action == "login"); err != nil {
		handler.internalError(writer, request, "issue MFA JWT", err)
		return
	}
	if len(codes) > 0 {
		handler.renderMFA(writer, mfaPageData{Codes: codes, Message: "MFA is enabled. Save these recovery codes now. Each works once; they will not be shown again."})
		return
	}
	if claims.Action == "login" {
		handler.redirectAfterLogin(writer, request, claims.Next)
		return
	}
	handler.redirect(writer, request, "/account/mfa")
}

func (handler *Handler) ResendMFA(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "private, no-store")
	if !handler.parseAuthForm(writer, request) {
		return
	}
	claims, err := handler.readMFA(request)
	if err != nil || subtle.ConstantTimeCompare([]byte(claims.CSRF), []byte(request.FormValue("csrf_token"))) != 1 {
		http.Error(writer, "Invalid verification request.", http.StatusForbidden)
		return
	}
	handler.resendMFA(writer, request, claims)
}

func (handler *Handler) resendMFA(writer http.ResponseWriter, request *http.Request, claims *appauth.Claims) {
	writer.Header().Set("Cache-Control", "no-store")
	if !handler.allowRequest(writer, request, "mfa-send", 5) {
		return
	}
	repo := handler.mfaRepository()
	if repo == nil {
		http.Error(writer, "MFA storage is unavailable.", http.StatusServiceUnavailable)
		return
	}
	code, err := appauth.NewEmailOTP()
	if err != nil {
		handler.internalError(writer, request, "generate MFA email", err)
		return
	}
	user, err := repo.MutateMFA(request.Context(), claims.Subject, claims.TokenVersion, func(user *db.User) error {
		now := time.Now().UTC()
		if !validMFAState(user, claims, now) || user.MFA.PendingMethod != "email" {
			return errMFAInvalid
		}
		if now.Before(user.MFA.SentAt.Add(time.Minute)) {
			return errMFACooldown
		}
		user.MFA.SentAt = now
		user.MFA.EmailHash = appauth.MFAHash(handler.settingsKey, user.ID+":"+user.MFA.Challenge, code)
		return nil
	})
	if err != nil {
		writer.Header().Set("Retry-After", "60")
		message := "Wait one minute between sends. Expired challenges require a new sign-in."
		if claims.Transport == transportCookie {
			handler.renderMFA(writer, mfaPageData{Action: claims.Action, Method: "email", CSRF: claims.CSRF, Error: message})
			return
		}
		http.Error(writer, message, http.StatusTooManyRequests)
		return
	}
	message := handler.sendMFACode(request, user.Email, code)
	if claims.Transport == transportBearer {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]string{"message": message})
		return
	}
	handler.renderMFA(writer, mfaPageData{Action: claims.Action, Method: "email", CSRF: claims.CSRF, Message: message})
}

func (handler *Handler) apiMFAInput(writer http.ResponseWriter, request *http.Request) (*appauth.Claims, string, bool) {
	writer.Header().Set("Cache-Control", "no-store")
	request.Body = http.MaxBytesReader(writer, request.Body, 8192)
	var input struct {
		Challenge string `json:"challenge_token"`
		Code      string `json:"code"`
	}
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		http.Error(writer, "Invalid MFA JSON.", http.StatusBadRequest)
		return nil, "", false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		http.Error(writer, "Invalid MFA JSON.", http.StatusBadRequest)
		return nil, "", false
	}
	claims, err := handler.jwt.ParseMFA(input.Challenge)
	if err != nil || claims.Transport != transportBearer || claims.Action != "login" {
		http.Error(writer, "Invalid MFA challenge.", http.StatusUnauthorized)
		return nil, "", false
	}
	return claims, input.Code, true
}

func (handler *Handler) APIVerifyMFA(writer http.ResponseWriter, request *http.Request) {
	if claims, code, ok := handler.apiMFAInput(writer, request); ok {
		handler.completeMFA(writer, request, claims, code)
	}
}

func (handler *Handler) APIResendMFA(writer http.ResponseWriter, request *http.Request) {
	if claims, _, ok := handler.apiMFAInput(writer, request); ok {
		handler.resendMFA(writer, request, claims)
	}
}
