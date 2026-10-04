package htmx

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
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
// Disabling or replacing recovery codes requires a recent sign-in to start and
// always proves the existing factor to complete.
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
		var valid bool
		if id.User.PasswordHash == "" {
			valid = recentlyAuthenticated(id)
		} else {
			ok, lockedUntil, err := handler.verifyCurrentPassword(request, id.User, request.FormValue("current_password"))
			if err != nil {
				handler.internalError(writer, request, "verify current password for MFA setup", err)
				return
			}
			if !lockedUntil.IsZero() {
				writer.Header().Set("Retry-After", fmt.Sprint(max(1, int(time.Until(lockedUntil).Seconds()))))
				http.Error(writer, "Too many incorrect password attempts. Try again later.", http.StatusTooManyRequests)
				return
			}
			valid = ok
		}
		if !valid {
			handler.renderMFA(writer, mfaPageData{User: id.User, CSRF: id.Claims.CSRF, EmailAvailable: handler.mfaEmailAvailable(), Error: "Confirm your current password. For an OAuth-only account, sign out and sign in again, then enroll within five minutes."})
			return
		}
	} else if !recentlyAuthenticated(id) {
		handler.renderMFA(writer, mfaPageData{User: id.User, CSRF: id.Claims.CSRF, EmailAvailable: handler.mfaEmailAvailable(), Error: "To disable MFA or replace recovery codes, sign out and sign in again, then try within five minutes."})
		return
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
		slot := state.ChallengeSlot(action)
		if now.Before(slot.LockedUntil) {
			retryAt = slot.LockedUntil
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
		// The one-minute cooldown limits how often codes are emailed. An
		// authenticator challenge sends nothing, so it may restart at once.
		if method == "email" && now.Before(slot.SentAt.Add(time.Minute)) {
			retryAt = slot.SentAt.Add(time.Minute)
			return errMFACooldown
		}
		slot.Challenge, slot.Action = appauth.TokenHash(claims.ID), action
		slot.PendingMethod, slot.PendingSecret = method, sealed
		slot.Email, slot.EmailHash = current.Email, ""
		slot.Expires = claims.ExpiresAt.Time
		if method == "email" {
			slot.SentAt = now
		}
		// Starting a new challenge does not reset failed attempts. Only a
		// successful proof or the end of a lockout resets the slot's budget.
		if !slot.LockedUntil.IsZero() {
			slot.Failures = 0
			slot.LockedUntil = time.Time{}
		}
		slot.AuthHash = ""
		if action != "login" {
			slot.AuthHash = appauth.TokenHash(currentIdentity(request).Claims.ID)
		}
		if method == "email" {
			slot.EmailHash = appauth.MFAHash(handler.settingsKey, current.ID+":"+slot.Challenge, code)
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
		handler.logger.Warn("send MFA email code failed", "error", err)
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
	s := user.MFA.ChallengeSlot(claims.Action)
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
	handler.renderMFA(writer, mfaPageData{Action: claims.Action, Method: user.MFA.ChallengeSlot(claims.Action).PendingMethod, CSRF: claims.CSRF})
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
		state := &user.MFA
		s := state.ChallengeSlot(claims.Action)
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
			for i, saved := range state.Recovery {
				if subtle.ConstantTimeCompare([]byte(hash), []byte(saved)) == 1 {
					state.Recovery = append(state.Recovery[:i:i], state.Recovery[i+1:]...)
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
			sealed, last := state.Secret, state.LastStep
			if setup {
				sealed, last = s.PendingSecret, 0
			}
			secret, openErr := appauth.OpenMFASecret(handler.settingsKey, user.ID, sealed)
			if openErr != nil {
				return openErr
			}
			if step, ok := appauth.VerifyTOTP(secret, code, now, last); ok {
				state.LastStep, success = step, true
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
			state.Recovery = nil
			for _, value := range codes {
				state.Recovery = append(state.Recovery, appauth.MFAHash(handler.settingsKey, user.ID+":recovery", value))
			}
		}
		if setup {
			state.Method, state.Secret = method, s.PendingSecret
		}
		if claims.Action == "disable" {
			*state = db.MFAState{}
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
		writeAccessToken(writer, token, issued, nil)
		return
	}
	http.SetCookie(writer, &http.Cookie{Name: handler.mfaCookieName(), Path: "/", MaxAge: -1, HttpOnly: true, Secure: handler.config.SecureCookies, SameSite: http.SameSiteStrictMode})
	// A management change bumped the token version. A bearer-authenticated
	// account gets its replacement JWT (and any new recovery codes) as JSON.
	if id := currentIdentity(request); claims.Action != "login" && id != nil && id.Transport == transportBearer {
		token, issued, issueErr := handler.issueReplacementJWT(request, user, identityAuthTime(id), false)
		if issueErr != nil {
			handler.internalError(writer, request, "issue MFA API JWT", issueErr)
			return
		}
		var extra map[string]any
		if len(codes) > 0 {
			extra = map[string]any{"recovery_codes": codes}
		}
		writeAccessToken(writer, token, issued, extra)
		return
	}
	if claims.Action == "login" {
		err = handler.startJWT(writer, request, user, true)
	} else {
		// Managing MFA re-issues the session JWT; it is not a new sign-in.
		err = handler.replaceJWT(writer, request, user, identityAuthTime(currentIdentity(request)), false)
	}
	if err != nil {
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
		slot := user.MFA.ChallengeSlot(claims.Action)
		if !validMFAState(user, claims, now) || slot.PendingMethod != "email" {
			return errMFAInvalid
		}
		if now.Before(slot.SentAt.Add(time.Minute)) {
			return errMFACooldown
		}
		slot.SentAt = now
		slot.EmailHash = appauth.MFAHash(handler.settingsKey, user.ID+":"+slot.Challenge, code)
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
