package htmx

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/AutisticShark/ObjectShare/email"
	"github.com/google/uuid"
)

func (handler *Handler) verificationSettings() config.EmailVerificationConfig {
	if handler.config.Auth == nil {
		return config.EmailVerificationConfig{}
	}
	return handler.config.Auth.EmailVerification
}

func (handler *Handler) verificationEnabled() bool {
	return handler.emailSender != nil && handler.verificationSettings().PublicURL != "" && handler.config.Email != nil && handler.config.Email.Provider != "none" && handler.config.Email.Provider != ""
}

var errVerificationCooldown = errors.New("verification email cooldown")

func (handler *Handler) sendVerification(ctx context.Context, user *db.User) error {
	if user.EmailVerifiedAt != nil {
		return nil
	}
	if !handler.verificationEnabled() {
		return email.ErrDisabled
	}
	repo, ok := handler.users.(db.EmailVerificationRepository)
	if !ok {
		return errors.New("email verification storage unavailable")
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(random)
	now := time.Now().UTC()
	reserved, err := repo.ReserveEmailVerification(ctx, user.ID, user.Email, appauth.TokenHash(token), now, now.Add(24*time.Hour))
	if err != nil {
		return err
	}
	if !reserved {
		return errVerificationCooldown
	}
	link := handler.verificationSettings().PublicURL + "/verify-email?" + url.Values{"user": {user.ID}, "token": {token}}.Encode()
	return handler.emailSender.Send(ctx, email.Message{To: user.Email, Subject: "Verify your email address",
		Text: "Confirm your email address for " + handler.config.Branding.Display().SiteName + " by opening this link and selecting Verify email:\n\n" + link + "\n\nThis link expires in 24 hours and can be used once. If you did not request this, you can ignore this email."})
}

func (handler *Handler) verificationDeliveryMessage(ctx context.Context, user *db.User) string {
	err := handler.sendVerification(ctx, user)
	switch {
	case err == nil:
		return "verification-sent"
	case errors.Is(err, email.ErrDisabled):
		return "verification-disabled"
	case errors.Is(err, errVerificationCooldown):
		return "verification-wait"
	default:
		// Never log provider errors or the verification URL/token.
		handler.logger.Warn("verification email could not be confirmed", "user_id", user.ID)
		return "verification-failed"
	}
}

func (handler *Handler) ResendVerification(writer http.ResponseWriter, request *http.Request) {
	if !handler.parseAuthForm(writer, request) || !handler.verifyAuthenticatedMutationCSRF(writer, request) {
		return
	}
	user := identityUser(request)
	if user == nil {
		http.Error(writer, "Log in to request a verification email.", http.StatusUnauthorized)
		return
	}
	if user.EmailVerifiedAt != nil {
		handler.redirect(writer, request, "/account?message=email-verified")
		return
	}
	if !handler.allowRequest(writer, request, "email-verification", 5) {
		return
	}
	handler.redirect(writer, request, "/account?message="+handler.verificationDeliveryMessage(request.Context(), user))
}

type verificationPageData struct {
	Version, CSRF, Token, UserID, Error string
	Success                             bool
	User                                *db.User
}

func (handler *Handler) verificationCSRFSecret() []byte {
	// A purpose-specific shared key lets a form render and submit on different
	// replicas, without changing the existing login or signup CSRF lifecycle.
	mac := hmac.New(sha256.New, []byte(handler.config.Auth.JWTSecret))
	_, _ = mac.Write([]byte("objectshare-email-verification-csrf-v1"))
	return mac.Sum(nil)
}

// GET only renders a confirmation form so mail scanners cannot consume a link.
func (handler *Handler) VerifyEmailPage(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	csrf := handler.preAuthCSRFWithSecret(writer, request, handler.verificationCSRFSecret())
	if csrf == "" {
		return
	}
	data := verificationPageData{Version: config.GetVersion(), CSRF: csrf, User: identityUser(request)}
	id, token := request.URL.Query().Get("user"), request.URL.Query().Get("token")
	if validVerificationInput(id, token) {
		data.UserID, data.Token = id, token
	} else {
		data.Error = "This verification link is invalid. Request a new email from My account."
	}
	handler.render(writer, "verify_email.html", data)
}

func validVerificationInput(id, token string) bool {
	if len(id) != 36 || len(token) != 43 {
		return false
	}
	parsed, err := uuid.Parse(id)
	decoded, tokenErr := base64.RawURLEncoding.DecodeString(token)
	return err == nil && parsed.String() == id && tokenErr == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == token
}

func (handler *Handler) VerifyEmail(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	if !handler.parseAuthForm(writer, request) || !handler.verifyPreAuthCSRFWithSecret(writer, request, handler.verificationCSRFSecret()) {
		return
	}
	if !handler.allowRequest(writer, request, "email-verify", 20) {
		return
	}
	id, token := request.FormValue("user"), request.FormValue("token")
	data := verificationPageData{Version: config.GetVersion(), User: identityUser(request), Error: "This verification link is invalid, expired, or already used. Request a new email from My account."}
	if validVerificationInput(id, token) {
		repo, ok := handler.users.(db.EmailVerificationRepository)
		if !ok {
			http.Error(writer, "Email verification storage is unavailable.", http.StatusServiceUnavailable)
			return
		}
		verified, err := repo.VerifyEmail(request.Context(), id, appauth.TokenHash(token), time.Now().UTC())
		if err != nil {
			handler.internalError(writer, request, "verify account email", err)
			return
		}
		if verified {
			data.Error, data.Success = "", true
		}
	}
	if !data.Success {
		writer.WriteHeader(http.StatusBadRequest)
	}
	handler.render(writer, "verify_email.html", data)
}

func (handler *Handler) purchaseAllowed(writer http.ResponseWriter, request *http.Request) bool {
	if handler.verificationSettings().RequireForPurchases {
		user := identityUser(request)
		if user == nil || user.EmailVerifiedAt == nil {
			http.Error(writer, "Verify your email from My account before purchasing a plan.", http.StatusForbidden)
			return false
		}
	}
	return true
}

func (handler *Handler) directUploadVerificationAllowed(writer http.ResponseWriter, request *http.Request, file *db.FileList) bool {
	// Intents can be finalized using the owner token without the original JWT.
	// Recheck the persisted owner, not just the current browser identity.
	if file.FileOwner == nil {
		return handler.uploadAllowed(writer, request)
	}
	if !handler.verificationSettings().RequireForUploads {
		return true
	}
	user, err := handler.users.UserByID(request.Context(), *file.FileOwner)
	if errors.Is(err, db.ErrNotFound) || (err == nil && (!user.Active || user.EmailVerifiedAt == nil)) {
		http.Error(writer, "The upload owner must verify their email before completing this upload.", http.StatusForbidden)
		return false
	}
	if err != nil {
		handler.internalError(writer, request, "check upload owner verification", err)
		return false
	}
	return true
}
