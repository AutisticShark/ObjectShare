package htmx

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type identityContextKey struct{}

type identity struct {
	User      *db.User
	Claims    *appauth.Claims
	RawToken  string
	Transport string
}

const (
	transportCookie = "cookie"
	transportBearer = "bearer"

	loginDestinationAdminUsers    = "admin-users"
	loginDestinationAdminSettings = "admin-settings"
)

type authPageData struct {
	Version, CSRF, Error, Email, DisplayName, Next string
	SignupEnabled, Setup                           bool
	OAuthProviders                                 []oauthButton
	Captcha                                        *captchaWidget
}

type accountFile struct {
	ID, Name, Size, CreatedAt string
}

type accountPageData struct {
	Version, CSRF, Error, Message, QuotaLabel, CreditBalance, CreditCurrency string
	User                                                                     *db.User
	Files                                                                    []accountFile
	OAuthProviders                                                           []oauthAccountProvider
	CreditTransactions                                                       []creditTransactionRow
	TopUpGateways                                                            []billingGatewayOption
	HasPassword                                                              bool
	PlanName, PlanRenews, PlanStatus                                         string
	PlanActive, PlanCanceling, BillingEnabled, BillingAccount, CreditPlan    bool
	MinTopUpCredits, MaxTopUpCredits                                         int64
}

type creditTransactionRow struct {
	Delta, Balance, Description, CreatedAt string
	Positive                               bool
}

type adminUserRow struct {
	ID, Email, DisplayName, Role, CreatedAt, LastLogin, StorageUsed, CreditBalance, CreditRequestID string
	Active, IsCurrent, IsPaid                                                                       bool
	UploadQuotaMiB                                                                                  int64
}

type adminPageData struct {
	Version, CSRF, Error, Message, TotalStorageUsed string
	User                                            *db.User
	Users                                           []adminUserRow
}

var errInvalidAdminForm = errors.New("invalid administrator form")

func (handler *Handler) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if handler.users == nil {
			next.ServeHTTP(writer, request)
			return
		}
		rawToken, transport := handler.authenticationToken(request)
		if rawToken == "" {
			next.ServeHTTP(writer, request)
			return
		}
		claims, err := handler.jwt.Parse(rawToken)
		if err != nil {
			if transport == transportCookie {
				handler.clearJWTCookie(writer)
			}
			next.ServeHTTP(writer, request)
			return
		}
		parsedSubject, err := uuid.Parse(claims.Subject)
		if err != nil || parsedSubject.String() != strings.ToLower(claims.Subject) {
			if transport == transportCookie {
				handler.clearJWTCookie(writer)
			}
			next.ServeHTTP(writer, request)
			return
		}
		user, err := handler.users.UserByID(request.Context(), claims.Subject)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				if transport == transportCookie {
					handler.clearJWTCookie(writer)
				}
				next.ServeHTTP(writer, request)
				return
			}
			handler.internalError(writer, request, "load JWT subject", err)
			return
		}
		now := time.Now().UTC()
		revoked, err := handler.users.TokenRevoked(request.Context(), appauth.TokenHash(claims.ID), now)
		if err != nil {
			handler.internalError(writer, request, "check JWT revocation", err)
			return
		}
		if revoked || !user.Active || user.Role != claims.Role || user.TokenVersion != claims.TokenVersion {
			if transport == transportCookie {
				handler.clearJWTCookie(writer)
			}
			next.ServeHTTP(writer, request)
			return
		}
		ctx := context.WithValue(request.Context(), identityContextKey{}, &identity{User: user, Claims: claims, RawToken: rawToken, Transport: transport})
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func (handler *Handler) authenticationToken(request *http.Request) (string, string) {
	if authorization := strings.TrimSpace(request.Header.Get("Authorization")); authorization != "" {
		parts := strings.Fields(authorization)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return parts[1], transportBearer
		}
		return "", transportBearer
	}
	cookie, err := request.Cookie(handler.jwtCookieName())
	if err != nil {
		return "", ""
	}
	return cookie.Value, transportCookie
}

func (handler *Handler) SetupComplete(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if handler.users == nil {
			next.ServeHTTP(writer, request)
			return
		}
		count, err := handler.users.AdminCount(request.Context())
		if err != nil {
			handler.internalError(writer, request, "check initial setup", err)
			return
		}
		if count == 0 {
			handler.redirect(writer, request, "/setup")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func (handler *Handler) RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if currentIdentity(request) == nil {
			if request.Method == http.MethodGet {
				handler.redirectToLogin(writer, request)
			} else {
				writer.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(writer, "Authentication required.", http.StatusUnauthorized)
			}
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func (handler *Handler) RequireAdmin(next http.Handler) http.Handler {
	return handler.RequireUser(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if currentIdentity(request).User.Role != db.RoleAdmin {
			http.Error(writer, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(writer, request)
	}))
}

func currentIdentity(request *http.Request) *identity {
	value, _ := request.Context().Value(identityContextKey{}).(*identity)
	return value
}

func (handler *Handler) SetupPage(writer http.ResponseWriter, request *http.Request) {
	if !handler.setupAvailable(writer, request) {
		return
	}
	csrf := handler.preAuthCSRF(writer, request)
	if csrf == "" {
		return
	}
	handler.render(writer, "setup.html", authPageData{Version: config.GetVersion(), CSRF: csrf, Setup: true})
}

func (handler *Handler) Setup(writer http.ResponseWriter, request *http.Request) {
	if !handler.setupAvailable(writer, request) || !handler.parseAuthForm(writer, request) || !handler.verifyPreAuthCSRF(writer, request) {
		return
	}
	email, displayName, password, err := validatedRegistration(request)
	if err != nil {
		csrf := handler.preAuthCSRF(writer, request)
		if csrf != "" {
			handler.render(writer, "setup.html", authPageData{Version: config.GetVersion(), CSRF: csrf, Error: err.Error(), Email: request.FormValue("email"), DisplayName: request.FormValue("display_name"), Setup: true})
		}
		return
	}
	hash, err := appauth.HashPassword(password)
	if err != nil {
		handler.internalError(writer, request, "hash setup password", err)
		return
	}
	user := &db.User{ID: uuid.NewString(), Email: email, DisplayName: displayName, PasswordHash: hash, Role: db.RoleAdmin, Active: true, TokenVersion: 1}
	if err := handler.users.BootstrapAdmin(request.Context(), user); err != nil {
		if errors.Is(err, db.ErrAdminExists) {
			handler.redirect(writer, request, "/login")
			return
		}
		if errors.Is(err, db.ErrConflict) {
			csrf := handler.preAuthCSRF(writer, request)
			if csrf != "" {
				handler.render(writer, "setup.html", authPageData{Version: config.GetVersion(), CSRF: csrf, Error: "That email address is already registered.", Email: email, DisplayName: displayName, Setup: true})
			}
			return
		}
		handler.internalError(writer, request, "create initial administrator", err)
		return
	}
	if err := handler.startJWT(writer, request, user, true); err != nil {
		handler.internalError(writer, request, "issue setup JWT", err)
		return
	}
	handler.redirect(writer, request, "/admin/users?message=setup")
}

func (handler *Handler) LoginPage(writer http.ResponseWriter, request *http.Request) {
	if currentIdentity(request) != nil {
		handler.redirect(writer, request, "/account")
		return
	}
	csrf := handler.preAuthCSRF(writer, request)
	if csrf == "" {
		return
	}
	next := safeLoginDestination(request.URL.Query().Get("next"))
	handler.render(writer, "login.html", authPageData{Version: config.GetVersion(), CSRF: csrf, SignupEnabled: handler.config.Auth.SignupEnabled, Next: next, OAuthProviders: handler.oauthLoginButtons(next), Captcha: handler.captchaWidget("login")})
}

func (handler *Handler) Login(writer http.ResponseWriter, request *http.Request) {
	if !handler.allowRequest(writer, request, "login", handler.rateLimitSettings().LoginLimit) {
		return
	}
	if !handler.parseAuthForm(writer, request) || !handler.verifyPreAuthCSRF(writer, request) {
		return
	}
	if !handler.verifyCaptcha(writer, request, "login", "") {
		return
	}
	next := safeLoginDestination(request.FormValue("next"))
	user, locked, retryAt, err := handler.authenticateCredentials(request, request.FormValue("email"), request.FormValue("password"))
	if err != nil {
		handler.internalError(writer, request, "authenticate login", err)
		return
	}
	if locked {
		csrf := handler.preAuthCSRF(writer, request)
		if csrf == "" {
			return
		}
		writer.Header().Set("Retry-After", fmt.Sprint(max(1, int(time.Until(retryAt).Seconds()))))
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		writer.WriteHeader(http.StatusTooManyRequests)
		handler.render(writer, "login.html", authPageData{Version: config.GetVersion(), CSRF: csrf, SignupEnabled: handler.config.Auth.SignupEnabled, Error: "Too many login attempts. Try again in 15 minutes.", Email: request.FormValue("email"), Next: next, OAuthProviders: handler.oauthLoginButtons(next), Captcha: handler.captchaWidget("login")})
		return
	}
	if user == nil {
		csrf := handler.preAuthCSRF(writer, request)
		if csrf != "" {
			handler.render(writer, "login.html", authPageData{Version: config.GetVersion(), CSRF: csrf, SignupEnabled: handler.config.Auth.SignupEnabled, Error: "Email or password is incorrect.", Email: request.FormValue("email"), Next: next, OAuthProviders: handler.oauthLoginButtons(next), Captcha: handler.captchaWidget("login")})
		}
		return
	}
	if err := handler.startJWT(writer, request, user, true); err != nil {
		handler.internalError(writer, request, "issue login JWT", err)
		return
	}
	handler.redirectAfterLogin(writer, request, next)
}

func (handler *Handler) APILogin(writer http.ResponseWriter, request *http.Request) {
	if !handler.allowRequest(writer, request, "login", handler.rateLimitSettings().LoginLimit) {
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 32*1024)
	var input struct {
		Email        string `json:"email"`
		Password     string `json:"password"`
		CaptchaToken string `json:"captcha_token,omitempty"`
	}
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		http.Error(writer, "Invalid JSON login request.", http.StatusBadRequest)
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		http.Error(writer, "Invalid JSON login request.", http.StatusBadRequest)
		return
	}
	if !handler.verifyCaptcha(writer, request, "login", input.CaptchaToken) {
		return
	}
	user, locked, retryAt, err := handler.authenticateCredentials(request, input.Email, input.Password)
	if err != nil {
		handler.internalError(writer, request, "authenticate API login", err)
		return
	}
	if locked {
		writer.Header().Set("Retry-After", fmt.Sprint(max(1, int(time.Until(retryAt).Seconds()))))
		http.Error(writer, "Too many login attempts. Try again later.", http.StatusTooManyRequests)
		return
	}
	if user == nil {
		http.Error(writer, "Email or password is incorrect.", http.StatusUnauthorized)
		return
	}
	token, claims, err := handler.issueJWT(request, user, true)
	if err != nil {
		handler.internalError(writer, request, "issue API JWT", err)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"access_token": token, "token_type": "Bearer", "expires_in": int(time.Until(claims.ExpiresAt.Time).Seconds()),
	})
}

func (handler *Handler) authenticateCredentials(request *http.Request, emailValue, password string) (*db.User, bool, time.Time, error) {
	email, emailErr := appauth.NormalizeEmail(emailValue)
	throttleKey := handler.loginThrottleKey(request, email)
	allowed, retryAt, err := handler.users.LoginAllowed(request.Context(), throttleKey, time.Now().UTC())
	if err != nil {
		return nil, false, time.Time{}, err
	}
	if !allowed {
		return nil, true, retryAt, nil
	}
	var user *db.User
	if emailErr == nil {
		user, err = handler.users.UserByEmail(request.Context(), email)
		if err != nil && !errors.Is(err, db.ErrNotFound) {
			return nil, false, time.Time{}, err
		}
	}
	passwordCorrect := false
	if user != nil {
		passwordHash := user.PasswordHash
		if passwordHash == "" {
			passwordHash = appauth.DummyPasswordHash()
		}
		passwordCorrect = appauth.VerifyPassword(password, passwordHash)
	} else {
		_ = appauth.VerifyPassword(password, appauth.DummyPasswordHash())
	}
	if user == nil || !user.Active || !passwordCorrect {
		if recordErr := handler.users.RecordLoginFailure(request.Context(), throttleKey, time.Now().UTC()); recordErr != nil {
			handler.logger.Error("record login failure", "error", recordErr)
		}
		return nil, false, time.Time{}, nil
	}
	if err := handler.users.ClearLoginFailures(request.Context(), throttleKey); err != nil {
		handler.logger.Error("clear login failures", "error", err)
	}
	return user, false, time.Time{}, nil
}

func (handler *Handler) SignupPage(writer http.ResponseWriter, request *http.Request) {
	if !handler.config.Auth.SignupEnabled {
		http.NotFound(writer, request)
		return
	}
	if currentIdentity(request) != nil {
		handler.redirect(writer, request, "/account")
		return
	}
	csrf := handler.preAuthCSRF(writer, request)
	if csrf == "" {
		return
	}
	handler.render(writer, "signup.html", authPageData{Version: config.GetVersion(), CSRF: csrf, SignupEnabled: true, Captcha: handler.captchaWidget("signup")})
}

func (handler *Handler) Signup(writer http.ResponseWriter, request *http.Request) {
	if !handler.config.Auth.SignupEnabled {
		http.NotFound(writer, request)
		return
	}
	if !handler.allowRequest(writer, request, "signup", handler.rateLimitSettings().SignupLimit) {
		return
	}
	if !handler.parseAuthForm(writer, request) || !handler.verifyPreAuthCSRF(writer, request) {
		return
	}
	if !handler.verifyCaptcha(writer, request, "signup", "") {
		return
	}
	email, displayName, password, err := validatedRegistration(request)
	if err != nil {
		csrf := handler.preAuthCSRF(writer, request)
		if csrf != "" {
			handler.render(writer, "signup.html", authPageData{Version: config.GetVersion(), CSRF: csrf, SignupEnabled: true, Error: err.Error(), Email: request.FormValue("email"), DisplayName: request.FormValue("display_name"), Captcha: handler.captchaWidget("signup")})
		}
		return
	}
	hash, err := appauth.HashPassword(password)
	if err != nil {
		handler.internalError(writer, request, "hash signup password", err)
		return
	}
	user := &db.User{ID: uuid.NewString(), Email: email, DisplayName: displayName, PasswordHash: hash, Role: db.RoleUser, Active: true, TokenVersion: 1}
	if err := handler.users.CreateUser(request.Context(), user); err != nil {
		if errors.Is(err, db.ErrConflict) {
			csrf := handler.preAuthCSRF(writer, request)
			if csrf != "" {
				handler.render(writer, "signup.html", authPageData{Version: config.GetVersion(), CSRF: csrf, SignupEnabled: true, Error: "That email address is already registered.", Email: email, DisplayName: displayName, Captcha: handler.captchaWidget("signup")})
			}
			return
		}
		handler.internalError(writer, request, "create user", err)
		return
	}
	if err := handler.startJWT(writer, request, user, true); err != nil {
		handler.internalError(writer, request, "issue signup JWT", err)
		return
	}
	handler.redirect(writer, request, "/account?message=welcome")
}

func (handler *Handler) Logout(writer http.ResponseWriter, request *http.Request) {
	identity := currentIdentity(request)
	if !handler.verifyJWTCSRF(writer, request, identity) {
		return
	}
	if err := handler.revokeJWT(request, identity); err != nil {
		handler.internalError(writer, request, "revoke JWT", err)
		return
	}
	handler.clearJWTCookie(writer)
	handler.redirect(writer, request, "/login")
}

func (handler *Handler) APILogout(writer http.ResponseWriter, request *http.Request) {
	identity := currentIdentity(request)
	if !handler.verifyJWTCSRF(writer, request, identity) {
		return
	}
	if err := handler.revokeJWT(request, identity); err != nil {
		handler.internalError(writer, request, "revoke API JWT", err)
		return
	}
	handler.clearJWTCookie(writer)
	writer.WriteHeader(http.StatusNoContent)
}

func (handler *Handler) revokeJWT(request *http.Request, identity *identity) error {
	if identity == nil || identity.Claims.ExpiresAt == nil {
		return errors.New("JWT is missing expiration")
	}
	now := time.Now().UTC()
	return handler.users.RevokeToken(request.Context(), appauth.TokenHash(identity.Claims.ID), identity.Claims.ExpiresAt.Time, now)
}

func (handler *Handler) Account(writer http.ResponseWriter, request *http.Request) {
	identity := currentIdentity(request)
	handler.renderAccount(writer, request, identity, "", accountMessage(request.URL.Query().Get("message")))
}

func (handler *Handler) renderAccount(writer http.ResponseWriter, request *http.Request, identity *identity, formError, message string) {
	files, err := handler.users.ListFilesByOwner(request.Context(), identity.User.ID)
	if err != nil {
		handler.internalError(writer, request, "list account files", err)
		return
	}
	rows := make([]accountFile, 0, len(files))
	for _, file := range files {
		rows = append(rows, accountFile{ID: file.FileID, Name: file.FileName, Size: humanSize(file.FileSize), CreatedAt: file.CreatedAt.UTC().Format("2006-01-02 15:04 UTC")})
	}
	providers, err := handler.oauthAccountProviders(request.Context(), identity.User.ID)
	if err != nil {
		handler.internalError(writer, request, "list linked OAuth identities", err)
		return
	}
	data := accountPageData{Version: config.GetVersion(), CSRF: identity.Claims.CSRF, User: identity.User, Files: rows, OAuthProviders: providers, HasPassword: identity.User.PasswordHash != "", Error: formError, Message: message, QuotaLabel: handler.uploadQuotaLabel(request, identity.User)}
	if handler.billing != nil {
		data.CreditBalance = fmt.Sprintf("%d credits", identity.User.CreditBalance)
		if handler.config.Billing != nil {
			data.CreditCurrency = handler.config.Billing.CreditCurrency
			data.MinTopUpCredits, data.MaxTopUpCredits = handler.config.Billing.MinTopUpCredits, handler.config.Billing.MaxTopUpCredits
		}
		for _, option := range billingGatewayOptions() {
			if handler.billingGateways[option.Key] != nil {
				data.TopUpGateways = append(data.TopUpGateways, option)
			}
		}
		transactions, transactionErr := handler.billing.CreditTransactions(request.Context(), identity.User.ID, 20)
		if transactionErr != nil {
			handler.internalError(writer, request, "get account credit history", transactionErr)
			return
		}
		for _, transaction := range transactions {
			data.CreditTransactions = append(data.CreditTransactions, creditTransactionRow{
				Delta: fmt.Sprintf("%+d", transaction.Delta), Balance: fmt.Sprintf("%d", transaction.BalanceAfter),
				Description: transaction.Description, CreatedAt: transaction.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"), Positive: transaction.Delta > 0,
			})
		}
		subscription, subscriptionErr := handler.billing.SubscriptionForUser(request.Context(), identity.User.ID)
		if subscriptionErr == nil {
			data.BillingAccount, data.PlanName, data.PlanStatus = true, subscription.Plan.Name, subscription.Status
			data.CreditPlan = subscription.Gateway == db.BillingGatewayCredit
			if data.CreditPlan && !subscription.CurrentPeriodEnd.After(time.Now().UTC()) {
				data.PlanStatus = "expired"
			}
			data.BillingEnabled = !data.CreditPlan && handler.billingGateways[subscription.Gateway] != nil
		} else if !errors.Is(subscriptionErr, db.ErrNotFound) {
			handler.internalError(writer, request, "get billing account", subscriptionErr)
			return
		}
		entitlements, entitlementErr := handler.billing.Entitlements(request.Context(), identity.User.ID, time.Now().UTC())
		if entitlementErr != nil {
			handler.internalError(writer, request, "get account plan", entitlementErr)
			return
		}
		if entitlements.Active {
			data.PlanActive, data.PlanName, data.PlanCanceling = true, entitlements.PlanName, entitlements.CancelAtPeriodEnd
			data.PlanRenews = entitlements.CurrentPeriodEnd.UTC().Format("2006-01-02")
		}
	}
	handler.render(writer, "account.html", data)
}

func (handler *Handler) UpdateProfile(writer http.ResponseWriter, request *http.Request) {
	identity := currentIdentity(request)
	if !handler.parseAuthForm(writer, request) || !handler.verifyJWTCSRF(writer, request, identity) {
		return
	}
	email, err := appauth.NormalizeEmail(request.FormValue("email"))
	var displayName string
	if err == nil {
		displayName, err = appauth.ValidateDisplayName(request.FormValue("display_name"))
	}
	if err != nil {
		handler.renderAccount(writer, request, identity, err.Error(), "")
		return
	}
	err = handler.users.UpdateProfile(request.Context(), identity.User.ID, email, displayName)
	if errors.Is(err, db.ErrConflict) {
		handler.renderAccount(writer, request, identity, "That email address is already registered.", "")
		return
	}
	if err != nil {
		handler.internalError(writer, request, "update profile", err)
		return
	}
	handler.redirect(writer, request, "/account?message=profile")
}

func (handler *Handler) UpdateTheme(writer http.ResponseWriter, request *http.Request) {
	identity := currentIdentity(request)
	if !handler.parseAuthForm(writer, request) || !handler.verifyJWTCSRF(writer, request, identity) {
		return
	}
	theme := request.FormValue("theme")
	if theme != "light" && theme != "dark" {
		handler.renderAccount(writer, request, identity, "Choose either the light or dark theme.", "")
		return
	}
	if err := handler.users.UpdateDarkMode(request.Context(), identity.User.ID, theme == "dark"); err != nil {
		handler.internalError(writer, request, "update account theme", err)
		return
	}
	handler.redirect(writer, request, "/account?message=theme")
}

func (handler *Handler) UpdateOwnPassword(writer http.ResponseWriter, request *http.Request) {
	identity := currentIdentity(request)
	if !handler.parseAuthForm(writer, request) || !handler.verifyJWTCSRF(writer, request, identity) {
		return
	}
	if identity.User.PasswordHash != "" && !appauth.VerifyPassword(request.FormValue("current_password"), identity.User.PasswordHash) {
		handler.renderAccount(writer, request, identity, "Current password is incorrect.", "")
		return
	}
	password := request.FormValue("password")
	if password != request.FormValue("password_confirm") {
		handler.renderAccount(writer, request, identity, "New passwords do not match.", "")
		return
	}
	hash, err := appauth.HashPassword(password)
	if err != nil {
		if validationErr := appauth.ValidatePassword(password); validationErr != nil {
			handler.renderAccount(writer, request, identity, validationErr.Error(), "")
			return
		}
		handler.internalError(writer, request, "hash changed password", err)
		return
	}
	updatedUser, err := handler.users.UpdatePassword(request.Context(), identity.User.ID, hash)
	if err != nil {
		handler.internalError(writer, request, "change password", err)
		return
	}
	if err := handler.startJWT(writer, request, updatedUser, false); err != nil {
		handler.internalError(writer, request, "issue JWT after password change", err)
		return
	}
	handler.redirect(writer, request, "/account?message=password")
}

func (handler *Handler) AdminUsers(writer http.ResponseWriter, request *http.Request) {
	identity := currentIdentity(request)
	data, err := handler.adminUsersPageData(request.Context(), identity)
	if err != nil {
		handler.internalError(writer, request, "load user management data", err)
		return
	}
	data.Message = adminMessage(request.URL.Query().Get("message"))
	handler.render(writer, "admin_users.html", data)
}

func (handler *Handler) AdminCreateUser(writer http.ResponseWriter, request *http.Request) {
	identity := currentIdentity(request)
	if !handler.parseAuthForm(writer, request) || !handler.verifyJWTCSRF(writer, request, identity) {
		return
	}
	email, displayName, password, err := validatedRegistration(request)
	uploadQuotaBytes, quotaErr := uploadQuotaFromForm(request.FormValue("upload_quota_mib"))
	if err == nil {
		err = quotaErr
	}
	role := request.FormValue("role")
	if role != db.RoleAdmin && role != db.RoleUser {
		err = errors.New("Choose a valid role.")
	}
	if err != nil {
		handler.renderAdminError(writer, request, identity, err.Error())
		return
	}
	hash, err := appauth.HashPassword(password)
	if err != nil {
		handler.internalError(writer, request, "hash administrator-created password", err)
		return
	}
	err = handler.users.CreateUser(request.Context(), &db.User{ID: uuid.NewString(), Email: email, DisplayName: displayName, PasswordHash: hash, Role: role, Active: true, TokenVersion: 1, IsPaid: checked(request, "is_paid"), UploadQuotaBytes: uploadQuotaBytes})
	if errors.Is(err, db.ErrConflict) {
		handler.renderAdminError(writer, request, identity, "That email address is already registered.")
		return
	}
	if err != nil {
		handler.internalError(writer, request, "create administrator-managed user", err)
		return
	}
	handler.redirect(writer, request, "/admin/users?message=created")
}

func (handler *Handler) AdminUpdateAccess(writer http.ResponseWriter, request *http.Request) {
	handler.adminUserAction(writer, request, func(ctx context.Context, id string) error {
		role := request.FormValue("role")
		if role != db.RoleAdmin && role != db.RoleUser {
			return fmt.Errorf("%w: Choose a valid role.", errInvalidAdminForm)
		}
		return handler.users.AdminUpdateUser(ctx, id, role, request.FormValue("active") == "true")
	}, "updated")
}

func (handler *Handler) AdminUpdateUploadQuota(writer http.ResponseWriter, request *http.Request) {
	handler.adminUserAction(writer, request, func(ctx context.Context, id string) error {
		quotaBytes, err := uploadQuotaFromForm(request.FormValue("upload_quota_mib"))
		if err != nil {
			return fmt.Errorf("%w: %v", errInvalidAdminForm, err)
		}
		return handler.users.UpdateUploadQuota(ctx, id, quotaBytes)
	}, "quota")
}

func (handler *Handler) AdminUpdatePaidStatus(writer http.ResponseWriter, request *http.Request) {
	handler.adminUserAction(writer, request, func(ctx context.Context, id string) error {
		paid := request.FormValue("is_paid")
		if paid != "true" && paid != "false" {
			return fmt.Errorf("%w: Choose a valid payment status.", errInvalidAdminForm)
		}
		return handler.users.UpdatePaidStatus(ctx, id, paid == "true")
	}, "paid")
}

func (handler *Handler) AdminAdjustCredit(writer http.ResponseWriter, request *http.Request) {
	if handler.billing == nil {
		http.Error(writer, "Billing storage is unavailable.", http.StatusServiceUnavailable)
		return
	}
	identity := currentIdentity(request)
	handler.adminUserAction(writer, request, func(ctx context.Context, id string) error {
		delta, err := strconv.ParseInt(strings.TrimSpace(request.FormValue("credit_delta")), 10, 64)
		description := strings.TrimSpace(request.FormValue("credit_description"))
		if err != nil || delta == 0 || delta < -1_000_000_000 || delta > 1_000_000_000 || description == "" || len(description) > 200 {
			return fmt.Errorf("%w: Enter a non-zero adjustment from -1000000000 to 1000000000 credits and a reason of at most 200 characters.", errInvalidAdminForm)
		}
		requestID := request.FormValue("credit_request_id")
		if _, err := uuid.Parse(requestID); err != nil {
			return fmt.Errorf("%w: Reload the users page before recording an adjustment.", errInvalidAdminForm)
		}
		_, err = handler.billing.AdjustCredit(ctx, id, delta, description, identity.User.ID, requestID, time.Now().UTC())
		if errors.Is(err, db.ErrConflict) {
			return fmt.Errorf("%w: This form was already used for another adjustment. Reload the users page.", errInvalidAdminForm)
		}
		if errors.Is(err, db.ErrInvalidCredit) {
			return fmt.Errorf("%w: The adjustment would exceed the supported account-credit range.", errInvalidAdminForm)
		}
		return err
	}, "credit")
}

func (handler *Handler) AdminResetPassword(writer http.ResponseWriter, request *http.Request) {
	handler.adminUserAction(writer, request, func(ctx context.Context, id string) error {
		password := request.FormValue("password")
		if password != request.FormValue("password_confirm") {
			return fmt.Errorf("%w: Passwords do not match.", errInvalidAdminForm)
		}
		if err := appauth.ValidatePassword(password); err != nil {
			return fmt.Errorf("%w: %v", errInvalidAdminForm, err)
		}
		hash, err := appauth.HashPassword(password)
		if err != nil {
			return err
		}
		_, err = handler.users.UpdatePassword(ctx, id, hash)
		return err
	}, "password")
}

func (handler *Handler) AdminDeleteUser(writer http.ResponseWriter, request *http.Request) {
	handler.adminUserAction(writer, request, func(ctx context.Context, id string) error {
		return handler.users.DeleteUser(ctx, id)
	}, "deleted")
}

func (handler *Handler) adminUserAction(writer http.ResponseWriter, request *http.Request, action func(context.Context, string) error, message string) {
	identity := currentIdentity(request)
	if !handler.parseAuthForm(writer, request) || !handler.verifyJWTCSRF(writer, request, identity) {
		return
	}
	id := chi.URLParam(request, "id")
	if parsed, err := uuid.Parse(id); err != nil || parsed.String() != strings.ToLower(id) {
		http.NotFound(writer, request)
		return
	}
	if err := action(request.Context(), id); err != nil {
		if errors.Is(err, db.ErrLastAdmin) {
			handler.renderAdminError(writer, request, identity, "The final active administrator cannot be disabled, demoted, or deleted.")
			return
		}
		if errors.Is(err, db.ErrNotFound) {
			http.NotFound(writer, request)
			return
		}
		if errors.Is(err, errInvalidAdminForm) {
			handler.renderAdminError(writer, request, identity, strings.TrimPrefix(err.Error(), errInvalidAdminForm.Error()+": "))
			return
		}
		handler.internalError(writer, request, "perform administrator user action", err)
		return
	}
	handler.redirect(writer, request, "/admin/users?message="+message)
}

func (handler *Handler) renderAdminError(writer http.ResponseWriter, request *http.Request, identity *identity, message string) {
	data, err := handler.adminUsersPageData(request.Context(), identity)
	if err != nil {
		handler.internalError(writer, request, "render admin error", err)
		return
	}
	data.Error = message
	handler.render(writer, "admin_users.html", data)
}

func (handler *Handler) adminUsersPageData(ctx context.Context, identity *identity) (adminPageData, error) {
	users, err := handler.users.ListUsers(ctx)
	if err != nil {
		return adminPageData{}, err
	}
	usage, err := handler.users.StorageUsageByUser(ctx)
	if err != nil {
		return adminPageData{}, err
	}
	rows := make([]adminUserRow, 0, len(users))
	var totalStorageUsed int64
	for _, user := range users {
		lastLogin := "Never"
		if user.LastLoginAt != nil {
			lastLogin = user.LastLoginAt.UTC().Format("2006-01-02 15:04 UTC")
		}
		storageUsed := usage[user.ID]
		totalStorageUsed += storageUsed
		rows = append(rows, adminUserRow{ID: user.ID, Email: user.Email, DisplayName: user.DisplayName, Role: user.Role,
			Active: user.Active, CreatedAt: user.CreatedAt.UTC().Format("2006-01-02"), LastLogin: lastLogin,
			IsCurrent: user.ID == identity.User.ID, IsPaid: user.IsPaid, UploadQuotaMiB: user.UploadQuotaBytes / mebibyte,
			StorageUsed: humanSize(storageUsed), CreditBalance: fmt.Sprintf("%d credits", user.CreditBalance), CreditRequestID: uuid.NewString()})
	}
	return adminPageData{Version: config.GetVersion(), CSRF: identity.Claims.CSRF, User: identity.User, Users: rows, TotalStorageUsed: humanSize(totalStorageUsed)}, nil
}

func (handler *Handler) setupAvailable(writer http.ResponseWriter, request *http.Request) bool {
	if handler.users == nil {
		http.Error(writer, "User storage is unavailable.", http.StatusServiceUnavailable)
		return false
	}
	count, err := handler.users.AdminCount(request.Context())
	if err != nil {
		handler.internalError(writer, request, "check setup availability", err)
		return false
	}
	if count != 0 {
		handler.redirect(writer, request, "/login")
		return false
	}
	return true
}

func (handler *Handler) parseAuthForm(writer http.ResponseWriter, request *http.Request) bool {
	request.Body = http.MaxBytesReader(writer, request.Body, 32*1024)
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "Invalid form.", http.StatusBadRequest)
		return false
	}
	return true
}

func validatedRegistration(request *http.Request) (string, string, string, error) {
	email, err := appauth.NormalizeEmail(request.FormValue("email"))
	if err != nil {
		return "", "", "", err
	}
	displayName, err := appauth.ValidateDisplayName(request.FormValue("display_name"))
	if err != nil {
		return "", "", "", err
	}
	password := request.FormValue("password")
	if password != request.FormValue("password_confirm") {
		return "", "", "", errors.New("Passwords do not match.")
	}
	if err := appauth.ValidatePassword(password); err != nil {
		return "", "", "", err
	}
	return email, displayName, password, nil
}

const maxUploadQuotaMiB int64 = 8_796_093_022_207

func uploadQuotaFromForm(value string) (int64, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, nil
	}
	quotaMiB, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil || quotaMiB < 0 || quotaMiB > maxUploadQuotaMiB {
		return 0, fmt.Errorf("Upload quota must be a whole number from 0 to %d MiB.", maxUploadQuotaMiB)
	}
	return quotaMiB * mebibyte, nil
}

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
	mac := hmac.New(sha256.New, handler.csrfSecret)
	_, _ = mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (handler *Handler) verifyPreAuthCSRF(writer http.ResponseWriter, request *http.Request) bool {
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
	mac := hmac.New(sha256.New, handler.csrfSecret)
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
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		host = request.RemoteAddr
	}
	return appauth.TokenHash(strings.ToLower(strings.TrimSpace(email)) + "|" + host)
}

func safeLoginDestination(value string) string {
	switch value {
	case loginDestinationAdminUsers:
		return loginDestinationAdminUsers
	case loginDestinationAdminSettings:
		return loginDestinationAdminSettings
	default:
		return ""
	}
}

func (handler *Handler) redirectToLogin(writer http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/admin/users":
		handler.redirect(writer, request, "/login?next="+loginDestinationAdminUsers)
	case "/admin/settings":
		handler.redirect(writer, request, "/login?next="+loginDestinationAdminSettings)
	default:
		handler.redirect(writer, request, "/login")
	}
}

func (handler *Handler) redirectAfterLogin(writer http.ResponseWriter, request *http.Request, destination string) {
	switch destination {
	case loginDestinationAdminUsers:
		handler.redirect(writer, request, "/admin/users")
	case loginDestinationAdminSettings:
		handler.redirect(writer, request, "/admin/settings")
	default:
		handler.redirect(writer, request, "/account")
	}
}

func accountMessage(value string) string {
	return map[string]string{"welcome": "Welcome to ObjectShare.", "profile": "Profile updated.", "theme": "Appearance updated.", "password": "Password changed and all earlier JWTs were invalidated.", "oauth-linked": "OAuth login linked.", "oauth-unlinked": "OAuth login removed.", "topup-pending": "Checkout returned. Credit will appear after the gateway confirms payment.", "topup-complete": "Your account credit has been added.", "credit-plan": "Plan purchased with account credit."}[value]
}

func adminMessage(value string) string {
	return map[string]string{"setup": "Initial administrator created.", "created": "User created.", "updated": "Access updated; that user's earlier JWTs were invalidated.", "quota": "Upload quota updated.", "paid": "Manual retention exemption updated.", "credit": "Account credit adjusted.", "password": "Password reset; that user's earlier JWTs were invalidated.", "deleted": "User deleted."}[value]
}
