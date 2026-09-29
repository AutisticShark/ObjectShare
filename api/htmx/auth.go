package htmx

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
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
	SignupEnabled, Setup, SetupTokenRequired       bool
	OAuthProviders                                 []oauthButton
	Captcha                                        *captchaWidget
}

type accountFile struct {
	ID, Name, Size, CreatedAt string
}

type accountPageData struct {
	VerificationEnabled, VerificationPurchases, VerificationUploads          bool
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

// adminExistsCacheTTL bounds how long SetupComplete trusts a positive
// administrator check.
const adminExistsCacheTTL = time.Minute

func (handler *Handler) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		request = request.WithContext(withRequestMemo(request.Context()))
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
		if user.ModerationStatus == db.ModerationBanned {
			writer.Header().Set("Cache-Control", "private, no-store")
			http.Error(writer, "This account is banned.", http.StatusForbidden)
			return
		}
		now := time.Now().UTC()
		revoked, err := handler.users.TokenRevoked(request.Context(), appauth.TokenHash(claims.ID), now)
		if err != nil {
			handler.internalError(writer, request, "check JWT revocation", err)
			return
		}
		if revoked || !user.CanAuthenticate() || user.Role != claims.Role || user.TokenVersion != claims.TokenVersion {
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
		now := time.Now()
		if handler.adminsExistUntil.Load() > now.UnixNano() {
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
		// Only "an administrator exists" is cached, and briefly, so every
		// request does not pay a COUNT query but setup still reappears if the
		// last administrator is removed. Setup itself always re-checks live.
		handler.adminsExistUntil.Store(now.Add(adminExistsCacheTTL).UnixNano())
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
		if !currentIdentity(request).User.IsAvailableAdmin() {
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
	if handler.setupToken() == "" {
		handler.logger.Warn("initial setup is open to anyone who can reach /setup; set OBJECTSHARE_SETUP_TOKEN to require a token, or create the administrator with -create-admin")
	}
	handler.render(writer, "setup.html", authPageData{Version: config.GetVersion(), CSRF: csrf, Setup: true, SetupTokenRequired: handler.setupToken() != ""})
}

// setupToken is the optional bootstrap secret required to create the first
// administrator through /setup.
func (handler *Handler) setupToken() string {
	if handler.config.Auth == nil {
		return ""
	}
	return handler.config.Auth.SetupToken
}

func (handler *Handler) Setup(writer http.ResponseWriter, request *http.Request) {
	if !handler.setupAvailable(writer, request) || !handler.allowRequest(writer, request, "login", handler.rateLimitSettings().LoginLimit) ||
		!handler.parseAuthForm(writer, request) || !handler.verifyPreAuthCSRF(writer, request) {
		return
	}
	if expected := handler.setupToken(); expected != "" && subtle.ConstantTimeCompare([]byte(request.FormValue("setup_token")), []byte(expected)) != 1 {
		csrf := handler.preAuthCSRF(writer, request)
		if csrf != "" {
			handler.renderStatus(writer, http.StatusForbidden, "setup.html", authPageData{Version: config.GetVersion(), CSRF: csrf, Error: "The setup token is incorrect.", Email: request.FormValue("email"), DisplayName: request.FormValue("display_name"), Setup: true, SetupTokenRequired: true})
		}
		return
	}
	email, displayName, password, err := validatedRegistration(request)
	if err != nil {
		csrf := handler.preAuthCSRF(writer, request)
		if csrf != "" {
			handler.render(writer, "setup.html", authPageData{Version: config.GetVersion(), CSRF: csrf, Error: err.Error(), Email: request.FormValue("email"), DisplayName: request.FormValue("display_name"), Setup: true, SetupTokenRequired: handler.setupToken() != ""})
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
				handler.render(writer, "setup.html", authPageData{Version: config.GetVersion(), CSRF: csrf, Error: "That email address is already registered.", Email: email, DisplayName: displayName, Setup: true, SetupTokenRequired: handler.setupToken() != ""})
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
	if user.MFA.Method != "" {
		handler.beginMFA(writer, request, user, "login", next, transportCookie)
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
	if user.MFA.Method != "" {
		handler.beginMFA(writer, request, user, "login", "", transportBearer)
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
	// The attempt is counted before the slow password check so parallel guesses
	// cannot all pass a separate check; success clears it below.
	allowed, retryAt, err := handler.users.ReserveLoginAttempt(request.Context(), throttleKey, time.Now().UTC())
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
		if user.PasswordHash == "" {
			// OAuth-only accounts have no password. Still burn one verification
			// so timing matches, but never let it succeed.
			_ = appauth.VerifyPassword(password, appauth.DummyPasswordHash())
		} else {
			passwordCorrect = appauth.VerifyPassword(password, user.PasswordHash)
		}
	} else {
		_ = appauth.VerifyPassword(password, appauth.DummyPasswordHash())
	}
	if user == nil || !user.CanAuthenticate() || !passwordCorrect {
		return nil, false, time.Time{}, nil
	}
	if err := handler.users.ClearLoginFailures(request.Context(), throttleKey); err != nil {
		handler.logger.Error("clear login failures", "error", err)
	}
	handler.upgradePasswordHash(request, user, password)
	return user, false, time.Time{}, nil
}

// upgradePasswordHash replaces a hash made with older Argon2id parameters after a
// successful login, when the plaintext is available. It is best effort: a
// failure is logged and never blocks the login.
func (handler *Handler) upgradePasswordHash(request *http.Request, user *db.User, password string) {
	if !appauth.NeedsRehash(user.PasswordHash) {
		return
	}
	upgraded, err := appauth.HashPassword(password)
	if err != nil {
		handler.logger.Warn("rehash password with current parameters", "user_id", user.ID, "error", err)
		return
	}
	if err := handler.users.RehashPassword(request.Context(), user.ID, user.PasswordHash, upgraded); err != nil {
		handler.logger.Warn("store upgraded password hash", "user_id", user.ID, "error", err)
		return
	}
	user.PasswordHash = upgraded
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
	handler.redirect(writer, request, "/account?message="+handler.verificationDeliveryMessage(request.Context(), user))
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

func (handler *Handler) BillingOverview(writer http.ResponseWriter, request *http.Request) {
	handler.renderAccountPage(writer, request, currentIdentity(request), "", "", "billing.html")
}

func (handler *Handler) renderAccount(writer http.ResponseWriter, request *http.Request, identity *identity, formError, message string) {
	handler.renderAccountPage(writer, request, identity, formError, message, "account.html")
}

func (handler *Handler) renderAccountPage(writer http.ResponseWriter, request *http.Request, identity *identity, formError, message, pageTemplate string) {
	handler.renderAccountPageStatus(writer, request, identity, http.StatusOK, formError, message, pageTemplate)
}

func (handler *Handler) renderAccountPageStatus(writer http.ResponseWriter, request *http.Request, identity *identity, status int, formError, message, pageTemplate string) {
	var rows []accountFile
	var providers []oauthAccountProvider
	if pageTemplate == "account.html" {
		files, err := handler.users.ListFilesByOwner(request.Context(), identity.User.ID)
		if err != nil {
			handler.internalError(writer, request, "list account files", err)
			return
		}
		rows = make([]accountFile, 0, len(files))
		for _, file := range files {
			rows = append(rows, accountFile{ID: file.FileID, Name: file.FileName, Size: humanSize(file.FileSize), CreatedAt: file.CreatedAt.UTC().Format("2006-01-02 15:04 UTC")})
		}
		providers, err = handler.oauthAccountProviders(request.Context(), identity.User.ID)
		if err != nil {
			handler.internalError(writer, request, "list linked OAuth identities", err)
			return
		}
	}
	data := accountPageData{Version: config.GetVersion(), CSRF: identity.Claims.CSRF, User: identity.User, Files: rows, OAuthProviders: providers, HasPassword: identity.User.PasswordHash != "", Error: formError, Message: message, QuotaLabel: handler.uploadQuotaLabel(request, identity.User)}
	data.VerificationEnabled = handler.verificationEnabled()
	data.VerificationPurchases = handler.verificationSettings().RequireForPurchases
	data.VerificationUploads = handler.verificationSettings().RequireForUploads
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
	handler.renderStatus(writer, status, pageTemplate, data)
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
	if errors.Is(err, db.ErrMFAEmailChange) {
		handler.renderAccount(writer, request, identity, "Disable email MFA using a current code or recovery code before changing your email address. You can enable it again after verifying the new address.", "")
		return
	}
	if errors.Is(err, db.ErrConflict) {
		handler.renderAccount(writer, request, identity, "That email address is already registered.", "")
		return
	}
	if err != nil {
		handler.internalError(writer, request, "update profile", err)
		return
	}
	if email != identity.User.Email {
		user, loadErr := handler.users.UserByID(request.Context(), identity.User.ID)
		if loadErr != nil {
			handler.internalError(writer, request, "reload changed email", loadErr)
			return
		}
		handler.redirect(writer, request, "/account?message="+handler.verificationDeliveryMessage(request.Context(), user))
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
	if request.Header.Get("HX-Request") == "true" && request.FormValue("theme_toggle") == "true" {
		writer.Header().Set("Cache-Control", "private, no-store")
		writer.Header().Set("HX-Trigger", `{"objectshare:theme":{"theme":"`+theme+`"}}`)
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	handler.redirect(writer, request, "/account?message=theme")
}

func (handler *Handler) UpdateOwnPassword(writer http.ResponseWriter, request *http.Request) {
	identity := currentIdentity(request)
	if !handler.parseAuthForm(writer, request) || !handler.verifyJWTCSRF(writer, request, identity) {
		return
	}
	if identity.User.PasswordHash != "" {
		ok, lockedUntil, err := handler.verifyCurrentPassword(request, identity.User, request.FormValue("current_password"))
		if err != nil {
			handler.internalError(writer, request, "verify current password", err)
			return
		}
		if !lockedUntil.IsZero() {
			writer.Header().Set("Retry-After", fmt.Sprint(max(1, int(time.Until(lockedUntil).Seconds()))))
			handler.renderAccountPageStatus(writer, request, identity, http.StatusTooManyRequests, "Too many incorrect password attempts. Try again later.", "", "account.html")
			return
		}
		if !ok {
			handler.renderAccount(writer, request, identity, "Current password is incorrect.", "")
			return
		}
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

func accountMessage(value string) string {
	if message, ok := map[string]string{
		"verification-sent":     "Account saved. A verification email was accepted for delivery. Check your inbox and spam folder.",
		"verification-disabled": "Account saved. Email verification is not configured yet; contact the administrator if needed.",
		"verification-wait":     "Please wait at least one minute before requesting another verification email.",
		"verification-failed":   "Account saved, but verification email delivery could not be confirmed. Check your inbox; if no email arrives, wait one minute and request another below.",
		"email-verified":        "Your email address is already verified.",
	}[value]; ok {
		return message
	}
	return map[string]string{"welcome": "Welcome to ObjectShare.", "profile": "Profile updated.", "theme": "Appearance updated.", "password": "Password changed and all earlier JWTs were invalidated.", "oauth-linked": "OAuth login linked.", "oauth-unlinked": "OAuth login removed.", "topup-pending": "Checkout returned. Credit will appear after the gateway confirms payment.", "topup-complete": "Your account credit has been added.", "credit-plan": "Plan purchased with account credit."}[value]
}
