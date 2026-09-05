package htmx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/AutisticShark/ObjectShare/service"
	"github.com/go-chi/chi/v5"
)

type authMemoryRepository struct {
	*memoryRepository
	users      map[string]*db.User
	identities map[string]*db.OAuthIdentity
	revoked    map[string]time.Time
	throttles  map[string]int
	setting    *db.ApplicationSetting
}

func (repository *authMemoryRepository) ApplicationSettings(context.Context) (*db.ApplicationSetting, error) {
	if repository.setting == nil {
		return nil, db.ErrNotFound
	}
	copy := *repository.setting
	return &copy, nil
}

func (repository *authMemoryRepository) InitializeApplicationSettings(_ context.Context, value string) error {
	if repository.setting == nil {
		repository.setting = &db.ApplicationSetting{Key: "runtime_config", Value: value, UpdatedBy: "bootstrap import", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	}
	return nil
}

func (repository *authMemoryRepository) SaveApplicationSettings(_ context.Context, value, updatedBy, previousValue string) error {
	if repository.setting == nil || repository.setting.Value != previousValue {
		return db.ErrConflict
	}
	repository.setting.Value, repository.setting.UpdatedBy, repository.setting.UpdatedAt = value, updatedBy, time.Now().UTC()
	return nil
}

func newAuthMemoryRepository() *authMemoryRepository {
	return &authMemoryRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList), quotaBytes: make(map[string]int64)}, users: make(map[string]*db.User), identities: make(map[string]*db.OAuthIdentity), revoked: make(map[string]time.Time), throttles: make(map[string]int)}
}

func (repository *authMemoryRepository) AdminCount(context.Context) (int64, error) {
	var count int64
	for _, user := range repository.users {
		if user.Role == db.RoleAdmin {
			count++
		}
	}
	return count, nil
}
func (repository *authMemoryRepository) BootstrapAdmin(_ context.Context, user *db.User) error {
	if count, _ := repository.AdminCount(context.Background()); count != 0 {
		return db.ErrAdminExists
	}
	return repository.CreateUser(context.Background(), user)
}
func (repository *authMemoryRepository) CreateUser(_ context.Context, user *db.User) error {
	for _, existing := range repository.users {
		if existing.Email == user.Email {
			return db.ErrConflict
		}
	}
	copy := *user
	if copy.TokenVersion < 1 {
		copy.TokenVersion = 1
	}
	copy.CreatedAt = time.Now().UTC()
	repository.users[user.ID] = &copy
	repository.quotaBytes[user.ID] = copy.UploadQuotaBytes
	return nil
}
func (repository *authMemoryRepository) CreateOAuthUser(ctx context.Context, user *db.User, identity *db.OAuthIdentity) error {
	if err := repository.CreateUser(ctx, user); err != nil {
		return err
	}
	identity.UserID = user.ID
	if err := repository.LinkOAuthIdentity(ctx, identity); err != nil {
		delete(repository.users, user.ID)
		return err
	}
	return nil
}
func (repository *authMemoryRepository) UserByEmail(_ context.Context, email string) (*db.User, error) {
	for _, user := range repository.users {
		if user.Email == email {
			copy := *user
			return &copy, nil
		}
	}
	return nil, db.ErrNotFound
}
func (repository *authMemoryRepository) UserByID(_ context.Context, id string) (*db.User, error) {
	user, ok := repository.users[id]
	if !ok {
		return nil, db.ErrNotFound
	}
	copy := *user
	return &copy, nil
}
func (repository *authMemoryRepository) OAuthUser(_ context.Context, provider, subject string) (*db.User, error) {
	identity, ok := repository.identities[provider+"\x00"+subject]
	if !ok {
		return nil, db.ErrNotFound
	}
	return repository.UserByID(context.Background(), identity.UserID)
}
func (repository *authMemoryRepository) OAuthIdentities(_ context.Context, userID string) ([]db.OAuthIdentity, error) {
	var identities []db.OAuthIdentity
	for _, identity := range repository.identities {
		if identity.UserID == userID {
			identities = append(identities, *identity)
		}
	}
	return identities, nil
}
func (repository *authMemoryRepository) LinkOAuthIdentity(_ context.Context, identity *db.OAuthIdentity) error {
	key := identity.Provider + "\x00" + identity.Subject
	if _, exists := repository.identities[key]; exists {
		return db.ErrConflict
	}
	for _, existing := range repository.identities {
		if existing.UserID == identity.UserID && existing.Provider == identity.Provider {
			return db.ErrConflict
		}
	}
	copy := *identity
	repository.identities[key] = &copy
	return nil
}
func (repository *authMemoryRepository) UnlinkOAuthIdentity(_ context.Context, userID, provider string) error {
	var foundKey string
	count := 0
	for key, identity := range repository.identities {
		if identity.UserID == userID {
			count++
			if identity.Provider == provider {
				foundKey = key
			}
		}
	}
	if foundKey == "" {
		return db.ErrNotFound
	}
	user := repository.users[userID]
	if user.PasswordHash == "" && count <= 1 {
		return db.ErrLastLoginMethod
	}
	delete(repository.identities, foundKey)
	return nil
}
func (repository *authMemoryRepository) ListUsers(context.Context) ([]db.User, error) {
	users := make([]db.User, 0, len(repository.users))
	for _, user := range repository.users {
		users = append(users, *user)
	}
	return users, nil
}
func (repository *authMemoryRepository) StorageUsageByUser(context.Context) (map[string]int64, error) {
	usage := make(map[string]int64)
	for _, file := range repository.files {
		if file.FileOwner != nil && (file.UploadStatus == "pending" || file.UploadStatus == "complete" || file.UploadStatus == "deleting") {
			usage[*file.FileOwner] += file.FileSize
		}
	}
	return usage, nil
}
func (repository *authMemoryRepository) UpdateProfile(_ context.Context, id, email, name string) error {
	user, ok := repository.users[id]
	if !ok {
		return db.ErrNotFound
	}
	user.Email, user.DisplayName = email, name
	return nil
}
func (repository *authMemoryRepository) UpdateDarkMode(_ context.Context, id string, enabled bool) error {
	user, ok := repository.users[id]
	if !ok {
		return db.ErrNotFound
	}
	user.DarkMode = enabled
	return nil
}
func (repository *authMemoryRepository) UpdatePassword(_ context.Context, id, hash string) (*db.User, error) {
	user, ok := repository.users[id]
	if !ok {
		return nil, db.ErrNotFound
	}
	user.PasswordHash = hash
	user.TokenVersion++
	copy := *user
	return &copy, nil
}
func (repository *authMemoryRepository) AdminUpdateUser(_ context.Context, id, role string, active bool) error {
	user, ok := repository.users[id]
	if !ok {
		return db.ErrNotFound
	}
	if user.Role == db.RoleAdmin && user.Active && (role != db.RoleAdmin || !active) {
		var activeAdmins int
		for _, candidate := range repository.users {
			if candidate.Role == db.RoleAdmin && candidate.Active {
				activeAdmins++
			}
		}
		if activeAdmins == 1 {
			return db.ErrLastAdmin
		}
	}
	if user.Role != role || user.Active != active {
		user.TokenVersion++
	}
	user.Role, user.Active = role, active
	return nil
}
func (repository *authMemoryRepository) UpdatePaidStatus(_ context.Context, id string, paid bool) error {
	user, ok := repository.users[id]
	if !ok {
		return db.ErrNotFound
	}
	user.IsPaid = paid
	return nil
}
func (repository *authMemoryRepository) UpdateUploadQuota(_ context.Context, id string, quotaBytes int64) error {
	user, ok := repository.users[id]
	if !ok {
		return db.ErrNotFound
	}
	if quotaBytes < 0 {
		return db.ErrInvalidQuota
	}
	user.UploadQuotaBytes = quotaBytes
	repository.quotaBytes[id] = quotaBytes
	return nil
}
func (repository *authMemoryRepository) DeleteUser(_ context.Context, id string) error {
	if _, ok := repository.users[id]; !ok {
		return db.ErrNotFound
	}
	delete(repository.users, id)
	delete(repository.quotaBytes, id)
	for key, identity := range repository.identities {
		if identity.UserID == id {
			delete(repository.identities, key)
		}
	}
	return nil
}
func (repository *authMemoryRepository) ListFilesByOwner(_ context.Context, id string) ([]db.FileList, error) {
	var files []db.FileList
	for _, file := range repository.files {
		if file.FileOwner != nil && *file.FileOwner == id {
			files = append(files, *file)
		}
	}
	return files, nil
}
func (repository *authMemoryRepository) RecordLogin(_ context.Context, id string, now time.Time) error {
	user, ok := repository.users[id]
	if !ok {
		return db.ErrNotFound
	}
	user.LastLoginAt = &now
	return nil
}
func (repository *authMemoryRepository) RevokeToken(_ context.Context, jtiHash string, expiresAt, _ time.Time) error {
	repository.revoked[jtiHash] = expiresAt
	return nil
}
func (repository *authMemoryRepository) TokenRevoked(_ context.Context, jtiHash string, now time.Time) (bool, error) {
	expiresAt, ok := repository.revoked[jtiHash]
	return ok && expiresAt.After(now), nil
}
func (repository *authMemoryRepository) LoginAllowed(_ context.Context, key string, _ time.Time) (bool, time.Time, error) {
	if repository.throttles[key] >= 5 {
		return false, time.Now().Add(15 * time.Minute), nil
	}
	return true, time.Time{}, nil
}
func (repository *authMemoryRepository) RecordLoginFailure(_ context.Context, key string, _ time.Time) error {
	repository.throttles[key]++
	return nil
}
func (repository *authMemoryRepository) ClearLoginFailures(_ context.Context, key string) error {
	delete(repository.throttles, key)
	return nil
}

func TestInitialSetupIsCSRFProtectedAndOneTime(t *testing.T) {
	repository := newAuthMemoryRepository()
	handler := newAuthTestHandler(t, repository, false)
	page := httptest.NewRecorder()
	handler.SetupPage(page, httptest.NewRequest(http.MethodGet, "/setup", nil))
	csrf := strings.TrimSpace(page.Body.String())
	if csrf == "" || len(page.Result().Cookies()) != 1 {
		t.Fatal("setup page did not issue a pre-authentication CSRF token")
	}

	withoutCSRF := httptest.NewRecorder()
	handler.Setup(withoutCSRF, httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(url.Values{
		"display_name": {"Admin"}, "email": {"admin@example.com"}, "password": {"a sufficiently long password"}, "password_confirm": {"a sufficiently long password"},
	}.Encode())))
	if withoutCSRF.Code != http.StatusForbidden || len(repository.users) != 0 {
		t.Fatalf("CSRF-free setup status=%d users=%d", withoutCSRF.Code, len(repository.users))
	}

	request := formRequest("/setup", url.Values{"csrf_token": {csrf}, "display_name": {"Admin"}, "email": {"admin@example.com"}, "password": {"a sufficiently long password"}, "password_confirm": {"a sufficiently long password"}})
	request.AddCookie(page.Result().Cookies()[0])
	response := httptest.NewRecorder()
	handler.Setup(response, request)
	if response.Code != http.StatusSeeOther || len(repository.users) != 1 {
		t.Fatalf("setup status=%d users=%d body=%q", response.Code, len(repository.users), response.Body.String())
	}
	var setupJWT string
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == "objectshare_jwt" {
			setupJWT = cookie.Value
		}
	}
	if claims, err := handler.jwt.Parse(setupJWT); err != nil || claims.Role != db.RoleAdmin || claims.TokenVersion != 1 {
		t.Fatalf("initial administrator JWT is invalid: claims=%#v err=%v", claims, err)
	}
	for _, user := range repository.users {
		if user.Role != db.RoleAdmin || !user.Active || !appauth.VerifyPassword("a sufficiently long password", user.PasswordHash) {
			t.Fatal("initial account is not an active administrator with a password hash")
		}
	}
	again := httptest.NewRecorder()
	handler.SetupPage(again, httptest.NewRequest(http.MethodGet, "/setup", nil))
	if again.Code != http.StatusSeeOther || again.Header().Get("Location") != "/login" {
		t.Fatalf("second setup status=%d location=%q", again.Code, again.Header().Get("Location"))
	}
}

func TestSignupCreatesNormalUserAndSecureJWT(t *testing.T) {
	repository := newAuthMemoryRepository()
	repository.users["9dcaa8d1-3a21-4261-9c72-a25d437f58cb"] = &db.User{ID: "9dcaa8d1-3a21-4261-9c72-a25d437f58cb", Email: "admin@example.com", Role: db.RoleAdmin, Active: true, TokenVersion: 1}
	handler := newAuthTestHandler(t, repository, true)
	page := httptest.NewRecorder()
	handler.SignupPage(page, httptest.NewRequest(http.MethodGet, "/signup", nil))
	request := formRequest("/signup", url.Values{"csrf_token": {strings.TrimSpace(page.Body.String())}, "display_name": {"Regular User"}, "email": {"USER@example.com"}, "password": {"a sufficiently long password"}, "password_confirm": {"a sufficiently long password"}})
	request.AddCookie(page.Result().Cookies()[0])
	response := httptest.NewRecorder()
	handler.Signup(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("signup status=%d body=%q", response.Code, response.Body.String())
	}
	var jwtCookie *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == "__Host-objectshare_jwt" {
			jwtCookie = cookie
		}
	}
	if jwtCookie == nil || !jwtCookie.HttpOnly || !jwtCookie.Secure || jwtCookie.SameSite != http.SameSiteStrictMode || jwtCookie.Path != "/" {
		t.Fatalf("JWT cookie is not hardened: %#v", jwtCookie)
	}
	user, err := repository.UserByEmail(context.Background(), "user@example.com")
	claims, parseErr := handler.jwt.Parse(jwtCookie.Value)
	if err != nil || parseErr != nil || user.Role != db.RoleUser || claims.Subject != user.ID || claims.Role != db.RoleUser {
		t.Fatalf("signup role=%v err=%v", user, err)
	}
}

func TestLoginRejectsBadPasswordAndIssuesJWT(t *testing.T) {
	repository := newAuthMemoryRepository()
	hash, _ := appauth.HashPassword("a sufficiently long password")
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "user@example.com", DisplayName: "User", PasswordHash: hash, Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[user.ID] = user
	handler := newAuthTestHandler(t, repository, false)
	page := httptest.NewRecorder()
	handler.LoginPage(page, httptest.NewRequest(http.MethodGet, "/login", nil))
	csrf, preAuthCookie := strings.TrimSpace(page.Body.String()), page.Result().Cookies()[0]

	badRequest := formRequest("/login", url.Values{"csrf_token": {csrf}, "email": {user.Email}, "password": {"this password is wrong"}})
	badRequest.AddCookie(preAuthCookie)
	badResponse := httptest.NewRecorder()
	handler.Login(badResponse, badRequest)
	if badResponse.Code != http.StatusOK || !strings.Contains(badResponse.Body.String(), "Email or password is incorrect.") {
		t.Fatalf("bad login status=%d body=%q", badResponse.Code, badResponse.Body.String())
	}

	goodRequest := formRequest("/login", url.Values{"csrf_token": {csrf}, "email": {user.Email}, "password": {"a sufficiently long password"}, "next": {"https://attacker.example/phishing"}})
	goodRequest.AddCookie(preAuthCookie)
	goodResponse := httptest.NewRecorder()
	handler.Login(goodResponse, goodRequest)
	if goodResponse.Code != http.StatusSeeOther || goodResponse.Header().Get("Location") != "/account" {
		t.Fatalf("good login status=%d location=%q", goodResponse.Code, goodResponse.Header().Get("Location"))
	}
	var rawToken string
	for _, cookie := range goodResponse.Result().Cookies() {
		if cookie.Name == "objectshare_jwt" {
			rawToken = cookie.Value
		}
	}
	claims, err := handler.jwt.Parse(rawToken)
	if err != nil || claims.Subject != user.ID || claims.Role != db.RoleUser || claims.TokenVersion != 1 {
		t.Fatalf("login JWT is invalid: claims=%#v err=%v", claims, err)
	}
}

func TestAPILoginBearerAuthenticationAndRevocation(t *testing.T) {
	repository := newAuthMemoryRepository()
	hash, _ := appauth.HashPassword("a sufficiently long password")
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "user@example.com", DisplayName: "User", PasswordHash: hash, Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[user.ID] = user
	handler := newAuthTestHandler(t, repository, false)

	login := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"user@example.com","password":"a sufficiently long password"}`))
	login.Header.Set("Content-Type", "application/json")
	loginResponse := httptest.NewRecorder()
	handler.APILogin(loginResponse, login)
	if loginResponse.Code != http.StatusOK || loginResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("API login status=%d cache-control=%q body=%q", loginResponse.Code, loginResponse.Header().Get("Cache-Control"), loginResponse.Body.String())
	}
	var payload struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(loginResponse.Body.Bytes(), &payload); err != nil || payload.AccessToken == "" || payload.TokenType != "Bearer" || payload.ExpiresIn <= 0 {
		t.Fatalf("invalid API login payload: %#v err=%v", payload, err)
	}
	if len(loginResponse.Result().Cookies()) != 0 {
		t.Fatal("bearer-token login unexpectedly set a browser cookie")
	}

	protected := handler.Authenticate(handler.RequireUser(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if currentIdentity(request).Transport != transportBearer {
			t.Error("bearer JWT transport was not recorded")
		}
		writer.WriteHeader(http.StatusNoContent)
	})))
	request := httptest.NewRequest(http.MethodGet, "/account", nil)
	request.Header.Set("Authorization", "Bearer "+payload.AccessToken)
	response := httptest.NewRecorder()
	protected.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("bearer JWT status=%d", response.Code)
	}

	logout := handler.Authenticate(handler.RequireUser(http.HandlerFunc(handler.APILogout)))
	logoutRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	logoutRequest.Header.Set("Authorization", "Bearer "+payload.AccessToken)
	logoutResponse := httptest.NewRecorder()
	logout.ServeHTTP(logoutResponse, logoutRequest)
	if logoutResponse.Code != http.StatusNoContent || len(repository.revoked) != 1 {
		t.Fatalf("bearer logout status=%d revoked=%d", logoutResponse.Code, len(repository.revoked))
	}

	reuse := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	reuse.Header.Set("Authorization", "Bearer "+payload.AccessToken)
	reuseResponse := httptest.NewRecorder()
	protected.ServeHTTP(reuseResponse, reuse)
	if reuseResponse.Code != http.StatusUnauthorized {
		t.Fatalf("revoked bearer JWT status=%d", reuseResponse.Code)
	}
}

func TestAPIRejectsMalformedLoginJSONAndStaleJWT(t *testing.T) {
	repository := newAuthMemoryRepository()
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "user@example.com", DisplayName: "User", Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[user.ID] = user
	handler := newAuthTestHandler(t, repository, false)
	for _, body := range []string{
		`{"email":"user@example.com","password":"password","unexpected":true}`,
		`{"email":"user@example.com","password":"password"}{}`,
	} {
		response := httptest.NewRecorder()
		handler.APILogin(response, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body)))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("malformed API login body %q status=%d", body, response.Code)
		}
	}

	token, _ := issueTestJWT(t, handler, user)
	if _, err := repository.UpdatePassword(context.Background(), user.ID, "new hash"); err != nil {
		t.Fatal(err)
	}
	protected := handler.Authenticate(handler.RequireUser(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})))
	for name, candidate := range map[string]string{"stale": token, "tampered": token + "x"} {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
		request.Header.Set("Authorization", "Bearer "+candidate)
		response := httptest.NewRecorder()
		protected.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("%s JWT status=%d", name, response.Code)
		}
	}
}

func TestAuthenticationRejectsDisabledUserAndMissingCSRF(t *testing.T) {
	repository := newAuthMemoryRepository()
	hash, _ := appauth.HashPassword("a sufficiently long password")
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "user@example.com", DisplayName: "User", PasswordHash: hash, Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[user.ID] = user
	handler := newAuthTestHandler(t, repository, false)
	token, claims := issueTestJWT(t, handler, user)

	logout := handler.Authenticate(handler.RequireUser(http.HandlerFunc(handler.Logout)))
	request := formRequest("/logout", url.Values{})
	request.AddCookie(&http.Cookie{Name: "objectshare_jwt", Value: token})
	response := httptest.NewRecorder()
	logout.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || len(repository.revoked) != 0 {
		t.Fatalf("missing CSRF status=%d revoked=%d", response.Code, len(repository.revoked))
	}
	validRequest := formRequest("/logout", url.Values{"csrf_token": {claims.CSRF}})
	validRequest.AddCookie(&http.Cookie{Name: "objectshare_jwt", Value: token})
	validResponse := httptest.NewRecorder()
	logout.ServeHTTP(validResponse, validRequest)
	if validResponse.Code != http.StatusSeeOther || len(repository.revoked) != 1 {
		t.Fatalf("JWT logout status=%d revoked=%d", validResponse.Code, len(repository.revoked))
	}

	freshToken, _ := issueTestJWT(t, handler, user)
	user.Active = false
	disabledRequest := formRequest("/logout", url.Values{})
	disabledRequest.AddCookie(&http.Cookie{Name: "objectshare_jwt", Value: freshToken})
	disabled := httptest.NewRecorder()
	logout.ServeHTTP(disabled, disabledRequest)
	if disabled.Code != http.StatusUnauthorized {
		t.Fatalf("disabled user status=%d", disabled.Code)
	}
}

func TestAccountThemePreferencePersistsAndRequiresCSRF(t *testing.T) {
	repository := newAuthMemoryRepository()
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "user@example.com", DisplayName: "User", Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[user.ID] = user
	handler := newAuthTestHandler(t, repository, false)
	token, claims := issueTestJWT(t, handler, user)
	protected := handler.Authenticate(handler.RequireUser(http.HandlerFunc(handler.UpdateTheme)))

	request := formRequest("/account/theme", url.Values{"theme": {"dark"}})
	request.AddCookie(&http.Cookie{Name: "objectshare_jwt", Value: token})
	response := httptest.NewRecorder()
	protected.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || repository.users[user.ID].DarkMode {
		t.Fatalf("theme update without CSRF status=%d dark=%t", response.Code, repository.users[user.ID].DarkMode)
	}

	request = formRequest("/account/theme", url.Values{"theme": {"dark"}, "csrf_token": {claims.CSRF}})
	request.AddCookie(&http.Cookie{Name: "objectshare_jwt", Value: token})
	response = httptest.NewRecorder()
	protected.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/account?message=theme" || !repository.users[user.ID].DarkMode {
		t.Fatalf("dark theme update status=%d location=%q dark=%t", response.Code, response.Header().Get("Location"), repository.users[user.ID].DarkMode)
	}

	request = formRequest("/account/theme", url.Values{"theme": {"sepia"}, "csrf_token": {claims.CSRF}})
	request.AddCookie(&http.Cookie{Name: "objectshare_jwt", Value: token})
	response = httptest.NewRecorder()
	protected.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Choose either the light or dark theme.") || !repository.users[user.ID].DarkMode {
		t.Fatalf("invalid theme status=%d body=%q dark=%t", response.Code, response.Body.String(), repository.users[user.ID].DarkMode)
	}

	request = formRequest("/account/theme", url.Values{"theme": {"light"}, "csrf_token": {claims.CSRF}})
	request.AddCookie(&http.Cookie{Name: "objectshare_jwt", Value: token})
	response = httptest.NewRecorder()
	protected.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || repository.users[user.ID].DarkMode {
		t.Fatalf("light theme update status=%d dark=%t", response.Code, repository.users[user.ID].DarkMode)
	}
}

func TestNormalUserCannotReachAdministratorHandler(t *testing.T) {
	repository := newAuthMemoryRepository()
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "user@example.com", DisplayName: "User", Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[user.ID] = user
	handler := newAuthTestHandler(t, repository, false)
	token, _ := issueTestJWT(t, handler, user)
	protected := handler.Authenticate(handler.RequireAdmin(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})))
	request := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	request.AddCookie(&http.Cookie{Name: "objectshare_jwt", Value: token})
	response := httptest.NewRecorder()
	protected.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("normal user reached administrator handler: status=%d", response.Code)
	}
}

func TestAdministratorUserListDisplaysQuotaAccountedStorage(t *testing.T) {
	repository := newAuthMemoryRepository()
	admin := &db.User{ID: "11111111-1111-4111-8111-111111111111", Email: "admin@example.com", DisplayName: "Admin", Role: db.RoleAdmin, Active: true, TokenVersion: 1}
	user := &db.User{ID: "22222222-2222-4222-8222-222222222222", Email: "user@example.com", DisplayName: "User", Role: db.RoleUser, Active: true, TokenVersion: 1}
	for _, candidate := range []*db.User{admin, user} {
		if err := repository.CreateUser(context.Background(), candidate); err != nil {
			t.Fatal(err)
		}
	}
	repository.files["complete"] = &db.FileList{FileOwner: &user.ID, FileSize: mebibyte, UploadStatus: "complete"}
	repository.files["pending"] = &db.FileList{FileOwner: &user.ID, FileSize: mebibyte / 2, UploadStatus: "pending"}
	repository.files["failed"] = &db.FileList{FileOwner: &user.ID, FileSize: 20 * mebibyte, UploadStatus: "failed"}
	repository.files["anonymous"] = &db.FileList{FileSize: 40 * mebibyte, UploadStatus: "complete"}
	handler := newAuthTestHandler(t, repository, false)

	request := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: admin, Claims: &appauth.Claims{CSRF: "csrf"}}))
	response := httptest.NewRecorder()
	handler.AdminUsers(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "total=1.5 MiB") || !strings.Contains(response.Body.String(), "user@example.com=1.5 MiB") {
		t.Fatalf("administrator storage display status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestAdministratorPasswordResetValidatesAndInvalidatesJWTs(t *testing.T) {
	repository := newAuthMemoryRepository()
	admin := &db.User{ID: "11111111-1111-4111-8111-111111111111", Email: "admin@example.com", DisplayName: "Admin", Role: db.RoleAdmin, Active: true, TokenVersion: 2}
	user := &db.User{ID: "22222222-2222-4222-8222-222222222222", Email: "user@example.com", DisplayName: "User", PasswordHash: "old hash", Role: db.RoleUser, Active: true, TokenVersion: 7}
	for _, candidate := range []*db.User{admin, user} {
		if err := repository.CreateUser(context.Background(), candidate); err != nil {
			t.Fatal(err)
		}
	}
	handler := newAuthTestHandler(t, repository, false)
	router := chi.NewRouter()
	router.With(handler.RequireAdmin).Post("/{id}", handler.AdminResetPassword)

	request := formRequest("/"+user.ID, url.Values{"password": {"a sufficiently long password"}, "password_confirm": {"a sufficiently long password"}})
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: admin, Claims: &appauth.Claims{CSRF: "csrf"}, Transport: transportCookie}))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || repository.users[user.ID].TokenVersion != 7 {
		t.Fatalf("reset without CSRF status=%d version=%d", response.Code, repository.users[user.ID].TokenVersion)
	}

	request = formRequest("/"+user.ID, url.Values{"csrf_token": {"csrf"}, "password": {"a sufficiently long password"}, "password_confirm": {"different sufficiently long password"}})
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: admin, Claims: &appauth.Claims{CSRF: "csrf"}, Transport: transportCookie}))
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Passwords do not match.") || repository.users[user.ID].TokenVersion != 7 {
		t.Fatalf("mismatched reset status=%d version=%d body=%q", response.Code, repository.users[user.ID].TokenVersion, response.Body.String())
	}

	request = formRequest("/"+user.ID, url.Values{"csrf_token": {"csrf"}, "password": {"a new sufficiently long password"}, "password_confirm": {"a new sufficiently long password"}})
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: admin, Claims: &appauth.Claims{CSRF: "csrf"}, Transport: transportCookie}))
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	updated := repository.users[user.ID]
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/admin/users?message=password" || updated.TokenVersion != 8 || !appauth.VerifyPassword("a new sufficiently long password", updated.PasswordHash) {
		t.Fatalf("valid reset status=%d location=%q version=%d", response.Code, response.Header().Get("Location"), updated.TokenVersion)
	}

	request = formRequest("/"+user.ID, url.Values{"password": {"another sufficiently long password"}, "password_confirm": {"another sufficiently long password"}})
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: user, Claims: &appauth.Claims{CSRF: "csrf"}, Transport: transportBearer}))
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || repository.users[user.ID].TokenVersion != 8 {
		t.Fatalf("non-administrator reset status=%d version=%d", response.Code, repository.users[user.ID].TokenVersion)
	}
}

func TestAuthenticatedUploadIsOwnedByAccount(t *testing.T) {
	repository := newAuthMemoryRepository()
	user := &db.User{ID: "4d754f93-6968-4dea-a5f8-87cb074375f1", Email: "user@example.com", DisplayName: "User", Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[user.ID] = user
	handler := newAuthTestHandler(t, repository, false)
	handler.config.Upload = &config.UploadConfig{GuestEnabled: false}
	rejectedBody := new(bytes.Buffer)
	rejectedForm := multipart.NewWriter(rejectedBody)
	rejectedPart, _ := rejectedForm.CreateFormFile("file", "rejected.txt")
	_, _ = rejectedPart.Write([]byte("missing csrf"))
	_ = rejectedForm.Close()
	rejectedRequest := httptest.NewRequest(http.MethodPost, "/api/v1/upload", rejectedBody)
	rejectedRequest.Header.Set("Content-Type", rejectedForm.FormDataContentType())
	rejectedRequest = rejectedRequest.WithContext(context.WithValue(rejectedRequest.Context(), identityContextKey{}, &identity{User: user, Claims: &appauth.Claims{CSRF: "csrf"}, Transport: transportCookie}))
	rejectedResponse := httptest.NewRecorder()
	handler.Upload(rejectedResponse, rejectedRequest)
	if rejectedResponse.Code != http.StatusForbidden || len(repository.files) != 0 {
		t.Fatalf("cookie-authenticated upload without CSRF status=%d files=%d", rejectedResponse.Code, len(repository.files))
	}

	body := new(bytes.Buffer)
	form := multipart.NewWriter(body)
	_ = form.WriteField("csrf_token", "csrf")
	part, _ := form.CreateFormFile("file", "account.txt")
	_, _ = part.Write([]byte("account-owned contents"))
	_ = form.Close()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/upload", body)
	request.Header.Set("Content-Type", form.FormDataContentType())
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: user, Claims: &appauth.Claims{CSRF: "csrf"}}))
	response := httptest.NewRecorder()
	handler.Upload(response, request)
	if response.Code != http.StatusSeeOther || len(repository.files) != 1 {
		t.Fatalf("upload status=%d files=%d", response.Code, len(repository.files))
	}
	for _, file := range repository.files {
		if file.FileOwner == nil || *file.FileOwner != user.ID || file.IsAnonymousUpload || !handler.isOwner(request, file) {
			t.Fatalf("authenticated upload ownership is wrong: %#v", file)
		}
	}
}

func TestAccountQuotasAreDatabaseBackedAndPerUser(t *testing.T) {
	repository := newAuthMemoryRepository()
	userOne := &db.User{ID: "11111111-1111-4111-8111-111111111111", Email: "one@example.com", DisplayName: "One", Role: db.RoleUser, Active: true, TokenVersion: 1, UploadQuotaBytes: mebibyte}
	userTwo := &db.User{ID: "22222222-2222-4222-8222-222222222222", Email: "two@example.com", DisplayName: "Two", Role: db.RoleUser, Active: true, TokenVersion: 1, UploadQuotaBytes: 2 * mebibyte}
	admin := &db.User{ID: "33333333-3333-4333-8333-333333333333", Email: "admin@example.com", DisplayName: "Admin", Role: db.RoleAdmin, Active: true, TokenVersion: 1, UploadQuotaBytes: mebibyte}
	for _, user := range []*db.User{userOne, userTwo, admin} {
		if err := repository.CreateUser(context.Background(), user); err != nil {
			t.Fatal(err)
		}
	}
	repository.files["user-one-existing"] = &db.FileList{FileID: "user-one-existing", FileOwner: &userOne.ID, FileSize: 900 * 1024, UploadStatus: "complete"}
	repository.files["admin-existing"] = &db.FileList{FileID: "admin-existing", FileOwner: &admin.ID, FileSize: 900 * 1024, UploadStatus: "complete"}
	handler := newAuthTestHandler(t, repository, false)

	uploadAs := func(user *db.User, size int) *httptest.ResponseRecorder {
		request := multipartUploadRequest(t, bytes.Repeat([]byte("x"), size))
		request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: user, Transport: transportBearer}))
		response := httptest.NewRecorder()
		handler.Upload(response, request)
		return response
	}
	if response := uploadAs(userOne, 200*1024); response.Code != http.StatusRequestEntityTooLarge || response.Header().Get("X-Upload-Quota-Scope") != "user" {
		t.Fatalf("first user's quota status=%d scope=%q", response.Code, response.Header().Get("X-Upload-Quota-Scope"))
	}
	if response := uploadAs(userTwo, 200*1024); response.Code != http.StatusSeeOther {
		t.Fatalf("second user's independent quota status=%d body=%q", response.Code, response.Body.String())
	}
	if response := uploadAs(admin, 200*1024); response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("administrator bypassed its account quota: status=%d body=%q", response.Code, response.Body.String())
	}
	if err := repository.AdminUpdateUser(context.Background(), admin.ID, db.RoleAdmin, true); err != nil {
		t.Fatal(err)
	}
	if repository.users[admin.ID].UploadQuotaBytes != mebibyte {
		t.Fatal("role/access update changed the user's quota")
	}
	if err := repository.UpdateUploadQuota(context.Background(), userOne.ID, 2*mebibyte); err != nil {
		t.Fatal(err)
	}
	if response := uploadAs(userOne, 200*1024); response.Code != http.StatusSeeOther {
		t.Fatalf("upgraded user's upload status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestAdministratorQuotaUpdateIsAuthorizedAndDoesNotInvalidateJWTs(t *testing.T) {
	repository := newAuthMemoryRepository()
	admin := &db.User{ID: "11111111-1111-4111-8111-111111111111", Email: "admin@example.com", DisplayName: "Admin", Role: db.RoleAdmin, Active: true, TokenVersion: 3}
	user := &db.User{ID: "22222222-2222-4222-8222-222222222222", Email: "user@example.com", DisplayName: "User", Role: db.RoleUser, Active: true, TokenVersion: 7}
	for _, candidate := range []*db.User{admin, user} {
		if err := repository.CreateUser(context.Background(), candidate); err != nil {
			t.Fatal(err)
		}
	}
	handler := newAuthTestHandler(t, repository, false)
	router := chi.NewRouter()
	router.With(handler.RequireAdmin).Post("/{id}", handler.AdminUpdateUploadQuota)

	request := formRequest("/"+user.ID, url.Values{"upload_quota_mib": {"25"}})
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: admin, Claims: &appauth.Claims{CSRF: "csrf"}, Transport: transportBearer}))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || repository.users[user.ID].UploadQuotaBytes != 25*mebibyte {
		t.Fatalf("quota update status=%d quota=%d body=%q", response.Code, repository.users[user.ID].UploadQuotaBytes, response.Body.String())
	}
	if repository.users[user.ID].TokenVersion != 7 {
		t.Fatal("quota update unnecessarily invalidated the user's JWTs")
	}

	request = formRequest("/"+user.ID, url.Values{"upload_quota_mib": {"50"}})
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: user, Transport: transportBearer}))
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || repository.users[user.ID].UploadQuotaBytes != 25*mebibyte {
		t.Fatalf("non-admin quota update status=%d quota=%d", response.Code, repository.users[user.ID].UploadQuotaBytes)
	}
}

func TestAdministratorPaidStatusUpdateIsAuthorizedAndDoesNotInvalidateJWTs(t *testing.T) {
	repository := newAuthMemoryRepository()
	admin := &db.User{ID: "11111111-1111-4111-8111-111111111111", Email: "admin@example.com", DisplayName: "Admin", Role: db.RoleAdmin, Active: true, TokenVersion: 3}
	user := &db.User{ID: "22222222-2222-4222-8222-222222222222", Email: "user@example.com", DisplayName: "User", Role: db.RoleUser, Active: true, TokenVersion: 7}
	for _, candidate := range []*db.User{admin, user} {
		if err := repository.CreateUser(context.Background(), candidate); err != nil {
			t.Fatal(err)
		}
	}
	handler := newAuthTestHandler(t, repository, false)
	router := chi.NewRouter()
	router.With(handler.RequireAdmin).Post("/{id}", handler.AdminUpdatePaidStatus)

	request := formRequest("/"+user.ID, url.Values{"is_paid": {"true"}})
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: admin, Claims: &appauth.Claims{CSRF: "csrf"}, Transport: transportBearer}))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || !repository.users[user.ID].IsPaid {
		t.Fatalf("paid update status=%d paid=%t body=%q", response.Code, repository.users[user.ID].IsPaid, response.Body.String())
	}
	if repository.users[user.ID].TokenVersion != 7 {
		t.Fatal("paid-status update unnecessarily invalidated the user's JWTs")
	}
	request = formRequest("/"+user.ID, url.Values{"is_paid": {"yes"}})
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: admin, Claims: &appauth.Claims{CSRF: "csrf"}, Transport: transportBearer}))
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !repository.users[user.ID].IsPaid || !strings.Contains(response.Body.String(), "Choose a valid payment status.") {
		t.Fatalf("invalid paid update status=%d paid=%t body=%q", response.Code, repository.users[user.ID].IsPaid, response.Body.String())
	}

	request = formRequest("/"+user.ID, url.Values{"is_paid": {"false"}})
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: user, Transport: transportBearer}))
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || !repository.users[user.ID].IsPaid {
		t.Fatalf("non-admin paid update status=%d paid=%t", response.Code, repository.users[user.ID].IsPaid)
	}
}

func TestAdministratorCanCreatePaidAccount(t *testing.T) {
	repository := newAuthMemoryRepository()
	admin := &db.User{ID: "11111111-1111-4111-8111-111111111111", Email: "admin@example.com", DisplayName: "Admin", Role: db.RoleAdmin, Active: true, TokenVersion: 1}
	if err := repository.CreateUser(context.Background(), admin); err != nil {
		t.Fatal(err)
	}
	handler := newAuthTestHandler(t, repository, false)
	request := formRequest("/admin/users", url.Values{
		"email": {"paid@example.com"}, "display_name": {"Paid User"}, "password": {"a sufficiently long password"},
		"password_confirm": {"a sufficiently long password"}, "role": {db.RoleUser}, "is_paid": {"on"}, "upload_quota_mib": {"25"},
	})
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: admin, Transport: transportBearer}))
	response := httptest.NewRecorder()
	handler.AdminCreateUser(response, request)
	created, err := repository.UserByEmail(context.Background(), "paid@example.com")
	if response.Code != http.StatusSeeOther || err != nil || !created.IsPaid || created.UploadQuotaBytes != 25*mebibyte {
		t.Fatalf("create paid user status=%d user=%#v err=%v body=%q", response.Code, created, err, response.Body.String())
	}
}

func TestUploadQuotaFormValidation(t *testing.T) {
	for _, value := range []string{"-1", "1.5", "8796093022208", "not-a-number"} {
		if _, err := uploadQuotaFromForm(value); err == nil {
			t.Fatalf("upload quota %q was accepted", value)
		}
	}
	for _, test := range []struct {
		value string
		want  int64
	}{{"", 0}, {"0", 0}, {"25", 25 * mebibyte}} {
		got, err := uploadQuotaFromForm(test.value)
		if err != nil || got != test.want {
			t.Fatalf("upload quota %q = %d, %v; want %d", test.value, got, err, test.want)
		}
	}
}

func TestFinalAdministratorCannotLoseAccess(t *testing.T) {
	repository := newAuthMemoryRepository()
	admin := &db.User{ID: "admin", Email: "admin@example.com", Role: db.RoleAdmin, Active: true}
	repository.users[admin.ID] = admin
	if err := repository.AdminUpdateUser(context.Background(), admin.ID, db.RoleUser, true); !errors.Is(err, db.ErrLastAdmin) {
		t.Fatalf("demoting final administrator returned %v", err)
	}
	if err := repository.AdminUpdateUser(context.Background(), admin.ID, db.RoleAdmin, false); !errors.Is(err, db.ErrLastAdmin) {
		t.Fatalf("disabling final administrator returned %v", err)
	}
}

func TestLoginRedirectsUseOnlyServerOwnedDestinations(t *testing.T) {
	for _, test := range []struct {
		value, expected string
	}{
		{loginDestinationAdminUsers, loginDestinationAdminUsers},
		{loginDestinationAdminSettings, loginDestinationAdminSettings},
		{"", ""},
		{"account", ""},
		{"/account?tab=files", ""},
		{"https://attacker.example", ""},
		{"//attacker.example", ""},
		{"/\\attacker.example", ""},
		{"/%5c%5cattacker.example", ""},
		{"/%2f%2fattacker.example", ""},
		{"/ok\r\nLocation: https://attacker.example", ""},
	} {
		if got := safeLoginDestination(test.value); got != test.expected {
			t.Errorf("safeLoginDestination(%q) = %q, want %q", test.value, got, test.expected)
		}
	}

	handler := &Handler{}
	for _, test := range []struct {
		destination, expected string
	}{
		{loginDestinationAdminUsers, "/admin/users"},
		{loginDestinationAdminSettings, "/admin/settings"},
		{"https://attacker.example", "/account"},
		{"//attacker.example", "/account"},
		{"/ok\r\nLocation: https://attacker.example", "/account"},
	} {
		request := httptest.NewRequest(http.MethodPost, "/login", nil)
		response := httptest.NewRecorder()
		handler.redirectAfterLogin(response, request, test.destination)
		if response.Code != http.StatusSeeOther || response.Header().Get("Location") != test.expected {
			t.Errorf("destination %q redirected to %q with status %d, want %q", test.destination, response.Header().Get("Location"), response.Code, test.expected)
		}
	}

	htmxRequest := httptest.NewRequest(http.MethodPost, "/login", nil)
	htmxRequest.Header.Set("HX-Request", "true")
	htmxResponse := httptest.NewRecorder()
	handler.redirectAfterLogin(htmxResponse, htmxRequest, "https://attacker.example")
	if htmxResponse.Code != http.StatusNoContent || htmxResponse.Header().Get("HX-Redirect") != "/account" {
		t.Errorf("forged HTMX destination redirected to %q with status %d", htmxResponse.Header().Get("HX-Redirect"), htmxResponse.Code)
	}

	for _, test := range []struct {
		path, expected string
	}{
		{"/account", "/login"},
		{"/admin/users", "/login?next=admin-users"},
		{"/admin/settings", "/login?next=admin-settings"},
		{"//attacker.example", "/login"},
	} {
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		response := httptest.NewRecorder()
		handler.redirectToLogin(response, request)
		if response.Code != http.StatusSeeOther || response.Header().Get("Location") != test.expected {
			t.Errorf("protected path %q redirected to %q with status %d, want %q", test.path, response.Header().Get("Location"), response.Code, test.expected)
		}
	}
}

func newAuthTestHandler(t *testing.T, repository *authMemoryRepository, secure bool) *Handler {
	t.Helper()
	templates := fstest.MapFS{
		"template/setup.html":          {Data: []byte(`{{define "setup.html"}}{{.CSRF}}{{.Error}}{{end}}`)},
		"template/login.html":          {Data: []byte(`{{define "login.html"}}{{.CSRF}}{{.Error}}{{end}}`)},
		"template/signup.html":         {Data: []byte(`{{define "signup.html"}}{{.CSRF}}{{.Error}}{{end}}`)},
		"template/account.html":        {Data: []byte(`{{define "account.html"}}{{.User.Email}}{{.Error}}{{end}}`)},
		"template/admin_users.html":    {Data: []byte(`{{define "admin_users.html"}}{{.Error}}total={{.TotalStorageUsed}};{{range .Users}}{{.Email}}={{.StorageUsed}};{{end}}{{end}}`)},
		"template/admin_settings.html": {Data: []byte(`{{define "admin_settings.html"}}{{.Error}}{{.Message}}{{end}}`)},
		"template/index.html":          {Data: []byte(`{{define "index.html"}}index{{end}}`)},
		"template/file_view.html":      {Data: []byte(`{{define "file_view.html"}}file{{end}}`)},
		"template/oauth_error.html":    {Data: []byte(`{{define "oauth_error.html"}}{{.Error}}{{end}}`)},
		"template/branding.css":        {Data: []byte(`.site-logo { height: 2rem; }`)},
		"template/theme.js":            {Data: []byte(`console.log("theme test")`)},
		"template/upload.js":           {Data: []byte(`console.log("test")`)},
		"template/captcha.js":          {Data: []byte(`console.log("captcha test")`)},
		"template/admin_users.js":      {Data: []byte(`console.log("admin users test")`)},
		"template/admin_users.css":     {Data: []byte(`.admin-user-dialog { display: block; }`)},
	}
	cfg := &config.ServiceConfig{MaxFileSize: 1, StorageService: "filesystem", SecureCookies: secure, SettingsKey: "test-only-settings-key-with-at-least-32-bytes", Encryption: &config.EncryptionConfig{}, Auth: &config.AuthConfig{SignupEnabled: true, JWTSecret: "test-only-jwt-secret-with-at-least-32-bytes", TokenLifetime: config.Duration(12 * time.Hour)}}
	handler, err := New(cfg, repository, &memoryStorage{objects: make(map[string][]byte)}, templates, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func issueTestJWT(t *testing.T, handler *Handler, user *db.User) (string, *appauth.Claims) {
	t.Helper()
	token, claims, err := handler.jwt.Issue(user.ID, user.Role, user.TokenVersion, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return token, claims
}

func formRequest(path string, values url.Values) *http.Request {
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return request
}

var _ db.AuthRepository = (*authMemoryRepository)(nil)
var _ db.Repository = (*authMemoryRepository)(nil)
var _ db.SettingsRepository = (*authMemoryRepository)(nil)
var _ service.ObjectStore = (*memoryStorage)(nil)
