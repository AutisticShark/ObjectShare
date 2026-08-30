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
)

type authMemoryRepository struct {
	*memoryRepository
	users     map[string]*db.User
	revoked   map[string]time.Time
	throttles map[string]int
}

func newAuthMemoryRepository() *authMemoryRepository {
	return &authMemoryRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}, users: make(map[string]*db.User), revoked: make(map[string]time.Time), throttles: make(map[string]int)}
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
func (repository *authMemoryRepository) ListUsers(context.Context) ([]db.User, error) {
	users := make([]db.User, 0, len(repository.users))
	for _, user := range repository.users {
		users = append(users, *user)
	}
	return users, nil
}
func (repository *authMemoryRepository) UpdateProfile(_ context.Context, id, email, name string) error {
	user, ok := repository.users[id]
	if !ok {
		return db.ErrNotFound
	}
	user.Email, user.DisplayName = email, name
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
func (repository *authMemoryRepository) DeleteUser(_ context.Context, id string) error {
	if _, ok := repository.users[id]; !ok {
		return db.ErrNotFound
	}
	delete(repository.users, id)
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

	goodRequest := formRequest("/login", url.Values{"csrf_token": {csrf}, "email": {user.Email}, "password": {"a sufficiently long password"}})
	goodRequest.AddCookie(preAuthCookie)
	goodResponse := httptest.NewRecorder()
	handler.Login(goodResponse, goodRequest)
	if goodResponse.Code != http.StatusSeeOther {
		t.Fatalf("good login status=%d", goodResponse.Code)
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

func TestAuthenticatedUploadIsOwnedByAccount(t *testing.T) {
	repository := newAuthMemoryRepository()
	user := &db.User{ID: "4d754f93-6968-4dea-a5f8-87cb074375f1", Email: "user@example.com", DisplayName: "User", Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[user.ID] = user
	handler := newAuthTestHandler(t, repository, false)
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

func TestSafeNextRejectsExternalRedirects(t *testing.T) {
	for _, value := range []string{"https://attacker.example", "//attacker.example", "/ok\r\nLocation: bad"} {
		if got := safeNext(value); got != "" {
			t.Fatalf("safeNext(%q) = %q", value, got)
		}
	}
	if got := safeNext("/account?tab=files"); got != "/account?tab=files" {
		t.Fatalf("valid relative redirect = %q", got)
	}
}

func newAuthTestHandler(t *testing.T, repository *authMemoryRepository, secure bool) *Handler {
	t.Helper()
	templates := fstest.MapFS{
		"template/setup.html":       {Data: []byte(`{{define "setup.html"}}{{.CSRF}}{{.Error}}{{end}}`)},
		"template/login.html":       {Data: []byte(`{{define "login.html"}}{{.CSRF}}{{.Error}}{{end}}`)},
		"template/signup.html":      {Data: []byte(`{{define "signup.html"}}{{.CSRF}}{{.Error}}{{end}}`)},
		"template/account.html":     {Data: []byte(`{{define "account.html"}}{{.User.Email}}{{end}}`)},
		"template/admin_users.html": {Data: []byte(`{{define "admin_users.html"}}{{len .Users}}{{end}}`)},
		"template/index.html":       {Data: []byte(`{{define "index.html"}}index{{end}}`)},
		"template/file_view.html":   {Data: []byte(`{{define "file_view.html"}}file{{end}}`)},
		"template/upload.js":        {Data: []byte(`console.log("test")`)},
	}
	cfg := &config.ServiceConfig{MaxFileSize: 1, StorageService: "filesystem", SecureCookies: secure, Encryption: &config.EncryptionConfig{}, Auth: &config.AuthConfig{SignupEnabled: true, JWTSecret: "test-only-jwt-secret-with-at-least-32-bytes", TokenLifetime: config.Duration(12 * time.Hour)}}
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
var _ service.ObjectStore = (*memoryStorage)(nil)
