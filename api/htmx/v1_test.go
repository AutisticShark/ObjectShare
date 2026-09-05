package htmx

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/AutisticShark/ObjectShare/service"
	"github.com/go-chi/chi/v5"
)

type memoryRepository struct {
	mu         sync.Mutex
	files      map[string]*db.FileList
	quotaBytes map[string]int64
}

func (repository *memoryRepository) Create(_ context.Context, file *db.FileList) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	copy := *file
	repository.files[file.FileID] = &copy
	return nil
}
func (repository *memoryRepository) ReserveUpload(_ context.Context, file *db.FileList) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	var userID string
	if file.FileOwner != nil {
		userID = *file.FileOwner
	}
	usage := repository.uploadUsage(userID)
	if usage.Limit > 0 && (usage.Used >= usage.Limit || file.FileSize > usage.Limit-usage.Used) {
		return &db.UploadQuotaError{Scope: "user", Used: usage.Used, Limit: usage.Limit, Requested: file.FileSize}
	}
	copy := *file
	repository.files[file.FileID] = &copy
	return nil
}
func (repository *memoryRepository) UploadUsage(_ context.Context, userID string) (db.UploadUsage, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.uploadUsage(userID), nil
}
func (repository *memoryRepository) uploadUsage(userID string) db.UploadUsage {
	usage := db.UploadUsage{Limit: repository.quotaBytes[userID]}
	for _, file := range repository.files {
		if file.UploadStatus != "pending" && file.UploadStatus != "complete" && file.UploadStatus != "deleting" {
			continue
		}
		if file.FileOwner != nil && *file.FileOwner == userID {
			usage.Used += file.FileSize
		}
	}
	return usage
}
func (repository *memoryRepository) Get(_ context.Context, id string) (*db.FileList, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	file, ok := repository.files[id]
	if !ok {
		return nil, db.ErrNotFound
	}
	copy := *file
	return &copy, nil
}
func (repository *memoryRepository) CompleteUpload(_ context.Context, id string) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	file, ok := repository.files[id]
	if !ok || file.UploadStatus != "pending" {
		return db.ErrNotFound
	}
	file.UploadStatus = "complete"
	file.UploadExpiresAt = nil
	return nil
}
func (repository *memoryRepository) FinalizeUpload(_ context.Context, id, sha256Sum, sha3Sum string, encrypted bool, encryptionMethod string) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	file, ok := repository.files[id]
	if !ok || file.UploadStatus != "pending" {
		return db.ErrNotFound
	}
	file.FileSHA256 = sha256Sum
	file.FileSHA3 = sha3Sum
	file.IsEncrypted = encrypted
	file.EncryptionMethod = encryptionMethod
	file.UploadStatus = "complete"
	file.ChecksumStatus = "verified"
	file.UploadExpiresAt = nil
	return nil
}
func (repository *memoryRepository) ExpiredUploads(_ context.Context, before time.Time, limit int) ([]db.FileList, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	files := make([]db.FileList, 0, limit)
	for _, file := range repository.files {
		if file.UploadStatus == "pending" && file.UploadExpiresAt != nil && file.UploadExpiresAt.Before(before) {
			files = append(files, *file)
			if len(files) == limit {
				break
			}
		}
	}
	return files, nil
}
func (repository *memoryRepository) Rename(_ context.Context, id, name string) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	file, ok := repository.files[id]
	if !ok {
		return db.ErrNotFound
	}
	file.FileName = name
	return nil
}
func (repository *memoryRepository) Delete(_ context.Context, id string) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if _, ok := repository.files[id]; !ok {
		return db.ErrNotFound
	}
	delete(repository.files, id)
	return nil
}
func (*memoryRepository) Ping(context.Context) error { return nil }

type memoryStorage struct{ objects map[string][]byte }

func (storage *memoryStorage) Put(_ context.Context, key string, reader io.Reader, _ int64, _ string) error {
	data, err := io.ReadAll(reader)
	if err == nil {
		storage.objects[key] = data
	}
	return err
}
func (storage *memoryStorage) Open(_ context.Context, key string) (io.ReadCloser, error) {
	data, ok := storage.objects[key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}
func (storage *memoryStorage) Delete(_ context.Context, key string) error {
	delete(storage.objects, key)
	return nil
}
func (*memoryStorage) PresignGet(context.Context, string, string) (string, error) {
	return "", service.ErrPresignUnsupported
}

type directMemoryStorage struct{ *memoryStorage }

type failingPutStorage struct{ *memoryStorage }

func (*failingPutStorage) Put(context.Context, string, io.Reader, int64, string) error {
	return io.ErrUnexpectedEOF
}

func (*directMemoryStorage) PresignPut(context.Context, string, int64, string) (string, error) {
	return "https://example.r2.cloudflarestorage.com/upload", nil
}
func (*directMemoryStorage) DirectUploadPolicy() service.DirectUploadPolicy {
	return service.DirectUploadPolicy{Expires: time.Hour, MaxSize: service.MaxSinglePartUploadSize, ConnectSources: []string{"https://example.r2.cloudflarestorage.com"}}
}
func (storage *directMemoryStorage) Stat(_ context.Context, key string) (*service.ObjectInfo, error) {
	data, ok := storage.objects[key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return &service.ObjectInfo{Size: int64(len(data)), ContentType: "text/plain"}, nil
}

func TestUploadStoresContentHashesAndOwnerCookie(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	storage := &memoryStorage{objects: make(map[string][]byte)}
	handler := newTestHandler(t, repository, storage)
	body := new(bytes.Buffer)
	form := multipart.NewWriter(body)
	part, err := form.CreateFormFile("file", "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("hello, production")
	_, _ = part.Write(content)
	_ = form.Close()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/upload", body)
	request.Header.Set("Content-Type", form.FormDataContentType())
	response := httptest.NewRecorder()

	handler.Upload(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
	if len(repository.files) != 1 || len(storage.objects) != 1 {
		t.Fatalf("file was not persisted: records=%d objects=%d", len(repository.files), len(storage.objects))
	}
	for _, file := range repository.files {
		if file.FileSHA256 != "db187524cf46ab3f8cfb1415826949720f78657ef1157549a6c9238f8d0da556" {
			t.Fatalf("unexpected SHA-256: %s", file.FileSHA256)
		}
		if !bytes.Equal(storage.objects[file.FileID], content) {
			t.Fatal("stored content differs")
		}
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("secure owner cookie was not set")
	}
}

func TestGuestUploadsCanBeDisabledAcrossUploadPaths(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	storage := &memoryStorage{objects: make(map[string][]byte)}
	cfg := &config.ServiceConfig{MaxFileSize: 1, StorageService: "filesystem", Upload: &config.UploadConfig{GuestEnabled: false}, Encryption: &config.EncryptionConfig{}}
	handler := newTestHandlerConfig(t, cfg, repository, storage)
	response := httptest.NewRecorder()
	handler.Upload(response, multipartUploadRequest(t, []byte("guest")))
	if response.Code != http.StatusForbidden || len(repository.files) != 0 || len(storage.objects) != 0 {
		t.Fatalf("disabled proxied guest upload: status=%d records=%d objects=%d", response.Code, len(repository.files), len(storage.objects))
	}

	directStorage := &directMemoryStorage{&memoryStorage{objects: make(map[string][]byte)}}
	directHandler := newTestHandlerConfig(t, &config.ServiceConfig{MaxFileSize: 1, StorageService: "r2", Upload: &config.UploadConfig{GuestEnabled: false}, Encryption: &config.EncryptionConfig{}}, repository, directStorage)
	directResponse := httptest.NewRecorder()
	directHandler.BeginDirectUpload(directResponse, httptest.NewRequest(http.MethodPost, "/api/v1/uploads/direct", strings.NewReader(`{"file_name":"guest.txt","file_size":5,"content_type":"text/plain"}`)))
	if directResponse.Code != http.StatusForbidden || len(repository.files) != 0 {
		t.Fatalf("disabled direct guest upload: status=%d records=%d", directResponse.Code, len(repository.files))
	}
}

func TestAccountQuotaRejectsBeforeStoring(t *testing.T) {
	user := &db.User{ID: "quota-user", UploadQuotaBytes: mebibyte}
	repository := &memoryRepository{files: map[string]*db.FileList{
		"existing": {FileID: "existing", FileOwner: &user.ID, FileSize: mebibyte, UploadStatus: "complete"},
	}, quotaBytes: map[string]int64{user.ID: user.UploadQuotaBytes}}
	storage := &memoryStorage{objects: make(map[string][]byte)}
	handler := newTestHandlerConfig(t, &config.ServiceConfig{MaxFileSize: 1, StorageService: "filesystem", Upload: &config.UploadConfig{GuestEnabled: true}, Encryption: &config.EncryptionConfig{}}, repository, storage)
	request := multipartUploadRequest(t, []byte("x"))
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: user, Transport: transportBearer}))
	response := httptest.NewRecorder()
	handler.Upload(response, request)
	if response.Code != http.StatusRequestEntityTooLarge || response.Header().Get("X-Upload-Quota-Scope") != "user" {
		t.Fatalf("status=%d scope=%q body=%q", response.Code, response.Header().Get("X-Upload-Quota-Scope"), response.Body.String())
	}
	if len(repository.files) != 1 || len(storage.objects) != 0 {
		t.Fatalf("rejected upload changed storage: records=%d objects=%d", len(repository.files), len(storage.objects))
	}
}

func TestGuestUploadIsNotBlockedByAnotherUsersQuota(t *testing.T) {
	userID := "full-user"
	repository := &memoryRepository{files: map[string]*db.FileList{
		"existing": {FileID: "existing", FileOwner: &userID, FileSize: mebibyte, UploadStatus: "complete"},
	}, quotaBytes: map[string]int64{userID: mebibyte}}
	storage := &memoryStorage{objects: make(map[string][]byte)}
	handler := newTestHandlerConfig(t, &config.ServiceConfig{MaxFileSize: 1, StorageService: "filesystem", Upload: &config.UploadConfig{GuestEnabled: true}, Encryption: &config.EncryptionConfig{}}, repository, storage)
	response := httptest.NewRecorder()
	handler.Upload(response, multipartUploadRequest(t, []byte("guest")))
	if response.Code != http.StatusSeeOther || len(repository.files) != 2 || len(storage.objects) != 1 {
		t.Fatalf("another user's full quota blocked a guest: status=%d records=%d objects=%d", response.Code, len(repository.files), len(storage.objects))
	}
}

func TestFailedProxiedUploadReleasesReservation(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	storage := &failingPutStorage{&memoryStorage{objects: make(map[string][]byte)}}
	cfg := &config.ServiceConfig{MaxFileSize: 1, StorageService: "filesystem", Upload: &config.UploadConfig{GuestEnabled: true}, Encryption: &config.EncryptionConfig{}}
	handler := newTestHandlerConfig(t, cfg, repository, storage)
	response := httptest.NewRecorder()
	request := multipartUploadRequest(t, []byte("failed"))
	canceled, cancel := context.WithCancel(request.Context())
	cancel()
	handler.Upload(response, request.WithContext(canceled))
	if response.Code != http.StatusInternalServerError || len(repository.files) != 0 || len(storage.objects) != 0 {
		t.Fatalf("failed upload retained quota or object: status=%d records=%d objects=%d", response.Code, len(repository.files), len(storage.objects))
	}
}

func TestDirectUploadReservationConsumesAndReleasesQuota(t *testing.T) {
	user := &db.User{ID: "quota-user", UploadQuotaBytes: mebibyte}
	repository := &memoryRepository{files: make(map[string]*db.FileList), quotaBytes: map[string]int64{user.ID: user.UploadQuotaBytes}}
	storage := &directMemoryStorage{&memoryStorage{objects: make(map[string][]byte)}}
	cfg := &config.ServiceConfig{MaxFileSize: 1, StorageService: "r2", Upload: &config.UploadConfig{GuestEnabled: true}, Encryption: &config.EncryptionConfig{}}
	handler := newTestHandlerConfig(t, cfg, repository, storage)
	begin := func() (*httptest.ResponseRecorder, string, string) {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/api/v1/uploads/direct", strings.NewReader(`{"file_name":"account.txt","file_size":614400,"content_type":"text/plain"}`))
		request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: user, Transport: transportBearer}))
		handler.BeginDirectUpload(response, request)
		var authorization struct {
			FileID string `json:"file_id"`
			Token  string `json:"token"`
		}
		if response.Code == http.StatusCreated {
			if err := json.NewDecoder(response.Body).Decode(&authorization); err != nil {
				t.Fatal(err)
			}
		}
		return response, authorization.FileID, authorization.Token
	}
	first, fileID, token := begin()
	if first.Code != http.StatusCreated {
		t.Fatalf("first reservation status=%d body=%q", first.Code, first.Body.String())
	}
	second, _, _ := begin()
	if second.Code != http.StatusRequestEntityTooLarge || second.Header().Get("X-Upload-Quota-Scope") != "user" {
		t.Fatalf("second reservation status=%d scope=%q", second.Code, second.Header().Get("X-Upload-Quota-Scope"))
	}
	router := chi.NewRouter()
	router.Post("/{id}", handler.AbortDirectUpload)
	abort := httptest.NewRecorder()
	abortRequest := httptest.NewRequest(http.MethodPost, "/"+fileID, strings.NewReader(`{"token":"`+token+`"}`))
	abortRequest = abortRequest.WithContext(context.WithValue(abortRequest.Context(), identityContextKey{}, &identity{User: user, Transport: transportBearer}))
	router.ServeHTTP(abort, abortRequest)
	if abort.Code != http.StatusNoContent {
		t.Fatalf("abort status=%d body=%q", abort.Code, abort.Body.String())
	}
	third, _, _ := begin()
	if third.Code != http.StatusCreated {
		t.Fatalf("reservation after abort status=%d body=%q", third.Code, third.Body.String())
	}
}

func TestConcurrentDirectUploadReservationsDoNotOvercommit(t *testing.T) {
	user := &db.User{ID: "quota-user", UploadQuotaBytes: mebibyte}
	repository := &memoryRepository{files: make(map[string]*db.FileList), quotaBytes: map[string]int64{user.ID: user.UploadQuotaBytes}}
	storage := &directMemoryStorage{&memoryStorage{objects: make(map[string][]byte)}}
	cfg := &config.ServiceConfig{MaxFileSize: 1, StorageService: "r2", Upload: &config.UploadConfig{GuestEnabled: true}, Encryption: &config.EncryptionConfig{}}
	handler := newTestHandlerConfig(t, cfg, repository, storage)
	start := make(chan struct{})
	statuses := make(chan int, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/api/v1/uploads/direct", strings.NewReader(`{"file_name":"account.txt","file_size":716800,"content_type":"text/plain"}`))
			request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: user, Transport: transportBearer}))
			handler.BeginDirectUpload(response, request)
			statuses <- response.Code
		}()
	}
	close(start)
	group.Wait()
	close(statuses)
	counts := map[int]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts[http.StatusCreated] != 1 || counts[http.StatusRequestEntityTooLarge] != 1 || len(repository.files) != 1 {
		t.Fatalf("concurrent reservations were not atomic: statuses=%v records=%d", counts, len(repository.files))
	}
}

func multipartUploadRequest(t *testing.T, content []byte) *http.Request {
	t.Helper()
	body := new(bytes.Buffer)
	form := multipart.NewWriter(body)
	part, err := form.CreateFormFile("file", "quota.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/upload", body)
	request.Header.Set("Content-Type", form.FormDataContentType())
	return request
}

func TestSafeFileName(t *testing.T) {
	for _, value := range []string{"", ".", "bad\x00name"} {
		if _, err := safeFileName(value); err == nil {
			t.Fatalf("safeFileName(%q) succeeded", value)
		}
	}
	name, err := safeFileName("C:\\fakepath\\report.pdf")
	if err != nil || !strings.HasSuffix(name, "report.pdf") {
		t.Fatalf("got %q, %v", name, err)
	}
}

func TestTemplatesKeepTablerHtmxAndAuthorCredit(t *testing.T) {
	parsed, err := parseTemplates(os.DirFS("../.."), config.BrandingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"index.html", "file_view.html"} {
		var output strings.Builder
		if err := parsed.ExecuteTemplate(&output, name, map[string]any{"Version": "test"}); err != nil {
			t.Fatal(err)
		}
		for _, expected := range []string{"@tabler/core@1.4.0", "htmx.org@2.0.10", "Made with", "by Cat"} {
			if !strings.Contains(output.String(), expected) {
				t.Errorf("%s no longer contains %q", name, expected)
			}
		}
	}
}

func TestIndexReflectsGuestUploadPolicyWithoutGlobalQuota(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	storage := &memoryStorage{objects: make(map[string][]byte)}
	cfg := &config.ServiceConfig{
		MaxFileSize: 1, StorageService: "filesystem", Upload: &config.UploadConfig{GuestEnabled: false},
		Auth: &config.AuthConfig{SignupEnabled: true}, Encryption: &config.EncryptionConfig{},
	}
	handler, err := New(cfg, repository, storage, os.DirFS("../.."), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	disabled := httptest.NewRecorder()
	handler.Index(disabled, httptest.NewRequest(http.MethodGet, "/", nil))
	if disabled.Code != http.StatusOK || !strings.Contains(disabled.Body.String(), "Guest uploads are disabled") || strings.Contains(disabled.Body.String(), `id="upload-form"`) {
		t.Fatalf("disabled guest UI did not match policy: status=%d", disabled.Code)
	}

	cfg.Upload = &config.UploadConfig{GuestEnabled: true}
	repository.files["guest"] = &db.FileList{FileID: "guest", FileSize: 512 * 1024, UploadStatus: "complete"}
	enabled := httptest.NewRecorder()
	handler.Index(enabled, httptest.NewRequest(http.MethodGet, "/", nil))
	page := enabled.Body.String()
	if enabled.Code != http.StatusOK || !strings.Contains(page, `id="upload-form"`) || strings.Contains(page, "storage quota") || strings.Contains(page, "Server storage:") {
		t.Fatalf("enabled guest UI incorrectly showed a storage quota: status=%d", enabled.Code)
	}
}

func TestUploadRetentionNoticeExemptsPaidAccounts(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList), quotaBytes: make(map[string]int64)}
	storage := &memoryStorage{objects: make(map[string][]byte)}
	cfg := &config.ServiceConfig{
		MaxFileSize: 1, StorageService: "filesystem", Upload: &config.UploadConfig{GuestEnabled: true},
		Retention: &config.RetentionConfig{GuestDays: 1, UnpaidDays: 30}, Encryption: &config.EncryptionConfig{},
	}
	handler := newTestHandlerConfig(t, cfg, repository, storage)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	if notice := handler.uploadQuotaLabel(request, nil); !strings.Contains(notice, "Guest files are automatically deleted 1 day after upload") {
		t.Fatalf("guest notice = %q", notice)
	}
	unpaid := &db.User{ID: "unpaid"}
	if notice := handler.uploadQuotaLabel(request, unpaid); !strings.Contains(notice, "Files on unpaid accounts are automatically deleted 30 days after upload") {
		t.Fatalf("unpaid notice = %q", notice)
	}
	paid := &db.User{ID: "paid", IsPaid: true}
	if notice := handler.uploadQuotaLabel(request, paid); strings.Contains(notice, "automatically deleted") {
		t.Fatalf("paid account received retention notice: %q", notice)
	}
}

func TestAllProductionTemplatesParse(t *testing.T) {
	parsed, err := parseTemplates(os.DirFS("../.."), config.BrandingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"index.html", "file_view.html", "setup.html", "login.html", "signup.html", "oauth_error.html", "account.html", "admin_users.html"} {
		if parsed.Lookup(name) == nil {
			t.Errorf("template %q is missing", name)
		}
	}
	user := &db.User{ID: "user", Email: "user@example.com", DisplayName: "User", Role: db.RoleAdmin, Active: true}
	renders := []struct {
		name string
		data any
	}{
		{"index.html", map[string]any{"Version": "test", "MaxFileSize": int64(1), "User": user, "CSRF": "csrf"}},
		{"file_view.html", map[string]any{"Version": "test", "FileName": "file.txt", "User": user, "CSRF": "csrf"}},
		{"setup.html", authPageData{Version: "test", CSRF: "csrf"}},
		{"login.html", authPageData{Version: "test", CSRF: "csrf", OAuthProviders: []oauthButton{{Key: "discord", Label: "Discord", URL: "/oauth/discord/start"}}}},
		{"signup.html", authPageData{Version: "test", CSRF: "csrf"}},
		{"oauth_error.html", oauthErrorData{Version: "test", Error: "OAuth error", Back: "/login", BackLabel: "Back to login"}},
		{"account.html", accountPageData{Version: "test", CSRF: "csrf", User: user, OAuthProviders: []oauthAccountProvider{{Key: "discord", Label: "Discord", Configured: true, Linked: true}}}},
		{"admin_users.html", adminPageData{Version: "test", CSRF: "csrf", User: user}},
	}
	for _, render := range renders {
		if err := parsed.ExecuteTemplate(io.Discard, render.name, render.data); err != nil {
			t.Errorf("render %s: %v", render.name, err)
		}
	}
	for _, name := range []string{"account.html", "admin_users.html"} {
		contents, err := os.ReadFile("../../template/" + name)
		if err != nil {
			t.Fatal(err)
		}
		page := string(contents)
		for _, expected := range []string{"hx-", "{{template"} {
			if !strings.Contains(page, expected) {
				t.Errorf("%s no longer contains %q", name, expected)
			}
		}
	}
	partial, err := os.ReadFile("../../template/partials.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"@tabler/core@1.4.0", "htmx.org@2.0.10", "Made with", "by Cat"} {
		if !strings.Contains(string(partial), expected) {
			t.Errorf("partials.html no longer contains %q", expected)
		}
	}
}

func TestAuthenticatedTemplatesUsePersistedDarkTheme(t *testing.T) {
	parsed, err := parseTemplates(os.DirFS("../.."), config.BrandingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	user := &db.User{ID: "user", Email: "user@example.com", DisplayName: "User", Role: db.RoleAdmin, Active: true, DarkMode: true}
	renders := []struct {
		name string
		data any
	}{
		{"index.html", map[string]any{"Version": "test", "MaxFileSize": int64(1), "User": user, "CSRF": "csrf"}},
		{"file_view.html", map[string]any{"Version": "test", "FileName": "file.txt", "User": user, "CSRF": "csrf"}},
		{"account.html", accountPageData{Version: "test", CSRF: "csrf", User: user}},
		{"admin_users.html", adminPageData{Version: "test", CSRF: "csrf", User: user}},
		{"oauth_error.html", oauthErrorData{Version: "test", Error: "OAuth error", Back: "/account", BackLabel: "Back to My account", User: user}},
	}
	for _, render := range renders {
		var output bytes.Buffer
		if err := parsed.ExecuteTemplate(&output, render.name, render.data); err != nil {
			t.Fatalf("render %s: %v", render.name, err)
		}
		page := output.String()
		if !strings.Contains(page, `<html lang="en" data-bs-theme="dark">`) {
			t.Errorf("%s did not apply the account dark theme", render.name)
		}
		if render.name != "oauth_error.html" && (!strings.Contains(page, `action="/account/theme"`) || !strings.Contains(page, `name="csrf_token" value="csrf"`)) {
			t.Errorf("%s is missing the CSRF-protected theme toggle", render.name)
		}
		if render.name != "oauth_error.html" && (!strings.Contains(page, `class="border-0 bg-transparent text-secondary p-1 d-inline-flex align-items-center justify-content-center rounded"`) || !strings.Contains(page, `aria-label="Switch to light theme"`)) {
			t.Errorf("%s is missing the compact top-right theme icon", render.name)
		}
		if strings.Contains(page, `github.com/AutisticShark/ObjectShare`) || strings.Contains(page, ">Light mode</button>") || strings.Contains(page, ">Dark mode</button>") || strings.Contains(page, "btn-ghost-secondary") {
			t.Errorf("%s still renders a removed header control", render.name)
		}
	}

	account := renders[2]
	var output bytes.Buffer
	if err := parsed.ExecuteTemplate(&output, account.name, account.data); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `<option value="dark" selected>Dark</option>`) || !strings.Contains(output.String(), "follows you across browsers") {
		t.Fatal("account appearance control does not reflect the saved dark preference")
	}

	captcha, err := os.ReadFile("../../template/captcha.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(captcha), `document.documentElement.dataset.bsTheme || "auto"`) {
		t.Fatal("CAPTCHA widgets do not follow the rendered account theme")
	}
}

func TestAdministratorUserTemplateUsesStorageDisplayAndModalActions(t *testing.T) {
	parsed, err := parseTemplates(os.DirFS("../.."), config.BrandingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	user := &db.User{ID: "11111111-1111-4111-8111-111111111111", Email: "admin@example.com", DisplayName: "Admin", Role: db.RoleAdmin, Active: true}
	row := adminUserRow{ID: "22222222-2222-4222-8222-222222222222", Email: "user@example.com", DisplayName: "User", Role: db.RoleUser, Active: true, CreatedAt: "2026-09-03", LastLogin: "Never", StorageUsed: "1.5 MiB"}
	var output bytes.Buffer
	if err := parsed.ExecuteTemplate(&output, "admin_users.html", adminPageData{Version: "test", CSRF: "csrf", Error: "Passwords do not match.", TotalStorageUsed: "1.5 MiB", User: user, Users: []adminUserRow{row}}); err != nil {
		t.Fatal(err)
	}
	page := output.String()
	for _, expected := range []string{
		"Activity and storage",
		"Total user storage: <strong class=\"text-reset\">1.5 MiB</strong>",
		"Storage used:</span> <strong>1.5 MiB</strong>",
		`data-user-dialog-open="user-actions-22222222-2222-4222-8222-222222222222"`,
		`id="user-actions-22222222-2222-4222-8222-222222222222"`,
		`<dialog class="admin-user-dialog"`,
		`data-user-dialog-close`,
		`data-user-dialog-form="user-actions-22222222-2222-4222-8222-222222222222"`,
		`src="/assets/admin-users.js"`,
		`href="/assets/admin-users.css"`,
		`autocomplete="new-password"`,
		`hx-target=".page" hx-select=".page" hx-swap="outerHTML"`,
		`aria-live="polite"`,
		"Reset password and invalidate JWTs",
	} {
		if !strings.Contains(page, expected) {
			t.Errorf("administrator user template is missing %q", expected)
		}
	}
	for _, removed := range []string{`<details class="dropdown">`, `dropdown-menu dropdown-menu-end show`, `.admin-user-modal:target`} {
		if strings.Contains(page, removed) {
			t.Errorf("administrator user template still contains broken action markup %q", removed)
		}
	}
	if strings.Contains(page, "<style>") {
		t.Fatal("administrator user template contains inline styles blocked by the application CSP")
	}
	for name, expected := range map[string][]string{
		"admin_users.js":  {"showModal", "data-user-dialog-open", "htmx:afterSwap"},
		"admin_users.css": {".admin-user-dialog", "::backdrop", "overflow-y: auto"},
	} {
		contents, err := os.ReadFile("../../template/" + name)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range expected {
			if !strings.Contains(string(contents), fragment) {
				t.Errorf("%s is missing %q", name, fragment)
			}
		}
	}
}

func TestGuestEntryPagesUseAutomaticSystemTheme(t *testing.T) {
	parsed, err := parseTemplates(os.DirFS("../.."), config.BrandingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	renders := []struct {
		name string
		data any
	}{
		{"index.html", map[string]any{"Version": "test", "MaxFileSize": int64(1)}},
		{"login.html", authPageData{Version: "test", CSRF: "csrf"}},
		{"signup.html", authPageData{Version: "test", CSRF: "csrf"}},
	}
	for _, render := range renders {
		var output bytes.Buffer
		if err := parsed.ExecuteTemplate(&output, render.name, render.data); err != nil {
			t.Fatalf("render %s: %v", render.name, err)
		}
		page := output.String()
		if !strings.Contains(page, `<script src="/assets/theme.js"></script>`) {
			t.Errorf("%s does not load the automatic system theme before rendering", render.name)
		}
		if strings.Index(page, `/assets/theme.js`) > strings.Index(page, `tabler.min.css`) {
			t.Errorf("%s loads the automatic theme after Tabler CSS", render.name)
		}
	}

	user := &db.User{ID: "user", DarkMode: false}
	var authenticated bytes.Buffer
	if err := parsed.ExecuteTemplate(&authenticated, "index.html", map[string]any{"Version": "test", "MaxFileSize": int64(1), "User": user}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(authenticated.String(), `/assets/theme.js`) {
		t.Fatal("authenticated upload page replaced the persisted account theme with the system theme")
	}

	theme, err := os.ReadFile("../../template/theme.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`prefers-color-scheme: dark`, `"dark" : "light"`, `addEventListener("change", applyTheme)`} {
		if !strings.Contains(string(theme), expected) {
			t.Errorf("automatic theme script is missing %q", expected)
		}
	}
	captcha, err := os.ReadFile("../../template/captcha.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(captcha), `dataset.themePreference === "system" ? "auto"`) {
		t.Fatal("guest CAPTCHA widgets do not follow the automatic system theme")
	}
}

func TestEncryptedUploadAndDownload(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	storage := &memoryStorage{objects: make(map[string][]byte)}
	cfg := &config.ServiceConfig{
		MaxFileSize: 1, StorageService: "filesystem",
		Encryption: &config.EncryptionConfig{Enabled: true, Method: "aes-256-gcm", Key: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="},
	}
	handler := newTestHandlerConfig(t, cfg, repository, storage)
	content := []byte("encrypted contents")
	body := new(bytes.Buffer)
	form := multipart.NewWriter(body)
	part, _ := form.CreateFormFile("file", "private.txt")
	_, _ = part.Write(content)
	_ = form.Close()
	upload := httptest.NewRequest(http.MethodPost, "/api/v1/upload", body)
	upload.Header.Set("Content-Type", form.FormDataContentType())
	uploadResponse := httptest.NewRecorder()
	handler.Upload(uploadResponse, upload)
	if uploadResponse.Code != http.StatusSeeOther {
		t.Fatalf("upload status = %d", uploadResponse.Code)
	}

	var fileID string
	for id, file := range repository.files {
		fileID = id
		if !file.IsEncrypted {
			t.Fatal("record is not encrypted")
		}
		if bytes.Equal(storage.objects[id], content) {
			t.Fatal("object was stored as plaintext")
		}
	}
	router := chi.NewRouter()
	router.Get("/{id}", handler.Download)
	downloadResponse := httptest.NewRecorder()
	router.ServeHTTP(downloadResponse, httptest.NewRequest(http.MethodGet, "/"+fileID, nil))
	if downloadResponse.Code != http.StatusOK {
		t.Fatalf("download status = %d", downloadResponse.Code)
	}
	if !bytes.Equal(downloadResponse.Body.Bytes(), content) {
		t.Fatalf("download = %q", downloadResponse.Body.Bytes())
	}
}

func TestDirectUploadRequiresTokenAndVerifiesObject(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	storage := &directMemoryStorage{&memoryStorage{objects: make(map[string][]byte)}}
	cfg := &config.ServiceConfig{
		MaxFileSize: 10, StorageService: "r2", Encryption: &config.EncryptionConfig{},
	}
	handler := newTestHandlerConfig(t, cfg, repository, storage)
	beginRequest := httptest.NewRequest(http.MethodPost, "/api/v1/uploads/direct", strings.NewReader(
		`{"file_name":"hello.txt","file_size":5,"content_type":"text/plain"}`,
	))
	beginResponse := httptest.NewRecorder()
	handler.BeginDirectUpload(beginResponse, beginRequest)
	if beginResponse.Code != http.StatusCreated {
		t.Fatalf("begin status = %d, body = %q", beginResponse.Code, beginResponse.Body.String())
	}
	var authorization struct {
		FileID string `json:"file_id"`
		Token  string `json:"token"`
	}
	if err := json.NewDecoder(beginResponse.Body).Decode(&authorization); err != nil {
		t.Fatal(err)
	}
	storage.objects[authorization.FileID] = []byte("hello")

	router := chi.NewRouter()
	router.Post("/{id}", handler.CompleteDirectUpload)
	completeRequest := httptest.NewRequest(http.MethodPost, "/"+authorization.FileID, strings.NewReader(
		`{"token":"`+authorization.Token+`"}`,
	))
	completeResponse := httptest.NewRecorder()
	router.ServeHTTP(completeResponse, completeRequest)
	if completeResponse.Code != http.StatusOK {
		t.Fatalf("complete status = %d, body = %q", completeResponse.Code, completeResponse.Body.String())
	}
	if repository.files[authorization.FileID].UploadStatus != "complete" {
		t.Fatal("upload was not completed")
	}
	if len(completeResponse.Result().Cookies()) != 1 {
		t.Fatal("owner cookie was not set")
	}
}

func newTestHandler(t *testing.T, repository db.Repository, storage service.ObjectStore) *Handler {
	t.Helper()
	cfg := &config.ServiceConfig{
		MaxFileSize: 1, StorageService: "filesystem",
		Encryption: &config.EncryptionConfig{},
	}
	return newTestHandlerConfig(t, cfg, repository, storage)
}

func newTestHandlerConfig(t *testing.T, cfg *config.ServiceConfig, repository db.Repository, storage service.ObjectStore) *Handler {
	t.Helper()
	templates := fstest.MapFS{
		"template/index.html":      {Data: []byte(`{{define "index.html"}}index{{end}}`)},
		"template/file_view.html":  {Data: []byte(`{{define "file_view.html"}}file{{end}}`)},
		"template/branding.css":    {Data: []byte(`.site-logo { height: 2rem; }`)},
		"template/theme.js":        {Data: []byte(`console.log("theme test")`)},
		"template/sharing.js":      {Data: []byte(`// sharing`)},
		"template/upload.js":       {Data: []byte(`console.log("test")`)},
		"template/captcha.js":      {Data: []byte(`console.log("captcha test")`)},
		"template/admin_users.js":  {Data: []byte(`console.log("admin users test")`)},
		"template/admin_users.css": {Data: []byte(`.admin-user-dialog { display: block; }`)},
	}
	handler, err := New(cfg, repository, storage, templates, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

var _ db.Repository = (*memoryRepository)(nil)
var _ service.ObjectStore = (*memoryStorage)(nil)
