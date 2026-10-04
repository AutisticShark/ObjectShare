package htmx

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/go-chi/chi/v5"
)

const testEncryptionKey = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="

func (repository *memoryRepository) HasEncryptedFiles(context.Context) (bool, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	for _, file := range repository.files {
		if file.IsEncrypted {
			return true, nil
		}
	}
	return false, nil
}

// uploadEncrypted stores content through a handler that encrypts new uploads
// and returns the new file's ID.
func uploadEncrypted(t *testing.T, repository *memoryRepository, storage *memoryStorage, maxFileSize int64, content []byte) string {
	t.Helper()
	handler := newTestHandlerConfig(t, &config.ServiceConfig{MaxFileSize: maxFileSize, StorageService: "filesystem",
		Encryption: &config.EncryptionConfig{Enabled: true, Method: "aes-256-gcm", Key: testEncryptionKey}}, repository, storage)
	response := httptest.NewRecorder()
	handler.Upload(response, multipartUploadRequest(t, content))
	if response.Code != http.StatusSeeOther {
		t.Fatalf("encrypted upload status = %d %q", response.Code, response.Body.String())
	}
	for id, file := range repository.files {
		if file.IsEncrypted && file.FileSize == int64(len(content)) {
			return id
		}
	}
	t.Fatal("encrypted upload left no encrypted record")
	return ""
}

func downloadFile(handler *Handler, fileID string) *httptest.ResponseRecorder {
	router := chi.NewRouter()
	router.Get("/{id}", handler.Download)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/"+fileID, nil))
	return response
}

// Lowering max_file_size applies to new uploads only. Reading an older, larger
// encrypted object is bounded by its recorded size, not the current setting.
func TestLoweringMaxFileSizeKeepsEncryptedFilesDownloadable(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	storage := &memoryStorage{objects: make(map[string][]byte)}
	content := make([]byte, 2*mebibyte)
	for index := range content {
		content[index] = byte(index)
	}
	fileID := uploadEncrypted(t, repository, storage, 3, content)

	lowered := newTestHandlerConfig(t, &config.ServiceConfig{MaxFileSize: 1, StorageService: "filesystem",
		Encryption: &config.EncryptionConfig{Enabled: true, Method: "aes-256-gcm", Key: testEncryptionKey}}, repository, storage)
	response := downloadFile(lowered, fileID)
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), content) {
		t.Fatalf("download after lowering max_file_size: status=%d length=%d", response.Code, response.Body.Len())
	}

	// The recorded size still bounds the read: a stored object larger than
	// its record is refused instead of being read without limit.
	storage.objects[fileID] = append(storage.objects[fileID], 0)
	if response := downloadFile(lowered, fileID); response.Code != http.StatusInternalServerError {
		t.Fatalf("oversized encrypted object status = %d", response.Code)
	}
}

// Turning encryption off while keeping the key stops encrypting new uploads but
// keeps every object encrypted earlier downloadable.
func TestDisablingEncryptionKeepsEncryptedFilesDownloadable(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	storage := &memoryStorage{objects: make(map[string][]byte)}
	fileID := uploadEncrypted(t, repository, storage, 1, []byte("secret payload"))

	off := newTestHandlerConfig(t, &config.ServiceConfig{MaxFileSize: 1, StorageService: "filesystem",
		Encryption: &config.EncryptionConfig{Enabled: false, Method: "aes-256-gcm", Key: testEncryptionKey}}, repository, storage)
	if response := downloadFile(off, fileID); response.Code != http.StatusOK || response.Body.String() != "secret payload" {
		t.Fatalf("download after disabling encryption: status=%d body=%q", response.Code, response.Body.String())
	}

	response := httptest.NewRecorder()
	off.Upload(response, multipartUploadRequest(t, []byte("plain payload")))
	if response.Code != http.StatusSeeOther {
		t.Fatalf("upload with encryption off: %d %q", response.Code, response.Body.String())
	}
	for id, file := range repository.files {
		if id != fileID && (file.IsEncrypted || string(storage.objects[id]) != "plain payload") {
			t.Fatal("a new upload was encrypted although encryption is off")
		}
	}

	// With the key cleared as well, the old object cannot be read.
	keyless := newTestHandlerConfig(t, &config.ServiceConfig{MaxFileSize: 1, StorageService: "filesystem",
		Encryption: &config.EncryptionConfig{Method: "aes-256-gcm"}}, repository, storage)
	if response := downloadFile(keyless, fileID); response.Code != http.StatusInternalServerError {
		t.Fatalf("download without a key status = %d", response.Code)
	}
}

func TestSettingsRefuseEncryptionKeyChangeWhileEncryptedFilesExist(t *testing.T) {
	t.Setenv("OBJECTSHARE_JWT_SECRET", "encryption-guard-jwt-secret-with-at-least-32-bytes")
	t.Setenv("OBJECTSHARE_SETTINGS_KEY", "encryption-guard-settings-key-with-at-least-32-bytes")
	cfg, err := config.Load("../../config.json.example")
	if err != nil {
		t.Fatal(err)
	}
	cfg.RateLimit.Enabled = false
	runtime := config.RuntimeFromService(cfg)
	runtime.Encryption = config.EncryptionConfig{Enabled: true, Method: "aes-256-gcm", Key: testEncryptionKey}
	if runtime.MaxFileSize > config.MaxEncryptedFileSizeMiB {
		runtime.MaxFileSize = config.MaxEncryptedFileSizeMiB
	}
	sealed, err := config.SealRuntime(runtime, cfg.SettingsKey)
	if err != nil {
		t.Fatal(err)
	}
	repository := newAuthMemoryRepository()
	repository.setting = &db.ApplicationSetting{Key: "runtime_config", Value: sealed, UpdatedBy: "bootstrap import", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	admin := &db.User{ID: "admin", Email: "admin@example.com", DisplayName: "Admin", Role: db.RoleAdmin, Active: true, TokenVersion: 1}
	repository.users[admin.ID] = admin
	handler, err := New(cfg, repository, &memoryStorage{objects: make(map[string][]byte)}, os.DirFS("../.."), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	claims := &appauth.Claims{CSRF: "signed-csrf"}
	save := func(change func(values map[string][]string)) *httptest.ResponseRecorder {
		values := runtimeFormValues(runtime)
		values.Set("csrf_token", claims.CSRF)
		values.Set("revision", settingsRevision(repository.setting.Value))
		change(values)
		request := httptest.NewRequest(http.MethodPost, "/admin/settings", strings.NewReader(values.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: admin, Claims: claims, Transport: transportCookie}))
		response := httptest.NewRecorder()
		handler.AdminSaveSettings(response, request)
		return response
	}
	storedKey := func() string {
		stored, err := config.OpenRuntime(repository.setting.Value, cfg.SettingsKey)
		if err != nil {
			t.Fatal(err)
		}
		return stored.Encryption.Key
	}
	replacement := strings.Repeat("ab", 32)
	sameKeyAsHex := strings.Repeat("42", 32) // testEncryptionKey decodes to 32 bytes of 'B'

	repository.files["encrypted"] = &db.FileList{FileID: "encrypted", IsEncrypted: true, UploadStatus: "complete"}
	for name, change := range map[string]func(map[string][]string){
		"clear":   func(values map[string][]string) { values["clear_encryption_key"] = []string{"on"} },
		"replace": func(values map[string][]string) { values["encryption_key"] = []string{replacement} },
	} {
		response := save(change)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "encryption key cannot be changed or cleared") || storedKey() != testEncryptionKey {
			t.Fatalf("%s: key change was not refused: status=%d", name, response.Code)
		}
	}
	// Turning encryption off and re-entering the same key in another encoding
	// are not key changes.
	if response := save(func(values map[string][]string) {
		delete(values, "encryption_enabled")
		values["encryption_key"] = []string{sameKeyAsHex}
	}); response.Code != http.StatusSeeOther || storedKey() != sameKeyAsHex {
		t.Fatalf("same-key save refused: status=%d %q", response.Code, response.Body.String())
	}

	delete(repository.files, "encrypted")
	if response := save(func(values map[string][]string) { values["encryption_key"] = []string{replacement} }); response.Code != http.StatusSeeOther || storedKey() != replacement {
		t.Fatalf("key change without encrypted files refused: status=%d", response.Code)
	}
}
