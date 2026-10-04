package htmx

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/go-chi/chi/v5"
)

const testEncryptionKey = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="

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
