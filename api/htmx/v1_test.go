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
	"testing"
	"testing/fstest"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/AutisticShark/ObjectShare/service"
	"github.com/go-chi/chi/v5"
)

type memoryRepository struct{ files map[string]*db.FileList }

func (repository *memoryRepository) Create(_ context.Context, file *db.FileList) error {
	copy := *file
	repository.files[file.FileID] = &copy
	return nil
}
func (repository *memoryRepository) Get(_ context.Context, id string) (*db.FileList, error) {
	file, ok := repository.files[id]
	if !ok {
		return nil, db.ErrNotFound
	}
	copy := *file
	return &copy, nil
}
func (repository *memoryRepository) CompleteUpload(_ context.Context, id string) error {
	file, ok := repository.files[id]
	if !ok || file.UploadStatus != "pending" {
		return db.ErrNotFound
	}
	file.UploadStatus = "complete"
	file.UploadExpiresAt = nil
	return nil
}
func (repository *memoryRepository) ExpiredUploads(_ context.Context, before time.Time, limit int) ([]db.FileList, error) {
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
	file, ok := repository.files[id]
	if !ok {
		return db.ErrNotFound
	}
	file.FileName = name
	return nil
}
func (repository *memoryRepository) Delete(_ context.Context, id string) error {
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
	for _, name := range []string{"index.html", "file_view.html"} {
		contents, err := os.ReadFile("../../template/" + name)
		if err != nil {
			t.Fatal(err)
		}
		page := string(contents)
		for _, expected := range []string{"@tabler/core@1.4.0", "htmx.org@2.0.10", "Made with", "by Cat"} {
			if !strings.Contains(page, expected) {
				t.Errorf("%s no longer contains %q", name, expected)
			}
		}
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
		"template/index.html":     {Data: []byte(`{{define "index.html"}}index{{end}}`)},
		"template/file_view.html": {Data: []byte(`{{define "file_view.html"}}file{{end}}`)},
		"template/upload.js":      {Data: []byte(`console.log("test")`)},
	}
	handler, err := New(cfg, repository, storage, templates, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

var _ db.Repository = (*memoryRepository)(nil)
var _ service.ObjectStore = (*memoryStorage)(nil)
