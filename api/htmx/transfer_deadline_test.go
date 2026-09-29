package htmx

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/go-chi/chi/v5"
)

// deadlineRecorder is a ResponseWriter that, like net/http's connection-backed
// writer, lets http.ResponseController move the read and write deadlines.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	mu                    sync.Mutex
	readDeadlines, writes []time.Time
}

func (recorder *deadlineRecorder) SetReadDeadline(deadline time.Time) error {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.readDeadlines = append(recorder.readDeadlines, deadline)
	return nil
}

func (recorder *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.writes = append(recorder.writes, deadline)
	return nil
}

func TestProgressWrappersPushDeadlinesOutOnEveryReadAndWrite(t *testing.T) {
	recorder := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	window := 2 * time.Minute

	body := &progressBody{ReadCloser: io.NopCloser(strings.NewReader("abcdef")), controller: http.NewResponseController(recorder), window: window}
	buffer := make([]byte, 2)
	for range 3 {
		if _, err := body.Read(buffer); err != nil {
			t.Fatal(err)
		}
	}
	if len(recorder.readDeadlines) != 3 {
		t.Fatalf("read deadlines set %d times, want once per read", len(recorder.readDeadlines))
	}
	for _, deadline := range recorder.readDeadlines {
		if until := time.Until(deadline); until < window-5*time.Second || until > window+time.Second {
			t.Fatalf("read deadline is %v away, want about %v", until, window)
		}
	}

	writer := &progressWriter{ResponseWriter: recorder, controller: http.NewResponseController(recorder), window: window}
	for range 4 {
		if _, err := writer.Write([]byte("chunk")); err != nil {
			t.Fatal(err)
		}
	}
	if len(recorder.writes) != 4 || recorder.Body.String() != "chunkchunkchunkchunk" {
		t.Fatalf("write deadlines set %d times, body %q", len(recorder.writes), recorder.Body.String())
	}
}

func TestProxiedTransfersExtendDeadlinesWhileDataMoves(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	storage := &memoryStorage{objects: make(map[string][]byte)}
	cfg := &config.ServiceConfig{MaxFileSize: 1, StorageService: "filesystem", Encryption: &config.EncryptionConfig{},
		ReadTimeout: config.Duration(5 * time.Minute), WriteTimeout: config.Duration(5 * time.Minute)}
	handler := newTestHandlerConfig(t, cfg, repository, storage)

	upload := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler.Upload(upload, multipartUploadRequest(t, bytes.Repeat([]byte("x"), 300*1024)))
	if upload.Code != http.StatusSeeOther || len(upload.readDeadlines) == 0 {
		t.Fatalf("upload status=%d, read deadline extensions=%d", upload.Code, len(upload.readDeadlines))
	}

	var fileID string
	for id := range repository.files {
		fileID = id
	}
	download := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	router := chi.NewRouter()
	router.Get("/{id}", handler.Download)
	router.ServeHTTP(download, httptest.NewRequest(http.MethodGet, "/"+fileID, nil))
	if download.Code != http.StatusOK || len(download.writes) == 0 || download.Body.Len() != 300*1024 {
		t.Fatalf("download status=%d, write deadline extensions=%d, %d bytes", download.Code, len(download.writes), download.Body.Len())
	}

	// Without configured timeouts nothing is wrapped.
	cfg.ReadTimeout, cfg.WriteTimeout = 0, 0
	plain := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	router.ServeHTTP(plain, httptest.NewRequest(http.MethodGet, "/"+fileID, nil))
	if len(plain.writes) != 0 {
		t.Fatalf("deadlines were extended with no timeout configured: %d", len(plain.writes))
	}
}
