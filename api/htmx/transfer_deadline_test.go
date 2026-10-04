package htmx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
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

	body := &progressBody{ReadCloser: io.NopCloser(strings.NewReader("abcdef")), progress: &transferProgress{controller: http.NewResponseController(recorder), read: window, write: window}}
	buffer := make([]byte, 2)
	for range 3 {
		if _, err := body.Read(buffer); err != nil {
			t.Fatal(err)
		}
	}
	// Receiving an upload moves the write deadline as well, so the response can
	// still be written after a body that took longer than WriteTimeout.
	if len(recorder.readDeadlines) != 3 || len(recorder.writes) != 3 {
		t.Fatalf("deadlines set %d (read) and %d (write) times, want once per read", len(recorder.readDeadlines), len(recorder.writes))
	}
	for _, deadline := range append(recorder.readDeadlines, recorder.writes...) {
		if until := time.Until(deadline); until < window-5*time.Second || until > window+time.Second {
			t.Fatalf("deadline is %v away, want about %v", until, window)
		}
	}
	recorder.writes = nil

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

// trickleReader hands out its content in small chunks after a pause, like a
// slow but steady connection.
type trickleReader struct {
	data  []byte
	pause time.Duration
}

func (reader *trickleReader) Read(buffer []byte) (int, error) {
	if len(reader.data) == 0 {
		return 0, io.EOF
	}
	time.Sleep(reader.pause)
	n := copy(buffer[:min(len(buffer), 64*1024)], reader.data)
	reader.data = reader.data[n:]
	return n, nil
}

// trickleStorage writes slowly but steadily and fails if the request context
// is cancelled meanwhile.
type trickleStorage struct {
	*memoryStorage
	pause  time.Duration
	mu     sync.Mutex
	stored int
}

func (storage *trickleStorage) Put(ctx context.Context, key string, reader io.Reader, size int64, contentType string) error {
	var data bytes.Buffer
	buffer := make([]byte, 64*1024)
	for {
		time.Sleep(storage.pause)
		n, err := reader.Read(buffer)
		data.Write(buffer[:n])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	storage.mu.Lock()
	defer storage.mu.Unlock()
	storage.stored = data.Len()
	return storage.memoryStorage.Put(ctx, key, &data, size, contentType)
}

// A proxied upload that keeps moving must get its response even when receiving
// or storing it takes longer than the server's absolute WriteTimeout; otherwise
// the file is stored but the client never learns its location or receives the
// guest owner cookie.
func TestSlowProxiedUploadStillReceivesItsResponse(t *testing.T) {
	const timeout = time.Second
	content := bytes.Repeat([]byte("x"), 512*1024)
	for name, test := range map[string]struct{ bodyPause, storePause time.Duration }{
		"slow client":  {bodyPause: 200 * time.Millisecond},
		"slow storage": {storePause: 200 * time.Millisecond},
	} {
		t.Run(name, func(t *testing.T) {
			repository := &memoryRepository{files: make(map[string]*db.FileList)}
			storage := &trickleStorage{memoryStorage: &memoryStorage{objects: make(map[string][]byte)}, pause: test.storePause}
			cfg := &config.ServiceConfig{MaxFileSize: 1, StorageService: "filesystem", Encryption: &config.EncryptionConfig{},
				ReadTimeout: config.Duration(timeout), WriteTimeout: config.Duration(timeout)}
			handler := newTestHandlerConfig(t, cfg, repository, storage)
			server := httptest.NewUnstartedServer(http.HandlerFunc(handler.Upload))
			server.Config.ReadTimeout, server.Config.WriteTimeout = timeout, timeout
			server.Start()
			defer server.Close()

			body := new(bytes.Buffer)
			form := multipart.NewWriter(body)
			part, err := form.CreateFormFile("file", "slow.bin")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = part.Write(content)
			_ = form.Close()
			request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/upload", &trickleReader{data: body.Bytes(), pause: test.bodyPause})
			if err != nil {
				t.Fatal(err)
			}
			request.ContentLength = int64(body.Len())
			request.Header.Set("Content-Type", form.FormDataContentType())
			client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			started := time.Now()
			response, err := client.Do(request)
			elapsed := time.Since(started)
			if err != nil {
				t.Fatalf("no response after %v of steady progress (WriteTimeout %v): %v", elapsed.Round(time.Millisecond), timeout, err)
			}
			defer response.Body.Close()
			if elapsed <= timeout {
				t.Fatalf("the upload took only %v; it must outlast WriteTimeout to prove anything", elapsed)
			}
			storage.mu.Lock()
			stored := storage.stored
			storage.mu.Unlock()
			if response.StatusCode != http.StatusSeeOther || len(response.Cookies()) == 0 || stored != len(content) {
				t.Fatalf("status=%d cookies=%d stored=%d bytes", response.StatusCode, len(response.Cookies()), stored)
			}
		})
	}
}
