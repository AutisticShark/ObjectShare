package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/api/htmx"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/AutisticShark/ObjectShare/service"
)

// routerRepository answers readiness checks and counts file access, so a test
// can prove a handler did not run. Any other repository call panics.
type routerRepository struct {
	db.Repository
	fileCalls atomic.Int32
}

func (*routerRepository) Ping(context.Context) error { return nil }

func (repository *routerRepository) Get(context.Context, string) (*db.FileList, error) {
	repository.fileCalls.Add(1)
	return nil, db.ErrNotFound
}

func (repository *routerRepository) Delete(context.Context, string) error {
	repository.fileCalls.Add(1)
	return nil
}

type routerStorage struct{ service.ObjectStore }

func newTestRouter(t *testing.T) (http.Handler, *routerRepository) {
	t.Helper()
	repository := &routerRepository{}
	cfg := &config.ServiceConfig{MaxFileSize: 1, StorageService: "filesystem", SettingsKey: "test-only-settings-key-with-at-least-32-bytes", Encryption: &config.EncryptionConfig{},
		Auth: &config.AuthConfig{JWTSecret: "test-only-jwt-secret-with-at-least-32-bytes", TokenLifetime: config.Duration(12 * time.Hour)}}
	logger := slog.New(slog.DiscardHandler)
	handler, err := htmx.New(cfg, repository, routerStorage{}, os.DirFS(".."), logger)
	if err != nil {
		t.Fatal(err)
	}
	return Router(handler, logger), repository
}

func TestHeadIsServedForGetRoutes(t *testing.T) {
	router, _ := newTestRouter(t)
	server := httptest.NewServer(router)
	defer server.Close()
	for _, path := range []string{"/health/live", "/health/ready", "/assets/theme.js", "/assets/branding.css", "/login"} {
		get, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		getBody, _ := io.ReadAll(get.Body)
		get.Body.Close()
		head, err := http.Head(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		headBody, _ := io.ReadAll(head.Body)
		head.Body.Close()
		if head.StatusCode != get.StatusCode || head.StatusCode != http.StatusOK || len(headBody) != 0 || len(getBody) == 0 {
			t.Fatalf("HEAD %s: status %d (GET %d), %d body bytes", path, head.StatusCode, get.StatusCode, len(headBody))
		}
		if head.Header.Get("Content-Type") != get.Header.Get("Content-Type") || head.Header.Get("X-Request-Id") == "" {
			t.Fatalf("HEAD %s headers differ from GET: %v", path, head.Header)
		}
	}
}

func TestHeadNeverReachesStateChangingHandlers(t *testing.T) {
	router, repository := newTestRouter(t)
	for _, test := range []struct {
		path  string
		allow string
	}{
		// GET routes that capture a payment, complete an OAuth login, or stream
		// an object are GET-only.
		{"/billing/paypal/topup/return?topup=00000000-0000-4000-8000-000000000000&token=order", "GET"},
		{"/oauth/google/callback?state=x&code=y", "GET"},
		{"/api/v1/download/00000000-0000-4000-8000-000000000000", "GET"},
		// Routes without GET must not dispatch HEAD to their POST handler.
		{"/api/v1/delete/00000000-0000-4000-8000-000000000000", ""},
		{"/logout", ""},
	} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodHead, test.path, nil))
		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("HEAD %s status = %d", test.path, response.Code)
		}
		if test.allow != "" && response.Header().Get("Allow") != test.allow {
			t.Fatalf("HEAD %s Allow = %q", test.path, response.Header().Get("Allow"))
		}
	}
	if calls := repository.fileCalls.Load(); calls != 0 {
		t.Fatalf("HEAD reached a file handler %d times", calls)
	}
}
