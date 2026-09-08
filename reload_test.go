package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

// memoryApplicationRepository stores only the settings document. The reload
// path never touches file rows, and both background workers stop on the first
// empty claim.
type memoryApplicationRepository struct {
	memorySettingsRepository
	mu sync.Mutex
}

// ApplicationSettings and the store helpers are serialized because the watcher
// reads the document from its own goroutine while a test writes it.
func (repository *memoryApplicationRepository) ApplicationSettings(ctx context.Context) (*db.ApplicationSetting, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.memorySettingsRepository.ApplicationSettings(ctx)
}

func (repository *memoryApplicationRepository) Create(context.Context, *db.FileList) error {
	return nil
}

func (repository *memoryApplicationRepository) ReserveUpload(context.Context, *db.FileList) error {
	return nil
}

func (repository *memoryApplicationRepository) UploadUsage(context.Context, string) (db.UploadUsage, error) {
	return db.UploadUsage{}, nil
}

func (repository *memoryApplicationRepository) Get(context.Context, string) (*db.FileList, error) {
	return nil, db.ErrNotFound
}

func (repository *memoryApplicationRepository) CompleteUpload(context.Context, string) error {
	return nil
}

func (repository *memoryApplicationRepository) FinalizeUpload(context.Context, string, string, string, bool, string) error {
	return nil
}

func (repository *memoryApplicationRepository) ExpiredUploads(context.Context, time.Time, int) ([]db.FileList, error) {
	return nil, nil
}

func (repository *memoryApplicationRepository) Rename(context.Context, string, string) error {
	return nil
}

func (repository *memoryApplicationRepository) Delete(context.Context, string) error { return nil }

func (repository *memoryApplicationRepository) Ping(context.Context) error { return nil }

func (repository *memoryApplicationRepository) ClaimFilesForRetention(context.Context, time.Time, time.Time, *time.Time, *time.Time, int) ([]db.FileList, error) {
	return nil, nil
}

func (repository *memoryApplicationRepository) ReleaseRetentionClaim(context.Context, string) error {
	return nil
}

func (repository *memoryApplicationRepository) store(t *testing.T, cfg *config.ServiceConfig, runtime config.RuntimeConfig) {
	t.Helper()
	sealed, err := config.SealRuntime(runtime, cfg.SettingsKey)
	if err != nil {
		t.Fatal(err)
	}
	repository.storeSealed(sealed)
}

func (repository *memoryApplicationRepository) storeSealed(value string) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.setting = &db.ApplicationSetting{Key: "runtime_config", Value: value, UpdatedBy: "admin@example.com", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
}

func TestConfigurationReloadActivatesRevisionsWithoutRestart(t *testing.T) {
	t.Setenv("OBJECTSHARE_JWT_SECRET", "reload-test-jwt-secret-with-at-least-32-bytes")
	t.Setenv("OBJECTSHARE_SETTINGS_KEY", "reload-test-settings-key-with-at-least-32-bytes")
	base, err := config.Load("config.json.example")
	if err != nil {
		t.Fatal(err)
	}
	base.RateLimit.Enabled = false
	base.StorageService, base.StoragePath = "filesystem", t.TempDir()
	repository := &memoryApplicationRepository{}
	runtime := config.RuntimeFromService(base)
	repository.store(t, base, runtime)

	reloader := newConfigReloader(t.Context(), base, repository, templateFiles, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer reloader.Stop()
	if err := reloader.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
	first := reloader.current.Load()
	if first == nil {
		t.Fatal("the first revision was not activated")
	}
	assertServes(t, reloader)

	if err := reloader.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
	if reloader.current.Load() != first {
		t.Fatal("an unchanged revision was rebuilt")
	}

	runtime.MaxFileSize = 44
	runtime.Branding.SiteName = "Cat Cloud"
	repository.store(t, base, runtime)
	if err := reloader.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
	activated := reloader.current.Load()
	if activated == first {
		t.Fatal("a saved revision was not activated")
	}
	assertServes(t, reloader)
	// The bootstrap configuration stays pristine so the next snapshot is built
	// from it rather than from the revision it replaces.
	if base.MaxFileSize == 44 || base.Branding.SiteName != "ObjectShare" {
		t.Fatal("activation mutated the bootstrap configuration")
	}

	repository.storeSealed("enc:v1:not-valid-base64-ciphertext-!")
	if err := reloader.Reload(t.Context()); err == nil {
		t.Fatal("an unreadable revision was activated")
	}
	if reloader.current.Load() != activated {
		t.Fatal("a failed activation replaced the running configuration")
	}
	assertServes(t, reloader)
}

func assertServes(t *testing.T, reloader *configReloader) {
	t.Helper()
	response := httptest.NewRecorder()
	reloader.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("live endpoint returned %d after a reload", response.Code)
	}
}

func TestConfigurationWatchActivatesRevisionsSavedByAnotherReplica(t *testing.T) {
	t.Setenv("OBJECTSHARE_JWT_SECRET", "watch-test-jwt-secret-with-at-least-32-bytes")
	t.Setenv("OBJECTSHARE_SETTINGS_KEY", "watch-test-settings-key-with-at-least-32-bytes")
	base, err := config.Load("config.json.example")
	if err != nil {
		t.Fatal(err)
	}
	base.RateLimit.Enabled = false
	base.StorageService, base.StoragePath = "filesystem", t.TempDir()
	repository := &memoryApplicationRepository{}
	runtime := config.RuntimeFromService(base)
	repository.store(t, base, runtime)

	watchContext, stopWatch := context.WithCancel(t.Context())
	defer stopWatch()
	reloader := newConfigReloader(t.Context(), base, repository, templateFiles, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer reloader.Stop()
	if err := reloader.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
	first := reloader.current.Load()
	watchDone := make(chan struct{})
	go func() { defer close(watchDone); reloader.Watch(watchContext, 10*time.Millisecond) }()

	// Another replica saves a revision; polling must activate it here without
	// a restart and without a request to this replica.
	runtime.MaxFileSize = 44
	repository.store(t, base, runtime)
	deadline := time.Now().Add(10 * time.Second)
	for reloader.current.Load() == first {
		if time.Now().After(deadline) {
			t.Fatal("polling did not activate a revision saved by another replica")
		}
		time.Sleep(5 * time.Millisecond)
	}
	assertServes(t, reloader)

	stopWatch()
	select {
	case <-watchDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the configuration watcher did not stop with its context")
	}
}
