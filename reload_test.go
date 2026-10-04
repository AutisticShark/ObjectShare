package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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

func (repository *memoryApplicationRepository) ClaimUploadPublication(context.Context, string) error {
	return db.ErrNotFound
}

func (repository *memoryApplicationRepository) ReleaseUploadPublication(context.Context, string) error {
	return db.ErrNotFound
}

func (repository *memoryApplicationRepository) ExtendUploadReservation(context.Context, string, time.Time) error {
	return db.ErrNotFound
}

func (repository *memoryApplicationRepository) ClaimPendingUploadDeletion(context.Context, string) error {
	return db.ErrNotFound
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

func TestStopAndReloadCannotRaceOnTheWorkerGroup(t *testing.T) {
	t.Setenv("OBJECTSHARE_JWT_SECRET", "stop-test-jwt-secret-with-at-least-32-bytes")
	t.Setenv("OBJECTSHARE_SETTINGS_KEY", "stop-test-settings-key-with-at-least-32-bytes")
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
	if err := reloader.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}

	// Hammer Reload with fresh revisions while Stop runs. Run under -race, a
	// WaitGroup.Add concurrent with Wait is reported; here every reload after
	// Stop must also be refused rather than starting workers nobody waits for.
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for attempt := 0; attempt < 20; attempt++ {
				candidate := runtime
				candidate.MaxFileSize = int64(50 + worker*20 + attempt)
				repository.store(t, base, candidate)
				if err := reloader.Reload(t.Context()); err != nil && !errors.Is(err, errReloaderStopped) {
					t.Errorf("reload: %v", err)
					return
				}
			}
		}()
	}
	time.Sleep(5 * time.Millisecond)
	reloader.Stop()
	wg.Wait()

	stoppedAt := reloader.current.Load()
	candidate := runtime
	candidate.MaxFileSize = 99
	repository.store(t, base, candidate)
	if err := reloader.Reload(t.Context()); !errors.Is(err, errReloaderStopped) {
		t.Fatalf("Reload after Stop = %v, want errReloaderStopped", err)
	}
	if reloader.current.Load() != stoppedAt {
		t.Fatal("a snapshot was activated after Stop")
	}
	reloader.workers.Wait() // returns at once: no worker was added after Stop
}

// syncBuffer lets the watcher goroutine write logs the test goroutine reads.
type syncBuffer struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (buffer *syncBuffer) Write(data []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.data.Write(data)
}

func (buffer *syncBuffer) count(text string) int {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return strings.Count(buffer.data.String(), text)
}

func TestWatchLogsEachDistinctActivationFailureOnce(t *testing.T) {
	t.Setenv("OBJECTSHARE_JWT_SECRET", "quiet-test-jwt-secret-with-at-least-32-bytes")
	t.Setenv("OBJECTSHARE_SETTINGS_KEY", "quiet-test-settings-key-with-at-least-32-bytes")
	base, err := config.Load("config.json.example")
	if err != nil {
		t.Fatal(err)
	}
	base.RateLimit.Enabled = false
	base.StorageService, base.StoragePath = "filesystem", t.TempDir()
	repository := &memoryApplicationRepository{}
	runtime := config.RuntimeFromService(base)
	repository.store(t, base, runtime)
	logs := &syncBuffer{}
	reloader := newConfigReloader(t.Context(), base, repository, templateFiles, slog.New(slog.NewTextHandler(logs, nil)))
	defer reloader.Stop()
	if err := reloader.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}

	watchContext, stopWatch := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); reloader.Watch(watchContext, 5*time.Millisecond) }()
	repository.storeSealed("enc:v1:not-valid-base64-ciphertext-!")
	deadline := time.Now().Add(5 * time.Second)
	for logs.count("activate saved configuration failed") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("a failing revision was never reported")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond) // dozens of further polls of the same bad revision
	if got := logs.count("activate saved configuration failed"); got != 1 {
		t.Fatalf("the same failure was logged %d times, want once", got)
	}

	// A different failure is reported again, and a good revision resets the memory.
	repository.storeSealed("enc:v1:another-broken-ciphertext-!")
	for logs.count("activate saved configuration failed") < 2 {
		if time.Now().After(deadline) {
			t.Fatal("a different failure was suppressed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	stopWatch()
	<-done
}
