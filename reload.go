package main

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/AutisticShark/ObjectShare/api"
	"github.com/AutisticShark/ObjectShare/api/htmx"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/AutisticShark/ObjectShare/retention"
	"github.com/AutisticShark/ObjectShare/service"
)

// reloadTimeout bounds only the database read that fetches a candidate
// revision. Building the snapshot itself performs no network work.
const reloadTimeout = 15 * time.Second

// applicationRepository is the storage surface one configuration snapshot
// needs: request handling, its background workers, and the settings document
// that defines the snapshot.
type applicationRepository interface {
	db.Repository
	db.RetentionRepository
	db.SettingsRepository
}

// configSnapshot is one activated revision. Storage clients, encryption,
// authentication, CSP, cookies, and proxy trust are still built together as a
// single consistent set; a reload replaces the whole set at once instead of
// mutating a shared configuration while requests are running.
type configSnapshot struct {
	sealed  string
	handler *htmx.Handler
	router  http.Handler
	cancel  context.CancelFunc
}

// configReloader serves HTTP from the active snapshot and activates saved
// revisions without a restart. Requests read the snapshot pointer once, so an
// in-flight request always finishes against the configuration it started with.
type configReloader struct {
	lifetime   context.Context
	base       *config.ServiceConfig
	repository applicationRepository
	templates  fs.FS
	logger     *slog.Logger
	current    atomic.Pointer[configSnapshot]
	mu         sync.Mutex
	workers    sync.WaitGroup
}

// newConfigReloader keeps the bootstrap configuration as the pristine base for
// every snapshot. Listener, database, and JWT bootstrap settings are not part
// of the database document and therefore still require a restart to change.
func newConfigReloader(lifetime context.Context, base *config.ServiceConfig, repository applicationRepository, templates fs.FS, logger *slog.Logger) *configReloader {
	return &configReloader{lifetime: lifetime, base: base, repository: repository, templates: templates, logger: logger}
}

func (reloader *configReloader) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	snapshot := reloader.current.Load()
	if snapshot == nil {
		http.Error(writer, "Configuration is not active yet.", http.StatusServiceUnavailable)
		return
	}
	snapshot.router.ServeHTTP(writer, request)
}

// Reload activates the stored revision when it differs from the running one. A
// failure leaves the previous snapshot serving traffic, so an unusable revision
// saved by another replica cannot take this one down.
func (reloader *configReloader) Reload(ctx context.Context) error {
	reloader.mu.Lock()
	defer reloader.mu.Unlock()
	setting, err := reloader.repository.ApplicationSettings(ctx)
	if err != nil {
		return fmt.Errorf("load database configuration: %w", err)
	}
	previous := reloader.current.Load()
	if previous != nil && previous.sealed == setting.Value {
		return nil
	}
	runtime, err := config.OpenRuntime(setting.Value, reloader.base.SettingsKey)
	if err != nil {
		return fmt.Errorf("open database configuration: %w", err)
	}
	cfg, err := config.WithRuntime(reloader.base, runtime)
	if err != nil {
		return err
	}
	objectStore, err := service.New(cfg)
	if err != nil {
		return fmt.Errorf("initialize object storage: %w", err)
	}
	handler, err := htmx.New(cfg, reloader.repository, objectStore, reloader.templates, reloader.logger)
	if err != nil {
		return fmt.Errorf("initialize HTTP handlers: %w", err)
	}
	if previous != nil {
		handler.InheritProcessState(previous.handler)
	}
	handler.SetConfigReloader(reloader.Reload)
	workerContext, cancel := context.WithCancel(reloader.lifetime)
	reloader.workers.Add(2)
	go func() { defer reloader.workers.Done(); handler.RunInvoiceEmails(workerContext) }()
	go func() {
		defer reloader.workers.Done()
		retention.New(reloader.repository, objectStore, *cfg.Retention, reloader.logger).Run(workerContext)
	}()
	reloader.current.Store(&configSnapshot{sealed: setting.Value, handler: handler, router: api.Router(handler, reloader.logger), cancel: cancel})
	if previous != nil {
		// Requests already inside the replaced snapshot finish there; only its
		// background workers stop. Both workers claim their work with database
		// leases, so a brief overlap repeats no deletion or delivery.
		previous.cancel()
		reloader.logger.Info("configuration activated", "updated_at", setting.UpdatedAt.UTC(), "updated_by", setting.UpdatedBy, "storage_service", cfg.StorageService)
	}
	return nil
}

// Watch activates revisions saved by this or any other replica. SIGHUP forces
// an immediate check, which is the only trigger left when polling is disabled.
func (reloader *configReloader) Watch(ctx context.Context, interval time.Duration) {
	hangup := make(chan os.Signal, 1)
	signal.Notify(hangup, syscall.SIGHUP)
	defer signal.Stop(hangup)
	var poll <-chan time.Time
	if interval > 0 {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		poll = ticker.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-hangup:
		case <-poll:
		}
		reloadContext, cancel := context.WithTimeout(ctx, reloadTimeout)
		err := reloader.Reload(reloadContext)
		cancel()
		if err != nil && ctx.Err() == nil {
			reloader.logger.Error("activate saved configuration failed", "error", err)
		}
	}
}

// Stop ends the active snapshot's background workers and waits for every
// worker this process started, including those of replaced snapshots.
func (reloader *configReloader) Stop() {
	if snapshot := reloader.current.Load(); snapshot != nil {
		snapshot.cancel()
	}
	reloader.workers.Wait()
}
