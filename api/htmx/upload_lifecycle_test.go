package htmx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/db"
)

// Simulate completion committing after a handler reads pending state but before
// it claims deletion. No timing assumptions or concurrent mock map access.
type completionBeforeDeletionRepository struct {
	db.Repository
}

func (repo completionBeforeDeletionRepository) ClaimPendingUploadDeletion(ctx context.Context, id string) error {
	if err := repo.Repository.CompleteUpload(ctx, id); err != nil {
		return err
	}
	return repo.Repository.ClaimPendingUploadDeletion(ctx, id)
}

func TestStaleUploadDeletionCannotRemoveCompletedFile(t *testing.T) {
	for _, path := range []string{"abort", "expired authorization", "expiry cleanup", "size mismatch"} {
		t.Run(path, func(t *testing.T) {
			handler, repo, storage, file, owner := sharingTestHandler(t)
			direct := &directMemoryStorage{storage}
			handler.direct, handler.storage = direct, direct
			handler.repository = completionBeforeDeletionRepository{repo}
			token, hash, err := newOwnerToken()
			if err != nil {
				t.Fatal(err)
			}
			file.AnonymousSessionToken, file.UploadStatus = hash, "pending"
			expires := time.Now().Add(time.Hour)
			if path == "expired authorization" || path == "expiry cleanup" {
				expires = time.Now().Add(-time.Hour)
			}
			file.UploadExpiresAt = &expires
			body, _ := json.Marshal(map[string]string{"token": token})
			request := sharingRequest("POST", file.FileID, string(body), owner)
			response := httptest.NewRecorder()
			switch path {
			case "abort":
				handler.AbortDirectUpload(response, request)
				if response.Code != 404 {
					t.Fatalf("stale abort status=%d", response.Code)
				}
			case "expired authorization":
				handler.CompleteDirectUpload(response, request)
			case "expiry cleanup":
				handler.sweepExpiredUploads(request.Context())
			case "size mismatch":
				file.FileSize++
				handler.CompleteDirectUpload(response, request)
			}
			persisted, err := repo.Get(t.Context(), file.FileID)
			if err != nil || persisted.UploadStatus != "complete" || string(storage.objects[file.FileID]) != "secret" {
				t.Fatalf("stale %s removed a completed upload: file=%+v err=%v", path, persisted, err)
			}
		})
	}
}

type interruptedDeletionStorage struct {
	*memoryStorage
	repo db.Repository
	fail bool
	t    *testing.T
}

func (storage *interruptedDeletionStorage) Delete(ctx context.Context, id string) error {
	if err := storage.repo.CompleteUpload(ctx, id); !errors.Is(err, db.ErrNotFound) {
		storage.t.Fatalf("completion must fail before object deletion, got %v", err)
	}
	if storage.fail {
		return io.ErrUnexpectedEOF
	}
	return storage.memoryStorage.Delete(ctx, id)
}

func TestFailedUploadDeletionRetainsQuotaAndCleanupRetries(t *testing.T) {
	handler, repo, storage, file, owner := sharingTestHandler(t)
	file.UploadStatus = "pending"
	expires := time.Now().Add(time.Hour)
	file.UploadExpiresAt = &expires
	repo.quotaBytes = map[string]int64{owner.ID: file.FileSize}
	fault := &interruptedDeletionStorage{memoryStorage: storage, repo: repo, fail: true, t: t}
	handler.storage = fault
	if err := handler.deletePendingUpload(t.Context(), file.FileID); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected failed object deletion, got %v", err)
	}
	usage, err := repo.UploadUsage(t.Context(), owner.ID)
	if err != nil || usage.Used != file.FileSize || file.UploadStatus != "aborting" {
		t.Fatalf("failed deletion lost quota or retry state: %+v %v", usage, err)
	}
	fault.fail = false
	handler.sweepExpiredUploads(context.Background())
	if _, err := repo.Get(t.Context(), file.FileID); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("cleanup did not remove reservation: %v", err)
	}
	if _, exists := storage.objects[file.FileID]; exists {
		t.Fatal("cleanup did not remove object")
	}
	usage, err = repo.UploadUsage(t.Context(), owner.ID)
	if err != nil || usage.Used != 0 {
		t.Fatalf("successful cleanup did not release quota: %+v %v", usage, err)
	}
}

// slowDeleteStorage stalls deletions until released, like a slow object store.
type slowDeleteStorage struct {
	*memoryStorage
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (storage *slowDeleteStorage) Delete(ctx context.Context, key string) error {
	if storage.calls.Add(1) == 1 {
		close(storage.started)
	}
	<-storage.release
	return storage.memoryStorage.Delete(ctx, key)
}

func TestExpiredReservationCleanupRunsOffTheRequestPathAndIsSingleFlight(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	expired := time.Now().Add(-time.Hour)
	repository.files["2e8b6bd5-3ff0-4700-851f-95864db4f8a9"] = &db.FileList{FileID: "2e8b6bd5-3ff0-4700-851f-95864db4f8a9", UploadStatus: "pending", UploadExpiresAt: &expired, FileSize: 1}
	storage := &slowDeleteStorage{memoryStorage: &memoryStorage{objects: make(map[string][]byte)}, started: make(chan struct{}), release: make(chan struct{})}
	handler := newTestHandler(t, repository, storage)
	logs := new(bytes.Buffer)
	handler.logger = slog.New(slog.NewTextHandler(logs, nil))

	returned := make(chan struct{})
	go func() {
		handler.cleanupExpiredUploads(httptest.NewRequest(http.MethodPost, "/upload", nil))
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("the request waited for the object-storage delete")
	}
	<-storage.started // the background pass is now stuck in the slow delete
	handler.cleanupExpiredUploads(httptest.NewRequest(http.MethodPost, "/upload", nil))
	handler.cleanupExpiredUploads(httptest.NewRequest(http.MethodPost, "/upload", nil))
	if calls := storage.calls.Load(); calls != 1 {
		t.Fatalf("a second cleanup pass started while one was running: %d delete calls", calls)
	}
	close(storage.release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		repository.mu.Lock()
		left := len(repository.files)
		repository.mu.Unlock()
		if left == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the expired reservation was never cleaned up")
		}
		time.Sleep(5 * time.Millisecond)
	}
	for !strings.Contains(logs.String(), "cleaned up expired upload reservations") {
		if time.Now().After(deadline) {
			t.Fatalf("the cleanup was not logged: %q", logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Started passes are spaced apart, however many uploads arrive.
	handler.cleanupExpiredUploads(httptest.NewRequest(http.MethodPost, "/upload", nil))
	time.Sleep(50 * time.Millisecond)
	if calls := storage.calls.Load(); calls != 1 {
		t.Fatalf("passes were not spaced: %d delete calls", calls)
	}
}
