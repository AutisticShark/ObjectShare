package htmx

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
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
				handler.cleanupExpiredUploads(request)
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
	handler.cleanupExpiredUploads(httptest.NewRequest("POST", "/", nil))
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
