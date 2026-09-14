package db

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPostgresUploadCompletionAndDeletionAreExclusive(t *testing.T) {
	repo := creditTestRepository(t)
	if err := repo.connection.AutoMigrate(&FileList{}); err != nil {
		t.Fatal(err)
	}
	owner := creditTestUser(t, repo, 0)
	for _, finalize := range []bool{false, true} {
		for i := 0; i < 20; i++ {
			expires := time.Now().Add(time.Hour)
			file := FileList{FileID: uuid.NewString(), FileOwner: &owner.ID, FileName: "race.txt", FileSize: 6,
				UploadStatus: "pending", UploadExpiresAt: &expires, ShareUserIDs: []string{}}
			if err := repo.Create(t.Context(), &file); err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			completed, discarded := make(chan error, 1), make(chan error, 1)
			go func() {
				<-start
				if finalize {
					completed <- repo.FinalizeUpload(t.Context(), file.FileID, "sha256", "sha3", false, "")
				} else {
					completed <- repo.CompleteUpload(t.Context(), file.FileID)
				}
			}()
			go func() {
				<-start
				discarded <- repo.ClaimPendingUploadDeletion(t.Context(), file.FileID)
			}()
			close(start)
			completeErr, discardErr := <-completed, <-discarded
			if !((completeErr == nil && errors.Is(discardErr, ErrNotFound)) ||
				(discardErr == nil && errors.Is(completeErr, ErrNotFound))) {
				t.Fatalf("exactly one operation must win: finalize=%v complete=%v discard=%v", finalize, completeErr, discardErr)
			}
			stored, err := repo.Get(t.Context(), file.FileID)
			if err != nil {
				t.Fatal(err)
			}
			if completeErr == nil {
				if stored.UploadStatus != "complete" || stored.UploadExpiresAt != nil {
					t.Fatalf("successful completion was not preserved: %+v", stored)
				}
			} else {
				if stored.UploadStatus != "aborting" {
					t.Fatalf("deletion claim was not preserved: %+v", stored)
				}
				// Both a retry and quota accounting survive the committed claim.
				if err := repo.ClaimPendingUploadDeletion(t.Context(), file.FileID); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	used, err := uploadBytesUsed(repo.connection, owner.ID)
	if err != nil || used != 40*6 {
		t.Fatalf("completed and aborting files must both consume quota: %d %v", used, err)
	}
}

func TestPostgresUploadCleanupRetriesClaimsAndExcludesCompletedFiles(t *testing.T) {
	repo := creditTestRepository(t)
	if err := repo.connection.AutoMigrate(&FileList{}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	want := map[string]bool{}
	for _, state := range []string{"pending", "aborting", "complete", "deleting"} {
		expires := now.Add(-time.Hour)
		if state == "aborting" {
			expires = now.Add(time.Hour) // A failed cancellation needs no expiry wait.
		}
		file := FileList{FileID: uuid.NewString(), FileName: "cleanup.txt", FileSize: 6,
			UploadStatus: state, UploadExpiresAt: &expires, ShareUserIDs: []string{}}
		if err := repo.Create(t.Context(), &file); err != nil {
			t.Fatal(err)
		}
		if state == "pending" || state == "aborting" {
			want[file.FileID] = true
		}
	}
	files, err := repo.ExpiredUploads(t.Context(), now, 25)
	if err != nil || len(files) != len(want) {
		t.Fatalf("cleanup candidates=%d err=%v", len(files), err)
	}
	for _, file := range files {
		if !want[file.FileID] {
			t.Fatalf("cleanup included protected state %s", file.UploadStatus)
		}
	}
}
