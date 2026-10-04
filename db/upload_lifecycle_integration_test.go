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

func TestPostgresUploadPublicationExcludesCleanupUntilAbandoned(t *testing.T) {
	repo := creditTestRepository(t)
	if err := repo.connection.AutoMigrate(&FileList{}); err != nil {
		t.Fatal(err)
	}
	owner := creditTestUser(t, repo, 0)
	create := func(expires time.Time) FileList {
		file := FileList{FileID: uuid.NewString(), FileOwner: &owner.ID, FileName: "publish.txt", FileSize: 6,
			UploadStatus: "pending", UploadExpiresAt: &expires, ShareUserIDs: []string{}}
		if err := repo.Create(t.Context(), &file); err != nil {
			t.Fatal(err)
		}
		return file
	}
	for i := 0; i < 20; i++ {
		file := create(time.Now().Add(time.Hour))
		start := make(chan struct{})
		published, discarded := make(chan error, 1), make(chan error, 1)
		go func() { <-start; published <- repo.ClaimUploadPublication(t.Context(), file.FileID) }()
		go func() { <-start; discarded <- repo.ClaimPendingUploadDeletion(t.Context(), file.FileID) }()
		close(start)
		publishErr, discardErr := <-published, <-discarded
		if !((publishErr == nil && errors.Is(discardErr, ErrNotFound)) || (discardErr == nil && errors.Is(publishErr, ErrNotFound))) {
			t.Fatalf("exactly one claim must win: publish=%v discard=%v", publishErr, discardErr)
		}
		if publishErr == nil {
			if err := repo.CompleteUpload(t.Context(), file.FileID); err != nil {
				t.Fatalf("a publishing upload must complete: %v", err)
			}
		}
	}

	// A live claim is protected from expiry cleanup, still counts against the
	// quota, and returns to pending when released after a failed copy.
	expired := time.Now().Add(-time.Hour)
	file := create(expired)
	if err := repo.ClaimUploadPublication(t.Context(), file.FileID); err != nil {
		t.Fatal(err)
	}
	if err := repo.ClaimUploadPublication(t.Context(), file.FileID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a live publishing claim was claimed twice: %v", err)
	}
	if candidates, err := repo.ExpiredUploads(t.Context(), time.Now().UTC(), 100); err != nil || containsFile(candidates, file.FileID) {
		t.Fatalf("expiry cleanup selected a live publishing claim: %v", err)
	}
	if used, err := uploadBytesUsed(repo.connection, owner.ID); err != nil || used != 21*6 { // twenty raced files (complete or aborting) and this one
		t.Fatalf("publishing upload must consume quota: %d %v", used, err)
	}
	if err := repo.ReleaseUploadPublication(t.Context(), file.FileID); err != nil {
		t.Fatal(err)
	}
	if stored, err := repo.Get(t.Context(), file.FileID); err != nil || stored.UploadStatus != "pending" {
		t.Fatalf("released claim: %+v %v", stored, err)
	}

	// A claim abandoned by a stopped process can be claimed again by a retried
	// completion, or removed by cleanup once its authorization has expired.
	abandon := func() {
		t.Helper()
		if err := repo.ClaimUploadPublication(t.Context(), file.FileID); err != nil {
			t.Fatal(err)
		}
		if err := repo.connection.Model(&FileList{}).Where("file_id = ?", file.FileID).
			Update("updated_at", time.Now().UTC().Add(-UploadPublicationLease-time.Minute)).Error; err != nil {
			t.Fatal(err)
		}
	}
	abandon()
	if err := repo.ClaimUploadPublication(t.Context(), file.FileID); err != nil {
		t.Fatalf("abandoned claim could not be retried: %v", err)
	}
	if err := repo.ReleaseUploadPublication(t.Context(), file.FileID); err != nil {
		t.Fatal(err)
	}
	abandon()
	if candidates, err := repo.ExpiredUploads(t.Context(), time.Now().UTC(), 100); err != nil || !containsFile(candidates, file.FileID) {
		t.Fatalf("expiry cleanup skipped an abandoned publishing claim: %v", err)
	}
	if err := repo.ClaimPendingUploadDeletion(t.Context(), file.FileID); err != nil {
		t.Fatalf("abandoned claim could not be deleted: %v", err)
	}
}

func containsFile(files []FileList, fileID string) bool {
	for _, file := range files {
		if file.FileID == fileID {
			return true
		}
	}
	return false
}

func TestPostgresUploadReservationExtendsOnlyLivePendingUploads(t *testing.T) {
	repo := creditTestRepository(t)
	if err := repo.connection.AutoMigrate(&FileList{}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	create := func(status string, expires time.Time) string {
		file := FileList{FileID: uuid.NewString(), FileName: "renew.txt", FileSize: 6, UploadStatus: status, UploadExpiresAt: &expires, ShareUserIDs: []string{}}
		if err := repo.Create(t.Context(), &file); err != nil {
			t.Fatal(err)
		}
		return file.FileID
	}
	live := create("pending", now.Add(10*time.Minute))
	for _, until := range []time.Time{now.Add(2 * time.Hour), now.Add(time.Hour)} {
		if err := repo.ExtendUploadReservation(t.Context(), live, until); err != nil {
			t.Fatal(err)
		}
	}
	if stored, err := repo.Get(t.Context(), live); err != nil || stored.UploadExpiresAt.Sub(now.Add(2*time.Hour)).Abs() > time.Second {
		t.Fatalf("reservation must extend and never shorten: %+v %v", stored, err)
	}
	for _, id := range []string{create("pending", now.Add(-time.Minute)), create("publishing", now.Add(time.Hour)), create("aborting", now.Add(time.Hour))} {
		if err := repo.ExtendUploadReservation(t.Context(), id, now.Add(2*time.Hour)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("extended a reservation that is expired or no longer pending: %v", err)
		}
	}
}
