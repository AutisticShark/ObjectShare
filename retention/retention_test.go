package retention

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

type memoryRepository struct {
	files         []db.FileList
	claimErr      error
	deleteErrors  map[string]error
	releaseErrors map[string]error
	deleted       []string
	released      []string
	guestBefore   *time.Time
	unpaidBefore  *time.Time
	staleBefore   time.Time
}

func (repository *memoryRepository) ClaimFilesForRetention(_ context.Context, _ time.Time, staleBefore time.Time, guestBefore, unpaidBefore *time.Time, _ int) ([]db.FileList, error) {
	repository.guestBefore, repository.unpaidBefore, repository.staleBefore = guestBefore, unpaidBefore, staleBefore
	return append([]db.FileList(nil), repository.files...), repository.claimErr
}

func (repository *memoryRepository) ReleaseRetentionClaim(_ context.Context, id string) error {
	if err := repository.releaseErrors[id]; err != nil {
		return err
	}
	repository.released = append(repository.released, id)
	return nil
}

func (repository *memoryRepository) Delete(_ context.Context, id string) error {
	if err := repository.deleteErrors[id]; err != nil {
		return err
	}
	repository.deleted = append(repository.deleted, id)
	return nil
}

type memoryStorage struct {
	deleteErrors map[string]error
	deleted      []string
}

func (storage *memoryStorage) Delete(_ context.Context, id string) error {
	if err := storage.deleteErrors[id]; err != nil {
		return err
	}
	storage.deleted = append(storage.deleted, id)
	return nil
}

func TestSweepUsesIndependentGuestAndUnpaidCutoffs(t *testing.T) {
	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	repository := &memoryRepository{}
	cleaner := New(repository, &memoryStorage{}, config.RetentionConfig{GuestDays: 7, UnpaidDays: 30}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := cleaner.Sweep(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	if repository.guestBefore == nil || !repository.guestBefore.Equal(now.Add(-7*24*time.Hour)) {
		t.Fatalf("guest cutoff = %v", repository.guestBefore)
	}
	if repository.unpaidBefore == nil || !repository.unpaidBefore.Equal(now.Add(-30*24*time.Hour)) {
		t.Fatalf("unpaid cutoff = %v", repository.unpaidBefore)
	}
	if !repository.staleBefore.Equal(now.Add(-claimTimeout)) {
		t.Fatalf("stale claim cutoff = %v", repository.staleBefore)
	}
}

func TestSweepDisablesZeroDayCategories(t *testing.T) {
	repository := &memoryRepository{}
	cleaner := New(repository, &memoryStorage{}, config.RetentionConfig{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := cleaner.Sweep(t.Context(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if repository.guestBefore != nil || repository.unpaidBefore != nil {
		t.Fatal("zero-day policy produced a destructive cutoff")
	}
}

func TestSweepDeletesObjectBeforeMetadataAndReleasesStorageFailures(t *testing.T) {
	storageFailure := errors.New("storage unavailable")
	databaseFailure := errors.New("database unavailable")
	repository := &memoryRepository{
		files:         []db.FileList{{FileID: "ok"}, {FileID: "storage-fails"}, {FileID: "database-fails"}},
		deleteErrors:  map[string]error{"database-fails": databaseFailure},
		releaseErrors: make(map[string]error),
	}
	storage := &memoryStorage{deleteErrors: map[string]error{"storage-fails": storageFailure}}
	cleaner := New(repository, storage, config.RetentionConfig{GuestDays: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	result, err := cleaner.Sweep(t.Context(), time.Now().UTC())
	if err == nil || !errors.Is(err, storageFailure) || !errors.Is(err, databaseFailure) {
		t.Fatalf("sweep error = %v", err)
	}
	if result.Claimed != 3 || result.Deleted != 1 || result.Released != 1 {
		t.Fatalf("result = %#v", result)
	}
	if len(repository.deleted) != 1 || repository.deleted[0] != "ok" {
		t.Fatalf("metadata deletions = %v", repository.deleted)
	}
	if len(repository.released) != 1 || repository.released[0] != "storage-fails" {
		t.Fatalf("released claims = %v", repository.released)
	}
	if len(storage.deleted) != 2 {
		t.Fatalf("object deletions = %v", storage.deleted)
	}
}

func TestRunStopsWhenContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cleaner := New(&memoryRepository{}, &memoryStorage{}, config.RetentionConfig{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	done := make(chan struct{})
	go func() {
		cleaner.Run(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("retention worker did not stop after cancellation")
	}
}

var _ db.RetentionRepository = (*memoryRepository)(nil)
var _ ObjectStore = (*memoryStorage)(nil)
