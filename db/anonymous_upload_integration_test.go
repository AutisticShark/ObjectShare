package db

import (
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/stdlib"
)

// Account-owned uploads must be stored as not anonymous. A true column default
// used to make GORM replace the explicit false, so every upload was stored as
// anonymous; startup corrects rows written that way.
func TestPostgresAnonymousUploadFlagIsPersistedAndMigrated(t *testing.T) {
	settings := creditTestSettings(t)
	location, err := time.LoadLocation("UTC")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.DatabaseConfig{MaxOpenConns: 1, MaxIdleConns: 1}
	open := func() *GormRepository {
		t.Helper()
		repo, err := openPostgres(t.Context(), cfg, settings, location)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = repo.Close() })
		return repo
	}
	repo := open()
	owner := creditTestUser(t, repo, 0)
	now := time.Now().UTC()
	reserve := func(fileOwner *string) string {
		t.Helper()
		file := &FileList{AnonymousSessionToken: "token", FileID: uuid.NewString(), FileOwner: fileOwner, FileName: "f.bin", FileSize: 1, ContentType: "application/octet-stream",
			IsAnonymousUpload: fileOwner == nil, StorageService: "r2", UploadStatus: "pending", ChecksumStatus: "pending", CreatedAt: now, UpdatedAt: now}
		if err := repo.ReserveUpload(t.Context(), file); err != nil {
			t.Fatal(err)
		}
		return file.FileID
	}
	anonymous := func(fileID string) bool {
		t.Helper()
		file, err := repo.Get(t.Context(), fileID)
		if err != nil {
			t.Fatal(err)
		}
		return file.IsAnonymousUpload
	}
	owned, guest := reserve(&owner.ID), reserve(nil)
	if anonymous(owned) || !anonymous(guest) {
		t.Fatalf("stored flags: owned anonymous=%v, guest anonymous=%v", anonymous(owned), anonymous(guest))
	}

	// Recreate what earlier releases stored, then restart twice.
	pool := stdlib.OpenDB(*settings)
	t.Cleanup(func() { _ = pool.Close() })
	for _, statement := range []string{
		"ALTER TABLE file_lists ALTER COLUMN is_anonymous_upload SET DEFAULT true",
		"UPDATE file_lists SET is_anonymous_upload = true",
	} {
		if _, err := pool.ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		repo = open()
		if anonymous(owned) || !anonymous(guest) {
			t.Fatalf("migrated flags: owned anonymous=%v, guest anonymous=%v", anonymous(owned), anonymous(guest))
		}
		if err := repo.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
