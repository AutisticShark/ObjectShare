package db

import (
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func TestPostgresClientKeyMigrationAndConcurrentCreation(t *testing.T) {
	repo := creditTestRepository(t)
	if err := repo.connection.AutoMigrate(&FileList{}, &ClientKeyVault{}); err != nil {
		t.Fatal(err)
	}
	user := creditTestUser(t, repo, 0)
	other := creditTestUser(t, repo, 0)
	legacy := &FileList{FileID: uuid.NewString(), FileOwner: &user.ID, FileName: "legacy.txt", FileSize: 3, StorageService: "filesystem", UploadStatus: "pending"}
	if err := repo.ReserveUpload(t.Context(), legacy); err != nil {
		t.Fatal(err)
	}
	// Repeated migrations keep existing rows and their plaintext interpretation.
	for range 2 {
		if err := repo.connection.AutoMigrate(&FileList{}, &ClientKeyVault{}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := repo.Get(t.Context(), legacy.FileID)
	if err != nil || got.ClientEncryption != "" || got.FileName != legacy.FileName {
		t.Fatalf("legacy migration: %v %+v", err, got)
	}
	vault := ClientKeyVault{UserID: user.ID, Version: 1, KeyID: "test-key", Salt: "test-salt", IV: "test-iv", WrappedKey: "test-ciphertext"}
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Go(func() { copy := vault; results <- repo.CreateClientKey(t.Context(), &copy) })
	}
	wg.Wait()
	close(results)
	created := 0
	for err := range results {
		if err == nil {
			created++
		} else if !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	if created != 1 {
		t.Fatalf("created %d account keys", created)
	}
	read, err := repo.ClientKey(t.Context(), user.ID)
	if err != nil || read.WrappedKey != vault.WrappedKey {
		t.Fatalf("vault persistence: %v", err)
	}
	if _, err := repo.ClientKey(t.Context(), other.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("vault crossed account boundary")
	}
	plaintext := &FileList{FileID: uuid.NewString(), FileOwner: &user.ID, FileName: "blocked.txt", FileSize: 3, StorageService: "filesystem", UploadStatus: "pending"}
	if err := repo.ReserveUpload(t.Context(), plaintext); err == nil {
		t.Fatal("plaintext reservation bypassed encryption requirement")
	}
	encrypted := *plaintext
	encrypted.FileID = uuid.NewString()
	encrypted.ClientEncryption = `{"version":1}`
	if err := repo.ReserveUpload(t.Context(), &encrypted); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateProfile(t.Context(), user.ID, "Renamed", "changed@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpdatePassword(t.Context(), user.ID, "new-hash"); err != nil {
		t.Fatal(err)
	}
	read, err = repo.ClientKey(t.Context(), user.ID)
	if err != nil || read.KeyID != vault.KeyID || read.WrappedKey != vault.WrappedKey {
		t.Fatal("account updates changed encryption key")
	}
}
