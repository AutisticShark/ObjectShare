package db

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPostgresHasEncryptedFiles(t *testing.T) {
	repo := creditTestRepository(t)
	if err := repo.connection.AutoMigrate(&FileList{}); err != nil {
		t.Fatal(err)
	}
	if found, err := repo.HasEncryptedFiles(t.Context()); err != nil || found {
		t.Fatalf("empty table: found=%v err=%v", found, err)
	}
	now := time.Now().UTC()
	file := FileList{AnonymousSessionToken: "token", FileID: uuid.NewString(), FileName: "f.bin", FileSize: 1, ContentType: "application/octet-stream",
		IsAnonymousUpload: true, StorageService: "r2", UploadStatus: "complete", ChecksumStatus: "verified", CreatedAt: now, UpdatedAt: now}
	if err := repo.connection.Create(&file).Error; err != nil {
		t.Fatal(err)
	}
	if found, err := repo.HasEncryptedFiles(t.Context()); err != nil || found {
		t.Fatalf("plaintext file: found=%v err=%v", found, err)
	}
	if err := repo.connection.Model(&FileList{}).Where("file_id = ?", file.FileID).Update("is_encrypted", true).Error; err != nil {
		t.Fatal(err)
	}
	if found, err := repo.HasEncryptedFiles(t.Context()); err != nil || !found {
		t.Fatalf("encrypted file: found=%v err=%v", found, err)
	}
}
