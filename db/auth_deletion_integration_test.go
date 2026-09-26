package db

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDeleteUserRevokesFileOwnerToken(t *testing.T) {
	repo := creditTestRepository(t)
	if err := repo.connection.AutoMigrate(&FileList{}); err != nil {
		t.Fatal(err)
	}
	user := User{ID: uuid.NewString(), Email: "deleted@example.test", DisplayName: "Deleted", Active: true, Role: RoleUser}
	if err := repo.connection.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	file := FileList{
		FileID: uuid.NewString(), FileOwner: &user.ID, FileName: "retained.txt", FileSize: 6,
		AnonymousSessionToken: "af0553066c22960cb89f503121ff5535ba5fe0c9e64e74003d7097a50ad0a13",
		UploadStatus:          "complete", ShareMode: ShareLink, CreatedAt: time.Now().UTC(),
	}
	if err := repo.Create(t.Context(), &file); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteUser(t.Context(), user.ID); err != nil {
		t.Fatal(err)
	}
	retained, err := repo.Get(t.Context(), file.FileID)
	if err != nil {
		t.Fatal(err)
	}
	if retained.FileOwner != nil || !retained.IsAnonymousUpload || retained.AnonymousSessionToken != "" || retained.ShareMode != ShareLink {
		t.Fatalf("deleted account retained a file owner credential or lost sharing: %#v", retained)
	}
}
