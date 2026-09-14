package db

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPostgresAdminDirectorySearchPaginationAndGlobalTotals(t *testing.T) {
	repo := creditTestRepository(t)
	if err := repo.connection.AutoMigrate(&FileList{}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	var users []User
	for i := 0; i < 31; i++ {
		user := User{ID: uuid.NewString(), Email: fmt.Sprintf("member%02d@example.test", i), DisplayName: "Member",
			PasswordHash: "must-not-be-loaded", EmailVerificationHash: "must-not-be-loaded", Active: true, EmailVerifiedAt: &now, Role: RoleUser}
		if i == 0 {
			user.Role = RoleAdmin
			user.DisplayName = "literal_100%"
		}
		if i == 1 {
			user.DisplayName = "literalX100Z"
		}
		if i == 2 {
			user.ModerationStatus = ModerationBanned
		}
		if i == 3 {
			user.ModerationStatus = ModerationShadowbanned
		}
		if i == 5 {
			user.EmailVerifiedAt = nil
		}
		if err := repo.connection.Create(&user).Error; err != nil {
			t.Fatal(err)
		}
		if i == 4 {
			if err := repo.connection.Model(&user).Update("active", false).Error; err != nil {
				t.Fatal(err)
			}
		}
		users = append(users, user)
		if i > 0 {
			file := FileList{FileID: uuid.NewString(), FileOwner: &user.ID, FileName: "fixture", FileSize: 10,
				UploadStatus: []string{"complete", "pending", "deleting", "aborting", "failed"}[(i-1)%5], ShareUserIDs: []string{}}
			if err := repo.Create(t.Context(), &file); err != nil {
				t.Fatal(err)
			}
		}
	}
	guest := FileList{FileID: uuid.NewString(), FileName: "guest", FileSize: 1000, UploadStatus: "complete", ShareUserIDs: []string{}}
	if err := repo.Create(t.Context(), &guest); err != nil {
		t.Fatal(err)
	}
	first, err := repo.AdminUserDirectory(t.Context(), "", "", 0)
	if err != nil || len(first.Users) != 26 || first.TotalUsers != 31 || first.TotalStorageUsed != 240 {
		t.Fatalf("first page: %+v %v", first, err)
	}
	seen := map[string]bool{}
	for _, user := range first.Users[:25] {
		seen[user.ID] = true
		if user.PasswordHash != "" || user.EmailVerificationHash != "" {
			t.Fatal("directory loaded account secrets")
		}
	}
	second, err := repo.AdminUserDirectory(t.Context(), "", "", 1)
	if err != nil || len(second.Users) != 6 || second.TotalStorageUsed != 240 {
		t.Fatalf("second page: %+v %v", second, err)
	}
	for _, user := range second.Users {
		if seen[user.ID] {
			t.Fatal("duplicate account across pages")
		}
		seen[user.ID] = true
	}
	if len(seen) != 31 {
		t.Fatal("pagination lost accounts")
	}
	for _, test := range []struct {
		search, filter string
		count          int
	}{
		{"literal_", "", 1}, {"100%", "", 1}, {"LITERAL_", "admin", 1}, {"literal_", "banned", 0},
		{users[17].ID, "", 1}, {"MEMBER17@EXAMPLE.TEST", "", 1}, {"' OR 1=1 --", "", 0},
		{"", "admin", 1}, {"", "disabled", 1}, {"", "banned", 1}, {"", "shadowbanned", 1},
		{"", "verified", 26}, {"", "unverified", 1},
	} {
		directory, err := repo.AdminUserDirectory(t.Context(), test.search, test.filter, 0)
		if err != nil || len(directory.Users) != test.count || directory.TotalUsers != 31 || directory.TotalStorageUsed != 240 {
			t.Fatalf("search %q filter %q: count=%d totals=%d/%d err=%v", test.search, test.filter, len(directory.Users), directory.TotalUsers, directory.TotalStorageUsed, err)
		}
		ids := map[string]bool{}
		for _, user := range directory.Users {
			ids[user.ID] = true
		}
		for id := range directory.Usage {
			if !ids[id] {
				t.Fatal("storage query returned an account outside the bounded directory")
			}
		}
	}
	for _, page := range []int{-1, 100001} {
		if _, err := repo.AdminUserDirectory(t.Context(), "", "", page); err == nil {
			t.Fatal("accepted unbounded page")
		}
	}
	if _, err := repo.AdminUserDirectory(t.Context(), "", "unknown", 0); err == nil {
		t.Fatal("accepted unknown filter")
	}
}
