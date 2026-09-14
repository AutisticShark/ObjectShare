package db

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPostgresWorkspaceOwnerIsolationSearchPaginationAndOverview(t *testing.T) {
	repo := creditTestRepository(t)
	if err := repo.connection.AutoMigrate(&FileList{}); err != nil {
		t.Fatal(err)
	}
	owner := creditTestUser(t, repo, 0)
	other := creditTestUser(t, repo, 0)
	now := time.Now().UTC()
	for i := 0; i < 30; i++ {
		file := FileList{FileID: uuid.NewString(), FileOwner: &owner.ID, FileName: "report_100%.txt", FileSize: 10,
			UploadStatus: "complete", ShareMode: "private", ShareUserIDs: []string{}, CreatedAt: now}
		if i == 28 {
			file.FileOwner = &other.ID
		}
		if i == 29 {
			file.UploadStatus = "pending"
		}
		if err := repo.connection.Create(&file).Error; err != nil {
			t.Fatal(err)
		}
	}
	first, err := repo.OwnerFiles(t.Context(), owner.ID, "100%", "private", 0)
	if err != nil || len(first) != 26 {
		t.Fatalf("first page: %d %v", len(first), err)
	}
	seen := map[string]bool{}
	for _, file := range first[:WorkspacePageSize] {
		if *file.FileOwner != owner.ID || file.UploadStatus != "complete" {
			t.Fatal("another owner's or unfinished file leaked")
		}
		seen[file.FileID] = true
	}
	second, err := repo.OwnerFiles(t.Context(), owner.ID, "100%", "private", 1)
	if err != nil || len(second) != 3 {
		t.Fatalf("second page: %d %v", len(second), err)
	}
	for _, file := range second {
		if seen[file.FileID] {
			t.Fatal("unstable ordering across pages with identical timestamps")
		}
	}
	for _, search := range []string{"100_", "' OR 1=1 --"} {
		files, err := repo.OwnerFiles(t.Context(), owner.ID, search, "", 0)
		if err != nil || len(files) != 0 {
			t.Fatalf("literal search %q: %d %v", search, len(files), err)
		}
	}
	stats, err := repo.AdminOverview(t.Context(), now)
	if err != nil || stats.Users != 2 || stats.Files != 29 || stats.StorageBytes != 290 || stats.PendingUploads != 1 {
		t.Fatalf("overview: %+v %v", stats, err)
	}
}

func TestPostgresAdminInvoiceSearchAndReceiptStatus(t *testing.T) {
	repo := creditTestRepository(t)
	if err := repo.connection.AutoMigrate(&FileList{}); err != nil {
		t.Fatal(err)
	}
	user := creditTestUser(t, repo, 20)
	plan := invoiceTestPlan(t, repo)
	now := time.Now().UTC()
	paid, err := repo.CreatePlanInvoice(t.Context(), user.ID, plan.ID, uuid.NewString(), "USD", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.PayInvoiceCredit(t.Context(), user.ID, paid.ID, now); err != nil {
		t.Fatal(err)
	}
	other := creditTestUser(t, repo, 20)
	_, err = repo.CreatePlanInvoice(t.Context(), other.ID, plan.ID, uuid.NewString(), "EUR", now)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		search, filter string
		count          int
	}{
		{"", "", 2}, {"", "paid", 1}, {"", "pending", 1}, {"", "unsent", 1},
		{paid.ID, "", 1}, {user.Email, "", 1}, {"Plus", "", 2}, {"' OR 1=1 --", "", 0}, {"%", "", 0},
	} {
		rows, err := repo.AdminInvoices(t.Context(), test.search, test.filter, 0)
		if err != nil || len(rows) != test.count {
			t.Fatalf("search=%q filter=%q: %d %v", test.search, test.filter, len(rows), err)
		}
	}
	stats, err := repo.AdminOverview(t.Context(), now)
	if err != nil || stats.PaidInvoices != 1 || stats.PendingInvoices != 1 || stats.UnsentReceipts != 1 || stats.ActivePlans != 1 {
		t.Fatalf("billing overview: %+v %v", stats, err)
	}
	if err := repo.connection.Model(&Invoice{}).Where("id = ?", paid.ID).Update("email_sent_at", now).Error; err != nil {
		t.Fatal(err)
	}
	rows, err := repo.AdminInvoices(t.Context(), "", "unsent", 0)
	if err != nil || len(rows) != 0 {
		t.Fatalf("sent receipt still listed: %v", err)
	}
}
