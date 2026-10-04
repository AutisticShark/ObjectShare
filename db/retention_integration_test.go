package db

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The SQL pre-filter and the authoritative check both use the paid invoice's
// snapshot. Rows the snapshot protects must not starve eligible rows queued
// behind them, whichever of the two rejects them.
func TestPostgresRetentionClaimPagesPastRowsTheEntitlementCheckRejects(t *testing.T) {
	repo := creditTestRepository(t)
	if err := repo.connection.AutoMigrate(&FileList{}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	plan := PaidPlan{Name: "Short", Description: "one day in the catalogue", Price: 10, DurationDays: 30, StorageQuotaBytes: 2048, RetentionDays: 1, Active: true}
	if err := repo.CreatePlan(t.Context(), &plan); err != nil {
		t.Fatal(err)
	}
	user := creditTestUser(t, repo, 0)
	invoice := Invoice{ID: uuid.NewString(), UserID: user.ID, RequestID: uuid.NewString(), Kind: "plan", PlanID: plan.ID, Name: "Long", Description: "purchased with ten years of retention",
		Email: user.Email, Credits: 10, AmountMinor: 1000, Currency: "USD", DurationDays: 30, StorageQuotaBytes: 2048, RetentionDays: 3650, Status: "paid", CreatedAt: now, ExpiresAt: now.Add(time.Hour), PaidAt: &now}
	if err := repo.connection.Create(&invoice).Error; err != nil {
		t.Fatal(err)
	}
	subscription := Subscription{ID: uuid.NewString(), UserID: user.ID, PlanID: plan.ID, Gateway: BillingGatewayCredit, GatewaySubscriptionID: uuid.NewString(), Status: "active",
		CurrentPeriodEnd: now.Add(24 * time.Hour), InvoiceID: invoice.ID, CreatedAt: now, UpdatedAt: now}
	if err := repo.connection.Create(&subscription).Error; err != nil {
		t.Fatal(err)
	}
	newFile := func(owner *string, age time.Duration) string {
		id := uuid.NewString()
		file := FileList{AnonymousSessionToken: "token", FileID: id, FileOwner: owner, FileName: "f.bin", FileSize: 1, FileSHA256: "a", FileSHA3: "b", ContentType: "application/octet-stream",
			IsAnonymousUpload: owner == nil, StorageService: "r2", UploadStatus: "complete", ChecksumStatus: "verified", CreatedAt: now.Add(-age), UpdatedAt: now}
		if err := repo.connection.Create(&file).Error; err != nil {
			t.Fatal(err)
		}
		return id
	}
	protected := map[string]bool{}
	for range 4 {
		protected[newFile(&user.ID, 400*24*time.Hour)] = true // older than anything else, so they sort first
	}
	guest := newFile(nil, 200*24*time.Hour)

	guestBefore, unpaidBefore := now.AddDate(0, 0, -7), now.AddDate(0, 0, -30)
	claimed, err := repo.ClaimFilesForRetention(t.Context(), now, now.Add(-time.Hour), &guestBefore, &unpaidBefore, 2)
	if err != nil {
		t.Fatal(err)
	}
	foundGuest := false
	for _, file := range claimed {
		if protected[file.FileID] {
			t.Fatalf("a file protected by the purchased retention was claimed: %s", file.FileID)
		}
		foundGuest = foundGuest || file.FileID == guest
	}
	if !foundGuest {
		t.Fatalf("the eligible guest file starved behind rejected rows; claimed %d others", len(claimed))
	}
	if len(claimed) > 2 {
		t.Fatalf("claimed %d files, limit was 2", len(claimed))
	}
}

func TestPostgresClaimFileDeletionHidesTheFileAndCanBeReleased(t *testing.T) {
	repo := creditTestRepository(t)
	if err := repo.connection.AutoMigrate(&FileList{}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	id := uuid.NewString()
	file := FileList{AnonymousSessionToken: "token", FileID: id, FileName: "f.bin", FileSize: 1, FileSHA256: "a", FileSHA3: "b", ContentType: "application/octet-stream",
		IsAnonymousUpload: true, StorageService: "r2", UploadStatus: "complete", ChecksumStatus: "verified", CreatedAt: now, UpdatedAt: now}
	if err := repo.connection.Create(&file).Error; err != nil {
		t.Fatal(err)
	}
	if err := repo.ClaimFileDeletion(t.Context(), id, now); err != nil {
		t.Fatal(err)
	}
	if err := repo.ClaimFileDeletion(t.Context(), id, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a second claim = %v, want ErrNotFound", err)
	}
	var stored FileList
	if err := repo.connection.Where("file_id = ?", id).First(&stored).Error; err != nil || stored.UploadStatus != "deleting" || stored.RetentionClaimedAt == nil {
		t.Fatalf("claimed row = %#v, err %v", stored, err)
	}
	if err := repo.ReleaseRetentionClaim(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	if err := repo.connection.Where("file_id = ?", id).First(&stored).Error; err != nil || stored.UploadStatus != "complete" {
		t.Fatalf("released row = %#v, err %v", stored, err)
	}
	if err := repo.Delete(t.Context(), id); err != nil {
		t.Fatal(err)
	}
}

// Retention follows the invoice that paid for the current period: catalog edits
// after payment change nothing, and an early renewal's terms start only when
// the earlier period ends.
func TestPostgresRetentionClaimUsesThePaidInvoiceSnapshot(t *testing.T) {
	repo := creditTestRepository(t)
	if err := repo.connection.AutoMigrate(&FileList{}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	paid := now.AddDate(0, 0, -1)
	plan := PaidPlan{Name: "Week", Description: "seven days", Price: 10, DurationDays: 30, StorageQuotaBytes: 2048, RetentionDays: 7, Active: true}
	if err := repo.CreatePlan(t.Context(), &plan); err != nil {
		t.Fatal(err)
	}
	user := creditTestUser(t, repo, 100)
	buy := func(at time.Time) {
		t.Helper()
		invoice, err := repo.CreatePlanInvoice(t.Context(), user.ID, plan.ID, uuid.NewString(), "USD", at)
		if err != nil {
			t.Fatal(err)
		}
		if err = repo.PayInvoiceCredit(t.Context(), user.ID, invoice.ID, at); err != nil {
			t.Fatal(err)
		}
	}
	buy(paid) // 7 days of retention until paid+30d
	plan.RetentionDays = 30
	if err := repo.UpdatePlan(t.Context(), &plan); err != nil {
		t.Fatal(err)
	}
	buy(paid.Add(time.Hour)) // early renewal: 30 days of retention from paid+30d
	plan.RetentionDays = 0   // the catalog now keeps files forever
	if err := repo.UpdatePlan(t.Context(), &plan); err != nil {
		t.Fatal(err)
	}
	renewal := paid.AddDate(0, 0, 30).Add(time.Hour)
	newFile := func(created time.Time) string {
		t.Helper()
		id := uuid.NewString()
		file := FileList{AnonymousSessionToken: "token", FileID: id, FileOwner: &user.ID, FileName: "f.bin", FileSize: 1, FileSHA256: "a", FileSHA3: "b", ContentType: "application/octet-stream",
			StorageService: "r2", UploadStatus: "complete", ChecksumStatus: "verified", CreatedAt: created, UpdatedAt: now}
		if err := repo.connection.Create(&file).Error; err != nil {
			t.Fatal(err)
		}
		return id
	}
	expired := newFile(now.AddDate(0, 0, -10))              // past the first period's 7 days
	expiresInRenewal := newFile(renewal.AddDate(0, 0, -35)) // 4 days old now, 35 at the renewal check
	keptInRenewal := newFile(renewal.AddDate(0, 0, -20))    // 20 days old at the renewal check
	unpaidBefore := now.AddDate(0, 0, -365)
	claimIDs := func(at time.Time) map[string]bool {
		t.Helper()
		claimed, err := repo.ClaimFilesForRetention(t.Context(), at, now.Add(-time.Hour), nil, &unpaidBefore, 10)
		if err != nil {
			t.Fatal(err)
		}
		ids := map[string]bool{}
		for _, file := range claimed {
			ids[file.FileID] = true
		}
		return ids
	}
	if ids := claimIDs(now); !ids[expired] || len(ids) != 1 {
		t.Fatalf("claimed %v during the first period; want only the file past its 7 purchased days (%s)", ids, expired)
	}
	if ids := claimIDs(renewal); !ids[expiresInRenewal] || ids[keptInRenewal] || len(ids) != 1 {
		t.Fatalf("claimed %v during the renewal; want only the file past its 30 purchased days (%s)", ids, expiresInRenewal)
	}
}
