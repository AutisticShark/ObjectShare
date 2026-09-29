package db

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// The SQL pre-filter uses the plan's current retention while the authoritative
// check uses the paid invoice's snapshot. Rows the snapshot protects must not
// starve eligible rows queued behind them.
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
