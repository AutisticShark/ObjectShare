package db

import (
	"context"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Run explicitly with a disposable OBJECTSHARE_TEST_POSTGRES_DSN. This measures
// database-backed listing operations, not HTTP latency or object transfer capacity.
func BenchmarkPostgresWorkspace(b *testing.B) {
	repo := creditTestRepository(b)
	if err := repo.connection.AutoMigrate(&FileList{}); err != nil {
		b.Fatal(err)
	}
	const userCount, fileCount, invoiceCount = 5000, 50000, 25000
	now := time.Now().UTC()
	users := make([]User, userCount)
	for i := range users {
		users[i] = User{ID: uuid.NewString(), Email: fmt.Sprintf("member-%05d@example.test", i),
			DisplayName: fmt.Sprintf("Member %05d", i), Role: RoleUser, Active: true,
			PasswordHash: "benchmark-only-not-a-login", EmailVerifiedAt: &now}
		if i%100 == 0 {
			users[i].Role = RoleAdmin
		}
	}
	if err := repo.connection.CreateInBatches(&users, 250).Error; err != nil {
		b.Fatal(err)
	}
	files := make([]FileList, fileCount)
	for i := range files {
		owner := i % userCount
		if i < 10000 {
			owner = 0
		}
		files[i] = FileList{FileID: uuid.NewString(), FileOwner: &users[owner].ID,
			FileName: fmt.Sprintf("report-%06d.txt", i), FileSize: 1024 * 1024,
			UploadStatus: "complete", ShareMode: "private", ShareUserIDs: []string{},
			StorageService: "filesystem", CreatedAt: now.Add(-time.Duration(i) * time.Second)}
		if i%10 == 0 {
			files[i].UploadStatus = "pending"
		}
	}
	if err := repo.connection.CreateInBatches(&files, 250).Error; err != nil {
		b.Fatal(err)
	}
	invoices := make([]Invoice, invoiceCount)
	for i := range invoices {
		invoices[i] = Invoice{ID: uuid.NewString(), UserID: users[i%userCount].ID, RequestID: uuid.NewString(),
			Kind: "plan", Name: "Benchmark plan", Email: users[i%userCount].Email,
			Credits: 10, AmountMinor: 1000, Currency: "USD", Status: "paid", PaidAt: &now,
			DurationDays: 30, CreatedAt: now.Add(-time.Duration(i) * time.Second), ExpiresAt: now.Add(time.Hour)}
		if i%3 == 0 {
			invoices[i].Status = "pending"
			invoices[i].PaidAt = nil
		}
	}
	if err := repo.connection.CreateInBatches(&invoices, 250).Error; err != nil {
		b.Fatal(err)
	}
	for _, table := range []string{"users", "file_lists", "invoices", "subscriptions"} {
		if err := repo.connection.Exec("ANALYZE " + table).Error; err != nil {
			b.Fatal(err)
		}
	}
	ctx := b.Context()
	baseline, err := repo.AdminOverview(ctx, now)
	if err != nil || baseline.Users != userCount || baseline.Files != 45000 || baseline.PaidInvoices != 16666 {
		b.Fatalf("invalid benchmark fixture: %+v, %v", baseline, err)
	}
	ownerFiles := func(search string, page int) func(context.Context) (int, error) {
		return func(ctx context.Context) (int, error) {
			rows, err := repo.OwnerFiles(ctx, users[0].ID, search, "private", page)
			return len(rows), err
		}
	}
	directory := func(search, filter string) func(context.Context) (int, error) {
		return func(ctx context.Context) (int, error) {
			rows, err := repo.AdminUserDirectory(ctx, search, filter, 0)
			return len(rows.Users), err
		}
	}
	invoiceList := func(search, status string, page int) func(context.Context) (int, error) {
		return func(ctx context.Context) (int, error) {
			rows, err := repo.AdminInvoices(ctx, search, status, page)
			return len(rows), err
		}
	}
	for _, workload := range []struct {
		name string
		run  func(context.Context) (int, error)
	}{
		{"OwnerFirstPage", ownerFiles("", 0)},
		{"OwnerPage100", ownerFiles("", 100)},
		{"OwnerSearch", ownerFiles("report-000", 0)},
		{"DirectoryFirstPage", directory("", "")},
		{"DirectorySearch", directory("member-00", "")},
		{"DirectoryAdmins", directory("", "admin")},
		{"InvoicesFirstPage", invoiceList("", "", 0)},
		{"InvoicesPage100", invoiceList("", "", 100)},
		{"InvoicesPaid", invoiceList("", "paid", 0)},
		{"InvoicesSearch", invoiceList("member-00", "", 0)},
	} {
		b.Run(workload.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				count, err := workload.run(ctx)
				if err != nil || count != WorkspacePageSize+1 {
					b.Fatalf("listing returned %d rows: %v", count, err)
				}
			}
		})
	}
	b.Run("Overview", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			result, err := repo.AdminOverview(ctx, now)
			if err != nil || result != baseline {
				b.Fatalf("overview changed: %+v, %v", result, err)
			}
		}
	})
	b.Run("MixedParallel", func(b *testing.B) {
		// One worker per GOMAXPROCS, sharing the fixture's 12-connection pool.
		// ns/op is aggregate throughput cost here, not per-request latency.
		b.SetParallelism(1)
		b.ReportAllocs()
		var next atomic.Uint64
		queries := []func(context.Context) (int, error){ownerFiles("", 0), directory("", ""), invoiceList("", "paid", 0)}
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				count, err := queries[(next.Add(1)-1)%uint64(len(queries))](ctx)
				if err != nil || count != WorkspacePageSize+1 {
					b.Errorf("parallel listing returned %d rows: %v", count, err)
				}
			}
		})
		b.ReportMetric(float64(runtime.GOMAXPROCS(0)), "workers")
	})
}
