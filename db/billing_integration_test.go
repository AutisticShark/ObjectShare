package db

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Use a disposable PostgreSQL database. Each test creates and removes only its
// own random schema, and never migrates the database's public schema.
func creditTestRepository(t *testing.T) *GormRepository {
	t.Helper()
	dsn := os.Getenv("OBJECTSHARE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set OBJECTSHARE_TEST_POSTGRES_DSN to run PostgreSQL transaction tests")
	}
	settings, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid test PostgreSQL DSN")
	}
	settings.ConnectTimeout = 5 * time.Second
	admin := stdlib.OpenDB(*settings)
	t.Cleanup(func() { _ = admin.Close() })
	schemaName := "credit_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quotedSchema := pgx.Identifier{schemaName}.Sanitize()
	if _, err := admin.ExecContext(t.Context(), "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal("cannot create isolated test schema: ", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.ExecContext(ctx, "DROP SCHEMA "+quotedSchema+" CASCADE"); err != nil {
			t.Error("cannot remove isolated test schema: ", err)
		}
	})
	settings.RuntimeParams["search_path"] = schemaName
	pool := stdlib.OpenDB(*settings)
	pool.SetMaxOpenConns(12)
	t.Cleanup(func() { _ = pool.Close() })
	connection, err := gorm.Open(postgres.New(postgres.Config{Conn: pool}), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal("cannot connect to test database")
	}
	models := []any{&User{}, &PaidPlan{}, &Subscription{}, &BillingCheckout{}, &BillingEvent{}, &CreditTopUp{}, &CreditTransaction{}}
	for range 2 {
		if err := connection.AutoMigrate(models...); err != nil {
			t.Fatal(err)
		}
	}
	return &GormRepository{connection: connection}
}

func creditTestUser(t *testing.T, repo *GormRepository, balance int64) User {
	t.Helper()
	user := User{ID: uuid.NewString(), Email: uuid.NewString() + "@example.com", Active: true, CreditBalance: balance}
	if err := repo.connection.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	return user
}

func assertCreditState(t *testing.T, repo *GormRepository, userID string, balance, entries int64) {
	t.Helper()
	var user User
	if err := repo.connection.First(&user, "id = ?", userID).Error; err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := repo.connection.Model(&CreditTransaction{}).Where("user_id = ?", userID).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if user.CreditBalance != balance || count != entries {
		t.Fatalf("balance=%d entries=%d; want balance=%d entries=%d", user.CreditBalance, count, balance, entries)
	}
}

func TestPostgresCreditTopUpReplayAndValidation(t *testing.T) {
	repo := creditTestRepository(t)
	user := creditTestUser(t, repo, 0)
	now := time.Now().UTC()
	topUp := CreditTopUp{UserID: user.ID, Gateway: BillingGatewayStripe, Credits: 25, AmountMinor: 2500, Currency: "USD", ExpiresAt: now.Add(time.Hour)}
	if err := repo.CreateCreditTopUp(t.Context(), &topUp); err != nil {
		t.Fatal(err)
	}
	payment := CreditPayment{TopUpID: topUp.ID, Gateway: BillingGatewayStripe, GatewayPaymentID: "pi_test", AmountMinor: 2500, Currency: "USD"}
	invalid := payment
	invalid.AmountMinor = 2400
	if _, err := repo.ApplyCreditTopUp(t.Context(), invalid, now); !errors.Is(err, ErrInvalidCredit) {
		t.Fatalf("mismatched value: %v", err)
	}
	assertCreditState(t, repo, user.ID, 0, 0)
	var group sync.WaitGroup
	results := make(chan bool, 8)
	errorsFound := make(chan error, 8)
	for range 8 {
		group.Go(func() {
			applied, err := repo.ApplyCreditTopUp(t.Context(), payment, now)
			results <- applied
			errorsFound <- err
		})
	}
	group.Wait()
	close(results)
	close(errorsFound)
	appliedCount := 0
	for applied := range results {
		if applied {
			appliedCount++
		}
	}
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	if appliedCount != 1 {
		t.Fatalf("applied %d times", appliedCount)
	}
	assertCreditState(t, repo, user.ID, 25, 1)
	invalid = payment
	invalid.GatewayPaymentID = "pi_other"
	if _, err := repo.ApplyCreditTopUp(t.Context(), invalid, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("second receipt for completed top-up: %v", err)
	}
	other := CreditTopUp{UserID: user.ID, Gateway: BillingGatewayStripe, Credits: 25, AmountMinor: 2500, Currency: "USD", ExpiresAt: now.Add(time.Hour)}
	if err := repo.CreateCreditTopUp(t.Context(), &other); err != nil {
		t.Fatal(err)
	}
	invalid = payment
	invalid.TopUpID = other.ID
	if _, err := repo.ApplyCreditTopUp(t.Context(), invalid, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("receipt reused on another top-up: %v", err)
	}
	assertCreditState(t, repo, user.ID, 25, 1)
}

func TestPostgresCreditPurchasesCannotOverspend(t *testing.T) {
	repo := creditTestRepository(t)
	user := creditTestUser(t, repo, 15)
	plan := PaidPlan{ID: uuid.NewString(), Name: "Credit plan", Gateway: BillingGatewayStripe, GatewayPlanID: "price_test", StorageQuotaBytes: 1024, Active: true, CreditPrice: 10, CreditDurationDays: 30}
	if err := repo.CreatePlan(t.Context(), &plan); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	keys := []string{uuid.NewString(), uuid.NewString()}
	errs := make([]error, 2)
	var group sync.WaitGroup
	for i := range keys {
		group.Go(func() { _, errs[i] = repo.PurchasePlanWithCredit(t.Context(), user.ID, plan.ID, keys[i], now) })
	}
	group.Wait()
	winner := 0
	if errs[0] != nil {
		winner = 1
	}
	if errs[winner] != nil || !errors.Is(errs[1-winner], ErrInsufficientCredit) {
		t.Fatalf("concurrent purchases: %v", errs)
	}
	assertCreditState(t, repo, user.ID, 5, 1)
	sub, err := repo.PurchasePlanWithCredit(t.Context(), user.ID, plan.ID, keys[winner], now)
	if err != nil || sub.Gateway != BillingGatewayCredit || sub.CurrentPeriodEnd.Sub(now.AddDate(0, 0, 30)).Abs() > time.Millisecond {
		t.Fatalf("purchase replay: sub=%#v err=%v", sub, err)
	}
	assertCreditState(t, repo, user.ID, 5, 1)
	if _, err := repo.PurchasePlanWithCredit(t.Context(), user.ID, uuid.NewString(), keys[winner], now); !errors.Is(err, ErrConflict) {
		t.Fatalf("reused purchase key: %v", err)
	}
	if _, err := repo.ApplySubscription(t.Context(), SubscriptionUpdate{Gateway: BillingGatewayStripe, EventID: "late-checkout", UserID: user.ID,
		PlanID: plan.ID, SubscriptionID: "sub_late", Status: "active", CurrentPeriodEnd: now.AddDate(0, 0, 30), EventCreated: now.Unix() + 1}); !errors.Is(err, ErrConflict) {
		t.Fatalf("late provider checkout replaced prepaid access: %v", err)
	}
	sub, err = repo.SubscriptionForUser(t.Context(), user.ID)
	if err != nil || sub.Gateway != BillingGatewayCredit {
		t.Fatalf("prepaid subscription was lost: sub=%#v err=%v", sub, err)
	}
	assertCreditState(t, repo, user.ID, 5, 1)
}

func TestPostgresCreditAdjustmentReplayAndRollback(t *testing.T) {
	repo := creditTestRepository(t)
	user := creditTestUser(t, repo, 0)
	adminID, requestID := uuid.NewString(), uuid.NewString()
	for range 2 {
		balance, err := repo.AdjustCredit(t.Context(), user.ID, -7, "Refund correction", adminID, requestID, time.Now().UTC())
		if err != nil || balance != -7 {
			t.Fatalf("adjustment balance=%d err=%v", balance, err)
		}
	}
	if _, err := repo.AdjustCredit(t.Context(), user.ID, 10, "Changed", adminID, requestID, time.Now().UTC()); !errors.Is(err, ErrConflict) {
		t.Fatalf("reused adjustment key: %v", err)
	}
	assertCreditState(t, repo, user.ID, -7, 1)
	// Force the balance update to fail after the ledger insert; neither change
	// may commit. This constraint exists only in this test's isolated schema.
	if err := repo.connection.Exec("ALTER TABLE users ADD CONSTRAINT test_credit_limit CHECK (credit_balance < 100)").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := repo.AdjustCredit(t.Context(), user.ID, 200, "Must roll back", adminID, uuid.NewString(), time.Now().UTC()); err == nil {
		t.Fatal("expected balance update failure")
	}
	assertCreditState(t, repo, user.ID, -7, 1)
}
