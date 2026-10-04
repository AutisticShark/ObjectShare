package db

import (
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresMigrationCreditTopUpSchemaChanges(t *testing.T) {
	settings := creditTestSettings(t)
	settings.RuntimeParams["timezone"] = "Asia/Taipei"
	location, err := time.LoadLocation("Asia/Taipei")
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
		if !repo.connection.PrepareStmt {
			t.Fatal("runtime prepared statements were not enabled after migration")
		}
		return repo
	}

	// Exercise the real startup path first on an empty schema.
	repo := open()
	user := creditTestUser(t, repo, 37)
	expires := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	topUp := CreditTopUp{UserID: user.ID, Gateway: BillingGatewayStripe, Credits: 25, AmountMinor: 2500, Currency: "USD", ExpiresAt: expires}
	if err := repo.CreateCreditTopUp(t.Context(), &topUp); err != nil {
		t.Fatal(err)
	}
	paypalStarted := time.Now().UTC().Truncate(time.Second)
	paypalTopUp := CreditTopUp{UserID: user.ID, Gateway: BillingGatewayPayPal, Credits: 5, AmountMinor: 500, Currency: "USD", ExpiresAt: paypalStarted.Add(24 * time.Hour), CreatedAt: paypalStarted}
	if err := repo.CreateCreditTopUp(t.Context(), &paypalTopUp); err != nil {
		t.Fatal(err)
	}
	// A plan bought and then renewed early, before period starts were stored.
	buyer := creditTestUser(t, repo, 100)
	plan := PaidPlan{Name: "Plus", Description: "Purchased terms", Price: 10, DurationDays: 30, StorageQuotaBytes: 2048, Active: true}
	if err := repo.CreatePlan(t.Context(), &plan); err != nil {
		t.Fatal(err)
	}
	paidAt := time.Now().UTC().Truncate(time.Second)
	var planInvoices []*Invoice
	for range 2 {
		invoice, err := repo.CreatePlanInvoice(t.Context(), buyer.ID, plan.ID, uuid.NewString(), "USD", paidAt)
		if err != nil {
			t.Fatal(err)
		}
		if err = repo.PayInvoiceCredit(t.Context(), buyer.ID, invoice.ID, paidAt); err != nil {
			t.Fatal(err)
		}
		planInvoices = append(planInvoices, invoice)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate an older populated table. Adding the first model field changes
	// SELECT *'s result shape; widening amount_minor makes GORM inspect it again
	// in the same transaction. Either statement cache would break this upgrade.
	pool := stdlib.OpenDB(*settings)
	t.Cleanup(func() { _ = pool.Close() })
	for _, statement := range []string{
		"ALTER TABLE credit_topups DROP COLUMN checkout_url",
		"ALTER TABLE credit_topups ALTER COLUMN amount_minor TYPE integer",
		"ALTER TABLE credit_topups DROP COLUMN checkout_attempt, DROP COLUMN checkout_started_at, DROP COLUMN checkout_expires_at",
		"ALTER TABLE invoices DROP COLUMN period_start",
	} {
		if _, err := pool.ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}

	// Upgrade, then restart against the already migrated schema.
	for range 2 {
		repo = open()
		var got CreditTopUp
		if err := repo.connection.First(&got, "id = ?", topUp.ID).Error; err != nil {
			t.Fatal(err)
		}
		if got.UserID != user.ID || got.Credits != 25 || got.AmountMinor != 2500 || got.Currency != "USD" || got.CheckoutURL != "" || got.Status != CreditTopUpPending || !got.ExpiresAt.Equal(expires) {
			t.Fatalf("migration changed existing top-up: %+v", got)
		}
		if got.CheckoutExpiresAt == nil || !got.CheckoutExpiresAt.Equal(expires) {
			t.Fatalf("Stripe checkout deadline was not backfilled: %+v", got)
		}
		// Pending payments gain the checkout deadline their provider enforces.
		var paypal CreditTopUp
		if err := repo.connection.First(&paypal, "id = ?", paypalTopUp.ID).Error; err != nil {
			t.Fatal(err)
		}
		if paypal.CheckoutStartedAt == nil || !paypal.CheckoutStartedAt.Equal(paypalStarted) || paypal.CheckoutExpiresAt == nil || !paypal.CheckoutExpiresAt.Equal(paypalStarted.Add(PayPalCheckoutLifetime)) {
			t.Fatalf("PayPal checkout deadline was not backfilled: %+v", paypal)
		}
		// The renewal starts when the first purchase's period ends.
		for i, want := range []time.Time{paidAt, paidAt.AddDate(0, 0, 30)} {
			var invoice Invoice
			if err := repo.connection.First(&invoice, "id = ?", planInvoices[i].ID).Error; err != nil {
				t.Fatal(err)
			}
			if invoice.PeriodStart == nil || !invoice.PeriodStart.Equal(want) {
				t.Fatalf("plan invoice %d period start = %v, want %v", i, invoice.PeriodStart, want)
			}
		}
		assertCreditState(t, repo, user.ID, 37, 0)
		if err := repo.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
