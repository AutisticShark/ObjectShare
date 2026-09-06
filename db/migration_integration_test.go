package db

import (
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
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
		assertCreditState(t, repo, user.ID, 37, 0)
		if err := repo.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
