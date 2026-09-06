package db

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func invoiceTestPlan(t *testing.T, repo *GormRepository) PaidPlan {
	t.Helper()
	plan := PaidPlan{Name: "Plus", Description: "Purchased terms", Price: 10, DurationDays: 30, StorageQuotaBytes: 2048, RetentionDays: 60, DirectLinks: true, Active: true}
	if err := repo.CreatePlan(t.Context(), &plan); err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestPostgresInvoiceCreditSnapshotOwnershipReplayAndRollback(t *testing.T) {
	repo := creditTestRepository(t)
	user := creditTestUser(t, repo, 25)
	other := creditTestUser(t, repo, 25)
	plan := invoiceTestPlan(t, repo)
	now := time.Now().UTC()
	key := uuid.NewString()
	invoice, err := repo.CreatePlanInvoice(t.Context(), user.ID, plan.ID, key, "EUR", now)
	if err != nil {
		t.Fatal(err)
	}
	again, err := repo.CreatePlanInvoice(t.Context(), user.ID, plan.ID, key, "USD", now)
	if err != nil || again.ID != invoice.ID || again.Currency != "EUR" {
		t.Fatalf("replay: %#v %v", again, err)
	}
	if _, err = repo.InvoiceForUser(t.Context(), other.ID, invoice.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read ownership: %v", err)
	}
	if err = repo.PayInvoiceCredit(t.Context(), other.ID, invoice.ID, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pay ownership: %v", err)
	}
	ent, err := repo.Entitlements(t.Context(), user.ID, now)
	if err != nil || ent.Active {
		t.Fatalf("unpaid entitlement: %#v %v", ent, err)
	}
	plan.Price, plan.DurationDays, plan.StorageQuotaBytes, plan.Name = 20, 2, 4096, "Edited plan"
	if err := repo.UpdatePlan(t.Context(), &plan); err != nil {
		t.Fatal(err)
	}
	// Fail after subscription/ledger writes to prove the whole payment rolls back.
	if err := repo.connection.Exec("ALTER TABLE invoices ADD CONSTRAINT test_invoice_unpaid CHECK (status <> 'paid')").Error; err != nil {
		t.Fatal(err)
	}
	if err = repo.PayInvoiceCredit(t.Context(), user.ID, invoice.ID, now); err == nil {
		t.Fatal("expected rollback")
	}
	assertCreditState(t, repo, user.ID, 25, 0)
	ent, err = repo.Entitlements(t.Context(), user.ID, now)
	if err != nil || ent.Active {
		t.Fatal("rolled back plan activated")
	}
	if err := repo.connection.Exec("ALTER TABLE invoices DROP CONSTRAINT test_invoice_unpaid").Error; err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		group.Go(func() { errs <- repo.PayInvoiceCredit(t.Context(), user.ID, invoice.ID, now) })
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	assertCreditState(t, repo, user.ID, 15, 1)
	ent, err = repo.Entitlements(t.Context(), user.ID, now)
	if err != nil || !ent.Active || ent.StorageQuotaBytes != 2048 || ent.PlanName != "Plus" || ent.CurrentPeriodEnd.Sub(now.AddDate(0, 0, 30)).Abs() > time.Millisecond {
		t.Fatalf("snapshot: %#v %v", ent, err)
	}
	paid, err := repo.InvoiceForUser(t.Context(), user.ID, invoice.ID)
	if err != nil || paid.Status != "paid" || paid.PaidAt == nil || paid.EmailSentAt != nil {
		t.Fatalf("paid invoice: %#v %v", paid, err)
	}
}

func TestPostgresInvoiceGatewaySettlementAndPaymentLock(t *testing.T) {
	for _, gateway := range []string{BillingGatewayStripe, BillingGatewayPayPal} {
		t.Run(gateway, func(t *testing.T) {
			repo := creditTestRepository(t)
			user := creditTestUser(t, repo, 50)
			plan := invoiceTestPlan(t, repo)
			now := time.Now().UTC()
			invoice, err := repo.CreatePlanInvoice(t.Context(), user.ID, plan.ID, uuid.NewString(), "USD", now)
			if err != nil {
				t.Fatal(err)
			}
			payment, err := repo.ReserveInvoiceGateway(t.Context(), user.ID, invoice.ID, gateway, now)
			if err != nil {
				t.Fatal(err)
			}
			if err = repo.PayInvoiceCredit(t.Context(), user.ID, invoice.ID, now); !errors.Is(err, ErrConflict) {
				t.Fatalf("cross method: %v", err)
			}
			again, err := repo.ReserveInvoiceGateway(t.Context(), user.ID, invoice.ID, gateway, now)
			if err != nil || again.ID != payment.ID {
				t.Fatalf("reservation replay: %#v %v", again, err)
			}
			other, err := repo.CreatePlanInvoice(t.Context(), user.ID, plan.ID, uuid.NewString(), "USD", now)
			if err != nil {
				t.Fatal(err)
			}
			if err = repo.PayInvoiceCredit(t.Context(), user.ID, other.ID, now); !errors.Is(err, ErrConflict) {
				t.Fatalf("overlap: %v", err)
			}
			receipt := CreditPayment{TopUpID: payment.ID, Gateway: gateway, GatewayPaymentID: "receipt-123", AmountMinor: 999, Currency: "USD"}
			if _, err = repo.ApplyCreditTopUp(t.Context(), receipt, now); !errors.Is(err, ErrInvalidCredit) {
				t.Fatalf("amount mismatch: %v", err)
			}
			receipt.AmountMinor = 1000
			receipt.Currency = "EUR"
			if _, err = repo.ApplyCreditTopUp(t.Context(), receipt, now); !errors.Is(err, ErrInvalidCredit) {
				t.Fatalf("currency mismatch: %v", err)
			}
			receipt.Currency = "USD"
			// A genuine delayed receipt remains settleable after the payment window.
			applied, err := repo.ApplyCreditTopUp(t.Context(), receipt, now.Add(25*time.Hour))
			if err != nil || !applied {
				t.Fatalf("settle: %v %v", applied, err)
			}
			applied, err = repo.ApplyCreditTopUp(t.Context(), receipt, now.Add(25*time.Hour))
			if err != nil || applied {
				t.Fatalf("replay: %v %v", applied, err)
			}
			assertCreditState(t, repo, user.ID, 50, 1)
			paid, err := repo.InvoiceForUser(t.Context(), user.ID, invoice.ID)
			if err != nil || paid.Status != "paid" || paid.PaymentID != receipt.GatewayPaymentID {
				t.Fatalf("invoice: %#v %v", paid, err)
			}
			ent, err := repo.Entitlements(t.Context(), user.ID, now.Add(25*time.Hour))
			if err != nil || !ent.Active {
				t.Fatalf("activation: %#v %v", ent, err)
			}
		})
	}
}

func TestPostgresInvoiceOutboxLeaseRecovery(t *testing.T) {
	repo := creditTestRepository(t)
	user := creditTestUser(t, repo, 20)
	plan := invoiceTestPlan(t, repo)
	now := time.Now().UTC()
	invoice, err := repo.CreatePlanInvoice(t.Context(), user.ID, plan.ID, uuid.NewString(), "USD", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.ClaimInvoiceEmail(t.Context(), now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unpaid email: %v", err)
	}
	if err = repo.PayInvoiceCredit(t.Context(), user.ID, invoice.ID, now); err != nil {
		t.Fatal(err)
	}
	first, err := repo.ClaimInvoiceEmail(t.Context(), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.ClaimInvoiceEmail(t.Context(), now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double claim: %v", err)
	}
	second, err := repo.ClaimInvoiceEmail(t.Context(), now.Add(6*time.Minute))
	if err != nil || second.EmailLease == first.EmailLease {
		t.Fatalf("lease recovery: %v", err)
	}
	if err = repo.FinishInvoiceEmail(t.Context(), first.ID, first.EmailLease, true, now); err != nil {
		t.Fatal(err)
	}
	current, err := repo.InvoiceForUser(t.Context(), user.ID, invoice.ID)
	if err != nil || current.EmailSentAt != nil {
		t.Fatal("stale worker marked delivered")
	}
	if err = repo.FinishInvoiceEmail(t.Context(), second.ID, second.EmailLease, true, now); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.ClaimInvoiceEmail(t.Context(), now.Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("resent delivered mail: %v", err)
	}
}

func TestPostgresLegacyRenewalRequiresPaidInvoice(t *testing.T) {
	repo := creditTestRepository(t)
	user := creditTestUser(t, repo, 0)
	plan := invoiceTestPlan(t, repo)
	now := time.Now().UTC().Truncate(time.Second)
	update := SubscriptionUpdate{Gateway: BillingGatewayStripe, EventID: "created", UserID: user.ID, PlanID: plan.ID, SubscriptionID: "sub_existing", CustomerID: "cus_existing", Status: "active", CurrentPeriodEnd: now.AddDate(0, 0, 30), EventCreated: now.Unix()}
	if _, err := repo.ApplySubscription(t.Context(), update); err != nil {
		t.Fatal(err)
	}
	ent, err := repo.Entitlements(t.Context(), user.ID, now)
	if err != nil || ent.Active {
		t.Fatal("lifecycle event bypassed invoice")
	}
	receipt := LegacyInvoicePayment{Gateway: BillingGatewayStripe, SubscriptionID: "sub_existing", PaymentID: "in_paid", AmountMinor: 999, Currency: "USD", PeriodStart: now, PeriodEnd: now.AddDate(0, 0, 30), PaidAt: now}
	for range 2 {
		if err = repo.ApplyLegacyInvoicePayment(t.Context(), receipt, now); err != nil {
			t.Fatal(err)
		}
	}
	ent, err = repo.Entitlements(t.Context(), user.ID, now)
	if err != nil || !ent.Active {
		t.Fatalf("paid invoice did not activate: %#v %v", ent, err)
	}
	rows, err := repo.InvoicesForUser(t.Context(), user.ID, 0)
	if err != nil || len(rows) != 1 || rows[0].Status != "paid" || rows[0].AmountMinor != 999 {
		t.Fatalf("renewal invoice: %#v %v", rows, err)
	}
	update.EventID = "unpaid-next-period"
	update.EventCreated++
	update.CurrentPeriodEnd = now.AddDate(0, 0, 60)
	if _, err = repo.ApplySubscription(t.Context(), update); err != nil {
		t.Fatal(err)
	}
	ent, err = repo.Entitlements(t.Context(), user.ID, now)
	if err != nil || !ent.CurrentPeriodEnd.Equal(receipt.PeriodEnd) {
		t.Fatal("unpaid period extension")
	}
	update.EventID = "future-unpaid-failure"
	update.EventCreated++
	update.Status = "past_due"
	if _, err = repo.ApplySubscription(t.Context(), update); err != nil {
		t.Fatal(err)
	}
	update.EventID = "recover-without-receipt"
	update.EventCreated++
	update.Status = "active"
	if _, err = repo.ApplySubscription(t.Context(), update); err != nil {
		t.Fatal(err)
	}
	ent, err = repo.Entitlements(t.Context(), user.ID, now)
	if err != nil || !ent.CurrentPeriodEnd.Equal(receipt.PeriodEnd) {
		t.Fatal("failure/recovery bypassed paid period")
	}
	update.EventID = "cancel"
	update.EventCreated++
	update.Status = "canceled"
	if _, err = repo.ApplySubscription(t.Context(), update); err != nil {
		t.Fatal(err)
	}
	ent, err = repo.Entitlements(t.Context(), user.ID, now)
	if err != nil || ent.Active {
		t.Fatal("cancellation was not preserved")
	}
}
