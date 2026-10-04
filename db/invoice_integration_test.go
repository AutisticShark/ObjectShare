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

// PayPal sends BILLING.SUBSCRIPTION.CANCELLED (or EXPIRED) as soon as the
// subscriber cancels, not when the period they already paid for ends. That
// period must keep its access; a suspension still ends access immediately.
func TestPostgresPayPalCancellationKeepsThePaidPeriod(t *testing.T) {
	for _, status := range []string{"canceled", "expired", "suspended"} {
		t.Run(status, func(t *testing.T) {
			repo := creditTestRepository(t)
			user := creditTestUser(t, repo, 20)
			plan := invoiceTestPlan(t, repo)
			now := time.Now().UTC().Truncate(time.Second)
			update := SubscriptionUpdate{Gateway: BillingGatewayPayPal, EventID: "WH-active", UserID: user.ID, PlanID: plan.ID, SubscriptionID: "I-SUB", CustomerID: "PAYER", Status: "active", CurrentPeriodEnd: now.AddDate(0, 0, 30), EventCreated: now.Unix()}
			if _, err := repo.ApplySubscription(t.Context(), update); err != nil {
				t.Fatal(err)
			}
			receipt := LegacyInvoicePayment{Gateway: BillingGatewayPayPal, SubscriptionID: "I-SUB", PaymentID: "SALE-1", AmountMinor: 1000, Currency: "USD", PeriodStart: now, PeriodEnd: now.AddDate(0, 0, 30), PaidAt: now}
			if err := repo.ApplyLegacyInvoicePayment(t.Context(), receipt, now); err != nil {
				t.Fatal(err)
			}
			update.EventID, update.EventCreated, update.Status, update.CurrentPeriodEnd = "WH-"+status, now.Add(time.Hour).Unix(), status, now.Add(time.Hour)
			if _, err := repo.ApplySubscription(t.Context(), update); err != nil {
				t.Fatal(err)
			}
			ent, err := repo.Entitlements(t.Context(), user.ID, now.Add(2*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if status == "suspended" {
				if ent.Active {
					t.Fatal("a suspended PayPal subscription kept access")
				}
				return
			}
			if !ent.Active || !ent.CancelAtPeriodEnd || !ent.CurrentPeriodEnd.Equal(receipt.PeriodEnd) {
				t.Fatalf("paid period revoked by the %s event: %#v", status, ent)
			}
			// While paid access lasts, a local plan cannot overlap it.
			invoice, err := repo.CreatePlanInvoice(t.Context(), user.ID, plan.ID, uuid.NewString(), "USD", now.Add(2*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if err = repo.PayInvoiceCredit(t.Context(), user.ID, invoice.ID, now.Add(2*time.Hour)); !errors.Is(err, ErrConflict) {
				t.Fatalf("local plan overlapped the paid PayPal period: %v", err)
			}
			// PayPal sends nothing more; once the period ends access stops and the
			// account can buy a local plan.
			after := receipt.PeriodEnd.Add(time.Minute)
			if ent, err = repo.Entitlements(t.Context(), user.ID, after); err != nil || ent.Active {
				t.Fatalf("access outlived the paid period: %#v %v", ent, err)
			}
			invoice, err = repo.CreatePlanInvoice(t.Context(), user.ID, plan.ID, uuid.NewString(), "USD", after)
			if err != nil {
				t.Fatal(err)
			}
			if err = repo.PayInvoiceCredit(t.Context(), user.ID, invoice.ID, after); err != nil {
				t.Fatalf("ended PayPal subscription still blocks local plans: %v", err)
			}
		})
	}
}

func TestPostgresExpiredGatewayInvoiceDoesNotBlockLaterPlanPurchases(t *testing.T) {
	repo := creditTestRepository(t)
	user := creditTestUser(t, repo, 50)
	plan := invoiceTestPlan(t, repo)
	now := time.Now().UTC()
	abandoned, err := repo.CreatePlanInvoice(t.Context(), user.ID, plan.ID, uuid.NewString(), "USD", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.ReserveInvoiceGateway(t.Context(), user.ID, abandoned.ID, BillingGatewayStripe, now); err != nil {
		t.Fatal(err)
	}
	next, err := repo.CreatePlanInvoice(t.Context(), user.ID, plan.ID, uuid.NewString(), "USD", now)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.PayInvoiceCredit(t.Context(), user.ID, next.ID, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("open gateway checkout must still block another plan purchase: %v", err)
	}
	// After the abandoned invoice's payment window closes it no longer blocks.
	later := abandoned.ExpiresAt.Add(time.Minute)
	afterWindow, err := repo.CreatePlanInvoice(t.Context(), user.ID, plan.ID, uuid.NewString(), "USD", later)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.PayInvoiceCredit(t.Context(), user.ID, afterWindow.ID, later); err != nil {
		t.Fatalf("expired gateway invoice still blocks plan purchases: %v", err)
	}
}

// A PayPal order can only be paid for three hours, far less than the invoice
// window. Its dead approval URL must not keep blocking other plan purchases,
// and paying the invoice again must create a new order.
func TestPostgresExpiredPayPalCheckoutStopsBlockingAndIsReplaced(t *testing.T) {
	repo := creditTestRepository(t)
	user := creditTestUser(t, repo, 50)
	plan := invoiceTestPlan(t, repo)
	now := time.Now().UTC()
	abandoned, err := repo.CreatePlanInvoice(t.Context(), user.ID, plan.ID, uuid.NewString(), "USD", now)
	if err != nil {
		t.Fatal(err)
	}
	payment, err := repo.ReserveInvoiceGateway(t.Context(), user.ID, abandoned.ID, BillingGatewayPayPal, now)
	if err != nil {
		t.Fatal(err)
	}
	if !payment.CheckoutDeadline().Equal(now.Add(PayPalCheckoutLifetime)) || payment.CheckoutAttempt != 0 {
		t.Fatalf("PayPal checkout deadline = %v, attempt %d", payment.CheckoutDeadline(), payment.CheckoutAttempt)
	}
	const firstURL = "https://www.sandbox.paypal.com/checkoutnow?token=ORDER-1"
	if err = repo.BindInvoiceCheckout(t.Context(), user.ID, abandoned.ID, BillingGatewayPayPal, "ORDER-1", firstURL); err != nil {
		t.Fatal(err)
	}
	open := now.Add(2 * time.Hour)
	reopened, err := repo.ReserveInvoiceGateway(t.Context(), user.ID, abandoned.ID, BillingGatewayPayPal, open)
	if err != nil || reopened.CheckoutURL != firstURL {
		t.Fatalf("open PayPal order was not reused: %#v %v", reopened, err)
	}
	blocked, err := repo.CreatePlanInvoice(t.Context(), user.ID, plan.ID, uuid.NewString(), "USD", open)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.PayInvoiceCredit(t.Context(), user.ID, blocked.ID, open); !errors.Is(err, ErrConflict) {
		t.Fatalf("an open PayPal order must block another plan purchase: %v", err)
	}

	later := now.Add(PayPalCheckoutLifetime + time.Minute)
	next, err := repo.CreatePlanInvoice(t.Context(), user.ID, plan.ID, uuid.NewString(), "USD", later)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.PayInvoiceCredit(t.Context(), user.ID, next.ID, later); err != nil {
		t.Fatalf("an expired PayPal order still blocks plan purchases: %v", err)
	}
	replacement, err := repo.ReserveInvoiceGateway(t.Context(), user.ID, abandoned.ID, BillingGatewayPayPal, later)
	if err != nil || replacement.CheckoutURL != "" || replacement.GatewayReference != nil || replacement.CheckoutAttempt != 1 || !replacement.CheckoutDeadline().Equal(later.Add(PayPalCheckoutLifetime)) {
		t.Fatalf("expired PayPal order was not replaced: %#v %v", replacement, err)
	}
	const secondURL = "https://www.sandbox.paypal.com/checkoutnow?token=ORDER-2"
	if err = repo.BindInvoiceCheckout(t.Context(), user.ID, abandoned.ID, BillingGatewayPayPal, "ORDER-2", secondURL); err != nil {
		t.Fatal(err)
	}
	reopened, err = repo.ReserveInvoiceGateway(t.Context(), user.ID, abandoned.ID, BillingGatewayPayPal, later.Add(time.Minute))
	if err != nil || reopened.CheckoutURL != secondURL || reopened.CheckoutAttempt != 1 {
		t.Fatalf("replacement order was not reused: %#v %v", reopened, err)
	}
}

// The PayPal return captures (charges) an approved order. Before that, the
// invoice must still be inside its payment window and its plan still
// applicable; otherwise the customer would be charged for a payment that
// settlement rejects.
func TestPostgresInvoicePaymentCheckBeforeCapture(t *testing.T) {
	repo := creditTestRepository(t)
	user := creditTestUser(t, repo, 50)
	planX := invoiceTestPlan(t, repo)
	planY := PaidPlan{Name: "Pro", Description: "other", Price: 20, DurationDays: 30, StorageQuotaBytes: 4096, Active: true}
	if err := repo.CreatePlan(t.Context(), &planY); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	invoice, err := repo.CreatePlanInvoice(t.Context(), user.ID, planX.ID, uuid.NewString(), "USD", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.ReserveInvoiceGateway(t.Context(), user.ID, invoice.ID, BillingGatewayPayPal, now); err != nil {
		t.Fatal(err)
	}
	if err = repo.CheckInvoicePayment(t.Context(), invoice.ID, now.Add(time.Hour)); err != nil {
		t.Fatalf("payable invoice refused: %v", err)
	}
	if err = repo.CheckInvoicePayment(t.Context(), invoice.ID, invoice.ExpiresAt.Add(time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired invoice accepted: %v", err)
	}
	// After the PayPal order's own lifetime another plan can be bought; the old
	// order must not then be captured.
	later := now.Add(PayPalCheckoutLifetime + time.Minute)
	other, err := repo.CreatePlanInvoice(t.Context(), user.ID, planY.ID, uuid.NewString(), "USD", later)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.PayInvoiceCredit(t.Context(), user.ID, other.ID, later); err != nil {
		t.Fatal(err)
	}
	if err = repo.CheckInvoicePayment(t.Context(), invoice.ID, later); !errors.Is(err, ErrConflict) {
		t.Fatalf("inapplicable plan invoice accepted: %v", err)
	}
}

func TestPostgresInvoiceEmailRetriesBackOffAndStopAtTheCap(t *testing.T) {
	repo := creditTestRepository(t)
	user := creditTestUser(t, repo, 0)
	now := time.Now().UTC().Truncate(time.Second)
	invoice := Invoice{ID: uuid.NewString(), UserID: user.ID, RequestID: uuid.NewString(), Kind: "plan", Name: "Plus", Description: "d", Email: user.Email, Credits: 10, AmountMinor: 1000,
		Currency: "USD", Status: "paid", PaidAt: &now, CreatedAt: now, ExpiresAt: now, EmailRetryAt: now.Add(-time.Hour)}
	if err := repo.connection.Create(&invoice).Error; err != nil {
		t.Fatal(err)
	}
	at := now
	for attempt := 1; attempt <= MaxInvoiceEmailAttempts; attempt++ {
		claimed, err := repo.ClaimInvoiceEmail(t.Context(), at)
		if err != nil || claimed.ID != invoice.ID || claimed.EmailAttempts != attempt-1 {
			t.Fatalf("attempt %d: claim = %#v, %v", attempt, claimed, err)
		}
		if err = repo.FinishInvoiceEmail(t.Context(), invoice.ID, claimed.EmailLease, false, at); err != nil {
			t.Fatal(err)
		}
		var stored Invoice
		if err = repo.connection.First(&stored, "id = ?", invoice.ID).Error; err != nil {
			t.Fatal(err)
		}
		if want := at.Add(InvoiceEmailBackoff(attempt)); stored.EmailAttempts != attempt || !stored.EmailRetryAt.Equal(want) {
			t.Fatalf("attempt %d: stored attempts=%d retry=%v, want retry %v", attempt, stored.EmailAttempts, stored.EmailRetryAt, want)
		}
		at = stored.EmailRetryAt.Add(time.Second)
	}
	if _, err := repo.ClaimInvoiceEmail(t.Context(), at.Add(365*24*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an invoice past the attempt cap was claimed again: %v", err)
	}
}

func TestCheckoutDeadlinesFollowProviderLimits(t *testing.T) {
	start := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	window := start.Add(24 * time.Hour)
	for _, test := range []struct {
		gateway         string
		started, wanted time.Time
	}{
		{BillingGatewayPayPal, start, start.Add(3 * time.Hour)},
		{BillingGatewayPayPal, window.Add(-time.Hour), window},
		// Stripe rejects expires_at more than 24 hours after session creation.
		{BillingGatewayStripe, start, start.Add(24*time.Hour - 5*time.Minute)},
		{BillingGatewayStripe, start.Add(23 * time.Hour), window},
		{"other", start, window},
	} {
		if got := CheckoutDeadline(test.gateway, test.started, window); !got.Equal(test.wanted) {
			t.Errorf("%s checkout started %v: deadline %v, want %v", test.gateway, test.started, got, test.wanted)
		}
	}
}
