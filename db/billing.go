package db

import (
	"context"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Entitlements struct {
	PlanID, PlanName                       string
	StorageQuotaBytes                      int64
	RetentionDays                          int
	DirectLinks, Active, CancelAtPeriodEnd bool
	CurrentPeriodEnd                       time.Time
}

type SubscriptionUpdate struct {
	Gateway, EventID, UserID, PlanID, CustomerID, SubscriptionID, Status string
	EventCreated                                                         int64
	CurrentPeriodEnd                                                     time.Time
	CancelAtPeriodEnd                                                    bool
}

type CreditPayment struct {
	TopUpID, Gateway, GatewayPaymentID, Currency string
	AmountMinor                                  int64
}

type BillingRepository interface {
	PublicPlans(context.Context) ([]PaidPlan, error)
	AllPlans(context.Context) ([]PaidPlan, error)
	PlanByID(context.Context, string, bool) (*PaidPlan, error)
	PlanByGatewayID(context.Context, string, string) (*PaidPlan, error)
	CreatePlan(context.Context, *PaidPlan) error
	UpdatePlan(context.Context, *PaidPlan) error
	Entitlements(context.Context, string, time.Time) (Entitlements, error)
	SubscriptionForUser(context.Context, string) (*Subscription, error)
	ReserveBillingCheckout(context.Context, string, string, time.Time) error
	ReleaseBillingCheckout(context.Context, string, string) error
	ApplySubscription(context.Context, SubscriptionUpdate) (bool, error)
	CreateCreditTopUp(context.Context, *CreditTopUp) error
	BindCreditTopUp(context.Context, string, string, string) error
	CancelCreditTopUp(context.Context, string, string) error
	CreditTopUpByID(context.Context, string) (*CreditTopUp, error)
	ApplyCreditTopUp(context.Context, CreditPayment, time.Time) (bool, error)
	CreditTransactions(context.Context, string, int) ([]CreditTransaction, error)
	PurchasePlanWithCredit(context.Context, string, string, string, time.Time) (*Subscription, error)
	AdjustCredit(context.Context, string, int64, string, string, string, time.Time) (int64, error)
}

func (repo *GormRepository) CreateCreditTopUp(ctx context.Context, topUp *CreditTopUp) error {
	if topUp.ID == "" {
		topUp.ID = uuid.NewString()
	}
	if topUp.UserID == "" || topUp.Credits <= 0 || topUp.AmountMinor <= 0 || len(topUp.Currency) != 3 || topUp.ExpiresAt.IsZero() {
		return ErrInvalidCredit
	}
	topUp.Currency = strings.ToUpper(topUp.Currency)
	topUp.Status = CreditTopUpPending
	return repo.connection.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := lockInvoiceUser(tx, topUp.UserID); err != nil {
			return err
		}
		if err := tx.Create(topUp).Error; err != nil {
			return err
		}
		_, err := ensureTopUpInvoice(tx, topUp)
		return err
	})
}

func (repo *GormRepository) BindCreditTopUp(ctx context.Context, id, gateway, reference string) error {
	if reference == "" {
		return ErrInvalidCredit
	}
	return repo.connection.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var topUp CreditTopUp
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ? AND gateway = ?", id, gateway).First(&topUp).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if topUp.Status != CreditTopUpPending && topUp.Status != CreditTopUpCompleted {
			return ErrConflict
		}
		if topUp.GatewayReference != nil {
			if *topUp.GatewayReference == reference {
				return nil
			}
			return ErrConflict
		}
		return tx.Model(&CreditTopUp{}).Where("id = ?", id).Update("gateway_reference", reference).Error
	})
}

func (repo *GormRepository) CancelCreditTopUp(ctx context.Context, id, gateway string) error {
	return repo.connection.WithContext(ctx).Model(&CreditTopUp{}).
		Where("id = ? AND gateway = ? AND status = ?", id, gateway, CreditTopUpPending).
		Update("status", CreditTopUpCanceled).Error
}

func (repo *GormRepository) CreditTopUpByID(ctx context.Context, id string) (*CreditTopUp, error) {
	var topUp CreditTopUp
	if err := repo.connection.WithContext(ctx).Where("id = ?", id).First(&topUp).Error; errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	return &topUp, nil
}

func (repo *GormRepository) ApplyCreditTopUp(ctx context.Context, payment CreditPayment, now time.Time) (bool, error) {
	applied := false
	err := repo.connection.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var selected CreditTopUp
		if err := tx.Select("id", "user_id").Where("id = ?", payment.TopUpID).First(&selected).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		// Keep the account-row lock first, matching quota reservations,
		// subscription updates, plan purchases, and account deletion.
		var user User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id", "credit_balance").Where("id = ?", selected.UserID).First(&user).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		var topUp CreditTopUp
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", payment.TopUpID).First(&topUp).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if !creditPaymentMatches(topUp, payment) {
			return ErrInvalidCredit
		}
		deduplicationKey := payment.Gateway + ":" + payment.GatewayPaymentID
		var existing CreditTransaction
		if err := tx.Where("deduplication_key = ?", deduplicationKey).First(&existing).Error; err == nil {
			if existing.UserID == topUp.UserID && existing.ReferenceID == topUp.ID && (existing.Delta == topUp.Credits || (existing.Delta == 0 && existing.Kind == CreditTransactionPlan)) {
				return nil
			}
			return ErrConflict
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if topUp.Status == CreditTopUpCompleted {
			return ErrConflict
		}
		if topUp.Status != CreditTopUpPending {
			return ErrConflict
		}
		if topUp.UserID != user.ID {
			return ErrConflict
		}
		invoice, err := ensureTopUpInvoice(tx, &topUp)
		if err != nil {
			return err
		}
		if invoice.UserID != user.ID || invoice.Status != "pending" || invoice.Gateway != payment.Gateway || invoice.AmountMinor != payment.AmountMinor || invoice.Currency != strings.ToUpper(payment.Currency) {
			return ErrConflict
		}
		if invoice.Kind == "plan" {
			if err := activateInvoicePlan(tx, invoice, now); err != nil {
				return err
			}
			// A zero-delta ledger entry globally deduplicates gateway plan receipts.
			entry := CreditTransaction{ID: uuid.NewString(), UserID: user.ID, Delta: 0, BalanceAfter: user.CreditBalance, Kind: CreditTransactionPlan,
				Gateway: payment.Gateway, GatewayPaymentID: payment.GatewayPaymentID, ReferenceID: topUp.ID, DeduplicationKey: deduplicationKey, Description: "Invoice payment: " + invoice.Name, CreatedAt: now}
			if err := tx.Create(&entry).Error; err != nil {
				return err
			}
			if err := tx.Model(&CreditTopUp{}).Where("id = ?", topUp.ID).Updates(map[string]any{"status": CreditTopUpCompleted, "gateway_transaction_id": payment.GatewayPaymentID, "completed_at": now}).Error; err != nil {
				return err
			}
			if err := paidInvoice(tx, invoice, payment.Gateway, payment.GatewayPaymentID, now); err != nil {
				return err
			}
			applied = true
			return nil
		}
		balance, err := addCredit(user.CreditBalance, topUp.Credits)
		if err != nil {
			return err
		}
		entry := CreditTransaction{ID: uuid.NewString(), UserID: user.ID, Delta: topUp.Credits, BalanceAfter: balance,
			Kind: CreditTransactionTopUp, Gateway: payment.Gateway, GatewayPaymentID: payment.GatewayPaymentID,
			ReferenceID: topUp.ID, DeduplicationKey: deduplicationKey, Description: "Account credit top-up", CreatedAt: now}
		if err := tx.Create(&entry).Error; err != nil {
			return err
		}
		if err := tx.Model(&User{}).Where("id = ?", user.ID).Update("credit_balance", balance).Error; err != nil {
			return err
		}
		if err := tx.Model(&CreditTopUp{}).Where("id = ?", topUp.ID).Updates(map[string]any{
			"status": CreditTopUpCompleted, "gateway_transaction_id": payment.GatewayPaymentID, "completed_at": now,
		}).Error; err != nil {
			return err
		}
		if err := paidInvoice(tx, invoice, payment.Gateway, payment.GatewayPaymentID, now); err != nil {
			return err
		}
		applied = true
		return nil
	})
	return applied, err
}

func (repo *GormRepository) CreditTransactions(ctx context.Context, userID string, limit int) ([]CreditTransaction, error) {
	if limit < 1 || limit > 100 {
		limit = 20
	}
	var transactions []CreditTransaction
	err := repo.connection.WithContext(ctx).Where("user_id = ?", userID).Order("created_at DESC, id DESC").Limit(limit).Find(&transactions).Error
	return transactions, err
}

// PurchasePlanWithCredit settles an invoice previously generated with this
// account-scoped request key. It never guesses a currency from wallet units.
func (repo *GormRepository) PurchasePlanWithCredit(ctx context.Context, userID, planID, requestID string, now time.Time) (*Subscription, error) {
	var invoice Invoice
	if err := repo.connection.WithContext(ctx).Where("user_id = ? AND request_id = ?", userID, requestID).First(&invoice).Error; err != nil {
		return nil, invoiceError(err)
	}
	if invoice.Kind != "plan" || invoice.PlanID != planID {
		return nil, ErrConflict
	}
	if err := repo.PayInvoiceCredit(ctx, userID, invoice.ID, now); err != nil {
		return nil, err
	}
	return repo.SubscriptionForUser(ctx, userID)
}

func (repo *GormRepository) AdjustCredit(ctx context.Context, userID string, delta int64, description, administratorID, requestID string, now time.Time) (int64, error) {
	if _, err := uuid.Parse(requestID); err != nil {
		return 0, ErrInvalidCredit
	}
	if delta == 0 || strings.TrimSpace(description) == "" || len(description) > 200 || administratorID == "" {
		return 0, ErrInvalidCredit
	}
	var balance int64
	err := repo.connection.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var user User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id", "credit_balance").Where("id = ?", userID).First(&user).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		var err error
		deduplicationKey := "adjustment:" + userID + ":" + requestID
		var previous CreditTransaction
		if err := tx.Where("deduplication_key = ?", deduplicationKey).First(&previous).Error; err == nil {
			if previous.UserID != userID || previous.ReferenceID != administratorID || previous.Delta != delta || previous.Description != strings.TrimSpace(description) || previous.Kind != CreditTransactionAdjustment {
				return ErrConflict
			}
			balance = previous.BalanceAfter
			return nil
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		balance, err = addCredit(user.CreditBalance, delta)
		if err != nil {
			return err
		}
		adjustmentID := uuid.NewString()
		entry := CreditTransaction{ID: adjustmentID, UserID: userID, Delta: delta, BalanceAfter: balance,
			Kind: CreditTransactionAdjustment, ReferenceID: administratorID, DeduplicationKey: deduplicationKey,
			Description: strings.TrimSpace(description), CreatedAt: now}
		if err := tx.Create(&entry).Error; err != nil {
			return err
		}
		return tx.Model(&User{}).Where("id = ?", userID).Update("credit_balance", balance).Error
	})
	return balance, err
}

func addCredit(balance, delta int64) (int64, error) {
	if (delta > 0 && balance > math.MaxInt64-delta) || (delta < 0 && balance < math.MinInt64-delta) {
		return 0, ErrInvalidCredit
	}
	return balance + delta, nil
}

func creditPaymentMatches(topUp CreditTopUp, payment CreditPayment) bool {
	return topUp.ID == payment.TopUpID && topUp.Gateway == payment.Gateway && topUp.Currency == strings.ToUpper(payment.Currency) &&
		topUp.AmountMinor == payment.AmountMinor && payment.AmountMinor > 0 && payment.GatewayPaymentID != ""
}

func subscriptionTerminal(status string) bool {
	switch strings.ToLower(status) {
	case "canceled", "cancelled", "expired", "incomplete_expired":
		return true
	default:
		return false
	}
}

func (repo *GormRepository) ReserveBillingCheckout(ctx context.Context, userID, planID string, now time.Time) error {
	return repo.connection.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var user User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id").Where("id = ?", userID).First(&user).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		var checkout BillingCheckout
		err := tx.Where("user_id = ?", userID).First(&checkout).Error
		if err == nil && checkout.ExpiresAt.After(now) {
			return ErrConflict
		}
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		checkout = BillingCheckout{UserID: userID, PlanID: planID, ExpiresAt: now.Add(30 * time.Minute)}
		return tx.Save(&checkout).Error
	})
}

func (repo *GormRepository) ReleaseBillingCheckout(ctx context.Context, userID, planID string) error {
	return repo.connection.WithContext(ctx).Where("user_id = ? AND plan_id = ?", userID, planID).Delete(&BillingCheckout{}).Error
}

func (repo *GormRepository) PlanByGatewayID(ctx context.Context, gateway, planID string) (*PaidPlan, error) {
	var plan PaidPlan
	if err := repo.connection.WithContext(ctx).Where("gateway = ? AND gateway_plan_id = ?", gateway, planID).First(&plan).Error; errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	return &plan, nil
}

func (repo *GormRepository) PublicPlans(ctx context.Context) ([]PaidPlan, error) {
	var plans []PaidPlan
	err := repo.connection.WithContext(ctx).Where("active = ? AND credit_price > 0 AND credit_duration_days > 0", true).Order("sort_order ASC, name ASC").Find(&plans).Error
	return plans, err
}

func (repo *GormRepository) AllPlans(ctx context.Context) ([]PaidPlan, error) {
	var plans []PaidPlan
	err := repo.connection.WithContext(ctx).Order("sort_order ASC, name ASC").Find(&plans).Error
	return plans, err
}

func (repo *GormRepository) PlanByID(ctx context.Context, id string, activeOnly bool) (*PaidPlan, error) {
	var plan PaidPlan
	query := repo.connection.WithContext(ctx).Where("id = ?", id)
	if activeOnly {
		query = query.Where("active = ?", true)
	}
	if err := query.First(&plan).Error; errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	return &plan, nil
}

func (repo *GormRepository) CreatePlan(ctx context.Context, plan *PaidPlan) error {
	if !validLocalPlan(plan) {
		return ErrInvalidCredit
	}
	if plan.ID == "" {
		plan.ID = uuid.NewString()
	}
	// Local identifiers satisfy the legacy unique index without linking to a provider.
	plan.Gateway, plan.GatewayPlanID, plan.LegacyPriceLabel = BillingGatewayCredit, plan.ID, ""
	return repo.connection.WithContext(ctx).Create(plan).Error
}

func (repo *GormRepository) UpdatePlan(ctx context.Context, plan *PaidPlan) error {
	if !validLocalPlan(plan) {
		return ErrInvalidCredit
	}
	return repo.connection.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing PaidPlan
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", plan.ID).First(&existing).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		return tx.Model(&PaidPlan{}).Where("id = ?", plan.ID).Updates(map[string]any{
			"name": plan.Name, "description": plan.Description, "storage_quota_bytes": plan.StorageQuotaBytes,
			"retention_days": plan.RetentionDays, "direct_links": plan.DirectLinks,
			"credit_price": plan.Price, "credit_duration_days": plan.DurationDays,
			"active": plan.Active, "sort_order": plan.SortOrder,
		}).Error
	})
}

func subscriptionActive(status string, periodEnd, now time.Time) bool {
	return (status == "active" || status == "trialing") && periodEnd.After(now)
}

func (repo *GormRepository) Entitlements(ctx context.Context, userID string, now time.Time) (Entitlements, error) {
	return entitlementsWithDB(repo.connection.WithContext(ctx), userID, now)
}

func entitlementsWithDB(connection *gorm.DB, userID string, now time.Time) (Entitlements, error) {
	var subscription Subscription
	err := connection.Preload("Plan").Where("user_id = ?", userID).First(&subscription).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return Entitlements{}, nil
	}
	if err != nil {
		return Entitlements{}, err
	}
	if !subscriptionActive(subscription.Status, subscription.CurrentPeriodEnd, now) {
		return Entitlements{}, nil
	}
	if subscription.InvoiceID != "" {
		var invoice Invoice
		if err := connection.Where("id = ? AND status = 'paid'", subscription.InvoiceID).First(&invoice).Error; err != nil {
			return Entitlements{}, err
		}
		subscription.Plan.ID = invoice.PlanID
		subscription.Plan.Name, subscription.Plan.StorageQuotaBytes = invoice.Name, invoice.StorageQuotaBytes
		subscription.Plan.RetentionDays, subscription.Plan.DirectLinks = invoice.RetentionDays, invoice.DirectLinks
	}
	return Entitlements{PlanID: subscription.Plan.ID, PlanName: subscription.Plan.Name,
		StorageQuotaBytes: subscription.Plan.StorageQuotaBytes, RetentionDays: subscription.Plan.RetentionDays,
		DirectLinks: subscription.Plan.DirectLinks, Active: true, CancelAtPeriodEnd: subscription.CancelAtPeriodEnd,
		CurrentPeriodEnd: subscription.CurrentPeriodEnd}, nil
}

func (repo *GormRepository) SubscriptionForUser(ctx context.Context, userID string) (*Subscription, error) {
	var subscription Subscription
	err := repo.connection.WithContext(ctx).Preload("Plan").Where("user_id = ?", userID).First(&subscription).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &subscription, nil
}

func (repo *GormRepository) ApplySubscription(ctx context.Context, update SubscriptionUpdate) (bool, error) {
	applied := false
	err := repo.connection.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Serialize subscription changes with quota reservations and retention
		// claims for this account, including its first subscription.
		if update.UserID != "" {
			var user User
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id").Where("id = ?", update.UserID).First(&user).Error; errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			} else if err != nil {
				return err
			}
		}
		eventID := update.Gateway + ":" + update.EventID
		var seen BillingEvent
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("event_id = ?", eventID).First(&seen).Error; err == nil {
			return nil
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		var existing Subscription
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("gateway = ? AND gateway_subscription_id = ?", update.Gateway, update.SubscriptionID).First(&existing).Error
		if errors.Is(err, gorm.ErrRecordNotFound) && update.UserID != "" {
			err = tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("user_id = ?", update.UserID).First(&existing).Error
		}
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if err == nil && update.EventCreated < existing.LastEventCreated {
			return tx.Create(&BillingEvent{EventID: eventID}).Error
		}
		if update.UserID == "" && err == nil {
			update.UserID = existing.UserID
		}
		if update.PlanID == "" && err == nil {
			update.PlanID = existing.PlanID
		}
		if update.UserID == "" || update.PlanID == "" {
			return ErrNotFound
		}
		// A previously opened provider checkout can settle after its local
		// reservation expires. Never silently replace already purchased prepaid
		// time; leave the event unapplied for retry/operator reconciliation.
		if err == nil && existing.Gateway == BillingGatewayCredit && update.Gateway != BillingGatewayCredit &&
			subscriptionActive(existing.Status, existing.CurrentPeriodEnd, time.Now().UTC()) &&
			subscriptionActive(update.Status, update.CurrentPeriodEnd, time.Now().UTC()) {
			return ErrConflict
		}
		if err == nil && existing.Gateway != update.Gateway && !subscriptionActive(update.Status, update.CurrentPeriodEnd, time.Now().UTC()) {
			return tx.Create(&BillingEvent{EventID: eventID}).Error
		}
		// Lifecycle events cannot create or extend paid access. Paid invoice
		// receipts advance the period independently, including out-of-order events.
		sameSubscription := err == nil && existing.Gateway == update.Gateway && existing.GatewaySubscriptionID == update.SubscriptionID
		if sameSubscription {
			update.CurrentPeriodEnd = existing.CurrentPeriodEnd
		} else {
			update.CurrentPeriodEnd = time.Unix(0, 0).UTC()
		}
		if update.Status == "active" || update.Status == "trialing" {
			if !sameSubscription {
				update.Status = "incomplete"
				update.CurrentPeriodEnd = time.Unix(0, 0).UTC()
			} else {
				update.CurrentPeriodEnd = existing.CurrentPeriodEnd
				if existing.InvoiceID == "" && !subscriptionActive(existing.Status, existing.CurrentPeriodEnd, time.Now().UTC()) {
					update.Status = existing.Status
				}
			}
		}
		if err == nil {
			if existing.Gateway != update.Gateway || existing.GatewaySubscriptionID != update.SubscriptionID {
				existing.InvoiceID = ""
			}
			existing.PlanID, existing.Gateway, existing.CustomerID, existing.GatewaySubscriptionID = update.PlanID, update.Gateway, update.CustomerID, update.SubscriptionID
			existing.Status, existing.CurrentPeriodEnd, existing.CancelAtPeriodEnd, existing.LastEventCreated = update.Status, update.CurrentPeriodEnd, update.CancelAtPeriodEnd, update.EventCreated
			if saveErr := tx.Save(&existing).Error; saveErr != nil {
				return saveErr
			}
		} else {
			sub := Subscription{ID: uuid.NewString(), UserID: update.UserID, PlanID: update.PlanID,
				Gateway: update.Gateway, CustomerID: update.CustomerID, GatewaySubscriptionID: update.SubscriptionID,
				Status: update.Status, CurrentPeriodEnd: update.CurrentPeriodEnd,
				CancelAtPeriodEnd: update.CancelAtPeriodEnd, LastEventCreated: update.EventCreated}
			if createErr := tx.Create(&sub).Error; createErr != nil {
				return createErr
			}
		}
		if createErr := tx.Create(&BillingEvent{EventID: eventID}).Error; createErr != nil {
			return createErr
		}
		if deleteErr := tx.Where("user_id = ?", update.UserID).Delete(&BillingCheckout{}).Error; deleteErr != nil {
			return deleteErr
		}
		applied = true
		return nil
	})
	return applied, err
}

func validLocalPlan(plan *PaidPlan) bool {
	return plan != nil && plan.Price > 0 && plan.Price <= 1_000_000_000 && plan.DurationDays > 0 && plan.DurationDays <= 36500
}
