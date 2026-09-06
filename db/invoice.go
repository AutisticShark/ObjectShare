package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Invoice is an immutable purchase quotation. Only payment and delivery state
// changes after creation. AmountMinor is currency cents; Credits is account units.
type Invoice struct {
	ReceiptKey        *string `gorm:"type:varchar(320);uniqueIndex"`
	ID                string  `gorm:"type:uuid;primaryKey"`
	UserID            string  `gorm:"type:uuid;not null;index;uniqueIndex:idx_invoice_request"`
	RequestID         string  `gorm:"type:varchar(255);not null;uniqueIndex:idx_invoice_request"`
	Kind              string  `gorm:"type:varchar(16);not null"`
	PlanID            string  `gorm:"type:varchar(36);not null;default:''"`
	Name              string  `gorm:"type:text;not null"`
	Description       string  `gorm:"type:text;not null"`
	Email             string  `gorm:"type:varchar(320);not null"`
	Credits           int64   `gorm:"not null;check:chk_invoice_credits,credits >= 0"`
	AmountMinor       int64   `gorm:"not null;check:chk_invoice_amount,amount_minor >= 0"`
	Currency          string  `gorm:"type:char(3);not null"`
	DurationDays      int
	StorageQuotaBytes int64
	RetentionDays     int
	DirectLinks       bool
	Status            string `gorm:"type:varchar(16);not null;default:pending;index"`
	Gateway           string `gorm:"type:varchar(32);not null;default:''"`
	PaymentID         string `gorm:"type:varchar(255);not null;default:''"`
	PaidAt            *time.Time
	CreatedAt         time.Time
	ExpiresAt         time.Time
	EmailSentAt       *time.Time
	EmailRetryAt      time.Time `gorm:"index"`
	EmailLease        string    `gorm:"type:varchar(36);not null;default:''"`
	User              User      `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
}

type InvoiceRepository interface {
	BindInvoiceCheckout(context.Context, string, string, string, string, string) error
	ApplyLegacyInvoicePayment(context.Context, LegacyInvoicePayment, time.Time) error
	CreatePlanInvoice(context.Context, string, string, string, string, time.Time) (*Invoice, error)
	InvoicesForUser(context.Context, string, int) ([]Invoice, error)
	InvoiceForUser(context.Context, string, string) (*Invoice, error)
	PayInvoiceCredit(context.Context, string, string, time.Time) error
	ReserveInvoiceGateway(context.Context, string, string, string, time.Time) (*CreditTopUp, error)
	ClaimInvoiceEmail(context.Context, time.Time) (*Invoice, error)
	FinishInvoiceEmail(context.Context, string, string, bool, time.Time) error
}

func invoiceError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	return err
}

func lockInvoiceUser(tx *gorm.DB, userID string) (*User, error) {
	var user User
	err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ? AND active = ?", userID, true).First(&user).Error
	return &user, invoiceError(err)
}

func (repo *GormRepository) CreatePlanInvoice(ctx context.Context, userID, planID, requestID, currency string, now time.Time) (*Invoice, error) {
	if _, err := uuid.Parse(requestID); err != nil {
		return nil, ErrInvalidCredit
	}
	currency = strings.ToUpper(currency)
	if !config.SupportedCreditCurrency(currency) {
		return nil, ErrInvalidCredit
	}
	var invoice Invoice
	err := repo.connection.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		user, err := lockInvoiceUser(tx, userID)
		if err != nil {
			return err
		}
		err = tx.Where("user_id = ? AND request_id = ?", userID, requestID).First(&invoice).Error
		if err == nil {
			if invoice.PlanID != planID || invoice.Kind != "plan" {
				return ErrConflict
			}
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		var plan PaidPlan
		if err = tx.Where("id = ? AND active = ?", planID, true).First(&plan).Error; err != nil {
			return invoiceError(err)
		}
		if !validLocalPlan(&plan) {
			return ErrInvalidCredit
		}
		invoice = Invoice{ID: uuid.NewString(), UserID: userID, RequestID: requestID, Kind: "plan", PlanID: plan.ID,
			Name: plan.Name, Description: plan.Description, Email: user.Email, Credits: plan.Price, AmountMinor: plan.Price * 100,
			Currency: currency, DurationDays: plan.DurationDays, StorageQuotaBytes: plan.StorageQuotaBytes,
			RetentionDays: plan.RetentionDays, DirectLinks: plan.DirectLinks, Status: "pending", CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour)}
		return tx.Create(&invoice).Error
	})
	return &invoice, err
}

func (repo *GormRepository) InvoiceForUser(ctx context.Context, userID, id string) (*Invoice, error) {
	var invoice Invoice
	err := repo.connection.WithContext(ctx).Where("id = ? AND user_id = ?", id, userID).First(&invoice).Error
	return &invoice, invoiceError(err)
}

func (repo *GormRepository) InvoicesForUser(ctx context.Context, userID string, page int) ([]Invoice, error) {
	if page < 0 || page > 100000 {
		return nil, ErrInvalidCredit
	}
	var invoices []Invoice
	err := repo.connection.WithContext(ctx).Where("user_id = ?", userID).Order("created_at DESC, id DESC").Limit(25).Offset(page * 25).Find(&invoices).Error
	return invoices, err
}

// checkInvoicePlan runs under the account lock, before taking any payment.
func checkInvoicePlan(tx *gorm.DB, invoice *Invoice, now time.Time) error {
	var count int64
	if err := tx.Model(&Invoice{}).Where("user_id = ? AND id <> ? AND kind = 'plan' AND status = 'pending' AND gateway <> ''", invoice.UserID, invoice.ID).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return ErrConflict
	}
	var checkout BillingCheckout
	if err := tx.Where("user_id = ?", invoice.UserID).First(&checkout).Error; err == nil && checkout.ExpiresAt.After(now) {
		return ErrConflict
	} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	var sub Subscription
	err := tx.Where("user_id = ?", invoice.UserID).First(&sub).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if subscriptionActive(sub.Status, sub.CurrentPeriodEnd, now) && (sub.Gateway != BillingGatewayCredit || sub.PlanID != invoice.PlanID) {
		return ErrConflict
	}
	if sub.Gateway != BillingGatewayCredit && !subscriptionTerminal(sub.Status) {
		return ErrConflict
	}
	return nil
}

func activateInvoicePlan(tx *gorm.DB, invoice *Invoice, now time.Time) error {
	if err := checkInvoicePlan(tx, invoice, now); err != nil {
		return err
	}
	var sub Subscription
	err := tx.Where("user_id = ?", invoice.UserID).First(&sub).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	start := now
	if err == nil && subscriptionActive(sub.Status, sub.CurrentPeriodEnd, now) {
		start = sub.CurrentPeriodEnd
	}
	if sub.ID == "" {
		sub.ID = uuid.NewString()
		sub.UserID = invoice.UserID
	}
	sub.PlanID, sub.Gateway, sub.CustomerID = invoice.PlanID, BillingGatewayCredit, ""
	sub.GatewaySubscriptionID, sub.Status = "invoice:"+invoice.ID, "active"
	sub.CurrentPeriodEnd, sub.CancelAtPeriodEnd, sub.LastEventCreated = start.AddDate(0, 0, invoice.DurationDays), true, now.Unix()
	sub.InvoiceID = invoice.ID
	return tx.Save(&sub).Error
}

func paidInvoice(tx *gorm.DB, invoice *Invoice, gateway, paymentID string, now time.Time) error {
	return tx.Model(invoice).Updates(map[string]any{"status": "paid", "gateway": gateway, "payment_id": paymentID, "receipt_key": gateway + ":" + paymentID, "paid_at": now, "email_retry_at": now}).Error
}

func (repo *GormRepository) PayInvoiceCredit(ctx context.Context, userID, id string, now time.Time) error {
	return repo.connection.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		user, err := lockInvoiceUser(tx, userID)
		if err != nil {
			return err
		}
		var invoice Invoice
		if err = tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ? AND user_id = ?", id, userID).First(&invoice).Error; err != nil {
			return invoiceError(err)
		}
		if invoice.Status == "paid" {
			return nil
		}
		if invoice.Kind != "plan" || invoice.Status != "pending" || invoice.Gateway != "" || !invoice.ExpiresAt.After(now) {
			return ErrConflict
		}
		if user.CreditBalance < invoice.Credits {
			return ErrInsufficientCredit
		}
		if err = activateInvoicePlan(tx, &invoice, now); err != nil {
			return err
		}
		balance := user.CreditBalance - invoice.Credits
		entry := CreditTransaction{ID: uuid.NewString(), UserID: userID, Delta: -invoice.Credits, BalanceAfter: balance,
			Kind: CreditTransactionPlan, ReferenceID: invoice.PlanID, DeduplicationKey: "invoice:" + invoice.ID, Description: "Plan purchase: " + invoice.Name, CreatedAt: now}
		if err = tx.Create(&entry).Error; err != nil {
			return err
		}
		if err = tx.Model(&User{}).Where("id = ?", userID).Update("credit_balance", balance).Error; err != nil {
			return err
		}
		return paidInvoice(tx, &invoice, BillingGatewayCredit, entry.ID, now)
	})
}

func (repo *GormRepository) ReserveInvoiceGateway(ctx context.Context, userID, id, gateway string, now time.Time) (*CreditTopUp, error) {
	var payment CreditTopUp
	err := repo.connection.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := lockInvoiceUser(tx, userID); err != nil {
			return err
		}
		var invoice Invoice
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ? AND user_id = ?", id, userID).First(&invoice).Error; err != nil {
			return invoiceError(err)
		}
		if gateway == "" || gateway == BillingGatewayCredit || invoice.Status != "pending" {
			return ErrConflict
		}
		if invoice.Gateway != "" {
			if invoice.Gateway != gateway {
				return ErrConflict
			}
			// Gateway idempotency keys have limited lifetimes. Do not create another
			// remote checkout after the original local payment window.
			if !invoice.ExpiresAt.After(now) {
				return ErrConflict
			}
			if err := tx.Where("id = ?", invoice.ID).First(&payment).Error; err != nil {
				return err
			}
			if payment.CheckoutURL == "" && now.Sub(payment.CreatedAt) > 5*time.Minute {
				return ErrConflict
			}
			return nil
		}
		if !invoice.ExpiresAt.After(now) {
			return ErrConflict
		}
		if invoice.Kind == "plan" {
			if err := checkInvoicePlan(tx, &invoice, now); err != nil {
				return err
			}
		}
		payment = CreditTopUp{ID: invoice.ID, UserID: userID, Gateway: gateway, Credits: invoice.Credits, AmountMinor: invoice.AmountMinor, Currency: invoice.Currency, Status: CreditTopUpPending, ExpiresAt: invoice.ExpiresAt, CreatedAt: now}
		if err := tx.Create(&payment).Error; err != nil {
			return err
		}
		return tx.Model(&invoice).Update("gateway", gateway).Error
	})
	return &payment, err
}

// ensureTopUpInvoice also covers previously issued top-ups settling after upgrade.
func ensureTopUpInvoice(tx *gorm.DB, topUp *CreditTopUp) (*Invoice, error) {
	var invoice Invoice
	err := tx.Where("id = ?", topUp.ID).First(&invoice).Error
	if err == nil {
		return &invoice, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	var user User
	if err = tx.Where("id = ?", topUp.UserID).First(&user).Error; err != nil {
		return nil, err
	}
	invoice = Invoice{ID: topUp.ID, UserID: topUp.UserID, RequestID: "topup:" + topUp.ID, Kind: "topup", Name: fmt.Sprintf("%d account credits", topUp.Credits), Email: user.Email,
		Credits: topUp.Credits, AmountMinor: topUp.AmountMinor, Currency: topUp.Currency, Status: "pending", Gateway: topUp.Gateway, CreatedAt: topUp.CreatedAt, ExpiresAt: topUp.ExpiresAt}
	return &invoice, tx.Create(&invoice).Error
}

func (repo *GormRepository) ClaimInvoiceEmail(ctx context.Context, now time.Time) (*Invoice, error) {
	var invoice Invoice
	err := repo.connection.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).Where("status = 'paid' AND email_sent_at IS NULL AND email_retry_at <= ?", now).Order("email_retry_at, id").First(&invoice).Error; err != nil {
			return invoiceError(err)
		}
		invoice.EmailLease = uuid.NewString()
		return tx.Model(&invoice).Updates(map[string]any{"email_lease": invoice.EmailLease, "email_retry_at": now.Add(5 * time.Minute)}).Error
	})
	return &invoice, err
}

func (repo *GormRepository) FinishInvoiceEmail(ctx context.Context, id, lease string, sent bool, now time.Time) error {
	values := map[string]any{"email_lease": "", "email_retry_at": now.Add(5 * time.Minute)}
	if sent {
		values["email_sent_at"] = now
	}
	return repo.connection.WithContext(ctx).Model(&Invoice{}).Where("id = ? AND email_lease = ? AND email_sent_at IS NULL", id, lease).Updates(values).Error
}

// BindInvoiceCheckout stores only a URL already validated by a gateway module.
// Reopening an invoice reuses that checkout rather than creating a second charge.
func (repo *GormRepository) BindInvoiceCheckout(ctx context.Context, userID, id, gateway, reference, location string) error {
	if location == "" {
		return ErrInvalidCredit
	}
	return repo.connection.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := lockInvoiceUser(tx, userID); err != nil {
			return err
		}
		var payment CreditTopUp
		if err := tx.Where("id = ? AND user_id = ? AND gateway = ?", id, userID, gateway).First(&payment).Error; err != nil {
			return invoiceError(err)
		}
		if payment.CheckoutURL != "" && payment.CheckoutURL != location {
			return ErrConflict
		}
		if payment.GatewayReference != nil && *payment.GatewayReference != reference {
			return ErrConflict
		}
		values := map[string]any{"checkout_url": location}
		if reference != "" {
			values["gateway_reference"] = reference
		}
		return tx.Model(&payment).Updates(values).Error
	})
}
