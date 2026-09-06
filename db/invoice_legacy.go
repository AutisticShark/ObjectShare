package db

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type LegacyInvoicePayment struct {
	Gateway, PaymentID, SubscriptionID, Currency, PlanID string
	AmountMinor                                          int64
	PeriodStart, PeriodEnd, PaidAt                       time.Time
}

// ApplyLegacyInvoicePayment records provider-confirmed recurring purchases for
// old subscriptions. It cannot replace a different or prepaid subscription.
func (repo *GormRepository) ApplyLegacyInvoicePayment(ctx context.Context, payment LegacyInvoicePayment, now time.Time) error {
	if payment.PaymentID == "" || payment.SubscriptionID == "" || payment.Gateway == BillingGatewayCredit || payment.AmountMinor < 0 || !config.SupportedCreditCurrency(strings.ToUpper(payment.Currency)) || payment.PaidAt.IsZero() || !payment.PeriodEnd.After(payment.PeriodStart) {
		return ErrInvalidCredit
	}
	return repo.connection.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var selected Subscription
		if err := tx.Where("gateway = ? AND gateway_subscription_id = ?", payment.Gateway, payment.SubscriptionID).First(&selected).Error; err != nil {
			return invoiceError(err)
		}
		user, err := lockInvoiceUser(tx, selected.UserID)
		if err != nil {
			return err
		}
		key := "renewal:" + payment.Gateway + ":" + payment.PaymentID
		var existing Invoice
		if err = tx.Where("user_id = ? AND request_id = ?", user.ID, key).First(&existing).Error; err == nil {
			if existing.AmountMinor != payment.AmountMinor || existing.Currency != strings.ToUpper(payment.Currency) {
				return ErrConflict
			}
			return nil
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		var sub Subscription
		if err = tx.Clauses(clause.Locking{Strength: "UPDATE"}).Preload("Plan").Where("user_id = ?", user.ID).First(&sub).Error; err != nil {
			return err
		}
		if sub.Gateway != payment.Gateway || sub.GatewaySubscriptionID != payment.SubscriptionID {
			return ErrConflict
		}
		if payment.PlanID != "" && payment.PlanID != sub.PlanID {
			var purchasedPlan PaidPlan
			if err := tx.Where("id = ?", payment.PlanID).First(&purchasedPlan).Error; err != nil {
				return invoiceError(err)
			}
			sub.Plan = purchasedPlan
			sub.PlanID = payment.PlanID
		}
		receiptKey := payment.Gateway + ":" + payment.PaymentID
		invoice := Invoice{ReceiptKey: &receiptKey, ID: uuid.NewString(), UserID: user.ID, RequestID: key, Kind: "renewal", PlanID: sub.PlanID, Name: sub.Plan.Name,
			Description: "Subscription renewal", Email: user.Email, AmountMinor: payment.AmountMinor, Currency: strings.ToUpper(payment.Currency),
			DurationDays: int(payment.PeriodEnd.Sub(payment.PeriodStart).Hours() / 24), StorageQuotaBytes: sub.Plan.StorageQuotaBytes, RetentionDays: sub.Plan.RetentionDays,
			DirectLinks: sub.Plan.DirectLinks, Status: "paid", Gateway: payment.Gateway, PaymentID: payment.PaymentID, PaidAt: &payment.PaidAt, CreatedAt: payment.PaidAt, ExpiresAt: payment.PaidAt, EmailRetryAt: now}
		if err = tx.Create(&invoice).Error; err != nil {
			return err
		}
		if payment.PeriodEnd.After(sub.CurrentPeriodEnd) {
			values := map[string]any{"current_period_end": payment.PeriodEnd, "invoice_id": invoice.ID, "plan_id": invoice.PlanID}
			// An older receipt must not undo a newer cancellation/failure state.
			if payment.PaidAt.Unix() >= sub.LastEventCreated || sub.Status == "incomplete" {
				values["status"] = "active"
			}
			return tx.Model(&sub).Updates(values).Error
		}
		return nil
	})
}
