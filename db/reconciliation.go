package db

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm/clause"
)

// PaymentReconciliation records a payment a gateway has confirmed as captured
// but that ObjectShare could not apply to an account (missing, mismatched or
// already-settled top-up). Money has moved, so the record must survive until an
// operator resolves it; it is keyed by gateway payment so webhook retries
// collapse into one row.
type PaymentReconciliation struct {
	ID               string    `gorm:"column:id;type:uuid;primaryKey"`
	Gateway          string    `gorm:"column:gateway;type:varchar(32);not null;uniqueIndex:idx_payment_reconciliation_payment"`
	GatewayPaymentID string    `gorm:"column:gateway_payment_id;type:varchar(255);not null;uniqueIndex:idx_payment_reconciliation_payment"`
	TopUpID          string    `gorm:"column:top_up_id;type:varchar(64);not null;default:''"`
	AmountMinor      int64     `gorm:"column:amount_minor;not null"`
	Currency         string    `gorm:"column:currency;type:varchar(8);not null"`
	Reason           string    `gorm:"column:reason;type:text;not null"`
	CreatedAt        time.Time `gorm:"column:created_at;not null"`
}

func (PaymentReconciliation) TableName() string { return "payment_reconciliations" }

// PaymentReconciler is implemented by repositories that persist unapplied
// captured payments.
type PaymentReconciler interface {
	RecordPaymentReconciliation(context.Context, PaymentReconciliation) error
}

func (repo *GormRepository) RecordPaymentReconciliation(ctx context.Context, record PaymentReconciliation) error {
	if record.ID == "" {
		record.ID = uuid.NewString()
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	record.Currency = strings.ToUpper(record.Currency)
	return repo.connection.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&record).Error
}
