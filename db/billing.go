package db

import (
	"context"
	"errors"
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
	err := repo.connection.WithContext(ctx).Where("active = ?", true).Order("sort_order ASC, name ASC").Find(&plans).Error
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
	if plan.ID == "" {
		plan.ID = uuid.NewString()
	}
	return repo.connection.WithContext(ctx).Create(plan).Error
}

func (repo *GormRepository) UpdatePlan(ctx context.Context, plan *PaidPlan) error {
	return repo.connection.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing PaidPlan
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", plan.ID).First(&existing).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if existing.Gateway != plan.Gateway || existing.GatewayPlanID != plan.GatewayPlanID {
			var subscriptions int64
			if err := tx.Model(&Subscription{}).Where("plan_id = ?", plan.ID).Count(&subscriptions).Error; err != nil {
				return err
			}
			if subscriptions != 0 {
				return ErrConflict
			}
		}
		return tx.Model(&PaidPlan{}).Where("id = ?", plan.ID).Updates(map[string]any{
			"name": plan.Name, "description": plan.Description, "gateway": plan.Gateway, "gateway_plan_id": plan.GatewayPlanID,
			"price_label": plan.PriceLabel, "storage_quota_bytes": plan.StorageQuotaBytes,
			"retention_days": plan.RetentionDays, "direct_links": plan.DirectLinks,
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
		if err == nil && existing.Gateway != update.Gateway && !subscriptionActive(update.Status, update.CurrentPeriodEnd, time.Now().UTC()) {
			return tx.Create(&BillingEvent{EventID: eventID}).Error
		}
		if err == nil {
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
