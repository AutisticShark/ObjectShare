package db

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ConsumeRateLimit atomically consumes one request from a fixed-window bucket.
// Redis handles expiring counters when configured; otherwise PostgreSQL's
// transaction advisory lock makes the decision consistent across processes.
// Both backends store hashes rather than raw IP addresses or user identifiers.
func (repo *GormRepository) ConsumeRateLimit(ctx context.Context, scope, keyHash string, limit int, window time.Duration, now time.Time) (bool, time.Time, error) {
	if limit <= 0 {
		return true, time.Time{}, nil
	}
	if repo.redis != nil {
		return repo.redis.consume(ctx, scope, keyHash, limit, window)
	}
	// Cleanup is outside the per-key advisory-lock transaction to avoid lock
	// ordering between unrelated client buckets. Running it occasionally keeps
	// an attacker from growing the table forever without adding a DELETE to each
	// ordinary request.
	if repo.rateLimitCalls.Add(1)%1024 == 0 {
		if err := repo.connection.WithContext(ctx).Where("updated_at < ?", now.Add(-48*time.Hour)).Delete(&RateLimitBucket{}).Error; err != nil {
			return false, time.Time{}, err
		}
	}
	var allowed bool
	var retryAt time.Time
	err := repo.connection.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		lockKey := scope + ":" + keyHash
		if err := transaction.Exec("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", lockKey).Error; err != nil {
			return err
		}
		var bucket RateLimitBucket
		err := transaction.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("scope = ? AND key_hash = ?", scope, keyHash).First(&bucket).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			allowed = true
			return transaction.Create(&RateLimitBucket{Scope: scope, KeyHash: keyHash, WindowStarted: now, Used: 1, UpdatedAt: now}).Error
		}
		if err != nil {
			return err
		}
		if !now.Before(bucket.WindowStarted.Add(window)) {
			bucket.WindowStarted = now
			bucket.Used = 1
			bucket.UpdatedAt = now
			allowed = true
			return transaction.Save(&bucket).Error
		}
		retryAt = bucket.WindowStarted.Add(window)
		if bucket.Used >= limit {
			allowed = false
			return nil
		}
		bucket.Used++
		bucket.UpdatedAt = now
		allowed = true
		return transaction.Save(&bucket).Error
	})
	return allowed, retryAt, err
}
