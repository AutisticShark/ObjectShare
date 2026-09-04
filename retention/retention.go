package retention

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

const (
	batchSize       = 100
	claimTimeout    = 30 * time.Minute
	normalInterval  = time.Hour
	backlogInterval = time.Minute
)

type ObjectStore interface {
	Delete(context.Context, string) error
}

type Result struct {
	Claimed  int
	Deleted  int
	Released int
}

type Cleaner struct {
	repository db.RetentionRepository
	storage    ObjectStore
	policy     config.RetentionConfig
	logger     *slog.Logger
}

func New(repository db.RetentionRepository, storage ObjectStore, policy config.RetentionConfig, logger *slog.Logger) *Cleaner {
	return &Cleaner{repository: repository, storage: storage, policy: policy, logger: logger}
}

// Run performs one sweep at startup, then hourly. A full batch indicates a
// backlog and schedules the next batch sooner without blocking HTTP startup.
func (cleaner *Cleaner) Run(ctx context.Context) {
	delay := time.Duration(0)
	for {
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return
			case <-timer.C:
			}
		}
		result, err := cleaner.Sweep(ctx, time.Now().UTC())
		if err != nil && !errors.Is(err, context.Canceled) {
			cleaner.logger.Warn("automatic file retention sweep had failures", "claimed", result.Claimed, "deleted", result.Deleted, "released", result.Released, "error", err)
		} else if result.Deleted > 0 {
			cleaner.logger.Info("automatic file retention sweep completed", "claimed", result.Claimed, "deleted", result.Deleted)
		}
		delay = normalInterval
		if result.Claimed == batchSize {
			delay = backlogInterval
		}
	}
}

func (cleaner *Cleaner) Sweep(ctx context.Context, now time.Time) (Result, error) {
	guestBefore := cutoff(now, cleaner.policy.GuestDays)
	unpaidBefore := cutoff(now, cleaner.policy.UnpaidDays)
	files, err := cleaner.repository.ClaimFilesForRetention(ctx, now, now.Add(-claimTimeout), guestBefore, unpaidBefore, batchSize)
	result := Result{Claimed: len(files)}
	if err != nil {
		return result, fmt.Errorf("claim expired files: %w", err)
	}
	var failures []error
	for _, file := range files {
		if err := cleaner.storage.Delete(ctx, file.FileID); err != nil {
			releaseErr := cleaner.repository.ReleaseRetentionClaim(ctx, file.FileID)
			if releaseErr == nil || errors.Is(releaseErr, db.ErrNotFound) {
				result.Released++
			} else {
				failures = append(failures, fmt.Errorf("release retention claim for %s: %w", file.FileID, releaseErr))
			}
			failures = append(failures, fmt.Errorf("delete retained object %s: %w", file.FileID, err))
			continue
		}
		if err := cleaner.repository.Delete(ctx, file.FileID); err != nil && !errors.Is(err, db.ErrNotFound) {
			// The object is already gone. Keep the claim so a later sweep can
			// safely retry the idempotent object deletion and metadata removal.
			failures = append(failures, fmt.Errorf("delete retained file record %s: %w", file.FileID, err))
			continue
		}
		result.Deleted++
	}
	return result, errors.Join(failures...)
}

func cutoff(now time.Time, days int) *time.Time {
	if days <= 0 {
		return nil
	}
	value := now.Add(-time.Duration(days) * 24 * time.Hour)
	return &value
}
