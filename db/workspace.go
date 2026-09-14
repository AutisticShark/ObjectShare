package db

import (
	"context"
	"fmt"
	"time"
)

const WorkspacePageSize = 25

// WorkspaceRepository exposes bounded lists and aggregate counts for the UI.
// It does not grant file contents, sharing permissions, or payment mutations.
type WorkspaceRepository interface {
	OwnerFiles(context.Context, string, string, string, int) ([]FileList, error)
	AdminOverview(context.Context, time.Time) (Overview, error)
	AdminInvoices(context.Context, string, string, int) ([]Invoice, error)
}

type Overview struct {
	Users, BannedUsers, ShadowbannedUsers, DisabledUsers int64
	Files, StorageBytes, PendingUploads, ActivePlans     int64
	PaidInvoices, PendingInvoices, UnsentReceipts        int64
}

func validWorkspacePage(page int) bool { return page >= 0 && page <= 100000 }

func (repo *GormRepository) OwnerFiles(ctx context.Context, owner, search, mode string, page int) ([]FileList, error) {
	if owner == "" || !validWorkspacePage(page) {
		return nil, fmt.Errorf("invalid file list request")
	}
	query := repo.connection.WithContext(ctx).Model(&FileList{}).
		Where("file_owner = ? AND upload_status = ?", owner, "complete")
	if search != "" {
		// strpos treats percent, underscore, and backslash as literal characters.
		query = query.Where("strpos(lower(file_name), lower(?)) > 0", search)
	}
	if mode == "link" {
		query = query.Where("share_mode IN ?", []string{"", "link"})
	} else if mode != "" {
		query = query.Where("share_mode = ?", mode)
	}
	var files []FileList
	err := query.Order("created_at DESC, file_id DESC").Limit(WorkspacePageSize + 1).Offset(page * WorkspacePageSize).Find(&files).Error
	return files, err
}

func (repo *GormRepository) AdminOverview(ctx context.Context, now time.Time) (Overview, error) {
	var result Overview
	err := repo.connection.WithContext(ctx).Raw(`
      SELECT user_counts.*, file_counts.*, plan_counts.*, invoice_counts.* FROM
      (SELECT count(*) AS users,
        count(*) FILTER (WHERE moderation_status = 'banned') AS banned_users,
        count(*) FILTER (WHERE moderation_status = 'shadowbanned') AS shadowbanned_users,
        count(*) FILTER (WHERE NOT active) AS disabled_users FROM users) user_counts
      CROSS JOIN
      (SELECT count(*) FILTER (WHERE upload_status = 'complete') AS files,
        COALESCE(sum(file_size) FILTER (WHERE upload_status = 'complete'), 0) AS storage_bytes,
        count(*) FILTER (WHERE upload_status = 'pending') AS pending_uploads FROM file_lists) file_counts
      CROSS JOIN
      (SELECT count(*) AS active_plans FROM subscriptions
        WHERE status IN ('active', 'trialing') AND current_period_end > ?) plan_counts
      CROSS JOIN
      (SELECT count(*) FILTER (WHERE status = 'paid') AS paid_invoices,
        count(*) FILTER (WHERE status = 'pending') AS pending_invoices,
        count(*) FILTER (WHERE status = 'paid' AND email_sent_at IS NULL) AS unsent_receipts FROM invoices) invoice_counts
    `, now).Scan(&result).Error
	if err != nil {
		return Overview{}, err
	}
	return result, nil
}

func (repo *GormRepository) AdminInvoices(ctx context.Context, search, status string, page int) ([]Invoice, error) {
	if !validWorkspacePage(page) {
		return nil, fmt.Errorf("invalid invoice list request")
	}
	query := repo.connection.WithContext(ctx).Model(&Invoice{})
	if search != "" {
		query = query.Where("strpos(lower(email), lower(?)) > 0 OR strpos(lower(name), lower(?)) > 0 OR id::text = ? OR payment_id = ?", search, search, search, search)
	}
	if status == "unsent" {
		query = query.Where("status = 'paid' AND email_sent_at IS NULL")
	} else if status != "" {
		query = query.Where("status = ?", status)
	}
	var invoices []Invoice
	err := query.Order("created_at DESC, id DESC").Limit(WorkspacePageSize + 1).Offset(page * WorkspacePageSize).Find(&invoices).Error
	return invoices, err
}
