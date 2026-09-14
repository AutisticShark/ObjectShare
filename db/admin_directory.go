package db

import (
	"context"
	"fmt"
)

type AdminDirectory struct {
	Users                        []User
	Usage                        map[string]int64
	TotalUsers, TotalStorageUsed int64
}

// AdminUserDirectory bounds account rows and per-account storage aggregation.
// Global counters remain global when the operator searches or changes pages.
func (repo *GormRepository) AdminUserDirectory(ctx context.Context, search, filter string, page int) (AdminDirectory, error) {
	result := AdminDirectory{Usage: map[string]int64{}}
	if !validWorkspacePage(page) {
		return result, fmt.Errorf("invalid directory page")
	}
	connection := repo.connection.WithContext(ctx)
	query := connection.Model(&User{}).Select("id", "email", "display_name", "role", "active", "moderation_status", "email_verified_at", "created_at", "last_login_at", "is_paid", "upload_quota_bytes", "credit_balance")
	if search != "" {
		query = query.Where("strpos(lower(email), lower(?)) > 0 OR strpos(lower(display_name), lower(?)) > 0 OR id::text = ?", search, search, search)
	}
	switch filter {
	case "":
	case "admin":
		query = query.Where("role = ?", RoleAdmin)
	case "disabled":
		query = query.Where("active = FALSE")
	case "banned", "shadowbanned":
		query = query.Where("moderation_status = ?", filter)
	case "verified":
		query = query.Where("email_verified_at IS NOT NULL")
	case "unverified":
		query = query.Where("email_verified_at IS NULL")
	default:
		return result, fmt.Errorf("invalid directory filter")
	}
	if err := query.Order("role ASC, display_name ASC, email ASC, id ASC").Limit(WorkspacePageSize + 1).
		Offset(page * WorkspacePageSize).Find(&result.Users).Error; err != nil {
		return result, err
	}
	ids := make([]string, 0, len(result.Users))
	for _, user := range result.Users {
		ids = append(ids, user.ID)
	}
	if len(ids) != 0 {
		var usage []struct {
			FileOwner string
			Used      int64
		}
		if err := connection.Model(&FileList{}).Select("file_owner, COALESCE(SUM(file_size), 0) AS used").
			Where("file_owner IN ? AND upload_status IN ?", ids, []string{"pending", "complete", "deleting", "aborting"}).
			Group("file_owner").Scan(&usage).Error; err != nil {
			return result, err
		}
		for _, row := range usage {
			result.Usage[row.FileOwner] = row.Used
		}
	}
	var totals struct{ TotalUsers, TotalStorageUsed int64 }
	err := connection.Raw(`SELECT (SELECT count(*) FROM users) AS total_users,
        COALESCE((SELECT sum(f.file_size) FROM file_lists f JOIN users u ON u.id = f.file_owner
        WHERE f.upload_status IN ('pending','complete','deleting','aborting')), 0) AS total_storage_used`).Scan(&totals).Error
	result.TotalUsers, result.TotalStorageUsed = totals.TotalUsers, totals.TotalStorageUsed
	return result, err
}
