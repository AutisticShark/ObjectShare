package db

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
)

const (
	ShareLink     = "link"
	ShareSignedIn = "signed_in"
	ShareSelected = "selected"
	SharePrivate  = "private"
	MaxShareUsers = 50
)

type SharingRepository interface {
	SetFileSharing(context.Context, string, string, []string) error
}

func ValidShareMode(mode string) bool {
	return mode == ShareLink || mode == ShareSignedIn || mode == ShareSelected || mode == SharePrivate
}

// SetFileSharing replaces the access policy in one statement, so readers never
// observe a new mode with an old recipient list. Account IDs survive email edits.
func (repo *GormRepository) SetFileSharing(ctx context.Context, fileID, mode string, userIDs []string) error {
	if !ValidShareMode(mode) || len(userIDs) > MaxShareUsers || (mode == ShareSelected && len(userIDs) == 0) || (mode != ShareSelected && len(userIDs) != 0) {
		return errors.New("invalid sharing policy")
	}
	for _, id := range userIDs {
		if _, err := uuid.Parse(id); err != nil {
			return errors.New("invalid sharing account")
		}
	}
	if userIDs == nil {
		userIDs = []string{}
	}
	encoded, err := json.Marshal(userIDs)
	if err != nil {
		return err
	}
	result := repo.connection.WithContext(ctx).Model(&FileList{}).
		Where("file_id = ? AND upload_status = ?", fileID, "complete").
		Updates(map[string]any{"share_mode": mode, "share_user_ids": string(encoded)})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}
