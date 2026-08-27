package db

import "time"

type FileList struct {
	ID                    uint       `gorm:"primaryKey"`
	AnonymousSessionToken string     `gorm:"column:anonymous_session_token;type:varchar(64);not null"`
	FileID                string     `gorm:"column:file_id;type:uuid;uniqueIndex;not null"`
	FileOwner             *string    `gorm:"column:file_owner;type:uuid"`
	FileName              string     `gorm:"column:file_name;type:varchar(255);not null"`
	FileSize              int64      `gorm:"column:file_size;not null"`
	FileSHA256            string     `gorm:"column:file_sha256;type:varchar(64);not null"`
	FileSHA3              string     `gorm:"column:file_sha3;type:varchar(64);not null"`
	ContentType           string     `gorm:"column:content_type;type:varchar(255);not null;default:application/octet-stream"`
	IsAnonymousUpload     bool       `gorm:"column:is_anonymous_upload;not null;default:true"`
	IsEncrypted           bool       `gorm:"column:is_encrypted;not null;default:false"`
	EncryptionMethod      string     `gorm:"column:encryption_method;type:varchar(32)"`
	StorageService        string     `gorm:"column:storage_service;type:varchar(32);not null"`
	UploadStatus          string     `gorm:"column:upload_status;type:varchar(16);not null;default:complete;index"`
	ChecksumStatus        string     `gorm:"column:checksum_status;type:varchar(16);not null;default:verified"`
	UploadExpiresAt       *time.Time `gorm:"column:upload_expires_at;index"`
	CreatedAt             time.Time  `gorm:"column:created_at;not null"`
	UpdatedAt             time.Time  `gorm:"column:updated_at;not null"`
}

func (FileList) TableName() string { return "file_lists" }
