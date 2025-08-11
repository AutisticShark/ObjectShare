package db

type FileList struct {
	AnonymousSessionToken string `gorm:"type:varchar"`
	Id                    int    `gorm:"primary_key"`
	FileId                string `gorm:"unique;type:uuid"`
	FileOwner             string `gorm:"type:uuid"`
	FileName              string
	FileSize              int64
	FileSha256            string `gorm:"unique;type:varchar"`
	FileSha3              string `gorm:"unique;type:varchar"`
	IsEncrypted           bool   `gorm:"default:false"`
	IsAnonymousUpload     bool   `gorm:"default:true"`
	EncryptionMethod      string `gorm:"default:aes-256-gcm"`
	EncryptionKey         string `gorm:"unique;type:varchar"`
	StorageService        string `gorm:"type:varchar;default:r2"`
	CreatedAt             string `gorm:"type:timestamp"`
	UpdatedAt             string `gorm:"type:timestamp"`
}
