package db

type FileList struct {
	Id               int    `gorm:"primary_key"`
	FileId           string `gorm:"unique"`
	FileName         string
	FileSize         int64
	FileSha256       string
	FileSha3         string
	IsEncrypted      bool   `gorm:"default:false"`
	EncryptionMethod string `gorm:"default:aes-256-gcm"`
	EncryptionKey    string
	CreatedAt        string
	UpdatedAt        string
}
