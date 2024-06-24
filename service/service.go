package service

import (
	"ObjectShare/config"
	"mime/multipart"
)

func Upload(file multipart.File, fileId string, fileName string) error {
	switch config.Config.StorageService {
	case "r2":
		return UploadToR2(file, fileId, fileName)
	default:
		return nil
	}
}

func GeneratePreSignedDownloadURL(fileId string, fileName string) (string, error) {
	switch config.Config.StorageService {
	case "r2":
		return GenerateR2PreSignedDownloadURL(fileId, fileName)
	default:
		return "", nil
	}
}
