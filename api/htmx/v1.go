package htmx

import (
	"ObjectShare/config"
	"ObjectShare/db"
	"ObjectShare/service"
	"crypto/sha256"
	"encoding/hex"
	"github.com/c2h5oh/datasize"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/sha3"
	"html/template"
	"io"
	"net/http"
	"time"
)

var (
	dbConnection = db.GetConnection()
)

func IndexV1(writer http.ResponseWriter, request *http.Request) {
	html, err := template.ParseFiles("./template/index.html")
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
	}

	data := struct {
		Version string
	}{
		Version: config.GetVersion(),
	}

	if html != nil {
		err = html.Execute(writer, data)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
		}
		writer.WriteHeader(http.StatusOK)
	}

	writer.WriteHeader(http.StatusInternalServerError)
}

func FileViewV1(writer http.ResponseWriter, request *http.Request) {
	fileId := chi.URLParam(request, "id")
	file := db.FileList{}

	result := dbConnection.Where("file_id = ?", fileId).First(&file)
	if result.Error != nil {
		writer.Header().Set("Location", "/")
		writer.WriteHeader(http.StatusMovedPermanently)
		return
	}

	if file.FileId == "" {
		writer.Header().Set("Location", "/")
		writer.WriteHeader(http.StatusMovedPermanently)
		return
	}

	html, err := template.ParseFiles("./template/file_view.html")
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	data := struct {
		Version    string
		FileId     string
		FileName   string
		FileSize   string
		FileSha256 string
		FileSha3   string
		CreatedAt  string
		UpdatedAt  string
	}{
		Version:    config.GetVersion(),
		FileId:     file.FileId,
		FileName:   file.FileName,
		FileSize:   datasize.ByteSize(file.FileSize).HumanReadable(),
		FileSha256: file.FileSha256,
		FileSha3:   file.FileSha3,
		CreatedAt:  file.CreatedAt,
		UpdatedAt:  file.UpdatedAt,
	}

	if html != nil {
		err = html.Execute(writer, data)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.WriteHeader(http.StatusOK)
	}
}

func UploadV1(writer http.ResponseWriter, request *http.Request) {
	failReason := ""
	// Check file size
	fileSize := request.ContentLength
	if fileSize <= 0 || fileSize > (config.Config.MaxFileSize*1024*1024) {
		failReason = "Invalid file size"
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`
		<h3>Upload failed</h3>
		<p>` + failReason + `</p>`))
		return
	}

	fileObject, fileHeader, err := request.FormFile("file")
	if err != nil {
		failReason = "Failed to get file"
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`
		<h3>Upload failed</h3>
		<p>` + failReason + `</p>`))
		return
	}

	defer fileObject.Close()

	fileId, err := uuid.NewRandom()
	if err != nil {
		failReason = "Failed to generate file ID"
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`
		<h3>Upload failed</h3>
		<p>` + failReason + `</p>`))
		return
	}

	err = service.Upload(fileObject, fileId.String(), fileHeader.Filename)
	if err != nil {
		failReason = "Failed to upload file"
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`
		<h3>Upload failed</h3>
		<p>` + failReason + `</p>
		<p>` + err.Error() + `</p>`))
		return
	}

	Sha256Hasher := sha256.New()
	_, err = io.Copy(Sha256Hasher, fileObject)
	fileSha256 := hex.EncodeToString(Sha256Hasher.Sum(nil))
	Sha3Hasher := sha3.New256()
	_, err = io.Copy(Sha3Hasher, fileObject)
	fileSha3 := hex.EncodeToString(Sha3Hasher.Sum(nil))

	file := db.FileList{
		FileId:           fileId.String(),
		FileName:         fileHeader.Filename,
		FileSize:         fileSize,
		FileSha256:       fileSha256,
		FileSha3:         fileSha3,
		IsEncrypted:      false,
		EncryptionMethod: "",
		EncryptionKey:    "",
		CreatedAt:        time.Now().Format(time.RFC3339),
		UpdatedAt:        time.Now().Format(time.RFC3339),
	}

	result := dbConnection.Create(&file)
	if result.Error != nil {
		failReason = "Failed to create database record"
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`
		<h3>Upload failed</h3>
		<p>` + failReason + `</p>`))
		return
	}

	writer.Header().Set("HX-Redirect", "/file/"+fileId.String())
	writer.WriteHeader(http.StatusOK)
}

func DownloadV1(writer http.ResponseWriter, request *http.Request) {
	fileId := chi.URLParam(request, "id")
	file := db.FileList{}

	result := dbConnection.Where("file_id = ?", fileId).First(&file)
	if result.Error != nil {
		writer.WriteHeader(http.StatusNotFound)
		return
	}

	if !file.IsEncrypted {
		downloadLink, err := service.GeneratePreSignedDownloadURL(fileId, file.FileName)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		writer.Header().Set("HX-Redirect", downloadLink)
		writer.WriteHeader(http.StatusOK)
	}
}

func DeleteV1(writer http.ResponseWriter, request *http.Request) {
	writer.WriteHeader(http.StatusNoContent)
}

func UpdateV1(writer http.ResponseWriter, request *http.Request) {
	writer.WriteHeader(http.StatusOK)

	_, err := writer.Write([]byte("Ok"))
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
	}
}
