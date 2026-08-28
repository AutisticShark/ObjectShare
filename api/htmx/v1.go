package htmx

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	appcrypto "github.com/AutisticShark/ObjectShare/encryption"
	"github.com/AutisticShark/ObjectShare/service"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const mebibyte = int64(1024 * 1024)

type Handler struct {
	config     *config.ServiceConfig
	repository db.Repository
	storage    service.ObjectStore
	direct     service.DirectUploader
	templates  *template.Template
	uploadJS   []byte
	cipher     *appcrypto.Cipher
	cipherSlot chan struct{}
	logger     *slog.Logger
}

func New(cfg *config.ServiceConfig, repository db.Repository, storage service.ObjectStore, templates fs.FS, logger *slog.Logger) (*Handler, error) {
	parsed, err := template.ParseFS(templates, "template/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	uploadJS, err := fs.ReadFile(templates, "template/upload.js")
	if err != nil {
		return nil, fmt.Errorf("read upload script: %w", err)
	}
	handler := &Handler{config: cfg, repository: repository, storage: storage, templates: parsed, uploadJS: uploadJS, logger: logger}
	if cfg.Encryption != nil && cfg.Encryption.Enabled {
		key, err := config.DecodeEncryptionKey(cfg.Encryption.Key)
		if err != nil {
			return nil, err
		}
		handler.cipher, err = appcrypto.New(key)
		if err != nil {
			return nil, err
		}
		handler.cipherSlot = make(chan struct{}, 1)
	} else {
		handler.direct, _ = storage.(service.DirectUploader)
	}
	return handler, nil
}

func (handler *Handler) Index(writer http.ResponseWriter, _ *http.Request) {
	maxFileSize := handler.config.MaxFileSize
	if handler.direct != nil && maxFileSize*mebibyte > service.MaxSinglePartUploadSize {
		maxFileSize = service.MaxSinglePartUploadSize / mebibyte
	}
	handler.render(writer, "index.html", struct {
		Version      string
		MaxFileSize  int64
		DirectUpload bool
	}{config.GetVersion(), maxFileSize, handler.direct != nil})
}

func (handler *Handler) UploadScript(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	writer.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeContent(writer, request, "upload.js", time.Time{}, bytes.NewReader(handler.uploadJS))
}

func (handler *Handler) FileView(writer http.ResponseWriter, request *http.Request) {
	fileID, ok := validFileID(request)
	if !ok {
		http.NotFound(writer, request)
		return
	}
	file, err := handler.repository.Get(request.Context(), fileID)
	if errors.Is(err, db.ErrNotFound) {
		http.NotFound(writer, request)
		return
	}
	if err != nil {
		handler.internalError(writer, request, "get file", err)
		return
	}
	if file.UploadStatus != "complete" {
		http.NotFound(writer, request)
		return
	}
	handler.render(writer, "file_view.html", struct {
		Version, FileID, FileName, FileSize, FileSHA256, FileSHA3, CreatedAt, UpdatedAt string
		CanManage, Encrypted, ChecksumsVerified                                         bool
	}{
		Version: config.GetVersion(), FileID: file.FileID, FileName: file.FileName,
		FileSize: humanSize(file.FileSize), FileSHA256: file.FileSHA256, FileSHA3: file.FileSHA3,
		CreatedAt: file.CreatedAt.UTC().Format(time.RFC3339), UpdatedAt: file.UpdatedAt.UTC().Format(time.RFC3339),
		CanManage: handler.isOwner(request, file), Encrypted: file.IsEncrypted,
		ChecksumsVerified: file.ChecksumStatus == "verified",
	})
}

func (handler *Handler) Upload(writer http.ResponseWriter, request *http.Request) {
	maxBytes := handler.config.MaxFileSize * mebibyte
	request.Body = http.MaxBytesReader(writer, request.Body, maxBytes+mebibyte)
	fileObject, header, err := request.FormFile("file")
	if request.MultipartForm != nil {
		defer request.MultipartForm.RemoveAll()
	}
	if err != nil {
		var limitError *http.MaxBytesError
		if errors.As(err, &limitError) {
			http.Error(writer, "The upload exceeds the configured size limit.", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(writer, "A file is required and must be within the configured size limit.", http.StatusBadRequest)
		return
	}
	defer fileObject.Close()
	if header.Size <= 0 || header.Size > maxBytes {
		http.Error(writer, "Invalid file size.", http.StatusRequestEntityTooLarge)
		return
	}
	fileName, err := safeFileName(header.Filename)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	contentType, err := sniffContentType(fileObject)
	if err != nil {
		http.Error(writer, "Unable to read the uploaded file.", http.StatusBadRequest)
		return
	}
	fileID := uuid.NewString()
	sha256Hasher, sha3Hasher := sha256.New(), sha3.New256()
	counter := &byteCounter{}
	reader := io.TeeReader(fileObject, io.MultiWriter(sha256Hasher, sha3Hasher, counter))
	storedSize := header.Size
	if handler.cipher != nil {
		if !handler.acquireCipherSlot() {
			http.Error(writer, "Encryption capacity is busy; retry shortly.", http.StatusServiceUnavailable)
			return
		}
		defer handler.releaseCipherSlot()
		plaintext, readErr := io.ReadAll(io.LimitReader(reader, maxBytes+1))
		if readErr != nil || int64(len(plaintext)) != header.Size || int64(len(plaintext)) > maxBytes {
			http.Error(writer, "Unable to read the complete uploaded file.", http.StatusBadRequest)
			return
		}
		ciphertext, encryptErr := handler.cipher.Encrypt(plaintext)
		if encryptErr != nil {
			handler.internalError(writer, request, "encrypt file", encryptErr)
			return
		}
		storedSize = int64(len(ciphertext))
		reader = bytes.NewReader(ciphertext)
	}
	if err := handler.storage.Put(request.Context(), fileID, reader, storedSize, contentType); err != nil {
		handler.internalError(writer, request, "store file", err)
		return
	}
	if counter.total != header.Size {
		_ = handler.storage.Delete(request.Context(), fileID)
		handler.internalError(writer, request, "store complete file", fmt.Errorf("stored %d of %d plaintext bytes", counter.total, header.Size))
		return
	}

	token, tokenHash, err := newOwnerToken()
	if err != nil {
		_ = handler.storage.Delete(request.Context(), fileID)
		handler.internalError(writer, request, "create owner token", err)
		return
	}
	now := time.Now().UTC()
	record := &db.FileList{
		AnonymousSessionToken: tokenHash, FileID: fileID, FileName: fileName, FileSize: header.Size,
		FileSHA256: hex.EncodeToString(sha256Hasher.Sum(nil)), FileSHA3: hex.EncodeToString(sha3Hasher.Sum(nil)),
		ContentType: contentType, IsAnonymousUpload: true, IsEncrypted: handler.cipher != nil,
		StorageService: handler.config.StorageService, UploadStatus: "complete", ChecksumStatus: "verified",
		CreatedAt: now, UpdatedAt: now,
	}
	if handler.cipher != nil {
		record.EncryptionMethod = "aes-256-gcm"
	}
	if err := handler.repository.Create(request.Context(), record); err != nil {
		_ = handler.storage.Delete(request.Context(), fileID)
		handler.internalError(writer, request, "create file record", err)
		return
	}
	http.SetCookie(writer, ownerCookie(fileID, token, handler.config.SecureCookies, 30*24*time.Hour))
	handler.redirect(writer, request, "/file/"+fileID)
}

func (handler *Handler) Download(writer http.ResponseWriter, request *http.Request) {
	fileID, ok := validFileID(request)
	if !ok {
		http.NotFound(writer, request)
		return
	}
	file, err := handler.repository.Get(request.Context(), fileID)
	if errors.Is(err, db.ErrNotFound) {
		http.NotFound(writer, request)
		return
	}
	if err != nil {
		handler.internalError(writer, request, "get file", err)
		return
	}
	if file.UploadStatus != "complete" {
		http.NotFound(writer, request)
		return
	}
	if !file.IsEncrypted {
		if location, err := handler.storage.PresignGet(request.Context(), fileID, file.FileName); err == nil {
			http.Redirect(writer, request, location, http.StatusTemporaryRedirect)
			return
		} else if !errors.Is(err, service.ErrPresignUnsupported) {
			handler.internalError(writer, request, "presign download", err)
			return
		}
	}

	body, err := handler.storage.Open(request.Context(), fileID)
	if err != nil {
		handler.internalError(writer, request, "open object", err)
		return
	}
	defer body.Close()
	writer.Header().Set("Content-Type", file.ContentType)
	writer.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": file.FileName}))
	writer.Header().Set("Cache-Control", "private, no-store")
	if file.IsEncrypted {
		if handler.cipher == nil {
			handler.internalError(writer, request, "decrypt object", errors.New("encryption key is unavailable"))
			return
		}
		if !handler.acquireCipherSlot() {
			http.Error(writer, "Encryption capacity is busy; retry shortly.", http.StatusServiceUnavailable)
			return
		}
		defer handler.releaseCipherSlot()
		limit := handler.config.MaxFileSize*mebibyte + int64(handler.cipher.Overhead()) + 1
		ciphertext, err := io.ReadAll(io.LimitReader(body, limit))
		if err != nil || int64(len(ciphertext)) >= limit {
			handler.internalError(writer, request, "read encrypted object", err)
			return
		}
		plaintext, err := handler.cipher.Decrypt(ciphertext)
		if err != nil {
			handler.internalError(writer, request, "decrypt object", err)
			return
		}
		writer.Header().Set("Content-Length", fmt.Sprint(len(plaintext)))
		_, _ = io.Copy(writer, bytes.NewReader(plaintext))
		return
	}
	writer.Header().Set("Content-Length", fmt.Sprint(file.FileSize))
	_, _ = io.Copy(writer, body)
}

func (handler *Handler) Delete(writer http.ResponseWriter, request *http.Request) {
	fileID, ok := validFileID(request)
	if !ok {
		http.NotFound(writer, request)
		return
	}
	file, err := handler.repository.Get(request.Context(), fileID)
	if errors.Is(err, db.ErrNotFound) {
		http.NotFound(writer, request)
		return
	}
	if err != nil {
		handler.internalError(writer, request, "get file", err)
		return
	}
	if file.UploadStatus != "complete" {
		http.NotFound(writer, request)
		return
	}
	if !handler.isOwner(request, file) {
		http.Error(writer, "Forbidden", http.StatusForbidden)
		return
	}
	if err := handler.storage.Delete(request.Context(), fileID); err != nil {
		handler.internalError(writer, request, "delete object", err)
		return
	}
	if err := handler.repository.Delete(request.Context(), fileID); err != nil && !errors.Is(err, db.ErrNotFound) {
		handler.internalError(writer, request, "delete file record", err)
		return
	}
	http.SetCookie(writer, ownerCookie(fileID, "", handler.config.SecureCookies, -time.Hour))
	handler.redirect(writer, request, "/")
}

func (handler *Handler) Update(writer http.ResponseWriter, request *http.Request) {
	fileID, ok := validFileID(request)
	if !ok {
		http.NotFound(writer, request)
		return
	}
	file, err := handler.repository.Get(request.Context(), fileID)
	if errors.Is(err, db.ErrNotFound) {
		http.NotFound(writer, request)
		return
	}
	if err != nil {
		handler.internalError(writer, request, "get file", err)
		return
	}
	if file.UploadStatus != "complete" {
		http.NotFound(writer, request)
		return
	}
	if !handler.isOwner(request, file) {
		http.Error(writer, "Forbidden", http.StatusForbidden)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 4096)
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "Invalid form.", http.StatusBadRequest)
		return
	}
	name, err := safeFileName(request.FormValue("name"))
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	if err := handler.repository.Rename(request.Context(), fileID, name); err != nil {
		handler.internalError(writer, request, "rename file", err)
		return
	}
	handler.redirect(writer, request, "/file/"+fileID)
}

func (handler *Handler) Live(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(writer, `{"status":"ok"}`)
}

func (handler *Handler) Ready(writer http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
	defer cancel()
	if err := handler.repository.Ping(ctx); err != nil {
		http.Error(writer, "not ready", http.StatusServiceUnavailable)
		return
	}
	handler.Live(writer, request)
}

func (handler *Handler) render(writer http.ResponseWriter, name string, data any) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "private, no-store")
	if err := handler.templates.ExecuteTemplate(writer, name, data); err != nil {
		handler.logger.Error("render template", "template", name, "error", err)
	}
}

func (handler *Handler) internalError(writer http.ResponseWriter, request *http.Request, operation string, err error) {
	if err == nil {
		err = errors.New("unexpected empty error")
	}
	handler.logger.Error(operation, "request_id", request.Header.Get("X-Request-Id"), "error", err)
	http.Error(writer, "Internal server error.", http.StatusInternalServerError)
}

func (handler *Handler) redirect(writer http.ResponseWriter, request *http.Request, location string) {
	if request.Header.Get("HX-Request") == "true" {
		writer.Header().Set("HX-Redirect", location)
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(writer, request, location, http.StatusSeeOther)
}

func (handler *Handler) isOwner(request *http.Request, file *db.FileList) bool {
	cookie, err := request.Cookie(ownerCookieName(file.FileID))
	if err != nil {
		return false
	}
	return ownerTokenMatches(file, cookie.Value)
}

func ownerTokenMatches(file *db.FileList, token string) bool {
	hash := sha256.Sum256([]byte(token))
	want, err := hex.DecodeString(file.AnonymousSessionToken)
	return err == nil && len(want) == len(hash) && subtle.ConstantTimeCompare(hash[:], want) == 1
}

func validFileID(request *http.Request) (string, bool) {
	value := chi.URLParam(request, "id")
	parsed, err := uuid.Parse(value)
	return value, err == nil && parsed.String() == strings.ToLower(value)
}

func safeFileName(value string) (string, error) {
	value = path.Base(strings.ReplaceAll(strings.TrimSpace(value), "\\", "/"))
	if value == "" || value == "." || value == ".." || !utf8.ValidString(value) {
		return "", errors.New("Invalid file name.")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return "", errors.New("File name contains control characters.")
		}
	}
	if len([]byte(value)) > 255 {
		return "", errors.New("File name is too long.")
	}
	return value, nil
}

func sniffContentType(file io.ReadSeeker) (string, error) {
	buffer := make([]byte, 512)
	count, err := file.Read(buffer)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	return http.DetectContentType(buffer[:count]), nil
}

func newOwnerToken() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(hash[:]), nil
}

func ownerCookieName(fileID string) string {
	return "objectshare_owner_" + strings.ReplaceAll(fileID, "-", "")
}

func ownerCookie(fileID, token string, secure bool, lifetime time.Duration) *http.Cookie {
	return &http.Cookie{Name: ownerCookieName(fileID), Value: token, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: int(lifetime.Seconds())}
}

func humanSize(size int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	value := float64(size)
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d %s", size, units[unit])
	}
	return fmt.Sprintf("%.1f %s", value, units[unit])
}

type byteCounter struct{ total int64 }

func (counter *byteCounter) Write(buffer []byte) (int, error) {
	counter.total += int64(len(buffer))
	return len(buffer), nil
}

func (handler *Handler) acquireCipherSlot() bool {
	select {
	case handler.cipherSlot <- struct{}{}:
		return true
	default:
		return false
	}
}

func (handler *Handler) releaseCipherSlot() { <-handler.cipherSlot }
