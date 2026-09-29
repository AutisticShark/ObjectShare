package htmx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"path"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/google/uuid"
)

func (handler *Handler) Upload(writer http.ResponseWriter, request *http.Request) {
	if !handler.allowRequest(writer, request, "upload", handler.rateLimitSettings().UploadLimit) {
		return
	}
	maxBytes := handler.config.MaxFileSize * mebibyte
	maxFiles := handler.uploadSettings().MaxFilesPerBatch
	if maxFiles <= 0 {
		maxFiles = 10
	}
	handler.withUploadProgress(writer, request)
	request.Body = http.MaxBytesReader(writer, request.Body, maxBytes*int64(maxFiles)+int64(maxFiles)*mebibyte)
	defer func() {
		if request.MultipartForm != nil {
			_ = request.MultipartForm.RemoveAll()
		}
	}()
	if !handler.verifyAuthenticatedMutationCSRF(writer, request) {
		return
	}
	if !handler.uploadAllowed(writer, request) {
		return
	}
	captchaOK := handler.verifyCaptcha(writer, request, "upload", "")
	if !captchaOK {
		return
	}
	handler.cleanupExpiredUploads(request)
	fileObject, header, err := request.FormFile("file")
	if err != nil {
		var limitError *http.MaxBytesError
		if errors.As(err, &limitError) {
			http.Error(writer, "The upload exceeds the configured size limit.", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(writer, "A file is required and must be within the configured size limit.", http.StatusBadRequest)
		return
	}
	if _, ok := uploadShareMode(request.FormValue("share_mode")); !ok {
		_ = fileObject.Close()
		http.Error(writer, "Invalid upload access option.", http.StatusBadRequest)
		return
	}
	headers := request.MultipartForm.File["file"]
	if len(headers) > maxFiles {
		_ = fileObject.Close()
		http.Error(writer, fmt.Sprintf("Choose no more than %d files per upload.", maxFiles), http.StatusRequestEntityTooLarge)
		return
	}
	metadata := request.MultipartForm.Value["client_encryption"]
	if len(metadata) != 0 && len(metadata) != len(headers) {
		_ = fileObject.Close()
		http.Error(writer, "Encryption metadata must match every file.", http.StatusBadRequest)
		return
	}
	for index, item := range headers {
		raw := ""
		if len(metadata) != 0 {
			raw = metadata[index]
		}
		if err := handler.validateClientEncryption(request, raw, item.Size); err != nil {
			_ = fileObject.Close()
			if errors.Is(err, errInvalidUpload) {
				http.Error(writer, err.Error(), http.StatusBadRequest)
			} else {
				handler.internalError(writer, request, "validate client encryption", err)
			}
			return
		}
	}
	if len(headers) > 1 {
		_ = fileObject.Close()
		handler.uploadMultiple(writer, request, headers, maxBytes)
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
	token, tokenHash, err := newOwnerToken()
	if err != nil {
		handler.internalError(writer, request, "create owner token", err)
		return
	}
	fileID := uuid.NewString()
	now := time.Now().UTC()
	expiresAt := now.Add(handler.proxiedUploadReservationLifetime())
	record := &db.FileList{
		AnonymousSessionToken: tokenHash, FileID: fileID, FileName: fileName, FileSize: header.Size,
		ContentType: contentType, IsAnonymousUpload: true, IsEncrypted: handler.cipher != nil,
		StorageService: handler.config.StorageService, UploadStatus: "pending", ChecksumStatus: "pending",
		UploadExpiresAt: &expiresAt, CreatedAt: now, UpdatedAt: now,
	}
	if identity := currentIdentity(request); identity != nil {
		record.FileOwner = &identity.User.ID
		record.IsAnonymousUpload = false
	}
	if handler.cipher != nil {
		record.EncryptionMethod = "aes-256-gcm"
	}
	record.ClientEncryption = multipartClientEncryption(request, header)
	if record.ClientEncryption != "" {
		contentType = "application/octet-stream"
		record.ContentType = contentType
	}
	record.ShareMode, _ = uploadShareMode(request.FormValue("share_mode"))
	if !handler.reserveUpload(writer, request, record) {
		return
	}
	reservationActive := true
	objectMayExist := false
	defer func() {
		if reservationActive {
			handler.discardUpload(request, fileID, objectMayExist)
		}
	}()

	sha256Hasher, sha3Hasher := sha256.New(), sha3.New256()
	counter := &byteCounter{}
	reader := io.TeeReader(fileObject, io.MultiWriter(sha256Hasher, sha3Hasher, counter))
	storedSize := header.Size
	if handler.cipher != nil {
		ciphertext, encryptErr := handler.encryptUpload(reader, fileID, header.Size, maxBytes)
		switch {
		case errors.Is(encryptErr, errCipherBusy):
			http.Error(writer, "Encryption capacity is busy; retry shortly.", http.StatusServiceUnavailable)
			return
		case errors.Is(encryptErr, errIncompleteUpload):
			http.Error(writer, "Unable to read the complete uploaded file.", http.StatusBadRequest)
			return
		case encryptErr != nil:
			handler.internalError(writer, request, "encrypt file", encryptErr)
			return
		}
		storedSize = int64(len(ciphertext))
		reader = bytes.NewReader(ciphertext)
	}
	objectMayExist = true
	if err := handler.storage.Put(request.Context(), fileID, reader, storedSize, contentType); err != nil {
		handler.internalError(writer, request, "store file", err)
		return
	}
	if counter.total != header.Size {
		handler.internalError(writer, request, "store complete file", fmt.Errorf("stored %d of %d plaintext bytes", counter.total, header.Size))
		return
	}
	if err := handler.repository.FinalizeUpload(request.Context(), fileID,
		hex.EncodeToString(sha256Hasher.Sum(nil)), hex.EncodeToString(sha3Hasher.Sum(nil)),
		handler.cipher != nil, record.EncryptionMethod); err != nil {
		handler.internalError(writer, request, "finalize file record", err)
		return
	}
	reservationActive = false
	if record.FileOwner == nil {
		http.SetCookie(writer, ownerCookie(fileID, token, handler.config.SecureCookies, 30*24*time.Hour))
	}
	handler.redirect(writer, request, "/file/"+fileID)
}

type uploadedFileResult struct{ ID, Name string }

func (handler *Handler) uploadMultiple(writer http.ResponseWriter, request *http.Request, headers []*multipart.FileHeader, maxBytes int64) {
	results := make([]uploadedFileResult, 0, len(headers))
	tokens := make([]string, 0, len(headers))
	for _, header := range headers {
		result, token, err := handler.storeProxiedHeader(request, header, maxBytes)
		if err != nil {
			for _, completed := range results {
				handler.discardUpload(request, completed.ID, true)
			}
			var quotaError *db.UploadQuotaError
			if errors.As(err, &quotaError) && quotaError.Scope == db.GuestUploadScope {
				handler.writeUploadError(writer, request, "store upload batch", err)
			} else if errors.As(err, &quotaError) {
				http.Error(writer, "This upload batch would exceed your account storage quota.", http.StatusRequestEntityTooLarge)
			} else if errors.Is(err, errInvalidUpload) {
				http.Error(writer, err.Error(), http.StatusBadRequest)
			} else {
				handler.internalError(writer, request, "store upload batch", err)
			}
			return
		}
		results, tokens = append(results, result), append(tokens, token)
	}
	ids := make([]string, 0, len(results))
	for index, result := range results {
		if currentIdentity(request) == nil {
			http.SetCookie(writer, ownerCookie(result.ID, tokens[index], handler.config.SecureCookies, 30*24*time.Hour))
		}
		ids = append(ids, result.ID)
	}
	handler.redirect(writer, request, "/uploads/complete?ids="+strings.Join(ids, ","))
}

var errInvalidUpload = errors.New("invalid upload")

func (handler *Handler) storeProxiedHeader(request *http.Request, header *multipart.FileHeader, maxBytes int64) (uploadedFileResult, string, error) {
	if header.Size <= 0 || header.Size > maxBytes {
		return uploadedFileResult{}, "", fmt.Errorf("%w: every file must be between 1 byte and %s", errInvalidUpload, humanSize(maxBytes))
	}
	fileObject, err := header.Open()
	if err != nil {
		return uploadedFileResult{}, "", fmt.Errorf("open uploaded file: %w", err)
	}
	defer fileObject.Close()
	fileName, err := safeFileName(header.Filename)
	if err != nil {
		return uploadedFileResult{}, "", fmt.Errorf("%w: %s", errInvalidUpload, err)
	}
	contentType, err := sniffContentType(fileObject)
	if err != nil {
		return uploadedFileResult{}, "", fmt.Errorf("%w: unable to read %s", errInvalidUpload, fileName)
	}
	token, tokenHash, err := newOwnerToken()
	if err != nil {
		return uploadedFileResult{}, "", err
	}
	fileID, now := uuid.NewString(), time.Now().UTC()
	expiresAt := now.Add(handler.proxiedUploadReservationLifetime())
	record := &db.FileList{AnonymousSessionToken: tokenHash, FileID: fileID, FileName: fileName, FileSize: header.Size,
		ContentType: contentType, IsAnonymousUpload: true, IsEncrypted: handler.cipher != nil, StorageService: handler.config.StorageService,
		UploadStatus: "pending", ChecksumStatus: "pending", UploadExpiresAt: &expiresAt, CreatedAt: now, UpdatedAt: now}
	if identity := currentIdentity(request); identity != nil {
		record.FileOwner = &identity.User.ID
		record.IsAnonymousUpload = false
	}
	if handler.cipher != nil {
		record.EncryptionMethod = "aes-256-gcm"
	}
	record.ClientEncryption = multipartClientEncryption(request, header)
	if record.ClientEncryption != "" {
		contentType = "application/octet-stream"
		record.ContentType = contentType
	}
	record.ShareMode, _ = uploadShareMode(request.FormValue("share_mode"))
	if err := handler.reserveRecord(request.Context(), record); err != nil {
		return uploadedFileResult{}, "", err
	}
	objectMayExist, success := false, false
	defer func() {
		if !success {
			handler.discardUpload(request, fileID, objectMayExist)
		}
	}()
	sha256Hasher, sha3Hasher, counter := sha256.New(), sha3.New256(), &byteCounter{}
	reader := io.TeeReader(fileObject, io.MultiWriter(sha256Hasher, sha3Hasher, counter))
	storedSize := header.Size
	if handler.cipher != nil {
		ciphertext, encryptErr := handler.encryptUpload(reader, fileID, header.Size, maxBytes)
		if encryptErr != nil {
			return uploadedFileResult{}, "", encryptErr
		}
		storedSize, reader = int64(len(ciphertext)), bytes.NewReader(ciphertext)
	}
	objectMayExist = true
	if err := handler.storage.Put(request.Context(), fileID, reader, storedSize, contentType); err != nil {
		return uploadedFileResult{}, "", err
	}
	if counter.total != header.Size {
		return uploadedFileResult{}, "", fmt.Errorf("stored %d of %d bytes", counter.total, header.Size)
	}
	if err := handler.repository.FinalizeUpload(request.Context(), fileID, hex.EncodeToString(sha256Hasher.Sum(nil)), hex.EncodeToString(sha3Hasher.Sum(nil)), handler.cipher != nil, record.EncryptionMethod); err != nil {
		return uploadedFileResult{}, "", err
	}
	success = true
	return uploadedFileResult{ID: fileID, Name: fileName}, token, nil
}

func (handler *Handler) UploadResults(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "private, no-store")
	parts := strings.Split(request.URL.Query().Get("ids"), ",")
	maxFiles := handler.uploadSettings().MaxFilesPerBatch
	if len(parts) < 2 || len(parts) > maxFiles {
		http.NotFound(writer, request)
		return
	}
	results := make([]uploadedFileResult, 0, len(parts))
	for _, id := range parts {
		if _, err := uuid.Parse(id); err != nil {
			http.NotFound(writer, request)
			return
		}
		file, err := handler.repository.Get(request.Context(), id)
		if err != nil || !handler.canReadFile(request, file) {
			http.NotFound(writer, request)
			return
		}
		results = append(results, uploadedFileResult{ID: file.FileID, Name: file.FileName})
	}
	handler.render(writer, "upload_results.html", struct {
		Version, CSRF string
		User          *db.User
		Files         []uploadedFileResult
	}{config.GetVersion(), identityCSRF(request), identityUser(request), results})
}

func (handler *Handler) uploadAllowed(writer http.ResponseWriter, request *http.Request) bool {
	if user := identityUser(request); user != nil && user.EmailVerifiedAt == nil && handler.verificationSettings().RequireForUploads {
		http.Error(writer, "Verify your email from My account before uploading files.", http.StatusForbidden)
		return false
	}
	if currentIdentity(request) == nil && !handler.uploadSettings().GuestEnabled {
		http.Error(writer, "Guest uploads are disabled. Log in before uploading.", http.StatusForbidden)
		return false
	}
	return true
}

// reserveRecord reserves file's quota. Guest reservations also count against the
// global cap on unfinished guest uploads when the repository supports it.
func (handler *Handler) reserveRecord(ctx context.Context, file *db.FileList) error {
	if file.FileOwner == nil {
		if limiter, ok := handler.repository.(db.GuestUploadLimiter); ok {
			return limiter.ReserveGuestUpload(ctx, file, handler.uploadSettings().MaxPendingGuestMiB*mebibyte)
		}
	}
	return handler.repository.ReserveUpload(ctx, file)
}

var (
	errCipherBusy       = errors.New("encryption capacity is busy")
	errIncompleteUpload = errors.New("unable to read the complete uploaded file")
)

// encryptUpload reads the complete upload and encrypts it while holding the
// cipher slot, and releases the slot before returning. The caller then writes
// the ciphertext to object storage without blocking other encrypted transfers
// behind a slow storage or client connection.
func (handler *Handler) encryptUpload(reader io.Reader, fileID string, size, maxBytes int64) ([]byte, error) {
	if !handler.acquireCipherSlot() {
		return nil, errCipherBusy
	}
	defer handler.releaseCipherSlot()
	plaintext, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil || int64(len(plaintext)) != size || int64(len(plaintext)) > maxBytes {
		return nil, errIncompleteUpload
	}
	return handler.cipher.EncryptFor(fileID, plaintext)
}

func (handler *Handler) reserveUpload(writer http.ResponseWriter, request *http.Request, file *db.FileList) bool {
	err := handler.reserveRecord(request.Context(), file)
	if err == nil {
		return true
	}
	handler.writeUploadError(writer, request, "reserve upload quota", err)
	return false
}

func (handler *Handler) proxiedUploadReservationLifetime() time.Duration {
	lifetime := handler.config.WriteTimeout.Duration() + 5*time.Minute
	if lifetime < 15*time.Minute {
		return 15 * time.Minute
	}
	return lifetime
}

func (handler *Handler) discardUpload(request *http.Request, fileID string, deleteObject bool) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(request.Context()), 5*time.Second)
	defer cancel()
	if deleteObject {
		if err := handler.storage.Delete(ctx, fileID); err != nil {
			handler.logger.Warn("discard failed upload object", "file_id", fileID, "error", err)
			return
		}
	}
	if err := handler.repository.Delete(ctx, fileID); err != nil && !errors.Is(err, db.ErrNotFound) {
		handler.logger.Warn("discard failed upload reservation", "file_id", fileID, "error", err)
	}
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
