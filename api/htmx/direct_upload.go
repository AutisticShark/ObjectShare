package htmx

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/AutisticShark/ObjectShare/db"
	"github.com/google/uuid"
)

const directRequestLimit = 8 * 1024

type directUploadRequest struct {
	FileName     string `json:"file_name"`
	FileSize     int64  `json:"file_size"`
	ContentType  string `json:"content_type"`
	CaptchaToken string `json:"captcha_token,omitempty"`
}

type directUploadToken struct {
	Token string `json:"token"`
}

func (handler *Handler) BeginDirectUpload(writer http.ResponseWriter, request *http.Request) {
	if handler.direct == nil {
		http.Error(writer, "Direct uploads are unavailable for this storage or encryption mode.", http.StatusNotFound)
		return
	}
	if !handler.allowRequest(writer, request, "upload", handler.rateLimitSettings().UploadLimit) {
		return
	}
	if !handler.verifyAuthenticatedMutationCSRF(writer, request) {
		return
	}
	if !handler.uploadAllowed(writer, request) {
		return
	}

	var input directUploadRequest
	if err := decodeJSON(writer, request, &input); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	if !handler.verifyCaptcha(writer, request, "upload", input.CaptchaToken) {
		return
	}
	handler.cleanupExpiredUploads(request)
	fileName, err := safeFileName(input.FileName)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	maxBytes := handler.config.MaxFileSize * mebibyte
	if maxBytes > handler.directPolicy.MaxSize {
		maxBytes = handler.directPolicy.MaxSize
	}
	if input.FileSize <= 0 || input.FileSize > maxBytes {
		http.Error(writer, fmt.Sprintf("File size must be between 1 byte and %s.", humanSize(maxBytes)), http.StatusRequestEntityTooLarge)
		return
	}
	contentType := strings.TrimSpace(input.ContentType)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	if _, _, err := mime.ParseMediaType(contentType); err != nil || len(contentType) > 255 {
		http.Error(writer, "Invalid content type.", http.StatusBadRequest)
		return
	}

	token, tokenHash, err := newOwnerToken()
	if err != nil {
		handler.internalError(writer, request, "create direct-upload token", err)
		return
	}
	fileID := uuid.NewString()
	now := time.Now().UTC()
	expiresAt := now.Add(handler.directPolicy.Expires)
	record := &db.FileList{
		AnonymousSessionToken: tokenHash, FileID: fileID, FileName: fileName, FileSize: input.FileSize,
		ContentType: contentType, IsAnonymousUpload: true, StorageService: handler.config.StorageService,
		UploadStatus: "pending", ChecksumStatus: "unavailable", UploadExpiresAt: &expiresAt,
		CreatedAt: now, UpdatedAt: now,
	}
	if identity := currentIdentity(request); identity != nil {
		record.FileOwner = &identity.User.ID
		record.IsAnonymousUpload = false
	}
	if !handler.reserveUpload(writer, request, record) {
		return
	}
	uploadURL, err := handler.direct.PresignPut(request.Context(), fileID, input.FileSize, contentType)
	if err != nil {
		handler.discardUpload(request, fileID, false)
		handler.internalError(writer, request, "presign direct upload", err)
		return
	}

	writeJSON(writer, http.StatusCreated, map[string]any{
		"file_id": fileID, "upload_url": uploadURL,
		"complete_url": "/api/v1/uploads/direct/" + fileID + "/complete",
		"abort_url":    "/api/v1/uploads/direct/" + fileID + "/abort",
		"token":        token, "expires_at": expiresAt.Format(time.RFC3339),
	})
}

func (handler *Handler) CompleteDirectUpload(writer http.ResponseWriter, request *http.Request) {
	if !handler.verifyAuthenticatedMutationCSRF(writer, request) {
		return
	}
	file, token, ok := handler.directUploadIntent(writer, request)
	if !ok {
		return
	}
	info, err := handler.direct.Stat(request.Context(), file.FileID)
	if err != nil {
		handler.logger.Warn("direct upload is not available yet", "file_id", file.FileID, "error", err)
		http.Error(writer, "The uploaded object is not available yet.", http.StatusConflict)
		return
	}
	if info.Size != file.FileSize || !strings.EqualFold(info.ContentType, file.ContentType) {
		handler.discardUpload(request, file.FileID, true)
		http.Error(writer, "The uploaded object does not match the authorized upload.", http.StatusUnprocessableEntity)
		return
	}
	if err := handler.repository.CompleteUpload(request.Context(), file.FileID); err != nil {
		handler.internalError(writer, request, "complete direct upload", err)
		return
	}
	http.SetCookie(writer, ownerCookie(file.FileID, token, handler.config.SecureCookies, 30*24*time.Hour))
	writeJSON(writer, http.StatusOK, map[string]string{"location": "/file/" + file.FileID})
}

func (handler *Handler) AbortDirectUpload(writer http.ResponseWriter, request *http.Request) {
	if !handler.verifyAuthenticatedMutationCSRF(writer, request) {
		return
	}
	file, _, ok := handler.directUploadIntent(writer, request)
	if !ok {
		return
	}
	if err := handler.storage.Delete(request.Context(), file.FileID); err != nil {
		handler.internalError(writer, request, "abort direct-upload object", err)
		return
	}
	if err := handler.repository.Delete(request.Context(), file.FileID); err != nil && !errors.Is(err, db.ErrNotFound) {
		handler.internalError(writer, request, "abort direct-upload intent", err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (handler *Handler) directUploadIntent(writer http.ResponseWriter, request *http.Request) (*db.FileList, string, bool) {
	if handler.direct == nil {
		http.NotFound(writer, request)
		return nil, "", false
	}
	fileID, ok := validFileID(request)
	if !ok {
		http.NotFound(writer, request)
		return nil, "", false
	}
	var input directUploadToken
	if err := decodeJSON(writer, request, &input); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return nil, "", false
	}
	file, err := handler.repository.Get(request.Context(), fileID)
	if errors.Is(err, db.ErrNotFound) || (err == nil && file.UploadStatus != "pending") {
		http.NotFound(writer, request)
		return nil, "", false
	}
	if err != nil {
		handler.internalError(writer, request, "get direct-upload intent", err)
		return nil, "", false
	}
	if !ownerTokenMatches(file, input.Token) {
		http.Error(writer, "Forbidden", http.StatusForbidden)
		return nil, "", false
	}
	if file.UploadExpiresAt == nil || time.Now().UTC().After(*file.UploadExpiresAt) {
		_ = handler.storage.Delete(request.Context(), fileID)
		_ = handler.repository.Delete(request.Context(), fileID)
		http.Error(writer, "The upload authorization has expired.", http.StatusGone)
		return nil, "", false
	}
	return file, input.Token, true
}

func (handler *Handler) cleanupExpiredUploads(request *http.Request) {
	files, err := handler.repository.ExpiredUploads(request.Context(), time.Now().UTC(), 25)
	if err != nil {
		handler.logger.Warn("list expired direct uploads", "error", err)
		return
	}
	for _, file := range files {
		if err := handler.storage.Delete(request.Context(), file.FileID); err != nil {
			handler.logger.Warn("delete expired direct upload", "file_id", file.FileID, "error", err)
			continue
		}
		if err := handler.repository.Delete(request.Context(), file.FileID); err != nil && !errors.Is(err, db.ErrNotFound) {
			handler.logger.Warn("delete expired direct-upload intent", "file_id", file.FileID, "error", err)
		}
	}
}

func decodeJSON(writer http.ResponseWriter, request *http.Request, target any) error {
	request.Body = http.MaxBytesReader(writer, request.Body, directRequestLimit)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("Invalid JSON request.")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("Unexpected trailing JSON data.")
	}
	return nil
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
