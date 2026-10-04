package htmx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/AutisticShark/ObjectShare/db"
	"github.com/AutisticShark/ObjectShare/service"
	"github.com/google/uuid"
)

const directRequestLimit = 64 * 1024

type directUploadRequest struct {
	ClientEncryption string `json:"client_encryption,omitempty"`
	ShareMode        string `json:"share_mode,omitempty"`
	FileName         string `json:"file_name"`
	FileSize         int64  `json:"file_size"`
	ContentType      string `json:"content_type"`
	CaptchaToken     string `json:"captcha_token,omitempty"`
}

type directUploadToken struct {
	Token string `json:"token"`
}

type directUploadBatchRequest struct {
	Files        []directUploadRequest `json:"files"`
	CaptchaToken string                `json:"captcha_token,omitempty"`
}

type directUploadAuthorization struct {
	FileID      string `json:"file_id"`
	FileName    string `json:"file_name"`
	UploadURL   string `json:"upload_url"`
	CompleteURL string `json:"complete_url"`
	AbortURL    string `json:"abort_url"`
	RenewURL    string `json:"renew_url"`
	Token       string `json:"token"`
	ExpiresAt   string `json:"expires_at"`
}

func (handler *Handler) BeginDirectUploadBatch(writer http.ResponseWriter, request *http.Request) {
	if handler.direct == nil {
		http.Error(writer, "Direct uploads are unavailable for this storage or encryption mode.", http.StatusNotFound)
		return
	}
	if !handler.allowRequest(writer, request, "upload", handler.rateLimitSettings().UploadLimit) || !handler.verifyAuthenticatedMutationCSRF(writer, request) || !handler.uploadAllowed(writer, request) {
		return
	}
	var input directUploadBatchRequest
	if err := decodeJSON(writer, request, &input); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	maxFiles := handler.uploadSettings().MaxFilesPerBatch
	if len(input.Files) < 1 || len(input.Files) > maxFiles {
		http.Error(writer, fmt.Sprintf("Choose between 1 and %d files.", maxFiles), http.StatusBadRequest)
		return
	}
	if !handler.verifyCaptcha(writer, request, "upload", input.CaptchaToken) {
		return
	}
	handler.cleanupExpiredUploads(request)
	authorizations := make([]directUploadAuthorization, 0, len(input.Files))
	rollback := func() {
		for _, item := range authorizations {
			handler.discardUpload(request, item.FileID, false)
		}
	}
	for _, file := range input.Files {
		authorization, err := handler.reserveDirectUpload(request, file)
		if err != nil {
			rollback()
			handler.writeUploadError(writer, request, "authorize direct upload batch", err)
			return
		}
		authorizations = append(authorizations, authorization)
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"uploads": authorizations})
}

// uploadRejection is a client-visible refusal from authorizeDirectUpload with
// the HTTP status that both the single and batch endpoints report for it.
type uploadRejection struct {
	status  int
	message string
}

func (rejection *uploadRejection) Error() string { return rejection.message }

// reserveDirectUpload authorizes one file, reserves its quota, and presigns the
// upload URL. On failure the reservation it made (if any) has been discarded.
func (handler *Handler) reserveDirectUpload(request *http.Request, input directUploadRequest) (directUploadAuthorization, error) {
	authorization, record, err := handler.authorizeDirectUpload(request, input)
	if err != nil {
		return directUploadAuthorization{}, err
	}
	if err := handler.reserveRecord(request.Context(), record); err != nil {
		return directUploadAuthorization{}, err
	}
	uploadURL, err := handler.direct.PresignPut(request.Context(), service.PendingUploadKey(record.FileID), record.FileSize, record.ContentType)
	if err != nil {
		handler.discardUpload(request, record.FileID, false)
		return directUploadAuthorization{}, fmt.Errorf("presign direct upload: %w", err)
	}
	authorization.UploadURL = uploadURL
	return authorization, nil
}

// writeUploadError maps reserveDirectUpload failures onto one set of
// status codes and messages shared by the single and batch endpoints.
func (handler *Handler) writeUploadError(writer http.ResponseWriter, request *http.Request, operation string, err error) {
	var rejection *uploadRejection
	var quotaError *db.UploadQuotaError
	switch {
	case errors.As(err, &rejection):
		http.Error(writer, rejection.message, rejection.status)
	case errors.As(err, &quotaError) && quotaError.Scope == db.GuestUploadScope:
		writer.Header().Set("X-Upload-Quota-Scope", quotaError.Scope)
		writer.Header().Set("Retry-After", "60")
		http.Error(writer, "Guest uploads are busy right now. Try again in a minute, or sign in to upload.", http.StatusTooManyRequests)
	case errors.As(err, &quotaError):
		writer.Header().Set("X-Upload-Quota-Scope", quotaError.Scope)
		http.Error(writer, "This upload would exceed your account storage quota.", http.StatusRequestEntityTooLarge)
	case errors.Is(err, errInvalidUpload):
		http.Error(writer, err.Error(), http.StatusBadRequest)
	default:
		handler.internalError(writer, request, operation, err)
	}
}

func (handler *Handler) authorizeDirectUpload(request *http.Request, input directUploadRequest) (directUploadAuthorization, *db.FileList, error) {
	mode, ok := uploadShareMode(input.ShareMode)
	if !ok {
		return directUploadAuthorization{}, nil, &uploadRejection{http.StatusBadRequest, "Invalid upload access option."}
	}
	if err := handler.validateClientEncryption(request, input.ClientEncryption, input.FileSize); err != nil {
		return directUploadAuthorization{}, nil, err
	}
	if input.ClientEncryption != "" {
		input.ContentType = "application/octet-stream"
	}
	fileName, err := safeFileName(input.FileName)
	if err != nil {
		return directUploadAuthorization{}, nil, &uploadRejection{http.StatusBadRequest, err.Error()}
	}
	maxBytes := handler.config.MaxFileSize * mebibyte
	if maxBytes > handler.directPolicy.MaxSize {
		maxBytes = handler.directPolicy.MaxSize
	}
	if input.FileSize <= 0 {
		return directUploadAuthorization{}, nil, &uploadRejection{http.StatusBadRequest, emptyUploadMessage}
	}
	if input.FileSize > maxBytes {
		return directUploadAuthorization{}, nil, &uploadRejection{http.StatusRequestEntityTooLarge, fmt.Sprintf("File size must be between 1 byte and %s.", humanSize(maxBytes))}
	}
	contentType := strings.TrimSpace(input.ContentType)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	if _, _, err := mime.ParseMediaType(contentType); err != nil || len(contentType) > 255 {
		return directUploadAuthorization{}, nil, &uploadRejection{http.StatusBadRequest, "Invalid content type."}
	}
	token, tokenHash, err := newOwnerToken()
	if err != nil {
		return directUploadAuthorization{}, nil, err
	}
	fileID, now := uuid.NewString(), time.Now().UTC()
	expiresAt := now.Add(handler.directPolicy.Expires)
	reservedUntil := now.Add(handler.directUploadReservation())
	record := &db.FileList{ClientEncryption: input.ClientEncryption, ShareMode: mode, AnonymousSessionToken: tokenHash, FileID: fileID, FileName: fileName, FileSize: input.FileSize,
		ContentType: contentType, IsAnonymousUpload: true, StorageService: handler.config.StorageService,
		UploadStatus: "pending", ChecksumStatus: "unavailable", UploadExpiresAt: &reservedUntil, CreatedAt: now, UpdatedAt: now}
	if identity := currentIdentity(request); identity != nil {
		record.FileOwner = &identity.User.ID
		record.IsAnonymousUpload = false
	}
	authorization := directUploadAuthorization{FileID: fileID, FileName: fileName, CompleteURL: "/api/v1/uploads/direct/" + fileID + "/complete",
		AbortURL: "/api/v1/uploads/direct/" + fileID + "/abort", RenewURL: "/api/v1/uploads/direct/" + fileID + "/renew", Token: token, ExpiresAt: expiresAt.Format(time.RFC3339)}
	return authorization, record, nil
}

func (handler *Handler) BeginDirectUpload(writer http.ResponseWriter, request *http.Request) {
	if handler.direct == nil {
		http.Error(writer, "Direct uploads are unavailable for this storage or encryption mode.", http.StatusNotFound)
		return
	}
	if !handler.allowRequest(writer, request, "upload", handler.rateLimitSettings().UploadLimit) || !handler.verifyAuthenticatedMutationCSRF(writer, request) || !handler.uploadAllowed(writer, request) {
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
	authorization, err := handler.reserveDirectUpload(request, input)
	if err != nil {
		handler.writeUploadError(writer, request, "begin direct upload", err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{
		"file_id": authorization.FileID, "upload_url": authorization.UploadURL,
		"complete_url": authorization.CompleteURL, "abort_url": authorization.AbortURL, "renew_url": authorization.RenewURL,
		"token": authorization.Token, "expires_at": authorization.ExpiresAt,
	})
}

// directUploadReservation is how long a pending direct upload is kept after its
// upload URL is issued: the URL's lifetime plus an equal completion grace. Object
// storage accepts a PUT that starts before the URL expires, so a large file can
// still be arriving when the URL itself has expired; its completion must not be
// refused, or the reservation swept, while that PUT finishes.
func (handler *Handler) directUploadReservation() time.Duration {
	return 2 * handler.directPolicy.Expires
}

// RenewDirectUpload presigns a fresh upload URL for a pending direct upload just
// before the client starts its PUT. A batch is authorized at once but uploaded
// one file at a time, so a URL issued with the batch can expire before a later
// file's turn. The new URL has the same short lifetime, staging key, size and
// content type as the original authorization and needs the same owner token;
// the reservation is extended to cover it, up to a cap that keeps renewal from
// holding a reservation open indefinitely.
func (handler *Handler) RenewDirectUpload(writer http.ResponseWriter, request *http.Request) {
	if !handler.verifyAuthenticatedMutationCSRF(writer, request) {
		return
	}
	file, _, ok := handler.directUploadIntent(writer, request)
	if !ok {
		return
	}
	if file.UploadStatus != "pending" {
		http.Error(writer, "The upload is already being finalized.", http.StatusConflict)
		return
	}
	if !handler.directUploadVerificationAllowed(writer, request, file) {
		return
	}
	now := time.Now().UTC()
	reservedUntil := now.Add(handler.directUploadReservation())
	if limit := file.CreatedAt.Add(time.Duration(handler.uploadSettings().MaxFilesPerBatch) * handler.directUploadReservation()); reservedUntil.After(limit) {
		reservedUntil = limit
	}
	if !reservedUntil.After(now.Add(handler.directPolicy.Expires)) {
		http.Error(writer, "This upload authorization cannot be renewed again. Start a new upload.", http.StatusGone)
		return
	}
	if err := handler.repository.ExtendUploadReservation(request.Context(), file.FileID, reservedUntil); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			http.Error(writer, "The upload authorization has expired.", http.StatusGone)
			return
		}
		handler.internalError(writer, request, "extend direct upload reservation", err)
		return
	}
	uploadURL, err := handler.direct.PresignPut(request.Context(), service.PendingUploadKey(file.FileID), file.FileSize, file.ContentType)
	if err != nil {
		handler.internalError(writer, request, "renew direct upload", err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"upload_url": uploadURL, "expires_at": now.Add(handler.directPolicy.Expires).Format(time.RFC3339)})
}

func (handler *Handler) CompleteDirectUpload(writer http.ResponseWriter, request *http.Request) {
	if !handler.verifyAuthenticatedMutationCSRF(writer, request) {
		return
	}
	file, token, ok := handler.directUploadIntentState(writer, request, true)
	if !ok {
		return
	}
	if !handler.directUploadVerificationAllowed(writer, request, file) {
		return
	}
	// A response can be lost after the database commit. The owner may retrieve
	// completion again, including the guest owner cookie. Never
	// re-upload, revalidate storage, or mutate a completed record on this path.
	if file.UploadStatus == "complete" {
		if file.FileOwner == nil {
			http.SetCookie(writer, ownerCookie(file.FileID, token, handler.config.SecureCookies, 30*24*time.Hour))
		}
		writeJSON(writer, http.StatusOK, map[string]string{"location": "/file/" + file.FileID})
		return
	}
	// The presigned URL targets a staging key, so a repeated PUT after this
	// point can never replace the finished file. Uploads authorised before that
	// change were presigned for the final key; accept those when nothing is staged.
	pendingKey := service.PendingUploadKey(file.FileID)
	staged := true
	info, err := handler.direct.Stat(request.Context(), pendingKey)
	if err != nil {
		staged = false
		info, err = handler.direct.Stat(request.Context(), file.FileID)
	}
	if err != nil {
		handler.logger.Warn("direct upload is not available yet", "file_id", file.FileID, "error", err)
		http.Error(writer, "The uploaded object is not available yet.", http.StatusConflict)
		return
	}
	if info.Size != file.FileSize || !sameMediaType(info.ContentType, file.ContentType) {
		if err := handler.deletePendingUpload(request.Context(), file.FileID); err != nil && !errors.Is(err, db.ErrNotFound) {
			handler.logger.Warn("discard mismatched direct upload", "file_id", file.FileID, "error", err)
		}
		http.Error(writer, "The uploaded object does not match the authorized upload.", http.StatusUnprocessableEntity)
		return
	}
	if staged {
		// Claim the record before the copy creates the final object. Abort and
		// expiry cleanup refuse a publishing record, so they cannot remove it
		// mid-copy and leave a final object that no record references or counts.
		if err := handler.repository.ClaimUploadPublication(request.Context(), file.FileID); err != nil {
			if errors.Is(err, db.ErrNotFound) {
				http.Error(writer, "The upload is being finalized or has changed. Retry completion to check its status.", http.StatusConflict)
				return
			}
			handler.internalError(writer, request, "claim direct upload publication", err)
			return
		}
		if err := handler.publishStagedUpload(request.Context(), file, pendingKey); err != nil {
			handler.logger.Warn("publish staged direct upload", "file_id", file.FileID, "error", err)
			if err := handler.repository.ReleaseUploadPublication(context.WithoutCancel(request.Context()), file.FileID); err != nil && !errors.Is(err, db.ErrNotFound) {
				handler.logger.Warn("release direct upload publication", "file_id", file.FileID, "error", err)
			}
			http.Error(writer, "The uploaded object could not be finalized yet. Retry completion.", http.StatusConflict)
			return
		}
	}
	if err := handler.repository.CompleteUpload(request.Context(), file.FileID); err != nil {
		if staged {
			handler.removeUnreferencedPublication(request, file.FileID)
		}
		if errors.Is(err, db.ErrNotFound) {
			http.Error(writer, "The upload state changed. Retry completion to check its status.", http.StatusConflict)
			return
		}
		handler.internalError(writer, request, "complete direct upload", err)
		return
	}
	if file.FileOwner == nil {
		http.SetCookie(writer, ownerCookie(file.FileID, token, handler.config.SecureCookies, 30*24*time.Hour))
	}
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
	if err := handler.deletePendingUpload(request.Context(), file.FileID); err != nil {
		if errors.Is(err, db.ErrNotFound) && file.UploadStatus == "publishing" {
			http.Error(writer, "The upload is being finalized and can no longer be aborted.", http.StatusConflict)
			return
		}
		if errors.Is(err, db.ErrNotFound) {
			http.NotFound(writer, request)
			return
		}
		handler.internalError(writer, request, "abort direct upload", err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (handler *Handler) directUploadIntent(writer http.ResponseWriter, request *http.Request) (*db.FileList, string, bool) {
	return handler.directUploadIntentState(writer, request, false)
}

func (handler *Handler) directUploadIntentState(writer http.ResponseWriter, request *http.Request, allowComplete bool) (*db.FileList, string, bool) {
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
	if errors.Is(err, db.ErrNotFound) || (err == nil && file.UploadStatus != "pending" && file.UploadStatus != "publishing" && !(allowComplete && file.UploadStatus == "complete")) {
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
	moderation := handler.fileModeration(request, file)
	if moderation != db.ModerationNone && (moderation != db.ModerationShadowbanned || !signedInFileOwner(request, file)) {
		http.NotFound(writer, request)
		return nil, "", false
	}
	if file.FileOwner != nil && !signedInFileOwner(request, file) {
		http.Error(writer, "Authentication as the upload owner is required.", http.StatusForbidden)
		return nil, "", false
	}
	// A publishing upload was transferred in time; its claim, not the expiry,
	// decides whether completion may continue or cleanup may remove it.
	if file.UploadStatus == "complete" || file.UploadStatus == "publishing" {
		return file, input.Token, true
	}
	if file.UploadExpiresAt == nil || time.Now().UTC().After(*file.UploadExpiresAt) {
		if err := handler.deletePendingUpload(request.Context(), fileID); err != nil && !errors.Is(err, db.ErrNotFound) {
			handler.logger.Warn("delete expired upload authorization", "file_id", fileID, "error", err)
		}
		http.Error(writer, "The upload authorization has expired.", http.StatusGone)
		return nil, "", false
	}
	return file, input.Token, true
}

// expiredUploadCleanupInterval is the minimum gap between cleanup passes started
// by upload requests on one handler.
const expiredUploadCleanupInterval = 30 * time.Second

// cleanupExpiredUploads asks for a pass over expired upload reservations without
// making the request wait for it: object-storage deletes can be slow and the
// caller only needs its own upload to proceed. At most one pass runs at a time
// and passes are spaced by expiredUploadCleanupInterval, however many uploads
// arrive.
func (handler *Handler) cleanupExpiredUploads(request *http.Request) {
	if handler.inlineCleanup {
		handler.sweepExpiredUploads(request.Context())
		return
	}
	handler.cleanupMu.Lock()
	if handler.cleanupRunning || time.Since(handler.lastCleanup) < expiredUploadCleanupInterval {
		handler.cleanupMu.Unlock()
		return
	}
	handler.cleanupRunning, handler.lastCleanup = true, time.Now()
	handler.cleanupMu.Unlock()
	go func() {
		defer func() {
			handler.cleanupMu.Lock()
			handler.cleanupRunning = false
			handler.cleanupMu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		handler.sweepExpiredUploads(ctx)
	}()
}

// sweepExpiredUploads deletes up to 25 expired or aborting reservations, logs
// what it did and returns how many it removed.
func (handler *Handler) sweepExpiredUploads(ctx context.Context) int {
	files, err := handler.repository.ExpiredUploads(ctx, time.Now().UTC(), 25)
	if err != nil {
		handler.logger.Warn("list expired direct uploads", "error", err)
		return 0
	}
	removed := 0
	for _, file := range files {
		if err := handler.deletePendingUpload(ctx, file.FileID); err != nil {
			if !errors.Is(err, db.ErrNotFound) {
				handler.logger.Warn("delete unfinished upload", "file_id", file.FileID, "error", err)
			}
			continue
		}
		removed++
	}
	if len(files) != 0 {
		handler.logger.Info("cleaned up expired upload reservations", "found", len(files), "removed", removed)
	}
	return removed
}

// publishStagedUpload copies the verified staging object to the file's real key,
// re-checks its size there, and removes the staging copy.
func (handler *Handler) publishStagedUpload(ctx context.Context, file *db.FileList, pendingKey string) error {
	if err := handler.direct.Copy(ctx, pendingKey, file.FileID); err != nil {
		return err
	}
	published, err := handler.direct.Stat(ctx, file.FileID)
	if err != nil {
		return err
	}
	if published.Size != file.FileSize {
		_ = handler.storage.Delete(ctx, file.FileID)
		return fmt.Errorf("published object is %d bytes, authorised %d", published.Size, file.FileSize)
	}
	if err := handler.storage.Delete(ctx, pendingKey); err != nil {
		handler.logger.Warn("delete staged direct upload", "file_id", file.FileID, "error", err)
	}
	return nil
}

// removeUnreferencedPublication runs when completion fails after copying a
// staged upload to its final key. If the record is gone or being aborted (the
// publishing claim lapsed and cleanup won), that cleanup may have deleted the
// final key before the copy wrote it, so delete it again. Any other record
// still references the object and its own completion or cleanup owns it.
func (handler *Handler) removeUnreferencedPublication(request *http.Request, fileID string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(request.Context()), 5*time.Second)
	defer cancel()
	current, err := handler.repository.Get(ctx, fileID)
	if (err == nil && current.UploadStatus != "aborting") || (err != nil && !errors.Is(err, db.ErrNotFound)) {
		return
	}
	if err := handler.storage.Delete(ctx, fileID); err != nil {
		handler.logger.Warn("delete unreferenced published upload", "file_id", fileID, "error", err)
	}
}

func (handler *Handler) deletePendingUpload(ctx context.Context, fileID string) error {
	if err := handler.repository.ClaimPendingUploadDeletion(ctx, fileID); err != nil {
		return err
	}
	if err := handler.storage.Delete(ctx, fileID); err != nil {
		return err
	}
	if handler.direct != nil {
		if err := handler.storage.Delete(ctx, service.PendingUploadKey(fileID)); err != nil {
			return err
		}
	}
	if err := handler.repository.Delete(ctx, fileID); err != nil && !errors.Is(err, db.ErrNotFound) {
		return err
	}
	return nil
}

// sameMediaType compares the authorised and stored content types by media type
// only. Some S3-compatible services normalise the header they store (for
// example appending "; charset=utf-8" to text types), which must not make a
// correct upload look tampered with; size and the signed Content-Type still
// bind the object to what was authorised.
func sameMediaType(stored, authorized string) bool {
	storedType, _, storedErr := mime.ParseMediaType(stored)
	authorizedType, _, authorizedErr := mime.ParseMediaType(authorized)
	if storedErr != nil || authorizedErr != nil {
		return strings.EqualFold(strings.TrimSpace(stored), strings.TrimSpace(authorized))
	}
	return storedType == authorizedType
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
