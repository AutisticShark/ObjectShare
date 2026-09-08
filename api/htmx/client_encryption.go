package htmx

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"time"

	"github.com/AutisticShark/ObjectShare/db"
)

const clientChunkSize = int64(1024 * 1024)

func multipartClientEncryption(request *http.Request, header *multipart.FileHeader) string {
	values := request.MultipartForm.Value["client_encryption"]
	for i, item := range request.MultipartForm.File["file"] {
		if item == header && i < len(values) {
			return values[i]
		}
	}
	return ""
}

type clientEncryptionMetadata struct {
	Version int    `json:"version"`
	KeyID   string `json:"key_id"`
	Salt    string `json:"salt"`
	Size    int64  `json:"size"`
}

func encodedBytes(value string, size int) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == size && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func (handler *Handler) ClientEncryptionScript(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	http.ServeContent(writer, request, "client-encryption.js", time.Time{}, bytes.NewReader(handler.clientEncryptionJS))
}

func (handler *Handler) ClientKey(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "private, no-store")
	identity := currentIdentity(request)
	if identity == nil {
		http.Error(writer, "Log in to manage your encryption key.", http.StatusUnauthorized)
		return
	}
	repo, ok := handler.repository.(db.ClientKeyRepository)
	if !ok {
		http.Error(writer, "Client key storage is unavailable.", http.StatusServiceUnavailable)
		return
	}
	if request.Method == http.MethodGet {
		vault, err := repo.ClientKey(request.Context(), identity.User.ID)
		if errors.Is(err, db.ErrNotFound) {
			writeJSON(writer, http.StatusOK, map[string]any{"user_id": identity.User.ID, "vault": nil})
			return
		}
		if err != nil {
			handler.internalError(writer, request, "read client key", err)
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"user_id": identity.User.ID, "vault": vault})
		return
	}
	if !handler.verifyJWTCSRF(writer, request, identity) {
		return
	}
	var vault db.ClientKeyVault
	if err := decodeJSON(writer, request, &vault); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	if vault.UserID != identity.User.ID || vault.Version != 1 || !encodedBytes(vault.KeyID, 32) || !encodedBytes(vault.Salt, 16) || !encodedBytes(vault.IV, 12) || !encodedBytes(vault.WrappedKey, 48) {
		http.Error(writer, "Invalid encrypted account key.", http.StatusBadRequest)
		return
	}
	if err := repo.CreateClientKey(request.Context(), &vault); err != nil {
		if errors.Is(err, db.ErrConflict) {
			http.Error(writer, "An encryption key already exists. Unlock that key instead.", http.StatusConflict)
			return
		}
		handler.internalError(writer, request, "create client key", err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]bool{"created": true})
}

func (handler *Handler) validateClientEncryption(request *http.Request, raw string, storedSize int64) error {
	identity := currentIdentity(request)
	var vault *db.ClientKeyVault
	if identity != nil {
		if repo, ok := handler.repository.(db.ClientKeyRepository); ok {
			var err error
			vault, err = repo.ClientKey(request.Context(), identity.User.ID)
			if err != nil && !errors.Is(err, db.ErrNotFound) {
				return err
			}
		}
	}
	if raw == "" {
		if vault != nil {
			return fmt.Errorf("%w: this account requires client-encrypted uploads", errInvalidUpload)
		}
		return nil
	}
	if identity == nil || vault == nil {
		return fmt.Errorf("%w: set up your account encryption key first", errInvalidUpload)
	}
	var metadata clientEncryptionMetadata
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&metadata)
	var extra any
	if len(raw) > 512 || err != nil || decoder.Decode(&extra) != io.EOF || metadata.Version != 1 || metadata.KeyID != vault.KeyID || !encodedBytes(metadata.Salt, 32) || metadata.Size < 0 || metadata.Size > handler.config.MaxFileSize*mebibyte {
		return fmt.Errorf("%w: invalid client encryption metadata", errInvalidUpload)
	}
	chunks := (metadata.Size + clientChunkSize - 1) / clientChunkSize
	if chunks == 0 {
		chunks = 1
	}
	if storedSize != metadata.Size+chunks*16 {
		return fmt.Errorf("%w: encrypted file size does not match metadata", errInvalidUpload)
	}
	return nil
}
