package htmx

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

func fileShareMode(file *db.FileList) string {
	// Empty is the pre-migration representation used by older repositories.
	if file.ShareMode == "" {
		return db.ShareLink
	}
	return file.ShareMode
}

func (handler *Handler) canReadFile(request *http.Request, file *db.FileList) bool {
	if file.UploadStatus != "complete" {
		return false
	}
	if handler.isOwner(request, file) {
		return true
	}
	user := identityUser(request)
	switch fileShareMode(file) {
	case db.ShareLink:
		return true
	case db.ShareSignedIn:
		return user != nil && user.Active
	case db.ShareSelected:
		if user != nil && user.Active {
			for _, id := range file.ShareUserIDs {
				if id == user.ID {
					return true
				}
			}
		}
	}
	return false
}

func (handler *Handler) sharingFile(writer http.ResponseWriter, request *http.Request) *db.FileList {
	writer.Header().Set("Cache-Control", "private, no-store")
	fileID, ok := validFileID(request)
	if !ok {
		http.NotFound(writer, request)
		return nil
	}
	file, err := handler.repository.Get(request.Context(), fileID)
	if errors.Is(err, db.ErrNotFound) {
		http.NotFound(writer, request)
		return nil
	}
	if err != nil {
		handler.internalError(writer, request, "get sharing file", err)
		return nil
	}
	if file.UploadStatus != "complete" || !handler.isOwner(request, file) {
		http.NotFound(writer, request)
		return nil
	}
	return file
}

type sharingPageData struct {
	Version, CSRF, FileID, FileName, ShareURL, Mode, Recipients, Error, Message string
	User                                                                        *db.User
	SignupEnabled                                                               bool
}

func (handler *Handler) SharingPage(writer http.ResponseWriter, request *http.Request) {
	file := handler.sharingFile(writer, request)
	if file == nil {
		return
	}
	var recipients []string
	if handler.users != nil {
		for _, id := range file.ShareUserIDs {
			user, err := handler.users.UserByID(request.Context(), id)
			if errors.Is(err, db.ErrNotFound) {
				continue
			}
			if err != nil {
				handler.internalError(writer, request, "get sharing recipient", err)
				return
			}
			recipients = append(recipients, user.Email)
		}
	}
	message := ""
	if request.URL.Query().Get("saved") == "1" {
		message = "Sharing permissions saved."
	}
	handler.renderSharing(writer, request, file, fileShareMode(file), strings.Join(recipients, "\n"), "", message)
}

func (handler *Handler) renderSharing(writer http.ResponseWriter, request *http.Request, file *db.FileList, mode, recipients, formError, message string) {
	csrf := identityCSRF(request)
	if identityUser(request) == nil {
		csrf = guestSharingCSRF(file)
	}
	shareURL := "/file/" + file.FileID
	if handler.config.Billing != nil && handler.config.Billing.PublicURL != "" {
		shareURL = handler.config.Billing.PublicURL + shareURL
	}
	handler.render(writer, "sharing.html", sharingPageData{
		Version: config.GetVersion(), CSRF: csrf, FileID: file.FileID, FileName: file.FileName,
		ShareURL: shareURL, Mode: mode, Recipients: recipients, Error: formError, Message: message,
		User: identityUser(request), SignupEnabled: handler.config.Auth != nil && handler.config.Auth.SignupEnabled,
	})
}

func (handler *Handler) UpdateSharing(writer http.ResponseWriter, request *http.Request) {
	file := handler.sharingFile(writer, request)
	if file == nil {
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 32*1024)
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "Invalid sharing form.", http.StatusBadRequest)
		return
	}
	if identityUser(request) == nil {
		if subtle.ConstantTimeCompare([]byte(request.FormValue("csrf_token")), []byte(guestSharingCSRF(file))) != 1 {
			http.Error(writer, "Invalid CSRF token.", http.StatusForbidden)
			return
		}
	} else if !handler.verifyAuthenticatedMutationCSRF(writer, request) {
		return
	}
	mode, recipients := request.FormValue("share_mode"), request.FormValue("recipients")
	fail := func(message string) {
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		if request.Header.Get("HX-Request") != "true" {
			writer.WriteHeader(http.StatusBadRequest)
		}
		handler.renderSharing(writer, request, file, mode, recipients, message, "")
	}
	if !db.ValidShareMode(mode) {
		fail("Choose a valid access option.")
		return
	}
	userIDs := []string{}
	if mode == db.ShareSelected {
		emails := strings.FieldsFunc(recipients, func(r rune) bool { return r == ',' || r == ';' || r == '\n' || r == '\r' })
		if len(emails) == 0 || len(emails) > db.MaxShareUsers {
			fail("Enter between 1 and 50 account email addresses.")
			return
		}
		if handler.users == nil {
			fail("Account sharing is unavailable.")
			return
		}
		seen := map[string]bool{}
		for _, email := range emails {
			user, err := handler.users.UserByEmail(request.Context(), strings.ToLower(strings.TrimSpace(email)))
			if errors.Is(err, db.ErrNotFound) || (err == nil && !user.Active) {
				fail("One or more addresses do not belong to an active account.")
				return
			}
			if err != nil {
				handler.internalError(writer, request, "resolve sharing recipient", err)
				return
			}
			if !seen[user.ID] {
				userIDs = append(userIDs, user.ID)
				seen[user.ID] = true
			}
		}
	}
	repository, ok := handler.repository.(db.SharingRepository)
	if !ok {
		http.Error(writer, "Sharing settings are unavailable.", http.StatusServiceUnavailable)
		return
	}
	if err := repository.SetFileSharing(request.Context(), file.FileID, mode, userIDs); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			http.NotFound(writer, request)
			return
		}
		handler.internalError(writer, request, "save sharing policy", err)
		return
	}
	handler.redirect(writer, request, "/file/"+file.FileID+"/sharing?saved=1")
}

// Uploads may start private and be shared with selected accounts after completion.
func uploadShareMode(value string) (string, bool) {
	if value == "" {
		return db.ShareLink, true
	}
	return value, value == db.ShareLink || value == db.ShareSignedIn || value == db.SharePrivate
}

// The guest capability hash stays on the server. Domain separation gives the
// owner a file-specific form token that works across application replicas;
// possession of this form token alone never authorizes a sharing change.
func guestSharingCSRF(file *db.FileList) string {
	mac := hmac.New(sha256.New, []byte(file.AnonymousSessionToken))
	_, _ = mac.Write([]byte("objectshare-guest-sharing-csrf-v1\x00" + file.FileID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
