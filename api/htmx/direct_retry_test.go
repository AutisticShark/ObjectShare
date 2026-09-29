package htmx

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

func TestCompletedDirectUploadCanRestoreLostResponseWithoutMutatingObject(t *testing.T) {
	handler, _, storage, file, owner := sharingTestHandler(t)
	direct := &directMemoryStorage{storage}
	handler.direct, handler.storage = direct, direct
	token, hash, err := newOwnerToken()
	if err != nil {
		t.Fatal(err)
	}
	file.AnonymousSessionToken = hash
	file.UploadExpiresAt = nil // Cleared by the original completion commit.
	other := &db.User{ID: "4319ed31-1207-408a-a077-31158394e4d3", Active: true}
	for _, test := range []struct {
		name, token, moderation string
		actor                   *db.User
		want                    int
	}{
		{"owner replay", token, "", owner, 200},
		{"account token after logout", token, "", nil, 403},
		{"account token in another account", token, "", other, 403},
		{"wrong token", "not-the-token", "", owner, 403},
		{"banned owner", token, db.ModerationBanned, owner, 404},
		{"shadowban guest", token, db.ModerationShadowbanned, nil, 404},
		{"shadowban owner", token, db.ModerationShadowbanned, owner, 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner.ModerationStatus = test.moderation
			body, _ := json.Marshal(map[string]string{"token": test.token})
			request := sharingRequest("POST", file.FileID, string(body), test.actor)
			response := httptest.NewRecorder()
			handler.CompleteDirectUpload(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if len(response.Result().Cookies()) != 0 {
				t.Fatal("account-owned upload issued a guest owner cookie")
			}
			if file.UploadStatus != "complete" || string(storage.objects[file.FileID]) != "secret" {
				t.Fatal("completion replay changed file contents or status")
			}
		})
	}
	owner.ModerationStatus = ""
	body, _ := json.Marshal(map[string]string{"token": token})
	request := sharingRequest("POST", file.FileID, string(body), owner)
	response := httptest.NewRecorder()
	handler.AbortDirectUpload(response, request)
	if response.Code != 404 || string(storage.objects[file.FileID]) != "secret" {
		t.Fatal("abort deleted a completed upload")
	}
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: owner, Transport: transportCookie, Claims: &appauth.Claims{CSRF: "required"}}))
	response = httptest.NewRecorder()
	handler.CompleteDirectUpload(response, request)
	if response.Code != 403 {
		t.Fatal("cookie-authenticated completion replay bypassed CSRF")
	}
}

func TestGuestDirectUploadReplayRestoresOwnerCookie(t *testing.T) {
	handler, _, storage, file, _ := sharingTestHandler(t)
	direct := &directMemoryStorage{storage}
	handler.direct, handler.storage = direct, direct
	file.FileOwner, file.IsAnonymousUpload = nil, true
	token, hash, err := newOwnerToken()
	if err != nil {
		t.Fatal(err)
	}
	file.AnonymousSessionToken = hash
	body, _ := json.Marshal(map[string]string{"token": token})
	response := httptest.NewRecorder()
	handler.CompleteDirectUpload(response, sharingRequest("POST", file.FileID, string(body), nil))
	if response.Code != 200 || len(response.Result().Cookies()) != 1 || response.Result().Cookies()[0].Value != token {
		t.Fatalf("guest completion retry status=%d cookies=%v", response.Code, response.Result().Cookies())
	}
}

func TestCompletedUploadReplayRechecksEmailVerification(t *testing.T) {
	handler, _, storage, file, owner := sharingTestHandler(t)
	direct := &directMemoryStorage{storage}
	handler.direct, handler.storage = direct, direct
	token, hash, err := newOwnerToken()
	if err != nil {
		t.Fatal(err)
	}
	file.AnonymousSessionToken = hash
	handler.config.Auth = &config.AuthConfig{EmailVerification: config.EmailVerificationConfig{RequireForUploads: true}}
	body, _ := json.Marshal(map[string]string{"token": token})
	response := httptest.NewRecorder()
	handler.CompleteDirectUpload(response, sharingRequest("POST", file.FileID, string(body), owner))
	if response.Code != 403 || len(response.Result().Cookies()) != 0 {
		t.Fatal("replay bypassed newly required email verification")
	}
}

func TestDirectUploadEndpointsShareRejectionStatuses(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	handler := newTestHandler(t, repository, &directMemoryStorage{memoryStorage: &memoryStorage{objects: make(map[string][]byte)}})
	oversized := handler.config.MaxFileSize*mebibyte + 1
	for _, test := range []struct {
		name   string
		file   string
		status int
		text   string
	}{
		{"oversized", fmt.Sprintf(`{"file_name":"big.bin","file_size":%d,"content_type":"text/plain"}`, oversized), http.StatusRequestEntityTooLarge, "File size must be between"},
		{"empty", `{"file_name":"empty.txt","file_size":0,"content_type":"text/plain"}`, http.StatusRequestEntityTooLarge, "File size must be between"},
		{"bad name", `{"file_name":"..","file_size":3,"content_type":"text/plain"}`, http.StatusBadRequest, "Invalid file name."},
		{"bad type", `{"file_name":"a.txt","file_size":3,"content_type":"not a media type"}`, http.StatusBadRequest, "Invalid content type."},
		{"bad share mode", `{"file_name":"a.txt","file_size":3,"content_type":"text/plain","share_mode":"nope"}`, http.StatusBadRequest, "Invalid upload access option."},
	} {
		t.Run(test.name, func(t *testing.T) {
			single := httptest.NewRecorder()
			handler.BeginDirectUpload(single, httptest.NewRequest(http.MethodPost, "/api/v1/uploads/direct", strings.NewReader(test.file)))
			batch := httptest.NewRecorder()
			handler.BeginDirectUploadBatch(batch, httptest.NewRequest(http.MethodPost, "/api/v1/uploads/direct/batch", strings.NewReader(`{"files":[`+test.file+`]}`)))
			for name, response := range map[string]*httptest.ResponseRecorder{"single": single, "batch": batch} {
				if response.Code != test.status || !strings.Contains(response.Body.String(), test.text) {
					t.Fatalf("%s endpoint: status=%d body=%q, want %d containing %q", name, response.Code, response.Body.String(), test.status, test.text)
				}
			}
			if len(repository.files) != 0 {
				t.Fatalf("rejected upload left %d reservations", len(repository.files))
			}
		})
	}
}

func TestSameMediaTypeIgnoresProviderNormalisation(t *testing.T) {
	for _, test := range []struct {
		stored, authorized string
		want               bool
	}{
		{"text/plain", "text/plain", true},
		{"TEXT/Plain", "text/plain", true},
		{"text/plain; charset=utf-8", "text/plain", true},
		{"application/octet-stream", "application/octet-stream", true},
		{"text/html", "text/plain", false},
		{"application/octet-stream", "text/plain", false},
		{"", "text/plain", false},
		{"not a type", "NOT A TYPE", true},
	} {
		if got := sameMediaType(test.stored, test.authorized); got != test.want {
			t.Errorf("sameMediaType(%q, %q) = %v, want %v", test.stored, test.authorized, got, test.want)
		}
	}
}
