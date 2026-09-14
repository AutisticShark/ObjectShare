package htmx

import (
	"context"
	"encoding/json"
	"net/http/httptest"
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
	for _, test := range []struct {
		name, token, moderation string
		actor                   *db.User
		want                    int
	}{
		{"owner replay", token, "", owner, 200},
		{"lost guest cookie", token, "", nil, 200},
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
			if response.Code == 200 {
				cookies := response.Result().Cookies()
				if len(cookies) != 1 || cookies[0].Value != token || !cookies[0].HttpOnly {
					t.Fatal("owner cookie not safely restored")
				}
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
