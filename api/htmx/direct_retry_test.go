package htmx

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/AutisticShark/ObjectShare/service"
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
		{"empty", `{"file_name":"empty.txt","file_size":0,"content_type":"text/plain"}`, http.StatusBadRequest, "The file is empty."},
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

func TestDirectUploadIsStagedAndCannotBeOverwrittenAfterFinalize(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	direct := &directMemoryStorage{&memoryStorage{objects: make(map[string][]byte)}}
	handler := newTestHandler(t, repository, direct)
	begin := func() (fileID, token string) {
		response := httptest.NewRecorder()
		handler.BeginDirectUpload(response, httptest.NewRequest(http.MethodPost, "/api/v1/uploads/direct", strings.NewReader(`{"file_name":"a.txt","file_size":5,"content_type":"text/plain"}`)))
		if response.Code != http.StatusCreated {
			t.Fatalf("begin: %d %s", response.Code, response.Body.String())
		}
		var payload struct{ FileID, Token string }
		var raw map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &raw); err != nil {
			t.Fatal(err)
		}
		payload.FileID, payload.Token = raw["file_id"].(string), raw["token"].(string)
		return payload.FileID, payload.Token
	}
	call := func(handle func(http.ResponseWriter, *http.Request), fileID, token string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"token": token})
		response := httptest.NewRecorder()
		handle(response, sharingRequest("POST", fileID, string(body), nil))
		return response
	}

	fileID, token := begin()
	pending := service.PendingUploadKey(fileID)
	if len(direct.presigned) != 1 || direct.presigned[0] != pending {
		t.Fatalf("presigned key = %v, want the staging key %q", direct.presigned, pending)
	}
	if response := call(handler.CompleteDirectUpload, fileID, token); response.Code != http.StatusConflict {
		t.Fatalf("completion before the browser upload = %d, want 409", response.Code)
	}
	direct.objects[pending] = []byte("hello") // the browser's PUT
	if response := call(handler.CompleteDirectUpload, fileID, token); response.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", response.Code, response.Body.String())
	}
	if string(direct.objects[fileID]) != "hello" {
		t.Fatalf("published object = %q", direct.objects[fileID])
	}
	if _, staged := direct.objects[pending]; staged {
		t.Fatal("the staged copy survived finalization")
	}

	// The still-valid presigned URL is replayed with different content: it can
	// only write the staging key and never the finished file.
	direct.objects[pending] = []byte("HACKD")
	if response := call(handler.CompleteDirectUpload, fileID, token); response.Code != http.StatusOK {
		t.Fatalf("completion replay: %d", response.Code)
	}
	if string(direct.objects[fileID]) != "hello" {
		t.Fatalf("a replayed PUT overwrote the finalized file: %q", direct.objects[fileID])
	}

	// Aborting removes every object the authorisation could have created.
	abortID, abortToken := begin()
	direct.objects[service.PendingUploadKey(abortID)] = []byte("hello")
	if response := call(handler.AbortDirectUpload, abortID, abortToken); response.Code != http.StatusNoContent {
		t.Fatalf("abort: %d %s", response.Code, response.Body.String())
	}
	if _, left := direct.objects[service.PendingUploadKey(abortID)]; left {
		t.Fatal("abort left the staged object behind")
	}
}

func TestLegacyDirectUploadToTheFinalKeyStillCompletes(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	direct := &directMemoryStorage{&memoryStorage{objects: make(map[string][]byte)}}
	handler := newTestHandler(t, repository, direct)
	response := httptest.NewRecorder()
	handler.BeginDirectUpload(response, httptest.NewRequest(http.MethodPost, "/api/v1/uploads/direct", strings.NewReader(`{"file_name":"a.txt","file_size":5,"content_type":"text/plain"}`)))
	var raw map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	fileID, token := raw["file_id"].(string), raw["token"].(string)
	direct.objects[fileID] = []byte("hello") // presigned for the final key before the staging change
	body, _ := json.Marshal(map[string]string{"token": token})
	done := httptest.NewRecorder()
	handler.CompleteDirectUpload(done, sharingRequest("POST", fileID, string(body), nil))
	if done.Code != http.StatusOK || string(direct.objects[fileID]) != "hello" {
		t.Fatalf("legacy in-flight upload: %d %s", done.Code, done.Body.String())
	}
}

// guestLimitedRepository adds the atomic guest-pending cap that PostgreSQL provides.
type guestLimitedRepository struct{ *memoryRepository }

func (repository *guestLimitedRepository) ReserveGuestUpload(ctx context.Context, file *db.FileList, maxPendingBytes int64) error {
	repository.mu.Lock()
	var pending int64
	for _, existing := range repository.files {
		if existing.FileOwner == nil && existing.UploadStatus == "pending" {
			pending += existing.FileSize
		}
	}
	repository.mu.Unlock()
	if pending+file.FileSize > maxPendingBytes {
		return &db.UploadQuotaError{Scope: db.GuestUploadScope, Used: pending, Limit: maxPendingBytes, Requested: file.FileSize}
	}
	return repository.memoryRepository.ReserveUpload(ctx, file)
}

func TestGuestDirectUploadsShareAGlobalPendingCap(t *testing.T) {
	repository := &guestLimitedRepository{&memoryRepository{files: make(map[string]*db.FileList)}}
	cfg := &config.ServiceConfig{MaxFileSize: 2, StorageService: "r2", Upload: &config.UploadConfig{GuestEnabled: true, MaxPendingGuestMiB: 1}, Encryption: &config.EncryptionConfig{}}
	handler := newTestHandlerConfig(t, cfg, repository, &directMemoryStorage{&memoryStorage{objects: make(map[string][]byte)}})
	begin := func(size int) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		handler.BeginDirectUpload(response, httptest.NewRequest(http.MethodPost, "/api/v1/uploads/direct", strings.NewReader(fmt.Sprintf(`{"file_name":"g.bin","file_size":%d,"content_type":"application/octet-stream"}`, size))))
		return response
	}
	if response := begin(600 * 1024); response.Code != http.StatusCreated {
		t.Fatalf("first guest upload: %d %s", response.Code, response.Body.String())
	}
	full := begin(600 * 1024)
	if full.Code != http.StatusTooManyRequests || full.Header().Get("Retry-After") == "" || full.Header().Get("X-Upload-Quota-Scope") != db.GuestUploadScope {
		t.Fatalf("second guest upload past the cap: %d headers=%v body=%q", full.Code, full.Header(), full.Body.String())
	}
	if len(repository.files) != 1 {
		t.Fatalf("a refused reservation was stored: %d files", len(repository.files))
	}
	if small := begin(300 * 1024); small.Code != http.StatusCreated {
		t.Fatalf("an upload that fits under the cap was refused: %d %s", small.Code, small.Body.String())
	}

	// Signed-in uploads are governed by account quotas, not the guest cap.
	user := &db.User{ID: "5a7b8c9d-1111-4222-8333-444455556666", Active: true}
	signedIn := httptest.NewRequest(http.MethodPost, "/api/v1/uploads/direct", strings.NewReader(`{"file_name":"u.bin","file_size":614400,"content_type":"application/octet-stream"}`))
	signedIn = signedIn.WithContext(context.WithValue(signedIn.Context(), identityContextKey{}, &identity{User: user, Transport: transportBearer}))
	response := httptest.NewRecorder()
	handler.BeginDirectUpload(response, signedIn)
	if response.Code != http.StatusCreated {
		t.Fatalf("signed-in upload was limited by the guest cap: %d %s", response.Code, response.Body.String())
	}
}

func TestBatchFilesAreAuthorizedWhenTheirUploadStartsAndCompleteWithinGrace(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	direct := &directMemoryStorage{&memoryStorage{objects: make(map[string][]byte)}}
	handler := newTestHandler(t, repository, direct)
	expires := direct.DirectUploadPolicy().Expires
	response := httptest.NewRecorder()
	handler.BeginDirectUploadBatch(response, httptest.NewRequest(http.MethodPost, "/api/v1/uploads/direct/batch", strings.NewReader(
		`{"files":[{"file_name":"a.txt","file_size":5,"content_type":"text/plain"},{"file_name":"b.txt","file_size":5,"content_type":"text/plain"}]}`)))
	if response.Code != http.StatusCreated {
		t.Fatalf("begin batch: %d %s", response.Code, response.Body.String())
	}
	var batch struct {
		Uploads []directUploadAuthorization `json:"uploads"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &batch); err != nil || len(batch.Uploads) != 2 {
		t.Fatalf("batch response: %v %s", err, response.Body.String())
	}
	second := batch.Uploads[1]
	if second.RenewURL != "/api/v1/uploads/direct/"+second.FileID+"/renew" {
		t.Fatalf("renew URL = %q", second.RenewURL)
	}
	call := func(handle func(http.ResponseWriter, *http.Request), token string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"token": token})
		response := httptest.NewRecorder()
		handle(response, sharingRequest("POST", second.FileID, string(body), nil))
		return response
	}
	age := func(begun time.Duration, reservedFor time.Duration) {
		repository.mu.Lock()
		defer repository.mu.Unlock()
		record := repository.files[second.FileID]
		reserved := time.Now().Add(reservedFor)
		record.CreatedAt, record.UploadExpiresAt = time.Now().Add(-begun), &reserved
	}

	// The first file took most of the batch URL's lifetime. The second file's
	// URL is issued when its own PUT starts, for the same staging key, and its
	// reservation now covers that URL plus the completion grace.
	age(expires-time.Minute, time.Minute+expires)
	if response := call(handler.RenewDirectUpload, "wrong-token"); response.Code != http.StatusForbidden {
		t.Fatalf("renewal with another token = %d", response.Code)
	}
	presigned := len(direct.presigned)
	renewed := call(handler.RenewDirectUpload, second.Token)
	var fresh struct {
		UploadURL string `json:"upload_url"`
		ExpiresAt string `json:"expires_at"`
	}
	if renewed.Code != http.StatusOK || json.Unmarshal(renewed.Body.Bytes(), &fresh) != nil || fresh.UploadURL == "" {
		t.Fatalf("renew: %d %s", renewed.Code, renewed.Body.String())
	}
	if len(direct.presigned) != presigned+1 || direct.presigned[presigned] != service.PendingUploadKey(second.FileID) {
		t.Fatalf("renewal presigned %v, want the staging key", direct.presigned[presigned:])
	}
	if urlExpiry, err := time.Parse(time.RFC3339, fresh.ExpiresAt); err != nil || time.Until(urlExpiry) > expires || time.Until(urlExpiry) < expires-time.Minute {
		t.Fatalf("renewed URL expiry %q is not the short upload lifetime", fresh.ExpiresAt)
	}
	record, _ := repository.Get(t.Context(), second.FileID)
	if until := time.Until(*record.UploadExpiresAt); until < 2*expires-time.Minute || until > 2*expires {
		t.Fatalf("reservation runs %v more, want the URL lifetime plus an equal grace", until)
	}

	// The PUT started before its URL expired but finished after it: completion
	// within the grace period still succeeds.
	age(2*expires, time.Minute)
	direct.objects[service.PendingUploadKey(second.FileID)] = []byte("hello")
	if response := call(handler.CompleteDirectUpload, second.Token); response.Code != http.StatusOK {
		t.Fatalf("completion within grace = %d %s", response.Code, response.Body.String())
	}

	// Renewal is refused once the batch's lifetime cap is used up, and an
	// expired reservation is not revived.
	first := batch.Uploads[0]
	repository.mu.Lock()
	repository.files[first.FileID].CreatedAt = time.Now().Add(-time.Duration(handler.uploadSettings().MaxFilesPerBatch) * 2 * expires)
	repository.mu.Unlock()
	body, _ := json.Marshal(map[string]string{"token": first.Token})
	capped := httptest.NewRecorder()
	handler.RenewDirectUpload(capped, sharingRequest("POST", first.FileID, string(body), nil))
	if capped.Code != http.StatusGone {
		t.Fatalf("renewal past the cap = %d", capped.Code)
	}
	past := time.Now().Add(-time.Second)
	repository.mu.Lock()
	repository.files[first.FileID].UploadExpiresAt = &past
	repository.mu.Unlock()
	expired := httptest.NewRecorder()
	handler.RenewDirectUpload(expired, sharingRequest("POST", first.FileID, string(body), nil))
	if _, err := repository.Get(t.Context(), first.FileID); expired.Code != http.StatusGone || err == nil {
		t.Fatalf("expired renewal = %d, record err=%v", expired.Code, err)
	}
}
