package htmx

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (repo *memoryRepository) SetFileSharing(_ context.Context, id, mode string, users []string) error {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	file, ok := repo.files[id]
	if !ok || file.UploadStatus != "complete" {
		return db.ErrNotFound
	}
	file.ShareMode, file.ShareUserIDs = mode, append([]string{}, users...)
	return nil
}

func sharingRequest(method, id, body string, user *db.User) *http.Request {
	r := httptest.NewRequest(method, "/file/"+id+"/sharing", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	route := chi.NewRouteContext()
	route.URLParams.Add("id", id)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, route))
	if user != nil {
		r = r.WithContext(context.WithValue(r.Context(), identityContextKey{}, &identity{User: user, Transport: transportBearer, Claims: &appauth.Claims{CSRF: "csrf"}}))
	}
	return r
}

func sharingTestHandler(t *testing.T) (*Handler, *authMemoryRepository, *memoryStorage, *db.FileList, *db.User) {
	t.Helper()
	repo := newAuthMemoryRepository()
	owner := &db.User{ID: uuid.NewString(), Email: "owner@example.com", Active: true}
	repo.users[owner.ID] = owner
	file := &db.FileList{FileID: uuid.NewString(), FileOwner: &owner.ID, FileName: "secret.txt", FileSize: 6, ContentType: "text/plain", UploadStatus: "complete", ShareMode: db.ShareLink}
	repo.files[file.FileID] = file
	storage := &memoryStorage{objects: map[string][]byte{file.FileID: []byte("secret")}}
	// Use the lightweight constructor then attach the auth repository, avoiding
	// unrelated login setup while exercising real templates and permission handlers.
	h := newTestHandler(t, repo.memoryRepository, storage)
	h.repository, h.users = repo, repo
	var err error
	h.templates, err = parseTemplates(os.DirFS("../.."), config.BrandingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return h, repo, storage, file, owner
}

func TestFileSharingReadAndManagementMatrix(t *testing.T) {
	h, repo, _, file, owner := sharingTestHandler(t)
	recipient := &db.User{ID: uuid.NewString(), Email: "recipient@example.com", Active: true}
	outsider := &db.User{ID: uuid.NewString(), Active: true}
	admin := &db.User{ID: uuid.NewString(), Active: true, Role: db.RoleAdmin}
	disabled := &db.User{ID: recipient.ID, Active: false}
	repo.users[recipient.ID] = recipient
	file.ShareUserIDs = []string{recipient.ID}
	for _, mode := range []string{"", db.ShareLink, db.ShareSignedIn, db.ShareSelected, db.SharePrivate, "invalid"} {
		file.ShareMode = mode
		for _, actor := range []struct {
			name string
			user *db.User
		}{{"guest", nil}, {"owner", owner}, {"recipient", recipient}, {"outsider", outsider}, {"admin", admin}, {"disabled", disabled}} {
			t.Run(mode+"/"+actor.name, func(t *testing.T) {
				allowed := actor.name == "owner" || mode == "" || mode == db.ShareLink || (mode == db.ShareSignedIn && actor.user != nil && actor.user.Active) || (mode == db.ShareSelected && actor.name == "recipient")
				for _, endpoint := range []struct {
					name, method string
					fn           http.HandlerFunc
				}{{"details", "GET", h.FileView}, {"download-get", "GET", h.Download}, {"download-post", "POST", h.Download}} {
					response := httptest.NewRecorder()
					endpoint.fn(response, sharingRequest(endpoint.method, file.FileID, "", actor.user))
					if !allowed && (response.Code != 404 || strings.Contains(response.Body.String(), "secret")) {
						t.Fatalf("%s leaked restricted file: %d %s", endpoint.name, response.Code, response.Body.String())
					}
					if allowed && response.Code != 200 && response.Code != 303 {
						t.Fatalf("%s denied allowed reader: %d %s", endpoint.name, response.Code, response.Body.String())
					}
					if response.Header().Get("Cache-Control") != "private, no-store" {
						t.Fatalf("%s may cache authorization", endpoint.name)
					}
				}
				response := httptest.NewRecorder()
				h.SharingPage(response, sharingRequest("GET", file.FileID, "", actor.user))
				if actor.name == "owner" {
					if response.Code != 200 || !strings.Contains(response.Body.String(), "Save permissions") {
						t.Fatalf("owner sharing page: %d %s", response.Code, response.Body.String())
					}
				} else if response.Code != 404 || strings.Contains(response.Body.String(), recipient.Email) {
					t.Fatal("recipient list or management exposed")
				}
				if actor.name != "owner" {
					response = httptest.NewRecorder()
					h.UpdateSharing(response, sharingRequest("POST", file.FileID, "share_mode=link", actor.user))
					if response.Code != 404 || file.ShareMode != mode {
						t.Fatal("non-owner changed sharing")
					}
				}
			})
		}
	}
	file.ShareMode = db.ShareLink
	for _, state := range []string{"pending", "deleting"} {
		file.UploadStatus = state
		for _, fn := range []http.HandlerFunc{h.FileView, h.Download, h.SharingPage, h.UpdateSharing} {
			response := httptest.NewRecorder()
			fn(response, sharingRequest("POST", file.FileID, "share_mode=private", owner))
			if response.Code != 404 {
				t.Fatalf("%s file accessible: %d", state, response.Code)
			}
		}
	}
}

func TestSharingUpdatesResolveAccountsAndRevokeAccess(t *testing.T) {
	h, repo, _, file, owner := sharingTestHandler(t)
	recipient := &db.User{ID: uuid.NewString(), Email: "reader@example.com", Active: true}
	repo.users[recipient.ID] = recipient
	save := func(mode, emails string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		h.UpdateSharing(response, sharingRequest("POST", file.FileID, url.Values{"share_mode": {mode}, "recipients": {emails}}.Encode(), owner))
		return response
	}
	response := save(db.ShareSelected, " READER@example.com,reader@example.com")
	if response.Code != 303 || file.ShareMode != db.ShareSelected || len(file.ShareUserIDs) != 1 || file.ShareUserIDs[0] != recipient.ID {
		t.Fatalf("selected policy not saved: %d %s %+v", response.Code, response.Body.String(), file)
	}
	recipient.Email = "renamed@example.com"
	if !h.canReadFile(sharingRequest("GET", file.FileID, "", recipient), file) {
		t.Fatal("email edit lost account grant")
	}
	for _, invalid := range []struct{ mode, emails string }{{"unknown", ""}, {db.ShareSelected, ""}, {db.ShareSelected, "missing@example.com"}, {db.ShareSelected, strings.Repeat("renamed@example.com,", 51)}} {
		response = save(invalid.mode, invalid.emails)
		if response.Code != 400 || file.ShareMode != db.ShareSelected || len(file.ShareUserIDs) != 1 {
			t.Fatalf("invalid policy modified file: %d %s", response.Code, response.Body.String())
		}
	}
	recipient.Active = false
	if response = save(db.ShareSelected, recipient.Email); response.Code != 400 {
		t.Fatal("disabled account granted access")
	}
	recipient.Active = true
	for _, mode := range []string{db.ShareLink, db.ShareSignedIn, db.SharePrivate} {
		response = save(mode, "ignored@example.com")
		if response.Code != 303 || len(file.ShareUserIDs) != 0 || file.ShareMode != mode {
			t.Fatal("policy change did not clear old recipients")
		}
	}
	if h.canReadFile(sharingRequest("GET", file.FileID, "", recipient), file) {
		t.Fatal("revoked recipient still has access")
	}
	// Filenames and recipient form values are escaped in real templates.
	file.FileName = `<script>alert(1)</script>`
	response = save(db.ShareSelected, `<img src=x onerror=alert(1)>`)
	if strings.Contains(response.Body.String(), `<img src=x`) || strings.Contains(response.Body.String(), `<script>alert`) {
		t.Fatal("sharing page rendered unescaped data")
	}
}

func TestSharingCSRFAndGuestOwnership(t *testing.T) {
	h, _, _, file, owner := sharingTestHandler(t)
	request := sharingRequest("POST", file.FileID, "share_mode=private", owner)
	currentIdentity(request).Transport = transportCookie
	response := httptest.NewRecorder()
	h.UpdateSharing(response, request)
	if response.Code != 403 || file.ShareMode != db.ShareLink {
		t.Fatal("cookie account sharing mutation bypassed CSRF")
	}
	request = sharingRequest("POST", file.FileID, "share_mode=private&csrf_token=csrf", owner)
	currentIdentity(request).Transport = transportCookie
	response = httptest.NewRecorder()
	h.UpdateSharing(response, request)
	if response.Code != 303 {
		t.Fatalf("valid account CSRF rejected: %d", response.Code)
	}
	token, hash, err := newOwnerToken()
	if err != nil {
		t.Fatal(err)
	}
	file.FileOwner, file.AnonymousSessionToken = nil, hash
	guestCookie := ownerCookie(file.FileID, token, false, 0)
	request = sharingRequest("POST", file.FileID, "share_mode=link", nil)
	request.AddCookie(guestCookie)
	response = httptest.NewRecorder()
	h.UpdateSharing(response, request)
	if response.Code != 403 || file.ShareMode != db.SharePrivate {
		t.Fatal("guest sharing mutation bypassed CSRF")
	}
	request = sharingRequest("GET", file.FileID, "", nil)
	request.AddCookie(guestCookie)
	response = httptest.NewRecorder()
	csrf := guestSharingCSRF(file)
	request = sharingRequest("POST", file.FileID, url.Values{"share_mode": {db.ShareSignedIn}, "csrf_token": {csrf}}.Encode(), nil)
	request.AddCookie(guestCookie)
	for _, cookie := range response.Result().Cookies() {
		request.AddCookie(cookie)
	}
	response = httptest.NewRecorder()
	h.UpdateSharing(response, request)
	if response.Code != 303 || file.ShareMode != db.ShareSignedIn {
		t.Fatalf("guest owner cannot share: %d %s", response.Code, response.Body.String())
	}
	file.ShareMode = db.SharePrivate
	if !h.canReadFile(request, file) {
		t.Fatal("guest owner cannot read private file")
	}
	forged := sharingRequest("GET", file.FileID, "", nil)
	forged.AddCookie(ownerCookie(file.FileID, "forged", false, 0))
	if h.canReadFile(forged, file) {
		t.Fatal("forged owner cookie bypassed private access")
	}
}

type sharingPresignStorage struct {
	*memoryStorage
	calls int
}

func (s *sharingPresignStorage) PresignGet(context.Context, string, string) (string, error) {
	s.calls++
	return "https://storage.example/download", nil
}

func TestRestrictedDownloadsNeverIssueStorageLinks(t *testing.T) {
	h, _, storage, file, owner := sharingTestHandler(t)
	signed := &sharingPresignStorage{memoryStorage: storage}
	h.storage = signed
	for _, mode := range []string{db.SharePrivate, db.ShareSignedIn, db.ShareSelected} {
		file.ShareMode = mode
		response := httptest.NewRecorder()
		h.Download(response, sharingRequest("POST", file.FileID, "", owner))
		if response.Code != 200 || response.Body.String() != "secret" || signed.calls != 0 {
			t.Fatal("restricted download issued a reusable storage URL")
		}
	}
	file.ShareMode = db.ShareLink
	response := httptest.NewRecorder()
	h.Download(response, sharingRequest("POST", file.FileID, "", nil))
	if response.Code != 303 || signed.calls != 1 {
		t.Fatal("unlisted storage download behavior changed")
	}
}

func TestUploadSharingModesAcrossPaths(t *testing.T) {
	for _, mode := range []string{"", db.ShareLink, db.SharePrivate, db.ShareSignedIn, "selected", "invalid"} {
		for _, path := range []string{"proxied", "proxied-batch", "direct", "direct-batch"} {
			t.Run(path+"/"+mode, func(t *testing.T) {
				repo := &memoryRepository{files: map[string]*db.FileList{}}
				storage := &directMemoryStorage{&memoryStorage{objects: map[string][]byte{}}}
				cfg := &config.ServiceConfig{MaxFileSize: 1, StorageService: "r2", Upload: &config.UploadConfig{GuestEnabled: true, MaxFilesPerBatch: 10}, Encryption: &config.EncryptionConfig{}}
				h := newTestHandlerConfig(t, cfg, repo, storage)
				response := httptest.NewRecorder()
				count := 1
				if strings.HasSuffix(path, "batch") {
					count = 2
				}
				if strings.HasPrefix(path, "proxied") {
					var body bytes.Buffer
					form := multipart.NewWriter(&body)
					if err := form.WriteField("share_mode", mode); err != nil {
						t.Fatal(err)
					}
					for i := 0; i < count; i++ {
						part, err := form.CreateFormFile("file", fmt.Sprintf("%d.txt", i))
						if err != nil {
							t.Fatal(err)
						}
						_, _ = part.Write([]byte("hello"))
					}
					_ = form.Close()
					request := httptest.NewRequest("POST", "/api/v1/upload", &body)
					request.Header.Set("Content-Type", form.FormDataContentType())
					h.Upload(response, request)
				} else {
					item := fmt.Sprintf(`{"file_name":"test.txt","file_size":5,"content_type":"text/plain","share_mode":%q}`, mode)
					if path == "direct" {
						h.BeginDirectUpload(response, httptest.NewRequest("POST", "/api/v1/uploads/direct", strings.NewReader(item)))
					} else {
						h.BeginDirectUploadBatch(response, httptest.NewRequest("POST", "/api/v1/uploads/direct/batch", strings.NewReader(`{"files":[`+item+`,`+item+`]}`)))
					}
				}
				want, valid := uploadShareMode(mode)
				if !valid {
					if response.Code != 400 || len(repo.files) != 0 || len(storage.objects) != 0 {
						t.Fatalf("invalid mode published an upload: %d %s", response.Code, response.Body.String())
					}
					return
				}
				if len(repo.files) != count {
					t.Fatalf("missing uploads: %d %s", response.Code, response.Body.String())
				}
				for _, file := range repo.files {
					if file.ShareMode != want {
						t.Fatalf("upload mode %q want %q", file.ShareMode, want)
					}
				}
			})
		}
	}
}

func TestDownloadEntitlementsAndFormTokensCannotBypassSharing(t *testing.T) {
	h, repo, _, file, owner := sharingTestHandler(t)
	billing := &entitlementRepository{memoryRepository: repo.memoryRepository, entitlements: db.Entitlements{Active: true, DirectLinks: true}}
	h.billing = billing
	token := h.downloadFormToken(file.FileID, time.Now().UTC().Add(5*time.Minute))
	file.ShareMode = db.SharePrivate
	for _, method := range []string{"GET", "POST"} {
		response := httptest.NewRecorder()
		h.Download(response, sharingRequest(method, file.FileID, url.Values{"download_token": {token}}.Encode(), nil))
		if response.Code != 404 || strings.Contains(response.Body.String(), "secret") {
			t.Fatal("paid direct links or old form token bypassed permissions")
		}
	}
	response := httptest.NewRecorder()
	h.Download(response, sharingRequest("POST", file.FileID, url.Values{"download_token": {token}}.Encode(), owner))
	if response.Code != 200 {
		t.Fatalf("owner lost billing-protected download: %d", response.Code)
	}
}

func TestSharingHTMXValidationAndGuestTokenBinding(t *testing.T) {
	h, _, _, file, owner := sharingTestHandler(t)
	request := sharingRequest("POST", file.FileID, "share_mode=selected", owner)
	request.Header.Set("HX-Request", "true")
	response := httptest.NewRecorder()
	h.UpdateSharing(response, request)
	if response.Code != 200 || !strings.Contains(response.Body.String(), "Enter between 1 and 50") || !strings.Contains(response.Body.String(), `hx-select=".page"`) {
		t.Fatal("HTMX validation cannot replace the page")
	}
	_, hash, err := newOwnerToken()
	if err != nil {
		t.Fatal(err)
	}
	file.AnonymousSessionToken = hash
	copy := *file
	copy.FileID = uuid.NewString()
	if guestSharingCSRF(file) == guestSharingCSRF(&copy) {
		t.Fatal("guest form token is not file-bound")
	}
	copy = *file
	copy.AnonymousSessionToken = "another-owner-hash"
	if guestSharingCSRF(file) == guestSharingCSRF(&copy) {
		t.Fatal("guest form token is not owner-bound")
	}
	outsider := &db.User{ID: uuid.NewString(), Active: true}
	file.ShareMode = db.ShareSelected
	file.ShareUserIDs = []string{outsider.ID}
	for _, action := range []http.HandlerFunc{h.Update, h.Delete} {
		response = httptest.NewRecorder()
		action(response, sharingRequest("POST", file.FileID, "name=changed.txt", outsider))
		if response.Code != 403 || file.FileName != "secret.txt" {
			t.Fatal("read-only recipient can mutate file")
		}
	}
}
