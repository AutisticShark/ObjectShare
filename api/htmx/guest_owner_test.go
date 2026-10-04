package htmx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/AutisticShark/ObjectShare/service"
)

// cookieJar keeps cookies the way a browser does: the last Set-Cookie for a
// name wins.
type cookieJar map[string]string

func (jar cookieJar) store(response *httptest.ResponseRecorder) {
	for _, cookie := range response.Result().Cookies() {
		if cookie.MaxAge < 0 {
			delete(jar, cookie.Name)
		} else {
			jar[cookie.Name] = cookie.Value
		}
	}
}

func (jar cookieJar) apply(request *http.Request) *http.Request {
	for name, value := range jar {
		request.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	return request
}

// Each guest upload used to add its own 30-day cookie, so about 90 guest files
// produced a Cookie header too large for common proxy buffers and browser
// limits. A browser now keeps one owner key that proves ownership of all of
// its guest files, through both upload paths.
func TestManyGuestUploadsShareOneBoundedOwnerCookie(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	handler := newTestHandler(t, repository, &memoryStorage{objects: make(map[string][]byte)})
	jar := cookieJar{}
	var ids []string
	for range 100 {
		response := httptest.NewRecorder()
		handler.Upload(response, jar.apply(multipartUploadRequest(t, []byte("guest file"))))
		if response.Code != http.StatusSeeOther {
			t.Fatalf("upload: %d %s", response.Code, response.Body.String())
		}
		jar.store(response)
		ids = append(ids, strings.TrimPrefix(response.Header().Get("Location"), "/file/"))
	}

	direct := &directMemoryStorage{&memoryStorage{objects: make(map[string][]byte)}}
	directHandler := newTestHandlerConfig(t, &config.ServiceConfig{MaxFileSize: 1, StorageService: "r2", Encryption: &config.EncryptionConfig{}}, repository, direct)
	begin := httptest.NewRecorder()
	directHandler.BeginDirectUploadBatch(begin, jar.apply(httptest.NewRequest(http.MethodPost, "/api/v1/uploads/direct/batch", strings.NewReader(
		`{"files":[{"file_name":"a.txt","file_size":5,"content_type":"text/plain"},{"file_name":"b.txt","file_size":5,"content_type":"text/plain"}]}`))))
	var batch struct {
		Uploads []directUploadAuthorization `json:"uploads"`
	}
	if begin.Code != http.StatusCreated || json.Unmarshal(begin.Body.Bytes(), &batch) != nil {
		t.Fatalf("begin batch: %d %s", begin.Code, begin.Body.String())
	}
	jar.store(begin)
	for _, authorization := range batch.Uploads {
		direct.objects[service.PendingUploadKey(authorization.FileID)] = []byte("hello")
		body, _ := json.Marshal(map[string]string{"token": authorization.Token})
		complete := httptest.NewRecorder()
		directHandler.CompleteDirectUpload(complete, jar.apply(sharingRequest("POST", authorization.FileID, string(body), nil)))
		if complete.Code != http.StatusOK {
			t.Fatalf("complete: %d %s", complete.Code, complete.Body.String())
		}
		jar.store(complete)
		ids = append(ids, authorization.FileID)
	}

	// The owner key, plus the per-file fallback from the browser's first upload.
	header := jar.apply(httptest.NewRequest(http.MethodGet, "/", nil)).Header.Get("Cookie")
	if len(jar) > 2 || len(header) > 256 {
		t.Fatalf("%d guest uploads left %d cookies (%d-byte Cookie header)", len(ids), len(jar), len(header))
	}
	for _, id := range ids {
		file, err := repository.Get(t.Context(), id)
		if err != nil || !handler.isOwner(jar.apply(httptest.NewRequest(http.MethodGet, "/file/"+id, nil)), file) {
			t.Fatalf("the browser lost ownership of %s: %v", id, err)
		}
	}

	// Per-file cookies issued by earlier releases keep working, and an owner
	// key from another browser proves nothing.
	token, hash, err := newOwnerToken()
	if err != nil {
		t.Fatal(err)
	}
	legacy := &db.FileList{FileID: "0b4a83b6-5a1d-4f5e-9c0e-3f1f6d8e2a10", AnonymousSessionToken: hash, UploadStatus: "complete"}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(ownerCookie(legacy.FileID, token, false, 0))
	if !handler.isOwner(request, legacy) {
		t.Fatal("an existing per-file owner cookie is no longer honored")
	}
	file, _ := repository.Get(t.Context(), ids[0])
	stranger, err := withGuestOwnerKey(httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	foreign := httptest.NewRequest(http.MethodGet, "/", nil)
	foreign.AddCookie(handler.guestOwnerKeyCookie(requestGuestOwnerState(stranger).key))
	if handler.isOwner(foreign, file) {
		t.Fatal("another browser's owner key was accepted")
	}
}

func TestGuestOwnerKeyCookieIsHardened(t *testing.T) {
	handler := newTestHandler(t, &memoryRepository{files: make(map[string]*db.FileList)}, &memoryStorage{objects: make(map[string][]byte)})
	handler.config.SecureCookies = true
	cookie := handler.guestOwnerKeyCookie(make([]byte, guestOwnerKeyBytes))
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.MaxAge != int(guestOwnerCookieLifetime.Seconds()) {
		t.Fatalf("owner key cookie = %+v", cookie)
	}
	// A malformed key cookie is ignored rather than trusted or reused.
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: guestOwnerKeyCookieName, Value: "short"})
	if requestGuestOwnerKey(request) != nil {
		t.Fatal("a malformed owner key was accepted")
	}
}
