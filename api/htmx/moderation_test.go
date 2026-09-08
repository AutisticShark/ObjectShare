package htmx

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/AutisticShark/ObjectShare/config"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestShadowbannedUploadsRemainOwnedAndHidden(t *testing.T) {
	for _, path := range []string{"proxied", "proxied-batch", "direct", "direct-batch"} {
		t.Run(path, func(t *testing.T) {
			repo := newAuthMemoryRepository()
			user := &db.User{ID: uuid.NewString(), Email: "owner@example.com", Active: true, Role: db.RoleUser, TokenVersion: 1, ModerationStatus: db.ModerationShadowbanned}
			repo.users[user.ID] = user
			h := newAuthTestHandler(t, repo, false)
			direct := &directMemoryStorage{&memoryStorage{objects: map[string][]byte{}}}
			h.storage, h.direct = direct, direct
			h.directPolicy = direct.DirectUploadPolicy()
			h.config.StorageService = "r2"
			h.config.MaxFileSize = 1
			h.config.Upload = &config.UploadConfig{GuestEnabled: true, MaxFilesPerBatch: 10}
			var req *http.Request
			fn := h.Upload
			want, count := 303, 1
			if strings.HasSuffix(path, "batch") {
				count = 2
			}
			if strings.HasPrefix(path, "proxied") {
				var body bytes.Buffer
				form := multipart.NewWriter(&body)
				for range count {
					part, err := form.CreateFormFile("file", "uploaded.txt")
					if err != nil {
						t.Fatal(err)
					}
					_, _ = part.Write([]byte("hello"))
				}
				_ = form.Close()
				req = httptest.NewRequest("POST", "/api/v1/upload", &body)
				req.Header.Set("Content-Type", form.FormDataContentType())
			} else {
				body := `{"file_name":"uploaded.txt","file_size":5,"content_type":"text/plain"}`
				fn, want = h.BeginDirectUpload, 201
				if count == 2 {
					body = `{"files":[` + body + `,` + body + `]}`
					fn = h.BeginDirectUploadBatch
				}
				req = httptest.NewRequest("POST", "/api/v1/uploads/direct", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
			}
			token, _ := issueTestJWT(t, h, user)
			req.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			h.Authenticate(http.HandlerFunc(fn)).ServeHTTP(response, req)
			if response.Code != want || len(repo.files) != count {
				t.Fatalf("upload=%d files=%d body=%s", response.Code, len(repo.files), response.Body.String())
			}
			for _, file := range repo.files {
				if file.FileOwner == nil || *file.FileOwner != user.ID {
					t.Fatal("shadowban lost account ownership")
				}
				file.UploadStatus = "complete"
				if h.canReadFile(sharingRequest("GET", file.FileID, "", nil), file) {
					t.Fatal("new shadowbanned upload is public")
				}
				if !h.canReadFile(sharingRequest("GET", file.FileID, "", user), file) {
					t.Fatal("shadowbanned uploader cannot see own upload")
				}
			}
		})
	}
}

func TestModerationFileAccessMatrix(t *testing.T) {
	h, repo, storage, file, owner := sharingTestHandler(t)
	other := &db.User{ID: uuid.NewString(), Active: true, Role: db.RoleAdmin}
	file.ShareUserIDs = []string{other.ID}
	token, hash, err := newOwnerToken()
	if err != nil {
		t.Fatal(err)
	}
	file.AnonymousSessionToken = hash
	signed := &sharingPresignStorage{memoryStorage: storage}
	h.storage = signed
	for _, status := range []string{db.ModerationBanned, db.ModerationShadowbanned} {
		owner.ModerationStatus = status
		for _, mode := range []string{"", db.ShareLink, db.SharePrivate, db.ShareSignedIn, db.ShareSelected} {
			file.ShareMode = mode
			for _, actor := range []struct {
				name string
				user *db.User
			}{{"guest", nil}, {"owner", owner}, {"recipient-admin", other}} {
				for _, endpoint := range []struct {
					name, method string
					fn           http.HandlerFunc
				}{{"details", "GET", h.FileView}, {"download", "GET", h.Download}, {"download-post", "POST", h.Download}, {"sharing", "GET", h.SharingPage}} {
					t.Run(status+"/"+mode+"/"+actor.name+"/"+endpoint.name, func(t *testing.T) {
						req := sharingRequest(endpoint.method, file.FileID, "", actor.user)
						// Even a valid leaked owner cookie must not bypass moderation.
						req.AddCookie(ownerCookie(file.FileID, token, false, time.Hour))
						response := httptest.NewRecorder()
						endpoint.fn(response, req)
						want := 404
						if status == db.ModerationShadowbanned && actor.name == "owner" {
							want = 200
						}
						if response.Code != want {
							t.Fatalf("status=%d want=%d body=%s", response.Code, want, response.Body.String())
						}
						if want == 404 && strings.Contains(response.Body.String(), file.FileName) {
							t.Fatal("file metadata leaked")
						}
						if response.Header().Get("Cache-Control") != "private, no-store" {
							t.Fatal("moderation response can be cached")
						}
					})
				}
			}
		}
	}
	if signed.calls != 0 {
		t.Fatal("moderated owner obtained reusable storage URL")
	}
	owner.ModerationStatus, file.ShareMode = db.ModerationNone, db.ShareLink
	if !h.canReadFile(sharingRequest("GET", file.FileID, "", nil), file) {
		t.Fatal("unban did not restore sharing")
	}
	delete(repo.users, owner.ID)
	if h.canReadFile(sharingRequest("GET", file.FileID, "", nil), file) {
		t.Fatal("missing owner failed open")
	}
	h.users = nil
	if h.canReadFile(sharingRequest("GET", file.FileID, "", nil), file) {
		t.Fatal("missing user repository failed open")
	}
}

func TestModerationLoginAndExistingJWTs(t *testing.T) {
	repo := newAuthMemoryRepository()
	hash, err := appauth.HashPassword("a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	user := &db.User{ID: uuid.NewString(), Email: "user@example.com", PasswordHash: hash, Role: db.RoleUser, Active: true, TokenVersion: 1}
	repo.users[user.ID] = user
	h := newAuthTestHandler(t, repo, false)
	token, _ := issueTestJWT(t, h, user)
	for _, status := range []string{db.ModerationShadowbanned, db.ModerationNone, db.ModerationBanned, db.ModerationNone} {
		if err := repo.AdminModerateUser(t.Context(), user.ID, status); err != nil {
			t.Fatal(err)
		}
		for _, transport := range []string{transportBearer, transportCookie} {
			req := httptest.NewRequest("POST", "/api/v1/upload", nil)
			if transport == transportBearer {
				req.Header.Set("Authorization", "Bearer "+token)
			} else {
				req.AddCookie(&http.Cookie{Name: h.jwtCookieName(), Value: token})
			}
			response := httptest.NewRecorder()
			h.Authenticate(h.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))).ServeHTTP(response, req)
			want := 204
			if user.TokenVersion != 1 {
				want = 401
			}
			if status == db.ModerationBanned {
				want = 403
			}
			if response.Code != want {
				t.Fatalf("%s %s JWT status=%d want=%d", status, transport, response.Code, want)
			}
		}
		response := httptest.NewRecorder()
		h.APILogin(response, httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"email":"user@example.com","password":"a sufficiently long password"}`)))
		want := 200
		if status == db.ModerationBanned {
			want = 401
		}
		if response.Code != want {
			t.Fatalf("%s login=%d body=%s", status, response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), "moderation") || strings.Contains(response.Body.String(), "shadowbanned") {
			t.Fatal("login discloses moderation status")
		}
	}
	user.ModerationStatus = db.ModerationBanned
	response := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/uploads/direct", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	h.Authenticate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("banned JWT downgraded to guest") })).ServeHTTP(response, req)
	if response.Code != 403 {
		t.Fatal("ban did not reject guest-capable route")
	}
}

func TestModerationOAuthLogin(t *testing.T) {
	for _, status := range []string{db.ModerationBanned, db.ModerationShadowbanned} {
		repo := newAuthMemoryRepository()
		user := &db.User{ID: uuid.NewString(), Email: "user@example.com", Role: db.RoleUser, Active: true, TokenVersion: 1, ModerationStatus: status}
		repo.users[user.ID] = user
		repo.identities["google\x00subject"] = &db.OAuthIdentity{UserID: user.ID, Provider: "google", Subject: "subject", Email: user.Email}
		h := newAuthTestHandler(t, repo, false)
		provider := &fakeOAuthProvider{key: "google", label: "Google", profile: &appauth.OAuthProfile{Subject: "subject", Email: user.Email, EmailVerified: true}}
		h.oauthProviders = map[string]appauth.OAuthProvider{"google": provider}
		_, cookie := startOAuth(t, h, "google", "", nil)
		req := oauthRouteRequest("GET", "/oauth/google/callback?code=code&state="+url.QueryEscape(provider.state), "google")
		req.AddCookie(cookie)
		response := httptest.NewRecorder()
		h.OAuthCallback(response, req)
		issued := false
		for _, c := range response.Result().Cookies() {
			if c.Name == h.jwtCookieName() && c.Value != "" {
				issued = true
			}
		}
		if issued != (status == db.ModerationShadowbanned) {
			t.Fatalf("%s OAuth issued=%v", status, issued)
		}
	}
}

func TestAdminModerationAuthorizationAndForms(t *testing.T) {
	repo := newAuthMemoryRepository()
	admin := &db.User{ID: uuid.NewString(), Email: "admin@example.com", Role: db.RoleAdmin, Active: true, TokenVersion: 1}
	user := &db.User{ID: uuid.NewString(), Email: "user@example.com", Role: db.RoleUser, Active: true, TokenVersion: 1}
	repo.users[admin.ID], repo.users[user.ID] = admin, user
	h := newAuthTestHandler(t, repo, false)
	var err error
	h.templates, err = parseTemplates(os.DirFS("../.."), config.BrandingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.With(h.RequireAdmin).Post("/{id}", h.AdminModerateUser)
	for _, test := range []struct {
		name                    string
		actor                   *db.User
		target, body, transport string
		want                    int
		status                  string
	}{
		{"non-admin", user, user.ID, "moderation_status=banned", transportBearer, 403, ""},
		{"missing-csrf", admin, user.ID, "moderation_status=banned", transportCookie, 403, ""},
		{"invalid", admin, user.ID, "moderation_status=invalid", transportBearer, 200, ""},
		{"missing", admin, user.ID, "", transportBearer, 200, ""},
		{"duplicate", admin, user.ID, "moderation_status=&moderation_status=banned", transportBearer, 200, ""},
		{"self", admin, admin.ID, "moderation_status=banned", transportBearer, 200, ""},
		{"shadowban", admin, user.ID, "moderation_status=shadowbanned&csrf_token=csrf", transportCookie, 303, db.ModerationShadowbanned},
		{"ban", admin, user.ID, "moderation_status=banned", transportBearer, 303, db.ModerationBanned},
		{"restore", admin, user.ID, "moderation_status=", transportBearer, 303, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/"+test.target, strings.NewReader(test.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req = req.WithContext(context.WithValue(req.Context(), identityContextKey{}, &identity{User: test.actor, Transport: test.transport, Claims: &appauth.Claims{CSRF: "csrf"}}))
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)
			if response.Code != test.want || user.ModerationStatus != test.status || admin.ModerationStatus != "" {
				t.Fatalf("status=%d moderation=%s body=%s", response.Code, user.ModerationStatus, response.Body.String())
			}
			if test.want == 200 && !strings.Contains(response.Body.String(), "moderation_status") {
				t.Fatal("moderation form absent from rendered page")
			}
		})
	}
	admin.ModerationStatus = db.ModerationShadowbanned
	req := sharingRequest("GET", user.ID, "", admin)
	response := httptest.NewRecorder()
	h.RequireAdmin(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("shadowbanned admin retained privileges") })).ServeHTTP(response, req)
	if response.Code != 403 {
		t.Fatal("shadowbanned admin not rejected")
	}
}

func TestModerationDirectUploadCompletion(t *testing.T) {
	h, _, storage, file, owner := sharingTestHandler(t)
	direct := &directMemoryStorage{storage}
	h.direct, h.storage = direct, direct
	token, hash, err := newOwnerToken()
	if err != nil {
		t.Fatal(err)
	}
	file.AnonymousSessionToken = hash
	expires := time.Now().Add(time.Hour)
	file.UploadExpiresAt = &expires
	for _, status := range []string{db.ModerationBanned, db.ModerationShadowbanned} {
		owner.ModerationStatus = status
		for _, actor := range []*db.User{nil, owner} {
			file.UploadStatus = "pending"
			body, _ := json.Marshal(map[string]string{"token": token})
			req := sharingRequest("POST", file.FileID, string(body), actor)
			req.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			_, _, ok := h.directUploadIntent(response, req)
			if ok != (status == db.ModerationShadowbanned && actor == owner) {
				t.Fatalf("%s direct intent allowed=%v actor=%v", status, ok, actor)
			}
		}
	}
}

func TestModerationUploadResultsDoNotLeakFileNames(t *testing.T) {
	h, _, _, file, owner := sharingTestHandler(t)
	for _, status := range []string{db.ModerationBanned, db.ModerationShadowbanned} {
		owner.ModerationStatus = status
		for _, actor := range []*db.User{nil, owner} {
			req := sharingRequest("GET", file.FileID, "", actor)
			req.URL.RawQuery = "ids=" + file.FileID + "," + file.FileID
			response := httptest.NewRecorder()
			h.UploadResults(response, req)
			want := 404
			if status == db.ModerationShadowbanned && actor == owner {
				want = 200
			}
			if response.Code != want {
				t.Fatalf("upload results status=%d want=%d", response.Code, want)
			}
			if want == 404 && strings.Contains(response.Body.String(), file.FileName) {
				t.Fatal("results leaked moderated filename")
			}
			if response.Header().Get("Cache-Control") != "private, no-store" {
				t.Fatal("results can be cached")
			}
		}
	}
}
