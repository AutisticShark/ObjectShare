package htmx

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/google/uuid"
)

type clientKeyMemoryRepository struct {
	*authMemoryRepository
	vaults map[string]*db.ClientKeyVault
}

func (repo *clientKeyMemoryRepository) ClientKey(_ context.Context, user string) (*db.ClientKeyVault, error) {
	if vault := repo.vaults[user]; vault != nil {
		copy := *vault
		return &copy, nil
	}
	return nil, db.ErrNotFound
}
func (repo *clientKeyMemoryRepository) CreateClientKey(_ context.Context, vault *db.ClientKeyVault) error {
	if repo.vaults[vault.UserID] != nil {
		return db.ErrConflict
	}
	copy := *vault
	repo.vaults[vault.UserID] = &copy
	return nil
}

func testClientVault(user string) *db.ClientKeyVault {
	encoded := func(n int) string { return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, n)) }
	return &db.ClientKeyVault{Version: 1, UserID: user, KeyID: encoded(32), Salt: encoded(16), IV: encoded(12), WrappedKey: encoded(48)}
}

func clientMetadata(vault *db.ClientKeyVault, size int64) string {
	value, _ := json.Marshal(clientEncryptionMetadata{Version: 1, KeyID: vault.KeyID, Salt: vault.KeyID, Size: size})
	return string(value)
}

func TestClientKeyAuthorizationValidationAndImmutableCreation(t *testing.T) {
	h, authRepo, _, _, owner := sharingTestHandler(t)
	repo := &clientKeyMemoryRepository{authMemoryRepository: authRepo, vaults: map[string]*db.ClientKeyVault{}}
	h.repository = repo
	vault := testClientVault(owner.ID)
	body, _ := json.Marshal(vault)
	for _, item := range []struct {
		name   string
		user   *db.User
		csrf   bool
		body   string
		status int
	}{
		{"anonymous", nil, true, string(body), 401},
		{"csrf", owner, false, string(body), 403},
		{"wrong account", &db.User{ID: uuid.NewString(), Active: true}, true, string(body), 400},
		{"malformed", owner, true, `{"version":99}`, 400},
		{"create", owner, true, string(body), 201},
		{"replace", owner, true, string(body), 409},
	} {
		t.Run(item.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/account/encryption", strings.NewReader(item.body))
			r.Header.Set("Content-Type", "application/json")
			if item.user != nil {
				r = r.WithContext(context.WithValue(r.Context(), identityContextKey{}, &identity{User: item.user, Claims: &appauth.Claims{CSRF: "csrf"}, Transport: transportCookie}))
			}
			if item.csrf {
				r.Header.Set("X-CSRF-Token", "csrf")
			}
			w := httptest.NewRecorder()
			h.ClientKey(w, r)
			if w.Code != item.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
		})
	}
	for _, user := range []*db.User{owner, {ID: uuid.NewString(), Active: true}} {
		r := sharingRequest("GET", "unused", "", user)
		w := httptest.NewRecorder()
		h.ClientKey(w, r)
		if w.Code != 200 || strings.Contains(w.Body.String(), vault.WrappedKey) != (user.ID == owner.ID) {
			t.Fatalf("vault isolation failed: %d %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
			t.Fatal("key response is cacheable")
		}
	}
}

func TestClientEncryptionUploadValidationAcrossPaths(t *testing.T) {
	for _, path := range []string{"proxied", "proxied-batch", "direct", "direct-batch"} {
		for _, kind := range []string{"valid", "missing", "wrong-key", "size", "unknown-version", "guest"} {
			t.Run(path+"/"+kind, func(t *testing.T) {
				h, authRepo, _, _, owner := sharingTestHandler(t)
				// Remove the fixture's existing file so rejected uploads must leave an empty repository.
				authRepo.files = map[string]*db.FileList{}
				vault := testClientVault(owner.ID)
				h.repository = &clientKeyMemoryRepository{authMemoryRepository: authRepo, vaults: map[string]*db.ClientKeyVault{owner.ID: vault}}
				metadata := clientMetadata(vault, 3)
				switch kind {
				case "missing":
					metadata = ""
				case "wrong-key":
					metadata = strings.Replace(metadata, vault.KeyID, base64.RawURLEncoding.EncodeToString(make([]byte, 32)), 1)
				case "size":
					metadata = clientMetadata(vault, 4)
				case "unknown-version":
					metadata = strings.Replace(metadata, `"version":1`, `"version":2`, 1)
				}
				var r *http.Request
				count := 1
				if strings.HasSuffix(path, "batch") {
					count = 2
				}
				if strings.HasPrefix(path, "proxied") {
					body := new(bytes.Buffer)
					form := multipart.NewWriter(body)
					for range count {
						_ = form.WriteField("client_encryption", metadata)
						part, _ := form.CreateFormFile("file", "encrypted.bin")
						_, _ = part.Write(make([]byte, 19))
					}
					_ = form.Close()
					r = httptest.NewRequest("POST", "/api/v1/upload", body)
					r.Header.Set("Content-Type", form.FormDataContentType())
				} else {
					item := directUploadRequest{FileName: "encrypted.bin", FileSize: 19, ContentType: "application/octet-stream", ClientEncryption: metadata}
					var input any = item
					if count == 2 {
						input = directUploadBatchRequest{Files: []directUploadRequest{item, item}}
					}
					body, _ := json.Marshal(input)
					r = httptest.NewRequest("POST", "/api/v1/uploads/direct", bytes.NewReader(body))
					h.direct = &directMemoryStorage{memoryStorage: &memoryStorage{objects: map[string][]byte{}}}
					h.directPolicy.MaxSize = mebibyte
				}
				if kind != "guest" {
					r = r.WithContext(context.WithValue(r.Context(), identityContextKey{}, &identity{User: owner, Claims: &appauth.Claims{CSRF: "csrf"}, Transport: transportBearer}))
				}
				w := httptest.NewRecorder()
				switch path {
				case "proxied", "proxied-batch":
					h.Upload(w, r)
				case "direct":
					h.BeginDirectUpload(w, r)
				case "direct-batch":
					h.BeginDirectUploadBatch(w, r)
				}
				if kind == "valid" {
					if w.Code != 201 && w.Code != 303 {
						t.Fatalf("valid upload: %d %s", w.Code, w.Body.String())
					}
					if len(authRepo.files) != count {
						t.Fatal("missing uploaded records")
					}
					for _, file := range authRepo.files {
						if file.ClientEncryption != metadata || file.ContentType != "application/octet-stream" || file.FileOwner == nil || *file.FileOwner != owner.ID {
							t.Fatal("encryption metadata or ownership lost")
						}
					}
				} else if w.Code != 400 || len(authRepo.files) != 0 {
					t.Fatalf("invalid upload: %d files=%d %s", w.Code, len(authRepo.files), w.Body.String())
				}
			})
		}
	}
}

func TestClientEncryptedDownloadsPreserveCiphertextAndAccess(t *testing.T) {
	h, _, storage, file, owner := sharingTestHandler(t)
	file.ClientEncryption = clientMetadata(testClientVault(owner.ID), 3)
	file.FileSize = 19
	file.ShareMode = db.SharePrivate
	storage.objects[file.FileID] = bytes.Repeat([]byte{9}, 19)
	for _, user := range []*db.User{owner, nil, {ID: uuid.NewString(), Active: true, Role: db.RoleAdmin}} {
		w := httptest.NewRecorder()
		h.Download(w, sharingRequest("POST", file.FileID, "", user))
		if user != owner {
			if w.Code != 404 {
				t.Fatalf("unauthorized encrypted download: %d", w.Code)
			}
			continue
		}
		if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), storage.objects[file.FileID]) || !strings.Contains(w.Header().Get("Content-Disposition"), ".objectshare") {
			t.Fatal("download did not return ciphertext")
		}
	}
	// The legacy server cipher may wrap the client ciphertext as another layer.
	cfg := &config.ServiceConfig{MaxFileSize: 1, StorageService: "filesystem", Encryption: &config.EncryptionConfig{Enabled: true, Method: "aes-256-gcm", Key: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="}}
	layered := newTestHandlerConfig(t, cfg, h.repository.(*authMemoryRepository).memoryRepository, storage)
	layered.users = h.users
	ciphertext := append([]byte{}, storage.objects[file.FileID]...)
	storage.objects[file.FileID], _ = layered.cipher.Encrypt(ciphertext)
	file.IsEncrypted = true
	w := httptest.NewRecorder()
	layered.Download(w, sharingRequest("POST", file.FileID, "", owner))
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), ciphertext) {
		t.Fatal("server layer did not preserve client ciphertext")
	}
}

func TestBrowserClientCryptography(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node is required for browser Web Crypto tests")
	}
	if output, err := exec.CommandContext(t.Context(), node, "--test", "../../tests/client-encryption.test.cjs").CombinedOutput(); err != nil {
		t.Fatalf("Web Crypto tests: %v\n%s", err, output)
	}
}
