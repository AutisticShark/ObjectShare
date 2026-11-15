package htmx

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

func frontendFixture(t *testing.T) *frontendAssets {
	t.Helper()
	assets, err := loadFrontend(fstest.MapFS{
		"template/frontend/manifest.json":        {Data: []byte(`{"src/main.ts":{"file":"assets/main-123.js","css":["assets/style-123.css"]}}`)},
		"template/frontend/assets/main-123.js":   {Data: []byte("export {};")},
		"template/frontend/assets/style-123.css": {Data: []byte("body {}")},
	})
	if err != nil {
		t.Fatal(err)
	}
	return assets
}

func TestFrontendProjectionDoesNotExposeDatabaseSecrets(t *testing.T) {
	user := db.User{ID: "id", Email: "owner@example.test", DisplayName: "Owner", PasswordHash: "password-hash-secret", TokenVersion: 99, EmailVerificationHash: "verification-hash-secret", ModerationStatus: db.ModerationShadowbanned}
	user.MFA.Method = "totp"
	data := accountPageData{User: &user, Files: []accountFile{{ID: "file", Name: "name"}}}
	projected, err := frontendValue(reflect.ValueOf(data))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"PasswordHash", "password-hash-secret", "TokenVersion", "EmailVerificationHash", "verification-hash-secret", "ModerationStatus", "shadowbanned", "Recovery", "Ciphertext"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("frontend contains private field %q", forbidden)
		}
	}
	if !strings.Contains(string(encoded), `"Method":"totp"`) {
		t.Fatal("MFA method is missing")
	}
	projected, err = frontendValue(reflect.ValueOf(workspaceFile{accountFile: accountFile{ID: "file", Name: "name"}, Access: "Private"}))
	if err != nil {
		t.Fatal(err)
	}
	fields := projected.(map[string]any)
	if fields["ID"] != "file" || fields["Name"] != "name" || fields["Access"] != "Private" {
		t.Fatalf("embedded display values were lost: %v", fields)
	}
	if _, err := frontendValue(reflect.ValueOf(db.FileList{})); err == nil {
		t.Fatal("raw file models must require a projection")
	}
	if _, err := frontendValue(reflect.ValueOf(db.OAuthIdentity{})); err == nil {
		t.Fatal("unknown database models must require a projection")
	}
}

func TestFrontendRuntimeProjectionRedactsSecretsAndFormatsDurations(t *testing.T) {
	runtime := config.RuntimeConfig{}
	runtime.Auth.OAuth.Google.ClientSecret = "oauth-secret"
	runtime.Email.SMTP.Password = "smtp-secret"
	runtime.S3.AccessKeyID = "storage-access"
	runtime.S3.SecretAccessKey = "storage-secret"
	runtime.Billing.Stripe.SecretKey = "gateway-secret"
	runtime.Encryption.Key = "encryption-secret"
	runtime.RateLimit.Window = config.Duration(time.Minute)
	projected, err := frontendValue(reflect.ValueOf(runtime))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"oauth-secret", "smtp-secret", "storage-access", "storage-secret", "gateway-secret", "encryption-secret"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("runtime credentials were exposed")
		}
	}
	if !strings.Contains(string(encoded), `"Window":"1m0s"`) {
		t.Fatal("duration is not in configuration input format")
	}
	if runtime.Email.SMTP.Password != "smtp-secret" {
		t.Fatal("projection mutated the active configuration")
	}
}

func TestFrontendPayloadIsInertAndPreservesNativeForms(t *testing.T) {
	handler := &Handler{frontend: frontendFixture(t), config: &config.ServiceConfig{Branding: config.BrandingConfig{SiteName: "Custom site"}}}
	page := []byte(`<html><head><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/core@1/tabler.css"><script defer src="/assets/upload.js?v=abc"></script></head><body><div class="page"><form action="/login" method="post"></form></div></body></html>`)
	output, err := handler.frontendPage(page, "login.html", authPageData{Email: `</script><script>alert(1)</script>`})
	if err != nil {
		t.Fatal(err)
	}
	body := string(output)
	for _, expected := range []string{`action="/login" method="post"`, `type="application/json"`, `"Page":"login"`, `"SiteName":"Custom site"`, `/assets/frontend/assets/main-123.js`, `/assets/frontend/assets/style-123.css`, `</script>`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("missing %q: %s", expected, body)
		}
	}
	for _, forbidden := range []string{"alert(1)</script>", "cdn.jsdelivr.net", "/assets/upload.js"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("unsafe or duplicate frontend source %q", forbidden)
		}
	}
	output, err = (&Handler{}).frontendPage(page, "login.html", authPageData{})
	if err != nil || string(output) != string(page) {
		t.Fatal("source-only native fallback changed")
	}
}

func TestFrontendManifestAndAssetBoundary(t *testing.T) {
	if assets, err := loadFrontend(fstest.MapFS{}); err != nil || assets != nil {
		t.Fatal("unbuilt source checkout should keep native pages")
	}
	for _, manifest := range []string{`{`, `{}`, `{"src/main.ts":{"file":"../secret"}}`, `{"src/main.ts":{"file":"assets/missing.js"}}`} {
		if _, err := loadFrontend(fstest.MapFS{"template/frontend/manifest.json": {Data: []byte(manifest)}}); err == nil {
			t.Fatalf("accepted invalid build: %s", manifest)
		}
	}
	handler := &Handler{frontend: frontendFixture(t)}
	for _, test := range []struct {
		path   string
		status int
	}{
		{"/assets/frontend/assets/main-123.js", http.StatusOK},
		{"/assets/frontend/manifest.json", http.StatusNotFound},
		{"/assets/frontend/../config.json", http.StatusNotFound},
		{"/assets/frontend/assets/missing.js", http.StatusNotFound},
	} {
		response := httptest.NewRecorder()
		handler.FrontendAsset(response, httptest.NewRequest(http.MethodGet, test.path, nil))
		if response.Code != test.status {
			t.Fatalf("%s: %d", test.path, response.Code)
		}
		if test.status == http.StatusOK && response.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
			t.Fatal("hashed assets should be immutable")
		}
	}
	if _, err := fs.ReadFile(handler.frontend.files, "assets/main-123.js"); err != nil {
		t.Fatal(err)
	}
}
