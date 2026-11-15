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
		"frontend/dist/manifest.json":        {Data: []byte(`{"src/main.ts":{"file":"assets/main-123.js","css":["assets/style-123.css"]}}`)},
		"frontend/dist/assets/main-123.js":   {Data: []byte("export {};")},
		"frontend/dist/assets/style-123.css": {Data: []byte("body {}")},
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

func TestPageShellCarriesOnlyInertDataAndTheBundle(t *testing.T) {
	handler := &Handler{frontend: frontendFixture(t), config: &config.ServiceConfig{Branding: config.BrandingConfig{SiteName: "Custom <site>", Tagline: "Fast \"files\""}}}
	output, err := handler.frontendPage("login.html", authPageData{Email: `</script><script>alert(1)</script>`})
	if err != nil {
		t.Fatal(err)
	}
	body := string(output)
	for _, expected := range []string{"<title>Custom &lt;site&gt;</title>", `content="Fast &#34;files&#34;"`, `<body><div id="objectshare-app"></div><noscript>`, `/assets/frontend/assets/main-123.js`, `/assets/frontend/assets/style-123.css`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("missing %q: %s", expected, body)
		}
	}
	for _, forbidden := range []string{"alert(1)</script>", "cdn.jsdelivr.net", "<form", "class=\"page", "data-bs-theme"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("shell contains %q: %s", forbidden, body)
		}
	}
	page, data := pageOf(t, body)
	if page != "login" || data["Email"] != "</script><script>alert(1)</script>" {
		t.Fatalf("page data did not round-trip: %s %v", page, data)
	}
	if strings.Count(body, "<script") != 2 {
		t.Fatal("the shell must contain only the bundle and the inert data element")
	}
}

func TestPageShellAppliesTheSavedThemeAndContinuesOAuthWithoutScripts(t *testing.T) {
	handler := &Handler{}
	for _, dark := range []bool{false, true} {
		output, err := handler.frontendPage("account.html", accountPageData{User: &db.User{ID: "u", DarkMode: dark}})
		if err != nil {
			t.Fatal(err)
		}
		want := map[bool]string{false: `data-bs-theme="light"`, true: `data-bs-theme="dark"`}[dark]
		if !strings.Contains(string(output), want) {
			t.Fatalf("signed-in first paint must use the saved theme %s", want)
		}
	}
	for location, refresh := range map[string]bool{"/account?message=oauth-linked": true, "//attacker.example": false, "https://attacker.example": false} {
		output, err := handler.frontendPage("oauth_continue.html", struct{ Version, Location string }{"t", location})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(output), `http-equiv="refresh"`) != refresh {
			t.Fatalf("refresh for %q = %v", location, !refresh)
		}
	}
}

func TestFrontendManifestAndAssetBoundary(t *testing.T) {
	if assets, err := loadFrontend(fstest.MapFS{}); err != nil || assets != nil {
		t.Fatal("an unbuilt checkout has no assets; main refuses to serve it")
	}
	for _, manifest := range []string{`{`, `{}`, `{"src/main.ts":{"file":"../secret"}}`, `{"src/main.ts":{"file":"assets/missing.js"}}`} {
		if _, err := loadFrontend(fstest.MapFS{"frontend/dist/manifest.json": {Data: []byte(manifest)}}); err == nil {
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
