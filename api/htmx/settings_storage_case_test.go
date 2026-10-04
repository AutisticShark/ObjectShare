package htmx

import (
	"bytes"
	"os"
	"regexp"
	"testing"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

// A deployment seeded with OBJECTSHARE_STORAGE_SERVICE=R2 must render with R2
// selected; otherwise the browser submits the first option (filesystem) on the
// next unrelated save and silently switches the storage backend.
func TestMixedCaseStorageServiceStaysSelectedInTheDashboard(t *testing.T) {
	t.Setenv("OBJECTSHARE_JWT_SECRET", "settings-test-jwt-secret-with-at-least-32-bytes")
	t.Setenv("OBJECTSHARE_SETTINGS_KEY", "settings-test-settings-key-with-at-least-32-bytes")
	t.Setenv("OBJECTSHARE_STORAGE_SERVICE", " R2 ")
	t.Setenv("OBJECTSHARE_R2_BUCKET_NAME", "bucket")
	t.Setenv("OBJECTSHARE_R2_ACCOUNT_ID", "account")
	t.Setenv("OBJECTSHARE_R2_ACCESS_KEY_ID", "access")
	t.Setenv("OBJECTSHARE_R2_SECRET_ACCESS_KEY", "secret")
	cfg, err := config.Load("../../config.json.example")
	if err != nil {
		t.Fatalf("mixed-case storage service rejected: %v", err)
	}
	runtime := config.RuntimeFromService(cfg)
	if runtime.StorageService != "r2" {
		t.Fatalf("seeded storage_service = %q, want the canonical r2", runtime.StorageService)
	}
	// A revision stored by an earlier release keeps its original spelling; the
	// dashboard normalizes it before rendering.
	runtime.StorageService = "R2"
	runtime, err = config.NormalizeRuntime(cfg, runtime)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseTemplates(os.DirFS("../.."), config.BrandingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	user := &db.User{ID: "11111111-1111-4111-8111-111111111111", Email: "admin@example.com", DisplayName: "Admin", Role: db.RoleAdmin, Active: true}
	var page bytes.Buffer
	if err := parsed.ExecuteTemplate(&page, "admin_settings.html", adminSettingsPageData{Version: "t", CSRF: "c", User: user, Config: runtime}); err != nil {
		t.Fatal(err)
	}
	selectBlock := regexp.MustCompile(`(?s)<select class="form-select" name="storage_service">.*?</select>`).Find(page.Bytes())
	if !regexp.MustCompile(`value="r2"\s+selected`).Match(selectBlock) {
		t.Fatalf("storage select has no selected option for stored %q:\n%s", runtime.StorageService, selectBlock)
	}
}
