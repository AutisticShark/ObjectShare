package htmx

import (
	"testing"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

// A deployment seeded with OBJECTSHARE_STORAGE_SERVICE=R2 must hand the page the
// canonical "r2"; otherwise the frontend cannot select the matching option and
// the browser submits the first one (filesystem) on the next unrelated save,
// silently switching the storage backend.
func TestMixedCaseStorageServiceIsCanonicalInTheDashboardData(t *testing.T) {
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
	user := &db.User{ID: "11111111-1111-4111-8111-111111111111", Email: "admin@example.com", DisplayName: "Admin", Role: db.RoleAdmin, Active: true}
	page, data := renderPage(t, "admin_settings.html", adminSettingsPageData{Version: "t", CSRF: "c", User: user, Config: runtime})
	shown, _ := data["Config"].(map[string]any)
	if page != "admin_settings" || shown["StorageService"] != "r2" {
		t.Fatalf("settings page carries storage service %v for stored %q, want the canonical r2", shown["StorageService"], runtime.StorageService)
	}
}
