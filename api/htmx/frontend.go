package htmx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io/fs"
	"net/http"
	"path"
	"reflect"
	"strings"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

// FrontendManifest is where the Vite build manifest lives inside the embedded
// file system passed to New.
const FrontendManifest = "frontend/dist/manifest.json"

type frontendManifestEntry struct {
	File string   `json:"file"`
	CSS  []string `json:"css"`
}

type frontendAssets struct {
	files fs.FS
	entry frontendManifestEntry
}

func loadFrontend(files fs.FS) (*frontendAssets, error) {
	if files == nil {
		return nil, nil
	}
	manifest, err := fs.ReadFile(files, FrontendManifest)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var entries map[string]frontendManifestEntry
	if err := json.Unmarshal(manifest, &entries); err != nil {
		return nil, fmt.Errorf("decode frontend manifest: %w", err)
	}
	entry, ok := entries["src/main.ts"]
	if !ok || !validFrontendPath(entry.File) || len(entry.CSS) == 0 {
		return nil, fmt.Errorf("frontend manifest has no valid entry")
	}
	dist := path.Dir(FrontendManifest)
	for _, file := range append([]string{entry.File}, entry.CSS...) {
		if !validFrontendPath(file) {
			return nil, fmt.Errorf("invalid frontend asset path")
		}
		if _, err := fs.Stat(files, dist+"/"+file); err != nil {
			return nil, fmt.Errorf("missing frontend asset: %w", err)
		}
	}
	sub, err := fs.Sub(files, dist)
	if err != nil {
		return nil, err
	}
	return &frontendAssets{files: sub, entry: entry}, nil
}

func validFrontendPath(file string) bool {
	return strings.HasPrefix(file, "assets/") && fs.ValidPath(file) && !strings.ContainsAny(file, "\\\"'<>?#")
}

func (handler *Handler) FrontendAsset(writer http.ResponseWriter, request *http.Request) {
	if handler.frontend == nil {
		http.NotFound(writer, request)
		return
	}
	file := strings.TrimPrefix(request.URL.Path, "/assets/frontend/")
	if !validFrontendPath(file) {
		http.NotFound(writer, request)
		return
	}
	data, err := fs.ReadFile(handler.frontend.files, file)
	if err != nil {
		http.NotFound(writer, request)
		return
	}
	writer.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	http.ServeContent(writer, request, path.Base(file), time.Time{}, bytes.NewReader(data))
}

// frontendPage renders the HTML shell for a page: document metadata, the
// bundle, an empty mount point, and the page data as inert JSON.
func (handler *Handler) frontendPage(name string, data any) ([]byte, error) {
	props, err := frontendValue(reflect.ValueOf(data))
	if err != nil {
		return nil, err
	}
	fields, _ := props.(map[string]any)
	if fields == nil {
		fields = map[string]any{}
	}
	switch context := data.(type) {
	case mfaPageData:
		if context.User != nil {
			fields["HasPassword"] = context.User.PasswordHash != ""
			fields["RecoveryCount"] = len(context.User.MFA.Recovery)
		}
	case adminPageData:
		fields["HasPassword"] = context.User != nil && context.User.PasswordHash != ""
	}
	branding := config.BrandingConfig{}.Display()
	if handler.config != nil {
		branding = handler.config.Branding.Display()
	}
	publicBranding, err := frontendValue(reflect.ValueOf(branding))
	if err != nil {
		return nil, err
	}
	page := strings.TrimSuffix(name, ".html")
	// encoding/json escapes <, >, and &, so text such as a filename containing
	// "</script>" cannot end the data element. The payload is never executed.
	payload, err := json.Marshal(struct {
		Page     string
		Data     any
		Branding any
	}{Page: page, Data: fields, Branding: publicBranding})
	if err != nil {
		return nil, err
	}

	var out strings.Builder
	out.WriteString(`<!doctype html><html lang="en"`)
	// Signed-in pages carry the saved theme so the first paint already matches
	// it; guests follow the operating system through CSS until the app starts.
	if user, ok := fields["User"].(map[string]any); ok {
		theme := "light"
		if dark, _ := user["DarkMode"].(bool); dark {
			theme = "dark"
		}
		fmt.Fprintf(&out, ` data-bs-theme="%s"`, theme)
	}
	out.WriteString(`><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">`)
	out.WriteString(`<meta name="color-scheme" content="light dark">`)
	fmt.Fprintf(&out, `<title>%s</title>`, html.EscapeString(branding.SiteName))
	if branding.Tagline != "" {
		fmt.Fprintf(&out, `<meta name="description" content="%s">`, html.EscapeString(branding.Tagline))
	}
	if branding.FaviconURL != "" {
		fmt.Fprintf(&out, `<link rel="icon" href="%s">`, html.EscapeString(branding.FaviconURL))
	}
	if page == "oauth_continue" {
		// The OAuth callback finishes with a same-site navigation so SameSite=Strict
		// cookies are sent; it must not depend on the bundle loading.
		if location, _ := fields["Location"].(string); strings.HasPrefix(location, "/") && !strings.HasPrefix(location, "//") {
			fmt.Fprintf(&out, `<meta http-equiv="refresh" content="0;url=%s">`, html.EscapeString(location))
		}
	}
	if handler.frontend != nil {
		for _, css := range handler.frontend.entry.CSS {
			fmt.Fprintf(&out, `<link rel="stylesheet" href="/assets/frontend/%s">`, html.EscapeString(css))
		}
		// blocking="render" keeps the empty shell from ever painting: the first
		// frame is the mounted app, so a page change (and its view transition)
		// goes straight from the old page to the new one.
		fmt.Fprintf(&out, `<script type="module" blocking="render" src="/assets/frontend/%s"></script>`, html.EscapeString(handler.frontend.entry.File))
	}
	fmt.Fprintf(&out, `</head><body><div id="objectshare-app"></div><noscript><p class="noscript">%s requires JavaScript.</p></noscript>`, html.EscapeString(branding.SiteName))
	out.WriteString(`<script id="objectshare-page" type="application/json">`)
	out.Write(payload)
	out.WriteString(`</script></body></html>`)
	return []byte(out.String()), nil
}

// Page contexts contain database models as well as presentation values. Project
// those models explicitly so adding a database column cannot expose a secret.
func frontendValue(value reflect.Value) (any, error) {
	if !value.IsValid() {
		return nil, nil
	}
	if value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil, nil
		}
		return frontendValue(value.Elem())
	}
	if value.CanInterface() {
		switch typed := value.Interface().(type) {
		case time.Time:
			return typed.UTC().Format(time.RFC3339Nano), nil
		case config.Duration:
			return typed.String(), nil
		case db.User:
			return frontendValue(reflect.ValueOf(struct {
				ID, Email, DisplayName, Role    string
				Active, DarkMode, IsPaid        bool
				UploadQuotaBytes, CreditBalance int64
				EmailVerifiedAt, LastLoginAt    *time.Time
				CreatedAt                       time.Time
				MFA                             struct{ Method string }
			}{typed.ID, typed.Email, typed.DisplayName, typed.Role,
				typed.Active, typed.DarkMode, typed.IsPaid, typed.UploadQuotaBytes, typed.CreditBalance,
				typed.EmailVerifiedAt, typed.LastLoginAt, typed.CreatedAt, struct{ Method string }{typed.MFA.Method}}))
		case db.Invoice:
			return projectFrontendFields(value, "ID", "Kind", "Name", "Description", "Email", "Credits", "AmountMinor", "Currency", "DurationDays", "StorageQuotaBytes", "RetentionDays", "DirectLinks", "Status", "Gateway", "PaymentID", "PaidAt", "CreatedAt", "ExpiresAt", "EmailSentAt", "PeriodStart")
		case db.PaidPlan:
			return projectFrontendFields(value, "ID", "Name", "Description", "StorageQuotaBytes", "RetentionDays", "DirectLinks", "Price", "DurationDays", "Active", "SortOrder")
		case db.FileList:
			return nil, fmt.Errorf("raw file records must not be serialized into frontend pages")
		case config.RuntimeConfig:
			redactRuntimeSecrets(&typed)
			return frontendStruct(reflect.ValueOf(typed))
		}
	}
	switch value.Kind() {
	case reflect.Struct:
		if value.Type().PkgPath() == "github.com/AutisticShark/ObjectShare/db" {
			if _, ok := value.Interface().(db.Overview); !ok {
				return nil, fmt.Errorf("database model %s has no frontend projection", value.Type().Name())
			}
		}
		return frontendStruct(value)
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String {
			return nil, fmt.Errorf("unsupported frontend map key %s", value.Type().Key())
		}
		result := make(map[string]any, value.Len())
		for _, key := range value.MapKeys() {
			item, err := frontendValue(value.MapIndex(key))
			if err != nil {
				return nil, err
			}
			result[key.String()] = item
		}
		return result, nil
	case reflect.Slice, reflect.Array:
		items := make([]any, value.Len())
		for i := range items {
			item, err := frontendValue(value.Index(i))
			if err != nil {
				return nil, err
			}
			items[i] = item
		}
		return items, nil
	case reflect.String:
		return value.String(), nil
	case reflect.Bool:
		return value.Bool(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return value.Int(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return value.Uint(), nil
	case reflect.Float32, reflect.Float64:
		return value.Float(), nil
	default:
		return nil, fmt.Errorf("unsupported frontend value %s", value.Kind())
	}
}

func frontendStruct(value reflect.Value) (map[string]any, error) {
	result := make(map[string]any)
	for i := 0; i < value.NumField(); i++ {
		field := value.Type().Field(i)
		if !field.IsExported() && !field.Anonymous {
			continue
		}
		projected, err := frontendValue(value.Field(i))
		if err != nil {
			return nil, err
		}
		if field.Anonymous {
			if fields, ok := projected.(map[string]any); ok {
				for key, item := range fields {
					result[key] = item
				}
				continue
			}
		}
		result[field.Name] = projected
	}
	return result, nil
}

func projectFrontendFields(value reflect.Value, names ...string) (map[string]any, error) {
	result := make(map[string]any, len(names))
	for _, name := range names {
		field, err := frontendValue(value.FieldByName(name))
		if err != nil {
			return nil, err
		}
		result[name] = field
	}
	return result, nil
}
