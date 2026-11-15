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
	"regexp"
	"strings"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

type frontendManifestEntry struct {
	File string   `json:"file"`
	CSS  []string `json:"css"`
}

type frontendAssets struct {
	files fs.FS
	entry frontendManifestEntry
}

func loadFrontend(files fs.FS) (*frontendAssets, error) {
	manifest, err := fs.ReadFile(files, "template/frontend/manifest.json")
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
	for _, file := range append([]string{entry.File}, entry.CSS...) {
		if !validFrontendPath(file) {
			return nil, fmt.Errorf("invalid frontend asset path")
		}
		if _, err := fs.Stat(files, "template/frontend/"+file); err != nil {
			return nil, fmt.Errorf("missing frontend asset: %w", err)
		}
	}
	sub, err := fs.Sub(files, "template/frontend")
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

var frontendScripts = regexp.MustCompile(`(?s)<script\b[^>]*\bsrc="(?:/assets/[^\"]+|https://cdn\.jsdelivr\.net/[^\"]+|https://challenges\.cloudflare\.com/[^\"]+)"[^>]*>\s*</script>`)
var frontendCDNStyle = regexp.MustCompile(`(?s)<link\s+rel="stylesheet"\s+href="https://cdn\.jsdelivr\.net/[^\"]+"[^>]*>`)

func (handler *Handler) frontendPage(page []byte, name string, data any) ([]byte, error) {
	if handler.frontend == nil || !strings.HasSuffix(name, ".html") {
		return page, nil
	}
	props, err := frontendValue(reflect.ValueOf(data))
	if err != nil {
		return nil, err
	}
	branding := config.BrandingConfig{}.Display()
	if handler.config != nil {
		branding = handler.config.Branding.Display()
	}
	if fields, ok := props.(map[string]any); ok {
		switch context := data.(type) {
		case mfaPageData:
			if context.User != nil {
				fields["HasPassword"] = context.User.PasswordHash != ""
				fields["RecoveryCount"] = len(context.User.MFA.Recovery)
			}
		case adminPageData:
			fields["HasPassword"] = context.User != nil && context.User.PasswordHash != ""
		}
	}
	publicBranding, err := frontendValue(reflect.ValueOf(branding))
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(struct {
		Page     string
		Data     any
		Branding any
	}{Page: strings.TrimSuffix(name, ".html"), Data: props, Branding: publicBranding})
	if err != nil {
		return nil, err
	}
	// encoding/json escapes HTML delimiters, including a closing script tag in
	// a filename. The payload is inert data, never executable JavaScript.
	boot := append([]byte(`<script id="objectshare-page" type="application/json">`), payload...)
	boot = append(boot, []byte(`</script>`)...)
	page = frontendScripts.ReplaceAll(page, nil)
	page = frontendCDNStyle.ReplaceAll(page, nil)
	var head strings.Builder
	for _, css := range handler.frontend.entry.CSS {
		fmt.Fprintf(&head, `<link rel="stylesheet" href="/assets/frontend/%s">`, html.EscapeString(css))
	}
	fmt.Fprintf(&head, `<script type="module" src="/assets/frontend/%s"></script>`, html.EscapeString(handler.frontend.entry.File))
	page = bytes.Replace(page, []byte("</head>"), []byte(head.String()+"</head>"), 1)
	if bytes.Contains(page, []byte("</body>")) {
		page = bytes.Replace(page, []byte("</body>"), append(boot, []byte("</body>")...), 1)
	} else {
		page = append(page, boot...)
	}
	return page, nil
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
