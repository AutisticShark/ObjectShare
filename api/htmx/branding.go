package htmx

import (
	"bytes"
	"html/template"
	"io/fs"
	"net/http"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
)

// Capture active branding once, just like the other restart-only settings.
// A shared template function keeps every page on the same branding revision.
func parseTemplates(files fs.FS, branding config.BrandingConfig) (*template.Template, error) {
	branding = branding.Display()
	return template.New("").Funcs(template.FuncMap{
		"branding": func() config.BrandingConfig { return branding },
	}).ParseFS(files, "template/*.html")
}

func (handler *Handler) BrandingImageSources() []string {
	return handler.config.Branding.ImageSources()
}

func (handler *Handler) BrandingStyles(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "text/css; charset=utf-8")
	writer.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeContent(writer, request, "branding.css", time.Time{}, bytes.NewReader(handler.brandingCSS))
}
