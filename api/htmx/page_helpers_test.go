package htmx

import (
	"encoding/json"
	"strings"
	"testing"
)

// pageOf decodes the page name and data that a rendered HTML response carries
// for the frontend.
func pageOf(t *testing.T, body string) (string, map[string]any) {
	t.Helper()
	const open = `<script id="objectshare-page" type="application/json">`
	start := strings.Index(body, open)
	end := strings.LastIndex(body, "</script>")
	if start < 0 || end < start {
		t.Fatalf("response carries no page data: %.300s", body)
	}
	var boot struct {
		Page string
		Data map[string]any
	}
	if err := json.Unmarshal([]byte(body[start+len(open):end]), &boot); err != nil {
		t.Fatalf("decode page data: %v", err)
	}
	return boot.Page, boot.Data
}

// renderPage renders a page context through the production projection.
func renderPage(t *testing.T, name string, data any) (string, map[string]any) {
	t.Helper()
	page, err := (&Handler{}).frontendPage(name, data)
	if err != nil {
		t.Fatalf("render %s: %v", name, err)
	}
	return pageOf(t, string(page))
}
