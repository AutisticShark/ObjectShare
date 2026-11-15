package web

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// csrfOf returns the CSRF token that a rendered page hands to the frontend.
func csrfOf(t *testing.T, body string) string {
	t.Helper()
	_, data := pageOf(t, body)
	token, _ := data["CSRF"].(string)
	if token == "" {
		t.Fatalf("page carries no CSRF token: %.300s", body)
	}
	return token
}

// continueLocation returns the destination of an OAuth continue page, or ""
// when body is not one.
func continueLocation(body string) string {
	_, data, ok := decodePage(body)
	if !ok {
		return ""
	}
	location, _ := data["Location"].(string)
	return location
}

// pageText returns every string that a rendered page carries as data, so that
// message assertions do not depend on how JSON escapes <, > and &. A body that
// is not a rendered page (a plain-text error, for example) is returned as is.
func pageText(body string) string {
	_, data, ok := decodePage(body)
	if !ok {
		return body
	}
	var out []string
	var walk func(value any)
	walk = func(value any) {
		switch typed := value.(type) {
		case string:
			out = append(out, typed)
		case []any:
			for _, item := range typed {
				walk(item)
			}
		case map[string]any:
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				walk(typed[key])
			}
		}
	}
	walk(data)
	return strings.Join(out, "\n")
}

func decodePage(body string) (string, map[string]any, bool) {
	const open = `<script id="objectshare-page" type="application/json">`
	start := strings.Index(body, open)
	end := strings.LastIndex(body, "</script>")
	if start < 0 || end < start {
		return "", nil, false
	}
	var boot struct {
		Page string
		Data map[string]any
	}
	if json.Unmarshal([]byte(body[start+len(open):end]), &boot) != nil {
		return "", nil, false
	}
	return boot.Page, boot.Data, true
}
