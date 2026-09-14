package htmx

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRenderFailureDoesNotCommitPartialPageOrSuccess(t *testing.T) {
	handler := newAuthTestHandler(t, newAuthMemoryRepository(), false)
	handler.templates = template.Must(template.New("broken").Parse(`<form>partial-sensitive-output{{.MissingField}}</form>`))
	for _, status := range []int{http.StatusOK, http.StatusPaymentRequired} {
		response := httptest.NewRecorder()
		handler.renderStatus(response, status, "broken", struct{}{})
		if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "partial-sensitive-output") || strings.Contains(response.Body.String(), "MissingField") {
			t.Fatalf("partial template or internal error escaped: %d %s", response.Code, response.Body.String())
		}
		if response.Header().Get("Cache-Control") != "private, no-store" || !strings.HasPrefix(response.Header().Get("Content-Type"), "text/plain") {
			t.Fatalf("unsafe error headers: %v", response.Header())
		}
	}
}

func TestRenderStatusCommitsCompleteEscapedPage(t *testing.T) {
	handler := newAuthTestHandler(t, newAuthMemoryRepository(), false)
	handler.templates = template.Must(template.New("page").Parse(`<html><body>{{.}}</body></html>`))
	response := httptest.NewRecorder()
	handler.renderStatus(response, http.StatusConflict, "page", "<script>untrusted</script>")
	if response.Code != http.StatusConflict || response.Body.String() != "<html><body>&lt;script&gt;untrusted&lt;/script&gt;</body></html>" || response.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("rendered response: %d %s", response.Code, response.Body.String())
	}
}
