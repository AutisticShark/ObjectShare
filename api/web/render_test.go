package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AutisticShark/ObjectShare/db"
)

func TestRenderFailureDoesNotCommitPartialPageOrSuccess(t *testing.T) {
	handler := newAuthTestHandler(t, newAuthMemoryRepository(), false)
	// Raw database models have no frontend projection, so putting one into a
	// page context must fail the whole render instead of leaking its columns.
	for name, data := range map[string]any{
		"file record":    struct{ File db.FileList }{db.FileList{FileName: "partial-sensitive-output"}},
		"unknown record": struct{ Identity db.OAuthIdentity }{db.OAuthIdentity{}},
	} {
		for _, status := range []int{http.StatusOK, http.StatusPaymentRequired} {
			response := httptest.NewRecorder()
			handler.renderStatus(response, status, "broken.html", data)
			if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "partial-sensitive-output") || strings.Contains(response.Body.String(), "objectshare-page") || strings.Contains(response.Body.String(), "OAuthIdentity") || strings.Contains(response.Body.String(), "FileList") {
				t.Fatalf("%s: partial page or internal error escaped: %d %s", name, response.Code, response.Body.String())
			}
			if response.Header().Get("Cache-Control") != "private, no-store" || !strings.HasPrefix(response.Header().Get("Content-Type"), "text/plain") {
				t.Fatalf("%s: unsafe error headers: %v", name, response.Header())
			}
		}
	}
}

func TestRenderStatusCommitsCompleteEscapedPage(t *testing.T) {
	handler := newAuthTestHandler(t, newAuthMemoryRepository(), false)
	const untrusted = "</script><script>untrusted()</script>"
	response := httptest.NewRecorder()
	handler.renderStatus(response, http.StatusConflict, "login.html", authPageData{Error: untrusted})
	body := response.Body.String()
	if response.Code != http.StatusConflict || response.Header().Get("Content-Type") != "text/html; charset=utf-8" || response.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("rendered response: %d %v", response.Code, response.Header())
	}
	if strings.Contains(body, untrusted) || strings.Contains(body, "<script>untrusted") {
		t.Fatalf("untrusted text was not escaped: %s", body)
	}
	if !strings.HasPrefix(body, "<!doctype html>") || !strings.HasSuffix(body, "</html>") {
		t.Fatalf("incomplete document: %s", body)
	}
	if page, data := pageOf(t, body); page != "login" || data["Error"] != untrusted {
		t.Fatalf("page data did not round-trip: %s %v", page, data)
	}
}
