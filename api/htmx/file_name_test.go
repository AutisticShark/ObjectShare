package htmx

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/AutisticShark/ObjectShare/db"
	"github.com/google/uuid"
)

// Invisible format characters can disguise a name: with a right-to-left
// override, "invoice\u202Efdp.exe" displays as "invoiceexe.pdf".
func TestSafeFileNameRejectsBidiAndFormatCharacters(t *testing.T) {
	for _, value := range []string{"invoice\u202Efdp.exe", "a\u202Ab.txt", "a\u2066b.txt", "a\u2069b.txt", "a\u200Fb.txt", "a\u061Cb.txt", "a\uFEFFb.txt", "a\u00ADb.txt"} {
		if got, err := safeFileName(value); err == nil {
			t.Errorf("safeFileName(%q) accepted %q", value, got)
		}
	}
	// Joiners are ordinary text in several scripts and in emoji sequences.
	for _, value := range []string{"\u0645\u06CC\u200C\u062E\u0648\u0627\u0647\u0645.txt", "family-\U0001F468\u200D\U0001F469.png", "r\u00E9sum\u00E9.pdf"} {
		if _, err := safeFileName(value); err != nil {
			t.Errorf("safeFileName(%q) rejected a legitimate name: %v", value, err)
		}
	}
}

func TestUploadAndRenameRejectBidiOverrideNames(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	handler := newTestHandler(t, repository, &memoryStorage{objects: make(map[string][]byte)})
	body := new(bytes.Buffer)
	form := multipart.NewWriter(body)
	part, err := form.CreateFormFile("file", "invoice\u202Efdp.exe")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("hello"))
	_ = form.Close()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/upload", body)
	request.Header.Set("Content-Type", form.FormDataContentType())
	response := httptest.NewRecorder()
	handler.Upload(response, request)
	if response.Code != http.StatusBadRequest || len(repository.files) != 0 {
		t.Fatalf("bidi-override upload status = %d, records = %d", response.Code, len(repository.files))
	}

	token, hash, err := newOwnerToken()
	if err != nil {
		t.Fatal(err)
	}
	file := &db.FileList{FileID: uuid.NewString(), AnonymousSessionToken: hash, FileName: "invoice.pdf", FileSize: 5, UploadStatus: "complete"}
	repository.files[file.FileID] = file
	rename := sharingRequest(http.MethodPost, file.FileID, url.Values{"name": {"invoice\u202Efdp.exe"}}.Encode(), nil)
	rename.AddCookie(ownerCookie(file.FileID, token, false, 0))
	response = httptest.NewRecorder()
	handler.Update(response, rename)
	if response.Code != http.StatusBadRequest || file.FileName != "invoice.pdf" {
		t.Fatalf("bidi-override rename status = %d, name = %q", response.Code, file.FileName)
	}
}

func TestOAuthDisplayNameDropsFormatCharacters(t *testing.T) {
	if name := oauthDisplayName("Eve\u202Elive", "Google"); name != "Evelive" {
		t.Fatalf("oauthDisplayName kept or rejected a bidi override: %q", name)
	}
}
