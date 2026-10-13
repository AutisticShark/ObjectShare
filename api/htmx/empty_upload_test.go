package htmx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AutisticShark/ObjectShare/db"
)

// An empty file is a bad request, not one that is too large. The direct-upload
// endpoints are covered by TestDirectUploadEndpointsShareRejectionStatuses.
func TestEmptyProxiedUploadIsABadRequest(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	handler := newTestHandler(t, repository, &memoryStorage{objects: make(map[string][]byte)})
	response := httptest.NewRecorder()
	handler.Upload(response, multipartUploadRequest(t, nil))
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "The file is empty") || len(repository.files) != 0 {
		t.Fatalf("empty upload: status=%d body=%q records=%d", response.Code, response.Body.String(), len(repository.files))
	}
}

// A batch rejects an empty or oversized file with the same status as a single
// upload and names the file, instead of returning the internal validator text.
func TestProxiedBatchRejectsFilesLikeSingleUploads(t *testing.T) {
	for name, test := range map[string]struct {
		files  []string
		status int
		want   string
	}{
		"empty":     {[]string{"data", ""}, http.StatusBadRequest, "batch-1.txt is empty. Choose files that contain data."},
		"oversized": {[]string{"data", strings.Repeat("x", int(mebibyte)+1)}, http.StatusRequestEntityTooLarge, "batch-1.txt is larger than the 1.0 MiB per-file limit."},
	} {
		t.Run(name, func(t *testing.T) {
			repository := &memoryRepository{files: make(map[string]*db.FileList)}
			handler := newTestHandler(t, repository, &memoryStorage{objects: make(map[string][]byte)})
			response := httptest.NewRecorder()
			handler.Upload(response, multipartBatchRequest(t, test.files...))
			if response.Code != test.status || strings.TrimSpace(response.Body.String()) != test.want {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
		})
	}
}
