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
