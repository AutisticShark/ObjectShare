package htmx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/AutisticShark/ObjectShare/service"
)

// Simulate completion committing after a handler reads pending state but before
// it claims deletion. No timing assumptions or concurrent mock map access.
type completionBeforeDeletionRepository struct {
	db.Repository
}

func (repo completionBeforeDeletionRepository) ClaimPendingUploadDeletion(ctx context.Context, id string) error {
	if err := repo.Repository.CompleteUpload(ctx, id); err != nil {
		return err
	}
	return repo.Repository.ClaimPendingUploadDeletion(ctx, id)
}

func TestStaleUploadDeletionCannotRemoveCompletedFile(t *testing.T) {
	for _, path := range []string{"abort", "expired authorization", "expiry cleanup", "size mismatch"} {
		t.Run(path, func(t *testing.T) {
			handler, repo, storage, file, owner := sharingTestHandler(t)
			direct := &directMemoryStorage{storage}
			handler.direct, handler.storage = direct, direct
			handler.repository = completionBeforeDeletionRepository{repo}
			token, hash, err := newOwnerToken()
			if err != nil {
				t.Fatal(err)
			}
			file.AnonymousSessionToken, file.UploadStatus = hash, "pending"
			expires := time.Now().Add(time.Hour)
			if path == "expired authorization" || path == "expiry cleanup" {
				expires = time.Now().Add(-time.Hour)
			}
			file.UploadExpiresAt = &expires
			body, _ := json.Marshal(map[string]string{"token": token})
			request := sharingRequest("POST", file.FileID, string(body), owner)
			response := httptest.NewRecorder()
			switch path {
			case "abort":
				handler.AbortDirectUpload(response, request)
				if response.Code != 404 {
					t.Fatalf("stale abort status=%d", response.Code)
				}
			case "expired authorization":
				handler.CompleteDirectUpload(response, request)
			case "expiry cleanup":
				handler.sweepExpiredUploads(request.Context())
			case "size mismatch":
				file.FileSize++
				handler.CompleteDirectUpload(response, request)
			}
			persisted, err := repo.Get(t.Context(), file.FileID)
			if err != nil || persisted.UploadStatus != "complete" || string(storage.objects[file.FileID]) != "secret" {
				t.Fatalf("stale %s removed a completed upload: file=%+v err=%v", path, persisted, err)
			}
		})
	}
}

type interruptedDeletionStorage struct {
	*memoryStorage
	repo db.Repository
	fail bool
	t    *testing.T
}

func (storage *interruptedDeletionStorage) Delete(ctx context.Context, id string) error {
	if err := storage.repo.CompleteUpload(ctx, id); !errors.Is(err, db.ErrNotFound) {
		storage.t.Fatalf("completion must fail before object deletion, got %v", err)
	}
	if storage.fail {
		return io.ErrUnexpectedEOF
	}
	return storage.memoryStorage.Delete(ctx, id)
}

func TestFailedUploadDeletionRetainsQuotaAndCleanupRetries(t *testing.T) {
	handler, repo, storage, file, owner := sharingTestHandler(t)
	file.UploadStatus = "pending"
	expires := time.Now().Add(time.Hour)
	file.UploadExpiresAt = &expires
	repo.quotaBytes = map[string]int64{owner.ID: file.FileSize}
	fault := &interruptedDeletionStorage{memoryStorage: storage, repo: repo, fail: true, t: t}
	handler.storage = fault
	if err := handler.deletePendingUpload(t.Context(), file.FileID); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected failed object deletion, got %v", err)
	}
	usage, err := repo.UploadUsage(t.Context(), owner.ID)
	if err != nil || usage.Used != file.FileSize || file.UploadStatus != "aborting" {
		t.Fatalf("failed deletion lost quota or retry state: %+v %v", usage, err)
	}
	fault.fail = false
	handler.sweepExpiredUploads(context.Background())
	if _, err := repo.Get(t.Context(), file.FileID); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("cleanup did not remove reservation: %v", err)
	}
	if _, exists := storage.objects[file.FileID]; exists {
		t.Fatal("cleanup did not remove object")
	}
	usage, err = repo.UploadUsage(t.Context(), owner.ID)
	if err != nil || usage.Used != 0 {
		t.Fatalf("successful cleanup did not release quota: %+v %v", usage, err)
	}
}

// slowDeleteStorage stalls deletions until released, like a slow object store.
type slowDeleteStorage struct {
	*memoryStorage
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (storage *slowDeleteStorage) Delete(ctx context.Context, key string) error {
	if storage.calls.Add(1) == 1 {
		close(storage.started)
	}
	<-storage.release
	return storage.memoryStorage.Delete(ctx, key)
}

func TestExpiredReservationCleanupRunsOffTheRequestPathAndIsSingleFlight(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	expired := time.Now().Add(-time.Hour)
	repository.files["2e8b6bd5-3ff0-4700-851f-95864db4f8a9"] = &db.FileList{FileID: "2e8b6bd5-3ff0-4700-851f-95864db4f8a9", UploadStatus: "pending", UploadExpiresAt: &expired, FileSize: 1}
	storage := &slowDeleteStorage{memoryStorage: &memoryStorage{objects: make(map[string][]byte)}, started: make(chan struct{}), release: make(chan struct{})}
	handler := newTestHandler(t, repository, storage)
	logs := new(lockedBuffer)
	handler.logger = slog.New(slog.NewTextHandler(logs, nil))
	handler.inlineCleanup = false // this test is about the background pass

	returned := make(chan struct{})
	go func() {
		handler.cleanupExpiredUploads(httptest.NewRequest(http.MethodPost, "/upload", nil))
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("the request waited for the object-storage delete")
	}
	<-storage.started // the background pass is now stuck in the slow delete
	handler.cleanupExpiredUploads(httptest.NewRequest(http.MethodPost, "/upload", nil))
	handler.cleanupExpiredUploads(httptest.NewRequest(http.MethodPost, "/upload", nil))
	if calls := storage.calls.Load(); calls != 1 {
		t.Fatalf("a second cleanup pass started while one was running: %d delete calls", calls)
	}
	close(storage.release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		repository.mu.Lock()
		left := len(repository.files)
		repository.mu.Unlock()
		if left == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the expired reservation was never cleaned up")
		}
		time.Sleep(5 * time.Millisecond)
	}
	for !strings.Contains(logs.String(), "cleaned up expired upload reservations") {
		if time.Now().After(deadline) {
			t.Fatalf("the cleanup was not logged: %q", logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Started passes are spaced apart, however many uploads arrive.
	handler.cleanupExpiredUploads(httptest.NewRequest(http.MethodPost, "/upload", nil))
	time.Sleep(50 * time.Millisecond)
	if calls := storage.calls.Load(); calls != 1 {
		t.Fatalf("passes were not spaced: %d delete calls", calls)
	}
}

// claimingRepository adds the delete-claim capability PostgreSQL provides.
type claimingRepository struct {
	*authMemoryRepository
	failDelete bool
}

func (repository *claimingRepository) ClaimFileDeletion(_ context.Context, fileID string, _ time.Time) error {
	file, ok := repository.files[fileID]
	if !ok || file.UploadStatus != "complete" {
		return db.ErrNotFound
	}
	file.UploadStatus = "deleting"
	return nil
}

func (repository *claimingRepository) ReleaseRetentionClaim(_ context.Context, fileID string) error {
	file, ok := repository.files[fileID]
	if !ok || file.UploadStatus != "deleting" {
		return db.ErrNotFound
	}
	file.UploadStatus = "complete"
	return nil
}

func (repository *claimingRepository) Delete(ctx context.Context, fileID string) error {
	if repository.failDelete {
		return errors.New("database unavailable")
	}
	return repository.authMemoryRepository.Delete(ctx, fileID)
}

type failingDeleteStorage struct{ *memoryStorage }

func (*failingDeleteStorage) Delete(context.Context, string) error {
	return errors.New("object store unavailable")
}

func TestOwnerDeleteClaimsBeforeRemovingTheObject(t *testing.T) {
	for name, test := range map[string]struct {
		failStorage, failRecord bool
		wantStatus              int
		wantRecord              string // status of the row afterwards, "" when removed
		wantObject              bool
	}{
		"success":                {false, false, http.StatusSeeOther, "", false},
		"object store failure":   {true, false, http.StatusInternalServerError, "complete", true},
		"database failure after": {false, true, http.StatusInternalServerError, "deleting", false},
	} {
		t.Run(name, func(t *testing.T) {
			handler, repo, storage, file, owner := sharingTestHandler(t)
			claiming := &claimingRepository{authMemoryRepository: repo, failDelete: test.failRecord}
			handler.repository = claiming
			if test.failStorage {
				handler.storage = &failingDeleteStorage{storage}
			}
			response := httptest.NewRecorder()
			handler.Delete(response, sharingRequest("POST", file.FileID, "", owner))
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.wantStatus, response.Body.String())
			}
			status := ""
			if row, exists := repo.files[file.FileID]; exists {
				status = row.UploadStatus
			}
			if status != test.wantRecord {
				t.Fatalf("row status = %q, want %q", status, test.wantRecord)
			}
			if _, hasObject := storage.objects[file.FileID]; hasObject != test.wantObject {
				t.Fatalf("object present = %v, want %v", hasObject, test.wantObject)
			}
		})
	}
}

// copyHookStorage models S3 CopyObject: the source is read when the copy starts
// and the destination appears only when it finishes. duringCopy runs in that
// window, like a request that arrives during a long server-side copy.
type copyHookStorage struct {
	*directMemoryStorage
	duringCopy func()
	failCopy   bool
}

func (storage *copyHookStorage) Copy(_ context.Context, sourceKey, destinationKey string) error {
	data, ok := storage.objects[sourceKey]
	if !ok || storage.failCopy {
		return errors.New("copy failed")
	}
	snapshot := append([]byte(nil), data...)
	if hook := storage.duringCopy; hook != nil {
		storage.duringCopy = nil
		hook()
	}
	storage.objects[destinationKey] = snapshot
	return nil
}

// beginStagedDirectUpload authorizes a guest direct upload and stages its bytes
// as the browser's presigned PUT would. It returns the file ID and the JSON body
// that completion and abort expect.
func beginStagedDirectUpload(t *testing.T, handler *Handler, direct *copyHookStorage) (string, string) {
	t.Helper()
	response := httptest.NewRecorder()
	handler.BeginDirectUpload(response, httptest.NewRequest(http.MethodPost, "/api/v1/uploads/direct", strings.NewReader(`{"file_name":"a.txt","file_size":5,"content_type":"text/plain"}`)))
	if response.Code != http.StatusCreated {
		t.Fatalf("begin: %d %s", response.Code, response.Body.String())
	}
	var authorization struct {
		FileID string `json:"file_id"`
		Token  string `json:"token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &authorization); err != nil {
		t.Fatal(err)
	}
	direct.objects[service.PendingUploadKey(authorization.FileID)] = []byte("hello")
	body, _ := json.Marshal(map[string]string{"token": authorization.Token})
	return authorization.FileID, string(body)
}

func TestCompletionClaimKeepsAbortAndCleanupFromOrphaningTheCopy(t *testing.T) {
	for _, interrupt := range []string{"abort", "expiry cleanup"} {
		t.Run(interrupt, func(t *testing.T) {
			repository := &memoryRepository{files: make(map[string]*db.FileList)}
			direct := &copyHookStorage{directMemoryStorage: &directMemoryStorage{&memoryStorage{objects: make(map[string][]byte)}}}
			handler := newTestHandler(t, repository, direct)
			fileID, body := beginStagedDirectUpload(t, handler, direct)
			interrupted := 0
			direct.duringCopy = func() {
				if interrupt == "abort" {
					abort := httptest.NewRecorder()
					handler.AbortDirectUpload(abort, sharingRequest("POST", fileID, body, nil))
					interrupted = abort.Code
					return
				}
				expired := time.Now().Add(-time.Minute)
				repository.mu.Lock()
				repository.files[fileID].UploadExpiresAt = &expired
				repository.mu.Unlock()
				interrupted = handler.sweepExpiredUploads(t.Context())
			}
			complete := httptest.NewRecorder()
			handler.CompleteDirectUpload(complete, sharingRequest("POST", fileID, body, nil))
			if (interrupt == "abort" && interrupted != http.StatusConflict) || (interrupt != "abort" && interrupted != 0) {
				t.Fatalf("%s removed an upload while it was being published: %d", interrupt, interrupted)
			}
			record, err := repository.Get(t.Context(), fileID)
			if complete.Code != http.StatusOK || err != nil || record.UploadStatus != "complete" || string(direct.objects[fileID]) != "hello" {
				t.Fatalf("completion status=%d record=%+v err=%v objects=%v", complete.Code, record, err, direct.objects)
			}
		})
	}
}

func TestCompletionRemovesTheCopyWhenItsLapsedClaimWasCleanedUp(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	direct := &copyHookStorage{directMemoryStorage: &directMemoryStorage{&memoryStorage{objects: make(map[string][]byte)}}}
	handler := newTestHandler(t, repository, direct)
	fileID, body := beginStagedDirectUpload(t, handler, direct)
	direct.duringCopy = func() {
		// The copy outlived its lease, so an abort is allowed to delete the
		// record and both keys before the copy writes the final object.
		repository.mu.Lock()
		repository.files[fileID].UpdatedAt = time.Now().Add(-db.UploadPublicationLease - time.Minute)
		repository.mu.Unlock()
		abort := httptest.NewRecorder()
		handler.AbortDirectUpload(abort, sharingRequest("POST", fileID, body, nil))
		if abort.Code != http.StatusNoContent {
			t.Fatalf("abort of an abandoned claim: %d %s", abort.Code, abort.Body.String())
		}
	}
	complete := httptest.NewRecorder()
	handler.CompleteDirectUpload(complete, sharingRequest("POST", fileID, body, nil))
	if _, err := repository.Get(t.Context(), fileID); !errors.Is(err, db.ErrNotFound) || complete.Code != http.StatusConflict {
		t.Fatalf("completion status=%d record err=%v", complete.Code, err)
	}
	for key := range direct.objects {
		t.Errorf("object %q survives although no file record references it", key)
	}
}

func TestFailedOrAbandonedPublicationCanBeRetried(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	direct := &copyHookStorage{directMemoryStorage: &directMemoryStorage{&memoryStorage{objects: make(map[string][]byte)}}, failCopy: true}
	handler := newTestHandler(t, repository, direct)
	fileID, body := beginStagedDirectUpload(t, handler, direct)
	complete := httptest.NewRecorder()
	handler.CompleteDirectUpload(complete, sharingRequest("POST", fileID, body, nil))
	if record, _ := repository.Get(t.Context(), fileID); complete.Code != http.StatusConflict || record.UploadStatus != "pending" {
		t.Fatalf("failed copy must release its claim: status=%d record=%+v", complete.Code, record)
	}

	// A process that stopped mid-copy leaves a publishing claim. While it is
	// live a retry is told to wait; once abandoned the retry takes it over.
	direct.failCopy = false
	repository.mu.Lock()
	repository.files[fileID].UploadStatus, repository.files[fileID].UpdatedAt = "publishing", time.Now()
	repository.mu.Unlock()
	complete = httptest.NewRecorder()
	handler.CompleteDirectUpload(complete, sharingRequest("POST", fileID, body, nil))
	if complete.Code != http.StatusConflict {
		t.Fatalf("live claim: status=%d", complete.Code)
	}
	repository.mu.Lock()
	repository.files[fileID].UpdatedAt = time.Now().Add(-db.UploadPublicationLease - time.Minute)
	repository.mu.Unlock()
	complete = httptest.NewRecorder()
	handler.CompleteDirectUpload(complete, sharingRequest("POST", fileID, body, nil))
	if record, _ := repository.Get(t.Context(), fileID); complete.Code != http.StatusOK || record.UploadStatus != "complete" || string(direct.objects[fileID]) != "hello" {
		t.Fatalf("abandoned claim retry: status=%d record=%+v", complete.Code, record)
	}
}

// A file above the in-memory multipart threshold is spooled to the temporary
// directory. When that fails (a full or missing TMPDIR) the client is not at
// fault: the response must be a logged server error, not a 400 that blames the
// upload's size.
func TestMultipartSpoolFailureIsALoggedServerError(t *testing.T) {
	content := make([]byte, uploadFormMemory+1024)
	for _, test := range []struct {
		name    string
		tempDir string
		want    int
	}{
		{"writable temporary directory", t.TempDir(), http.StatusSeeOther},
		{"missing temporary directory", t.TempDir() + "/missing", http.StatusInternalServerError},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
				t.Setenv(name, test.tempDir)
			}
			repository := &memoryRepository{files: make(map[string]*db.FileList)}
			storage := &memoryStorage{objects: make(map[string][]byte)}
			cfg := &config.ServiceConfig{MaxFileSize: 64, StorageService: "filesystem", Encryption: &config.EncryptionConfig{}}
			handler := newTestHandlerConfig(t, cfg, repository, storage)
			logs := &lockedBuffer{}
			handler.logger = slog.New(slog.NewTextHandler(logs, nil))
			response := httptest.NewRecorder()
			handler.Upload(response, multipartUploadRequest(t, content))
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.want, response.Body.String())
			}
			if test.want == http.StatusInternalServerError && (!strings.Contains(logs.String(), "spool multipart upload") || len(repository.files) != 0) {
				t.Fatalf("spool failure was not logged or left a reservation: records=%d log=%q", len(repository.files), logs.String())
			}
		})
	}
}

func multipartBatchRequest(t *testing.T, files ...string) *http.Request {
	t.Helper()
	body := new(bytes.Buffer)
	form := multipart.NewWriter(body)
	for index, content := range files {
		part, err := form.CreateFormFile("file", fmt.Sprintf("batch-%d.txt", index))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = part.Write([]byte(content))
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/upload", body)
	request.Header.Set("Content-Type", form.FormDataContentType())
	return request
}

// The batch path reports a busy cipher like the single-file path: as a
// retryable 503, not an internal error.
func TestProxiedBatchReportsBusyEncryptionAsRetryable(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	cfg := &config.ServiceConfig{MaxFileSize: 1, StorageService: "filesystem",
		Encryption: &config.EncryptionConfig{Enabled: true, Method: "aes-256-gcm", Key: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="}}
	handler := newTestHandlerConfig(t, cfg, repository, &memoryStorage{objects: make(map[string][]byte)})
	held := 0
	for handler.acquireCipherSlot() {
		held++
	}
	defer func() {
		for range held {
			handler.releaseCipherSlot()
		}
	}()
	for _, request := range []*http.Request{multipartUploadRequest(t, []byte("one")), multipartBatchRequest(t, "one", "two")} {
		response := httptest.NewRecorder()
		handler.Upload(response, request)
		if response.Code != http.StatusServiceUnavailable || len(repository.files) != 0 {
			t.Fatalf("busy cipher: status=%d records=%d", response.Code, len(repository.files))
		}
	}
}

// putFailingStorage stores the first object, then fails every later Put and
// every Delete, like an object store that goes away during a batch.
type putFailingStorage struct {
	*memoryStorage
	puts int
}

func (storage *putFailingStorage) Put(ctx context.Context, key string, reader io.Reader, size int64, contentType string) error {
	if storage.puts++; storage.puts > 1 {
		return errors.New("object store unavailable")
	}
	return storage.memoryStorage.Put(ctx, key, reader, size, contentType)
}

func (*putFailingStorage) Delete(context.Context, string) error {
	return errors.New("object store unavailable")
}

// Rolling back a batch must not leave an already completed file usable when
// its object cannot be deleted; it is claimed for deletion so the background
// sweep retries it instead.
func TestBatchRollbackWithdrawsCompletedFilesEvenWhenDeleteFails(t *testing.T) {
	handler, repo, storage, existing, _ := sharingTestHandler(t)
	delete(repo.files, existing.FileID)
	handler.repository = &claimingRepository{authMemoryRepository: repo}
	handler.storage = &putFailingStorage{memoryStorage: storage}
	response := httptest.NewRecorder()
	handler.Upload(response, multipartBatchRequest(t, "first", "second"))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	// The completed first file is withdrawn as "deleting" (retention retries it);
	// the failed second reservation is "aborting" (expiry cleanup retries it).
	statuses := map[string]int{}
	for _, file := range repo.files {
		statuses[file.UploadStatus]++
	}
	if len(repo.files) != 2 || statuses["deleting"] != 1 || statuses["aborting"] != 1 {
		t.Fatalf("records after rollback: %v, want one deleting and one aborting", statuses)
	}
}
