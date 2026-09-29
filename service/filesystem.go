package service

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var objectKeyPattern = regexp.MustCompile(`^[0-9a-fA-F-]{36}$`)

type FileSystem struct{ root string }

func NewFileSystem(root string) (*FileSystem, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve storage path: %w", err)
	}
	if err := os.MkdirAll(absolute, 0o750); err != nil {
		return nil, fmt.Errorf("create storage path: %w", err)
	}
	if removed := sweepStaleTemporaryObjects(absolute, time.Now().Add(-staleTemporaryAge)); removed > 0 {
		slog.Info("removed stale temporary upload files", "count", removed, "path", absolute)
	}
	return &FileSystem{root: absolute}, nil
}

// staleTemporaryAge is how old an unfinished ".upload-*" file must be before
// start-up treats it as debris from a crashed or killed upload. Put removes its
// own temporary file on every normal failure path, so anything this old is
// orphaned; the margin keeps a file that another replica is writing safe.
const staleTemporaryAge = time.Hour

// sweepStaleTemporaryObjects deletes temporary upload files last modified before
// cutoff and reports how many it removed.
func sweepStaleTemporaryObjects(root string, cutoff time.Time) int {
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0
	}
	removed := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), ".upload-") {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.ModTime().Before(cutoff) {
			continue
		}
		if os.Remove(filepath.Join(root, entry.Name())) == nil {
			removed++
		}
	}
	return removed
}

func (store *FileSystem) path(key string) (string, error) {
	if !objectKeyPattern.MatchString(key) {
		return "", errorsNewInvalidKey(key)
	}
	return filepath.Join(store.root, key), nil
}

func errorsNewInvalidKey(key string) error { return fmt.Errorf("invalid object key %q", key) }

func (store *FileSystem) Put(ctx context.Context, key string, body io.Reader, size int64, _ string) error {
	path, err := store.path(key)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(store.root, ".upload-*")
	if err != nil {
		return fmt.Errorf("create temporary object: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()

	source := io.Reader(&contextReader{ctx: ctx, reader: body})
	if size >= 0 {
		// Read one byte past the declared size so an over-long body is detected
		// instead of silently stored, and never write more than that.
		source = io.LimitReader(source, size+1)
	}
	written, err := io.Copy(temporary, source)
	if err != nil {
		return fmt.Errorf("write object: %w", err)
	}
	if size >= 0 && written != size {
		return fmt.Errorf("write object: got %d bytes, declared %d", written, size)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync object: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close object: %w", err)
	}
	if err := os.Chmod(temporaryPath, 0o640); err != nil {
		return fmt.Errorf("set object permissions: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("commit object: %w", err)
	}
	committed = true
	return nil
}

func (store *FileSystem) Open(_ context.Context, key string) (io.ReadCloser, error) {
	path, err := store.path(key)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open object: %w", err)
	}
	return file, nil
}

func (store *FileSystem) Delete(_ context.Context, key string) error {
	path, err := store.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete object: %w", err)
	}
	return nil
}

func (store *FileSystem) PresignGet(context.Context, string, string) (string, error) {
	return "", ErrPresignUnsupported
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	select {
	case <-reader.ctx.Done():
		return 0, reader.ctx.Err()
	default:
		return reader.reader.Read(buffer)
	}
}
