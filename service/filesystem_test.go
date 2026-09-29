package service

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileSystemRoundTrip(t *testing.T) {
	store, err := NewFileSystem(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key := "2e8b6bd5-3ff0-4700-851f-95864db4f8a9"
	want := []byte("contents")
	if err := store.Put(context.Background(), key, bytes.NewReader(want), int64(len(want)), "text/plain"); err != nil {
		t.Fatal(err)
	}
	body, err := store.Open(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(body)
	_ = body.Close()
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	if err := store.Delete(context.Background(), key); err != nil {
		t.Fatal(err)
	}
}

func TestFileSystemRejectsTraversal(t *testing.T) {
	store, _ := NewFileSystem(t.TempDir())
	if err := store.Put(context.Background(), "../escape", bytes.NewReader(nil), 0, ""); err == nil {
		t.Fatal("expected invalid key error")
	}
}

func TestFileSystemPutEnforcesTheDeclaredSize(t *testing.T) {
	store, err := NewFileSystem(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key := "2e8b6bd5-3ff0-4700-851f-95864db4f8a9"
	for name, test := range map[string]struct {
		body string
		size int64
	}{
		"short body": {"abc", 5},
		"long body":  {"abcdefgh", 5},
	} {
		t.Run(name, func(t *testing.T) {
			if err := store.Put(context.Background(), key, strings.NewReader(test.body), test.size, ""); err == nil {
				t.Fatal("a body that does not match the declared size was stored")
			}
			if _, err := store.Open(context.Background(), key); err == nil {
				t.Fatal("a rejected upload left an object behind")
			}
			entries, _ := os.ReadDir(store.root)
			if len(entries) != 0 {
				t.Fatalf("a rejected upload left %d files behind", len(entries))
			}
		})
	}
	if err := store.Put(context.Background(), key, strings.NewReader("exact"), 5, ""); err != nil {
		t.Fatalf("an exact-size body was rejected: %v", err)
	}
	// A negative size means "unknown" and is not enforced.
	if err := store.Put(context.Background(), key, strings.NewReader("anything"), -1, ""); err != nil {
		t.Fatalf("an unknown size was rejected: %v", err)
	}
}

func TestFileSystemStartupRemovesOnlyStaleTemporaryUploads(t *testing.T) {
	root := t.TempDir()
	stale := filepath.Join(root, ".upload-stale")
	fresh := filepath.Join(root, ".upload-fresh")
	object := filepath.Join(root, "2e8b6bd5-3ff0-4700-851f-95864db4f8a9")
	for _, path := range []string{stale, fresh, object} {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-3 * time.Hour)
	for _, path := range []string{stale, object} {
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := NewFileSystem(root); err != nil {
		t.Fatal(err)
	}
	for path, wantExists := range map[string]bool{stale: false, fresh: true, object: true} {
		if _, err := os.Stat(path); (err == nil) != wantExists {
			t.Errorf("%s exists=%v, want %v", filepath.Base(path), err == nil, wantExists)
		}
	}
}
