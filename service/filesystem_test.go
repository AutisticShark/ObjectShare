package service

import (
	"bytes"
	"context"
	"io"
	"testing"
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
