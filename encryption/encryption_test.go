package encryption

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	cipher, err := New(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("private file contents")
	encrypted, err := cipher.Encrypt(want)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, want) {
		t.Fatal("ciphertext contains plaintext")
	}
	got, err := cipher.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestRejectsTampering(t *testing.T) {
	cipher, _ := New(bytes.Repeat([]byte{0x42}, 32))
	encrypted, _ := cipher.Encrypt([]byte("contents"))
	encrypted[len(encrypted)-1] ^= 1
	if _, err := cipher.Decrypt(encrypted); err == nil {
		t.Fatal("expected authentication error")
	}
}
