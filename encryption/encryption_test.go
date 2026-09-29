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

func newTestCipher(t *testing.T, fill byte) *Cipher {
	t.Helper()
	cipher, err := New(bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func TestBoundObjectsRoundTripAndRefuseAnotherID(t *testing.T) {
	cipher := newTestCipher(t, 0x42)
	const first, second = "2e8b6bd5-3ff0-4700-851f-95864db4f8a9", "5b6c7d8e-1111-4222-8333-444455556666"
	encrypted, err := cipher.EncryptFor(first, []byte("bound contents"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(encrypted, magicV2) {
		t.Fatal("EncryptFor did not write the v2 format")
	}
	if got, err := cipher.DecryptFor(first, encrypted); err != nil || string(got) != "bound contents" {
		t.Fatalf("DecryptFor with the right ID = %q, %v", got, err)
	}
	if _, err := cipher.DecryptFor(second, encrypted); err == nil {
		t.Fatal("a ciphertext swapped onto another object ID still decrypted")
	}
	if _, err := cipher.DecryptFor("", encrypted); err == nil {
		t.Fatal("a bound ciphertext decrypted without its ID")
	}
	if _, err := cipher.Decrypt(encrypted); err == nil {
		t.Fatal("the ID-less API opened a bound object")
	}
}

func TestLegacyObjectsStillDecryptThroughDecryptFor(t *testing.T) {
	cipher := newTestCipher(t, 0x42)
	legacy, err := cipher.Encrypt([]byte("written by an earlier release"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(legacy, magic) {
		t.Fatal("Encrypt no longer writes the v1 layout")
	}
	if got, err := cipher.DecryptFor("any-object-id", legacy); err != nil || string(got) != "written by an earlier release" {
		t.Fatalf("legacy object = %q, %v", got, err)
	}
}

func TestEncryptionEdgeCases(t *testing.T) {
	cipher := newTestCipher(t, 0x42)
	const id = "2e8b6bd5-3ff0-4700-851f-95864db4f8a9"

	empty, err := cipher.EncryptFor(id, nil)
	if err != nil || len(empty) != cipher.Overhead() {
		t.Fatalf("empty plaintext: %d bytes (overhead %d), %v", len(empty), cipher.Overhead(), err)
	}
	if got, err := cipher.DecryptFor(id, empty); err != nil || len(got) != 0 {
		t.Fatalf("empty round trip = %q, %v", got, err)
	}

	large := bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB
	sealed, err := cipher.EncryptFor(id, large)
	if err != nil || len(sealed) != len(large)+cipher.Overhead() {
		t.Fatalf("large plaintext sealed to %d bytes, %v", len(sealed), err)
	}
	if got, err := cipher.DecryptFor(id, sealed); err != nil || !bytes.Equal(got, large) {
		t.Fatalf("large round trip failed: %v", err)
	}

	// Two encryptions of the same input differ (fresh random nonce).
	again, _ := cipher.EncryptFor(id, large)
	if bytes.Equal(sealed, again) {
		t.Fatal("nonce reuse: identical ciphertexts for identical input")
	}

	// Truncation, a wrong key, a wrong header and empty input are all refused.
	other := newTestCipher(t, 0x43)
	if _, err := other.DecryptFor(id, sealed); err == nil {
		t.Fatal("a different key opened the object")
	}
	for name, corrupt := range map[string][]byte{
		"nil":            nil,
		"empty":          {},
		"header only":    sealed[:len(magicV2)],
		"truncated tag":  sealed[:len(sealed)-1],
		"short of nonce": sealed[:len(magicV2)+4],
		"wrong header":   append([]byte("NOT-OBJECTSHARE-AES-GCM-9\x00"), sealed[len(magicV2):]...),
	} {
		if _, err := cipher.DecryptFor(id, corrupt); err == nil {
			t.Errorf("%s ciphertext was accepted", name)
		}
	}

	// Flipping any authenticated region (nonce, body, tag) is detected.
	for _, position := range []int{len(magicV2), len(magicV2) + 20, len(sealed) - 1} {
		tampered := append([]byte(nil), sealed...)
		tampered[position] ^= 0x80
		if _, err := cipher.DecryptFor(id, tampered); err == nil {
			t.Errorf("tampering at byte %d went unnoticed", position)
		}
	}
	if _, err := New(make([]byte, 16)); err == nil {
		t.Fatal("a 16-byte key was accepted for AES-256")
	}
}
