package auth

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("correct horse battery staple", hash) {
		t.Fatal("correct password did not verify")
	}
	if VerifyPassword("incorrect password value", hash) || VerifyPassword("x", "not-a-hash") {
		t.Fatal("invalid password or hash verified")
	}
	parts := strings.Split(hash, "$")
	parts[3] += ",unexpected=1"
	if VerifyPassword("correct horse battery staple", strings.Join(parts, "$")) {
		t.Fatal("hash with unexpected cost parameters verified")
	}
}

func TestPasswordValidation(t *testing.T) {
	for _, password := range []string{"short", string(make([]byte, 513))} {
		if err := ValidatePassword(password); err == nil {
			t.Fatalf("password %q should be rejected", password)
		}
	}
}

func TestNormalizeEmailAndDisplayName(t *testing.T) {
	email, err := NormalizeEmail(" Person@Example.COM ")
	if err != nil || email != "person@example.com" {
		t.Fatalf("email = %q, err = %v", email, err)
	}
	if _, err := NormalizeEmail("Display Name <person@example.com>"); err == nil {
		t.Fatal("display address should be rejected")
	}
	if _, err := ValidateDisplayName("bad\nname"); err == nil {
		t.Fatal("control character should be rejected")
	}
	if _, err := ValidateDisplayName("Admin\u202Enimda"); err == nil {
		t.Fatal("bidirectional override should be rejected")
	}
	if _, err := ValidateDisplayName("\u0645\u06CC\u200C\u0631\u0627"); err != nil {
		t.Fatalf("zero-width non-joiner rejected: %v", err)
	}
}

func TestTokensAreRandomAndHashable(t *testing.T) {
	first, firstHash, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	second, secondHash, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || firstHash == secondHash || TokenHash(first) != firstHash {
		t.Fatal("token generation is not unique or hash is inconsistent")
	}
}

func TestDummyPasswordHashIsNotAKnownCredential(t *testing.T) {
	hash := DummyPasswordHash()
	if hash == "" || hash != DummyPasswordHash() {
		t.Fatal("dummy hash must be a stable, non-empty value within one process")
	}
	for _, guess := range []string{"objectshare-dummy-password", "", "password", "dummy"} {
		if VerifyPassword(guess, hash) {
			t.Fatalf("dummy hash verifies the guessable password %q", guess)
		}
	}
}

func TestArgonGateBoundsConcurrency(t *testing.T) {
	g := newGate(2)
	var running, peak atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.acquire()
			defer g.release()
			now := running.Add(1)
			for {
				old := peak.Load()
				if now <= old || peak.CompareAndSwap(old, now) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			running.Add(-1)
		}()
	}
	wg.Wait()
	if peak.Load() > 2 || peak.Load() < 1 {
		t.Fatalf("peak concurrency %d exceeded the gate size 2", peak.Load())
	}
	if len(newGate(0)) != 0 || cap(newGate(0)) != 1 {
		t.Fatal("a non-positive size must still yield a usable gate")
	}
}

func TestParallelHashingAndVerificationStillWorkThroughTheGate(t *testing.T) {
	hash, err := HashPassword("a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan bool, 8)
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			guess := "a sufficiently long password"
			if i%2 == 1 {
				guess = "a sufficiently wrong password"
			}
			results <- VerifyPassword(guess, hash) == (i%2 == 0)
		}()
	}
	wg.Wait()
	close(results)
	for ok := range results {
		if !ok {
			t.Fatal("parallel verification returned a wrong answer")
		}
	}
}

// legacyHash builds a valid Argon2id hash with weaker parameters than the
// current ones, as an earlier release could have stored.
func legacyHash(t *testing.T, password string, memory, iterations uint32, threads uint8) string {
	t.Helper()
	salt := bytes.Repeat([]byte{7}, 16)
	key := argon2.IDKey([]byte(password), salt, iterations, memory, threads, 32)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, memory, iterations, threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

func TestNeedsRehashDetectsOutdatedParameters(t *testing.T) {
	current, err := HashPassword("a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	if NeedsRehash(current) {
		t.Fatal("a hash made with the current parameters wants a rehash")
	}
	weaker := legacyHash(t, "a sufficiently long password", 19*1024, 2, 1)
	if !VerifyPassword("a sufficiently long password", weaker) {
		t.Fatal("test setup: the legacy hash does not verify")
	}
	if !NeedsRehash(weaker) {
		t.Fatal("a hash with weaker parameters was not flagged")
	}
	for _, unparsable := range []string{"", "plain", "$bcrypt$x$y$z$w", "$argon2id$v=19$m=1$x"} {
		if NeedsRehash(unparsable) {
			t.Errorf("%q cannot verify, so it must not be reported as upgradable", unparsable)
		}
	}
}
