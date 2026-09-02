package auth

import (
	"strings"
	"testing"
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
