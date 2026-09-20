package auth

import (
	"encoding/base32"
	"github.com/golang-jwt/jwt/v5"
	"strings"
	"testing"
	"time"
)

func TestTOTPRFC6238VectorsAndReplay(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, tc := range []struct {
		unix int64
		code string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"}} {
		got, err := TOTPCode(secret, tc.unix/30)
		if err != nil || got != tc.code {
			t.Fatalf("RFC vector %d: got %s, %v", tc.unix, got, err)
		}
		step, ok := VerifyTOTP(secret, tc.code, time.Unix(tc.unix, 0), 0)
		if !ok || step != tc.unix/30 {
			t.Fatal("valid vector rejected")
		}
		if _, ok := VerifyTOTP(secret, tc.code, time.Unix(tc.unix, 0), step); ok {
			t.Fatal("replay accepted")
		}
	}
	for _, invalid := range []string{"", "28708", "0287082", "abcdef", " 287082"} {
		if _, ok := VerifyTOTP(secret, invalid, time.Unix(59, 0), 0); ok {
			t.Fatal("accepted invalid code")
		}
	}
	code, _ := TOTPCode(secret, 100)
	for _, step := range []int64{99, 100, 101} {
		if _, ok := VerifyTOTP(secret, code, time.Unix(step*30, 0), 0); !ok {
			t.Fatal("clock skew rejected")
		}
	}
	if _, ok := VerifyTOTP(secret, code, time.Unix(102*30, 0), 0); ok {
		t.Fatal("excess clock skew accepted")
	}
}

func TestMFASecretEncryptionAndCodes(t *testing.T) {
	key := strings.Repeat("k", 32)
	secret, err := NewTOTPSecret()
	if err != nil || len(secret) != 32 {
		t.Fatal("secret generation failed")
	}
	sealed, err := SealMFASecret(key, "user-one", secret)
	if err != nil || strings.Contains(sealed, secret) {
		t.Fatal("secret was not encrypted")
	}
	if got, err := OpenMFASecret(key, "user-one", sealed); err != nil || got != secret {
		t.Fatal("round trip failed")
	}
	for _, tc := range []struct{ key, id, value string }{{key, "user-two", sealed}, {strings.Repeat("x", 32), "user-one", sealed}, {key, "user-one", sealed + "!"}, {key, "user-one", "mfa:v1:"}, {"short", "user-one", sealed}} {
		if _, err := OpenMFASecret(tc.key, tc.id, tc.value); err == nil {
			t.Fatal("invalid ciphertext accepted")
		}
	}
	if MFAHash(key, "one", "123456") == MFAHash(key, "two", "123456") {
		t.Fatal("missing hash context binding")
	}
	codes, err := NewRecoveryCodes()
	if err != nil || len(codes) != 10 {
		t.Fatal("recovery generation failed")
	}
	seen := map[string]bool{}
	for _, code := range codes {
		if len(code) != 32 || seen[code] {
			t.Fatal("weak or repeated recovery code")
		}
		seen[code] = true
	}
	for range 30 {
		code, err := NewEmailOTP()
		if err != nil || len(code) != 6 || strings.Trim(code, "0123456789") != "" {
			t.Fatal("invalid email OTP")
		}
	}
}

func TestMFAJWTIsNeverAnAccessToken(t *testing.T) {
	manager, _ := NewJWTManager(strings.Repeat("k", 32), time.Hour)
	now := time.Now().UTC()
	challenge, claims, err := manager.IssueMFA("user", "user", 1, "login", "", "bearer", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Parse(challenge); err == nil {
		t.Fatal("challenge accepted as access token")
	}
	// Pre-MFA replicas do not know the purpose claim. Distinct audience AND
	// signing material must still prevent them from accepting a challenge.
	if _, err := manager.parser.ParseWithClaims(challenge, new(Claims), func(*jwt.Token) (any, error) { return manager.key, nil }); err == nil {
		t.Fatal("legacy access parser accepted MFA challenge")
	}
	if _, err := manager.ParseMFA(challenge); err != nil {
		t.Fatal(err)
	}
	access, _, _ := manager.Issue("user", "user", 1, now)
	if _, err := manager.ParseMFA(access); err == nil {
		t.Fatal("access token accepted as challenge")
	}
	if claims.ExpiresAt.Unix()-claims.IssuedAt.Unix() != 300 {
		t.Fatal("wrong challenge lifetime")
	}
	expired, _, _ := manager.IssueMFA("user", "user", 1, "login", "", "bearer", now.Add(-6*time.Minute))
	if _, err := manager.ParseMFA(expired); err == nil {
		t.Fatal("expired challenge accepted")
	}
	if _, err := manager.ParseMFA(challenge + "x"); err == nil {
		t.Fatal("tampered challenge accepted")
	}
}
