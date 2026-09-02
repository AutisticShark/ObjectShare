package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testJWTSecret = "test-only-jwt-secret-with-at-least-32-bytes"

func TestJWTRoundTripAndRequiredClaims(t *testing.T) {
	manager, err := NewJWTManager(testJWTSecret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	encoded, issued, err := manager.Issue("60c628c1-85cb-4463-b895-a629c31bfa55", "admin", 3, now)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := manager.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Subject != issued.Subject || parsed.Role != "admin" || parsed.TokenVersion != 3 || parsed.ID == "" || parsed.CSRF == "" ||
		parsed.Issuer != jwtIssuer || len(parsed.Audience) != 1 || parsed.Audience[0] != jwtAudience {
		t.Fatalf("unexpected claims: %#v", parsed)
	}
}

func TestJWTRejectsTamperingWrongKeyAndAlgorithm(t *testing.T) {
	manager, _ := NewJWTManager(testJWTSecret, time.Hour)
	encoded, _, _ := manager.Issue("60c628c1-85cb-4463-b895-a629c31bfa55", "user", 1, time.Now())
	parts := strings.Split(encoded, ".")
	replacement := "A"
	if strings.HasSuffix(parts[1], replacement) {
		replacement = "B"
	}
	parts[1] = parts[1][:len(parts[1])-1] + replacement
	if _, err := manager.Parse(strings.Join(parts, ".")); err == nil {
		t.Fatal("tampered JWT was accepted")
	}
	other, _ := NewJWTManager("different-test-secret-with-at-least-32-bytes", time.Hour)
	if _, err := other.Parse(encoded); err == nil {
		t.Fatal("JWT signed by a different key was accepted")
	}
	none := jwt.NewWithClaims(jwt.SigningMethodNone, &Claims{Role: "user", TokenVersion: 1, CSRF: "csrf", RegisteredClaims: jwt.RegisteredClaims{
		Issuer: jwtIssuer, Subject: "user", Audience: jwt.ClaimStrings{jwtAudience}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)), NotBefore: jwt.NewNumericDate(time.Now()), IssuedAt: jwt.NewNumericDate(time.Now()), ID: "jti",
	}})
	noneValue, _ := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if _, err := manager.Parse(noneValue); err == nil {
		t.Fatal("unsigned JWT was accepted")
	}
}

func TestJWTRejectsExpiredAndStaleStructure(t *testing.T) {
	manager, _ := NewJWTManager(testJWTSecret, time.Hour)
	claims := &Claims{Role: "user", TokenVersion: 0, CSRF: "", RegisteredClaims: jwt.RegisteredClaims{
		Issuer: jwtIssuer, Subject: "user", Audience: jwt.ClaimStrings{jwtAudience}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)), IssuedAt: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)), ID: "jti",
	}}
	value, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(manager.key)
	if _, err := manager.Parse(value); err == nil {
		t.Fatal("expired or structurally invalid JWT was accepted")
	}
}

func TestJWTManagerRejectsWeakSecret(t *testing.T) {
	if _, err := NewJWTManager("too-short", time.Hour); err == nil {
		t.Fatal("weak JWT secret was accepted")
	}
}
