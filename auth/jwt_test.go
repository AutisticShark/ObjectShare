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

func TestJWTAuthTimeIsCarriedForwardAndValidated(t *testing.T) {
	manager, err := NewJWTManager(testJWTSecret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	encoded, _, err := manager.Issue("60c628c1-85cb-4463-b895-a629c31bfa55", "user", 1, now)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := manager.Parse(encoded)
	if err != nil || parsed.AuthTime == nil || !parsed.AuthTime.Time.Equal(now) {
		t.Fatalf("a sign-in token must carry auth_time = iat: %#v %v", parsed, err)
	}
	signedIn := now.Add(-3 * time.Hour)
	encoded, _, err = manager.Reissue("60c628c1-85cb-4463-b895-a629c31bfa55", "user", 2, now, signedIn)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err = manager.Parse(encoded); err != nil || parsed.AuthTime == nil || !parsed.AuthTime.Time.Equal(signedIn) || !parsed.IssuedAt.Time.Equal(now) {
		t.Fatalf("a re-issued token must keep the original auth_time: %#v %v", parsed, err)
	}
	encoded, _, err = manager.Reissue("60c628c1-85cb-4463-b895-a629c31bfa55", "user", 2, now, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err = manager.Parse(encoded); err != nil || parsed.AuthTime != nil {
		t.Fatalf("a re-issue without a sign-in time must omit auth_time: %#v %v", parsed, err)
	}
	if _, _, err = manager.Reissue("60c628c1-85cb-4463-b895-a629c31bfa55", "user", 2, now, now.Add(time.Minute)); err == nil {
		t.Fatal("auth_time after iat was issued")
	}
	if _, mfa, err := manager.IssueMFA("60c628c1-85cb-4463-b895-a629c31bfa55", "user", 1, "login", "", "cookie", now); err != nil || mfa.AuthTime != nil {
		t.Fatalf("MFA challenges must not carry auth_time: %#v %v", mfa, err)
	}
	for name, authTime := range map[string]*jwt.NumericDate{"after iat": jwt.NewNumericDate(now.Add(time.Minute)), "at the epoch": jwt.NewNumericDate(time.Unix(0, 0))} {
		claims := validClaims(now)
		claims.AuthTime = authTime
		value, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(manager.key)
		if _, err := manager.Parse(value); err == nil {
			t.Fatalf("a token with auth_time %s was accepted", name)
		}
	}
}

func TestJWTManagerRejectsWeakSecret(t *testing.T) {
	if _, err := NewJWTManager("too-short", time.Hour); err == nil {
		t.Fatal("weak JWT secret was accepted")
	}
}

// validClaims returns claims that pass every check, so each test below can
// break exactly one property and prove that property is what is enforced.
func validClaims(now time.Time) *Claims {
	return &Claims{Role: "user", TokenVersion: 1, CSRF: "csrf-token", RegisteredClaims: jwt.RegisteredClaims{
		Issuer: jwtIssuer, Subject: "60c628c1-85cb-4463-b895-a629c31bfa55", Audience: jwt.ClaimStrings{jwtAudience},
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)), NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)), IssuedAt: jwt.NewNumericDate(now.Add(-time.Minute)), ID: "jti-1",
	}}
}

func TestJWTEachClaimIsEnforcedOnItsOwn(t *testing.T) {
	manager, err := NewJWTManager(testJWTSecret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	sign := func(method jwt.SigningMethod, claims *Claims) string {
		value, err := jwt.NewWithClaims(method, claims).SignedString(manager.key)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	if _, err := manager.Parse(sign(jwt.SigningMethodHS256, validClaims(now))); err != nil {
		t.Fatalf("the baseline token must be valid: %v", err)
	}
	for name, test := range map[string]struct {
		mutate func(*Claims)
		method jwt.SigningMethod
	}{
		"expired beyond the leeway":       {mutate: func(c *Claims) { c.ExpiresAt = jwt.NewNumericDate(now.Add(-time.Hour)) }},
		"not yet valid beyond the leeway": {mutate: func(c *Claims) { c.NotBefore = jwt.NewNumericDate(now.Add(time.Hour)) }},
		"issued in the future":            {mutate: func(c *Claims) { c.IssuedAt = jwt.NewNumericDate(now.Add(time.Hour)) }},
		"no expiry":                       {mutate: func(c *Claims) { c.ExpiresAt = nil }},
		"wrong issuer":                    {mutate: func(c *Claims) { c.Issuer = "somebody-else" }},
		"no issuer":                       {mutate: func(c *Claims) { c.Issuer = "" }},
		"wrong audience":                  {mutate: func(c *Claims) { c.Audience = jwt.ClaimStrings{"another-service"} }},
		"no audience":                     {mutate: func(c *Claims) { c.Audience = nil }},
		"no subject":                      {mutate: func(c *Claims) { c.Subject = "" }},
		"no token id":                     {mutate: func(c *Claims) { c.ID = "" }},
		"no csrf claim":                   {mutate: func(c *Claims) { c.CSRF = "" }},
		"token version zero":              {mutate: func(c *Claims) { c.TokenVersion = 0 }},
		"unknown role":                    {mutate: func(c *Claims) { c.Role = "superuser" }},
		"empty role":                      {mutate: func(c *Claims) { c.Role = "" }},
		"an MFA purpose claim":            {mutate: func(c *Claims) { c.Purpose = "mfa" }},
		"HS384 signature":                 {method: jwt.SigningMethodHS384},
		"HS512 signature":                 {method: jwt.SigningMethodHS512},
	} {
		t.Run(name, func(t *testing.T) {
			claims := validClaims(now)
			if test.mutate != nil {
				test.mutate(claims)
			}
			method := test.method
			if method == nil {
				method = jwt.SigningMethodHS256
			}
			if _, err := manager.Parse(sign(method, claims)); err == nil {
				t.Fatal("a token with this single defect was accepted")
			}
		})
	}
}

func TestJWTClockLeewayAcceptsSmallSkewOnly(t *testing.T) {
	manager, _ := NewJWTManager(testJWTSecret, time.Hour)
	now := time.Now().UTC()
	sign := func(mutate func(*Claims)) string {
		claims := validClaims(now)
		mutate(claims)
		value, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(manager.key)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	if _, err := manager.Parse(sign(func(c *Claims) { c.ExpiresAt = jwt.NewNumericDate(now.Add(-10 * time.Second)) })); err != nil {
		t.Fatalf("a token that expired 10s ago (inside the %v leeway) was refused: %v", JWTLeeway, err)
	}
	if _, err := manager.Parse(sign(func(c *Claims) { c.NotBefore = jwt.NewNumericDate(now.Add(10 * time.Second)) })); err != nil {
		t.Fatalf("a token valid from 10s in the future (inside the leeway) was refused: %v", err)
	}
	if _, err := manager.Parse(sign(func(c *Claims) { c.ExpiresAt = jwt.NewNumericDate(now.Add(-2 * JWTLeeway)) })); err == nil {
		t.Fatal("a token that expired well outside the leeway was accepted")
	}
}

func TestLoginAndMFATokensAreNotInterchangeable(t *testing.T) {
	manager, _ := NewJWTManager(testJWTSecret, time.Hour)
	now := time.Now().UTC()
	login, _, err := manager.Issue("60c628c1-85cb-4463-b895-a629c31bfa55", "user", 1, now)
	if err != nil {
		t.Fatal(err)
	}
	challenge, _, err := manager.IssueMFA("60c628c1-85cb-4463-b895-a629c31bfa55", "user", 1, "login", "", "cookie", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Parse(challenge); err == nil {
		t.Fatal("an MFA challenge authenticated an account")
	}
	if _, err := manager.ParseMFA(login); err == nil {
		t.Fatal("a login JWT was accepted as an MFA challenge")
	}
	if claims, err := manager.ParseMFA(challenge); err != nil || claims.Purpose != "mfa" || claims.Action != "login" {
		t.Fatalf("a genuine challenge was refused: %#v %v", claims, err)
	}
	if _, err := manager.ParseMFA(challenge + "x"); err == nil {
		t.Fatal("a corrupted challenge was accepted")
	}
}
