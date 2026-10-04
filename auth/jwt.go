package auth

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	jwtIssuer   = "objectshare"
	jwtAudience = "objectshare"
)

// JWTLeeway is the clock skew the parser tolerates on exp, nbf and iat. A
// token keeps authenticating until exp+JWTLeeway, so revocations must persist
// at least that long.
const JWTLeeway = 30 * time.Second

type Claims struct {
	Purpose      string `json:"purpose,omitempty"`
	Action       string `json:"action,omitempty"`
	Next         string `json:"next,omitempty"`
	Transport    string `json:"transport,omitempty"`
	Role         string `json:"role"`
	TokenVersion int    `json:"ver"`
	CSRF         string `json:"csrf"`
	// AuthTime is when the user last proved a login factor (password, OAuth,
	// completed login MFA, signup). Re-issued tokens carry it forward
	// unchanged, so it alone decides whether a session signed in recently.
	// Tokens without it never count as a recent sign-in.
	AuthTime *jwt.NumericDate `json:"auth_time,omitempty"`
	jwt.RegisteredClaims
}

func (claims Claims) Validate() error {
	if claims.Subject == "" || claims.ID == "" || claims.CSRF == "" || claims.TokenVersion < 1 ||
		claims.ExpiresAt == nil || claims.NotBefore == nil || claims.IssuedAt == nil {
		return errors.New("JWT is missing required claims")
	}
	if claims.Role != "admin" && claims.Role != "user" {
		return errors.New("JWT contains an invalid role")
	}
	if !claims.ExpiresAt.Time.After(claims.NotBefore.Time) || !claims.ExpiresAt.Time.After(claims.IssuedAt.Time) {
		return errors.New("JWT contains invalid temporal claims")
	}
	if claims.AuthTime != nil && (claims.AuthTime.Unix() <= 0 || claims.AuthTime.Time.After(claims.IssuedAt.Time)) {
		return errors.New("JWT contains an invalid authentication time")
	}
	return nil
}

type JWTManager struct {
	key       []byte
	mfaKey    []byte
	lifetime  time.Duration
	parser    *jwt.Parser
	mfaParser *jwt.Parser
}

func NewJWTManager(secret string, lifetime time.Duration) (*JWTManager, error) {
	if len(secret) < 32 {
		return nil, errors.New("JWT secret must contain at least 32 bytes")
	}
	if lifetime <= 0 {
		return nil, errors.New("JWT lifetime must be positive")
	}
	mfaKey := sha256.Sum256([]byte("objectshare-mfa-challenge-v1\x00" + secret))
	return &JWTManager{
		key:       []byte(secret),
		mfaKey:    mfaKey[:],
		lifetime:  lifetime,
		parser:    newJWTParser(jwtAudience),
		mfaParser: newJWTParser(jwtAudience + "-mfa"),
	}, nil
}

func newJWTParser(audience string) *jwt.Parser {
	return jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(jwtIssuer),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(JWTLeeway),
		jwt.WithStrictDecoding(),
	)
}

// Issue signs a token for a user who has just authenticated, so its auth_time is
// now.
func (manager *JWTManager) Issue(userID, role string, tokenVersion int, now time.Time) (string, *Claims, error) {
	return manager.Reissue(userID, role, tokenVersion, now, now)
}

// Reissue signs a replacement token that keeps the original sign-in time. A zero
// authTime omits auth_time, so the token never counts as a recent sign-in.
func (manager *JWTManager) Reissue(userID, role string, tokenVersion int, now, authTime time.Time) (string, *Claims, error) {
	jti, _, err := NewToken()
	if err != nil {
		return "", nil, fmt.Errorf("generate JWT ID: %w", err)
	}
	csrf, _, err := NewToken()
	if err != nil {
		return "", nil, fmt.Errorf("generate JWT CSRF claim: %w", err)
	}
	now = now.UTC()
	claims := &Claims{
		Role: role, TokenVersion: tokenVersion, CSRF: csrf,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: jwtIssuer, Subject: userID, Audience: jwt.ClaimStrings{jwtAudience},
			ExpiresAt: jwt.NewNumericDate(now.Add(manager.lifetime)), NotBefore: jwt.NewNumericDate(now),
			IssuedAt: jwt.NewNumericDate(now), ID: jti,
		},
	}
	if !authTime.IsZero() {
		claims.AuthTime = jwt.NewNumericDate(authTime.UTC())
	}
	if err := claims.Validate(); err != nil {
		return "", nil, err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(manager.key)
	if err != nil {
		return "", nil, fmt.Errorf("sign JWT: %w", err)
	}
	return signed, claims, nil
}

func (manager *JWTManager) Parse(value string) (*Claims, error) {
	return manager.parsePurpose(value, "")
}

// MFA challenges are signed JWTs, but cannot authenticate an account.
func (manager *JWTManager) IssueMFA(userID, role string, version int, action, next, transport string, now time.Time) (string, *Claims, error) {
	_, claims, err := manager.Issue(userID, role, version, now)
	if err != nil {
		return "", nil, err
	}
	claims.Purpose, claims.Action, claims.Next, claims.Transport = "mfa", action, next, transport
	claims.AuthTime = nil
	claims.Audience = jwt.ClaimStrings{jwtAudience + "-mfa"}
	claims.ExpiresAt = jwt.NewNumericDate(now.Add(5 * time.Minute))
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(manager.mfaKey)
	return token, claims, err
}

func (manager *JWTManager) ParseMFA(value string) (*Claims, error) {
	return manager.parsePurpose(value, "mfa")
}

func (manager *JWTManager) parsePurpose(value, purpose string) (*Claims, error) {
	parser, key := manager.parser, manager.key
	if purpose == "mfa" {
		parser, key = manager.mfaParser, manager.mfaKey
	}
	claims := new(Claims)
	token, err := parser.ParseWithClaims(value, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected JWT signing method")
		}
		return key, nil
	})
	if err != nil || token == nil || !token.Valid || claims.Purpose != purpose {
		return nil, errors.New("invalid JWT")
	}
	return claims, nil
}
