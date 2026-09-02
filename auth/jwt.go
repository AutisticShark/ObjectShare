package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	jwtIssuer   = "objectshare"
	jwtAudience = "objectshare"
	jwtLeeway   = 30 * time.Second
)

type Claims struct {
	Role         string `json:"role"`
	TokenVersion int    `json:"ver"`
	CSRF         string `json:"csrf"`
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
	return nil
}

type JWTManager struct {
	key      []byte
	lifetime time.Duration
	parser   *jwt.Parser
}

func NewJWTManager(secret string, lifetime time.Duration) (*JWTManager, error) {
	if len(secret) < 32 {
		return nil, errors.New("JWT secret must contain at least 32 bytes")
	}
	if lifetime <= 0 {
		return nil, errors.New("JWT lifetime must be positive")
	}
	return &JWTManager{
		key:      []byte(secret),
		lifetime: lifetime,
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
			jwt.WithIssuer(jwtIssuer),
			jwt.WithAudience(jwtAudience),
			jwt.WithExpirationRequired(),
			jwt.WithIssuedAt(),
			jwt.WithLeeway(jwtLeeway),
			jwt.WithStrictDecoding(),
		),
	}, nil
}

func (manager *JWTManager) Issue(userID, role string, tokenVersion int, now time.Time) (string, *Claims, error) {
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
	claims := new(Claims)
	token, err := manager.parser.ParseWithClaims(value, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected JWT signing method")
		}
		return manager.key, nil
	})
	if err != nil || token == nil || !token.Valid {
		return nil, errors.New("invalid JWT")
	}
	return claims, nil
}
