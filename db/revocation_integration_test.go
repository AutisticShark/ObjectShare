package db

import (
	"testing"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/google/uuid"
)

// The JWT parser accepts a token until exp+JWTLeeway, so a revocation must be
// honored, and survive cleanup, for that whole window.
func TestPostgresRevocationOutlastsJWTLeeway(t *testing.T) {
	repo := creditTestRepository(t)
	if err := repo.connection.AutoMigrate(&RevokedToken{}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	expires := now.Add(time.Hour)
	hash := uuid.NewString()
	if err := repo.RevokeToken(t.Context(), hash, expires, now); err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{expires.Add(-time.Second), expires.Add(10 * time.Second), expires.Add(appauth.JWTLeeway - time.Second)} {
		revoked, err := repo.TokenRevoked(t.Context(), hash, at)
		if err != nil || !revoked {
			t.Fatalf("TokenRevoked %v after exp = %v, %v; the parser still accepts the token", at.Sub(expires), revoked, err)
		}
	}

	// Cleanup triggered by a later revocation inside the leeway keeps the row.
	if err := repo.RevokeToken(t.Context(), uuid.NewString(), expires.Add(time.Hour), expires.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if revoked, err := repo.TokenRevoked(t.Context(), hash, expires.Add(10*time.Second)); err != nil || !revoked {
		t.Fatalf("revocation cleaned up inside the leeway: %v, %v", revoked, err)
	}

	// Once the parser would reject the token anyway, the row is no longer
	// needed and cleanup removes it.
	after := expires.Add(appauth.JWTLeeway + time.Second)
	if revoked, err := repo.TokenRevoked(t.Context(), hash, after); err != nil || revoked {
		t.Fatalf("TokenRevoked after the leeway = %v, %v", revoked, err)
	}
	if err := repo.RevokeToken(t.Context(), uuid.NewString(), after.Add(time.Hour), after); err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := repo.connection.Model(&RevokedToken{}).Where("jti_hash = ?", hash).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("expired revocation was not cleaned up: count=%d err=%v", count, err)
	}
}
