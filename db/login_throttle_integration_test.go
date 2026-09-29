package db

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPostgresReserveLoginAttemptIsAtomicAndClearsOnSuccess(t *testing.T) {
	repo := creditTestRepository(t)
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	now := time.Now().UTC()

	var wg sync.WaitGroup
	results := make(chan bool, 20)
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed, _, err := repo.ReserveLoginAttempt(t.Context(), key, now)
			if err != nil {
				t.Error(err)
			}
			results <- allowed
		}()
	}
	wg.Wait()
	close(results)
	granted := 0
	for allowed := range results {
		if allowed {
			granted++
		}
	}
	if granted != maxLoginFailures {
		t.Fatalf("%d parallel attempts were granted, want exactly %d", granted, maxLoginFailures)
	}
	allowed, retryAt, err := repo.ReserveLoginAttempt(t.Context(), key, now.Add(time.Minute))
	if err != nil || allowed || !retryAt.After(now) {
		t.Fatalf("locked key: allowed=%v retryAt=%v err=%v", allowed, retryAt, err)
	}
	if err = repo.ClearLoginFailures(t.Context(), key); err != nil {
		t.Fatal(err)
	}
	if allowed, _, err = repo.ReserveLoginAttempt(t.Context(), key, now.Add(2*time.Minute)); err != nil || !allowed {
		t.Fatalf("attempt after a successful login was refused: %v %v", allowed, err)
	}
	// The lockout also expires by itself.
	if err = repo.ClearLoginFailures(t.Context(), key); err != nil {
		t.Fatal(err)
	}
	for range maxLoginFailures {
		if _, _, err = repo.ReserveLoginAttempt(t.Context(), key, now); err != nil {
			t.Fatal(err)
		}
	}
	if allowed, _, err = repo.ReserveLoginAttempt(t.Context(), key, now.Add(loginLockout+time.Second)); err != nil || !allowed {
		t.Fatalf("lockout did not expire: %v %v", allowed, err)
	}
}

func TestPostgresClaimUnverifiedAccountRemovesTheSquattersAccess(t *testing.T) {
	repo := creditTestRepository(t)
	suffix := uuid.NewString()
	squatted := &User{ID: uuid.NewString(), Email: "owner-" + suffix + "@example.com", DisplayName: "Squatter", PasswordHash: "$argon2id$squatter", Role: RoleUser, Active: true, TokenVersion: 2, MFA: MFAState{Method: "totp"}}
	if err := repo.CreateUser(t.Context(), squatted); err != nil {
		t.Fatal(err)
	}
	if err := repo.LinkOAuthIdentity(t.Context(), &OAuthIdentity{UserID: squatted.ID, Provider: "github", Subject: "attacker-" + suffix, Email: "attacker@example.net"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	owner := &OAuthIdentity{Provider: "google", Subject: "owner-" + suffix, Email: squatted.Email}
	claimed, err := repo.ClaimUnverifiedAccountForOAuth(t.Context(), squatted.ID, owner, now)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.PasswordHash != "" || claimed.MFA.Method != "" || claimed.TokenVersion != 3 || claimed.EmailVerifiedAt == nil {
		t.Fatalf("claimed account kept the squatter's credentials: %#v", claimed)
	}
	identities, err := repo.OAuthIdentities(t.Context(), squatted.ID)
	if err != nil || len(identities) != 1 || identities[0].Provider != "google" {
		t.Fatalf("identities after claim: %#v %v", identities, err)
	}
	// A verified account can no longer be claimed.
	if _, err = repo.ClaimUnverifiedAccountForOAuth(t.Context(), squatted.ID, &OAuthIdentity{Provider: "github", Subject: "later-" + suffix, Email: squatted.Email}, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("second claim = %v, want ErrConflict", err)
	}
}

func TestPostgresReserveGuestUploadEnforcesTheGlobalPendingCap(t *testing.T) {
	repo := creditTestRepository(t)
	const limit = int64(1000)
	reserve := func(size int64) error {
		id := uuid.NewString()
		now := time.Now().UTC()
		expires := now.Add(time.Hour)
		return repo.ReserveGuestUpload(t.Context(), &FileList{FileID: id, AnonymousSessionToken: "token", FileName: "g.bin", FileSize: size, ContentType: "application/octet-stream",
			IsAnonymousUpload: true, StorageService: "r2", UploadStatus: "pending", ChecksumStatus: "unavailable", UploadExpiresAt: &expires, CreatedAt: now, UpdatedAt: now}, limit)
	}
	// Other tests share the database, so measure against whatever is already pending.
	var already int64
	if err := repo.connection.Model(&FileList{}).Select("COALESCE(SUM(file_size), 0)").Where("file_owner IS NULL AND upload_status = ?", "pending").Scan(&already).Error; err != nil {
		t.Fatal(err)
	}
	if already != 0 {
		t.Skip("unfinished guest uploads already exist in this database")
	}
	var wg sync.WaitGroup
	results := make(chan error, 10)
	for range 10 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- reserve(300) }()
	}
	wg.Wait()
	close(results)
	granted := 0
	for err := range results {
		var quotaError *UploadQuotaError
		switch {
		case err == nil:
			granted++
		case errors.As(err, &quotaError) && quotaError.Scope == GuestUploadScope:
		default:
			t.Fatal(err)
		}
	}
	if granted != 3 {
		t.Fatalf("%d parallel 300-byte reservations were granted under a 1000-byte cap, want 3", granted)
	}
}
