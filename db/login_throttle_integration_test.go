package db

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
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
	// file_lists is not in the shared helper: the legacy-migration test creates its own
	// older copy of that table, so tests that need it migrate it themselves.
	if err := repo.connection.AutoMigrate(&FileList{}); err != nil {
		t.Fatal(err)
	}
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

func TestPostgresPaymentReconciliationIsIdempotentPerGatewayPayment(t *testing.T) {
	repo := creditTestRepository(t)
	suffix := uuid.NewString()
	record := PaymentReconciliation{Gateway: "stripe", GatewayPaymentID: "pi_" + suffix, TopUpID: uuid.NewString(), AmountMinor: 2500, Currency: "usd", Reason: "conflict"}
	for range 3 {
		if err := repo.RecordPaymentReconciliation(t.Context(), record); err != nil {
			t.Fatal(err)
		}
	}
	var count int64
	if err := repo.connection.Model(&PaymentReconciliation{}).Where("gateway = ? AND gateway_payment_id = ?", "stripe", "pi_"+suffix).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("reconciliation rows = %d, err %v", count, err)
	}
}

func TestPostgresLegacySessionsCleanupOnlyDropsTheSessionShape(t *testing.T) {
	repo := creditTestRepository(t)
	schema := "objectshare_sessions_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	err := repo.connection.Transaction(func(tx *gorm.DB) error {
		for _, statement := range []string{
			`CREATE SCHEMA ` + schema,
			`SET LOCAL search_path TO ` + schema,
			`CREATE TABLE sessions (id integer, note text)`, // another application's table
		} {
			if err := tx.Exec(statement).Error; err != nil {
				return err
			}
		}
		if err := tx.Exec(dropLegacySessionsSQL).Error; err != nil {
			return err
		}
		var foreign int64
		if err := tx.Raw(`SELECT count(*) FROM information_schema.tables WHERE table_schema = ? AND table_name = 'sessions'`, schema).Scan(&foreign).Error; err != nil || foreign != 1 {
			t.Fatalf("a table without the session shape was dropped (count %d, err %v)", foreign, err)
		}
		if err := tx.Exec(`DROP TABLE sessions`).Error; err != nil {
			return err
		}
		if err := tx.Exec(`CREATE TABLE sessions (token_hash text, user_id uuid, expires_at timestamptz)`).Error; err != nil {
			return err
		}
		if err := tx.Exec(dropLegacySessionsSQL).Error; err != nil {
			return err
		}
		var legacy int64
		if err := tx.Raw(`SELECT count(*) FROM information_schema.tables WHERE table_schema = ? AND table_name = 'sessions'`, schema).Scan(&legacy).Error; err != nil || legacy != 0 {
			t.Fatalf("the legacy sessions table survived (count %d, err %v)", legacy, err)
		}
		// Idempotent once the table is gone.
		if err := tx.Exec(dropLegacySessionsSQL).Error; err != nil {
			return err
		}
		return errRollbackSessionsTest
	})
	if err != errRollbackSessionsTest {
		t.Fatal(err)
	}
}

var errRollbackSessionsTest = errors.New("roll back the scratch schema")

func TestPostgresRehashPasswordOnlyReplacesTheVerifiedHash(t *testing.T) {
	repo := creditTestRepository(t)
	user := &User{ID: uuid.NewString(), Email: uuid.NewString() + "@example.com", PasswordHash: "old-hash", Role: RoleUser, Active: true, TokenVersion: 3}
	if err := repo.CreateUser(t.Context(), user); err != nil {
		t.Fatal(err)
	}
	if err := repo.RehashPassword(t.Context(), user.ID, "old-hash", "new-hash"); err != nil {
		t.Fatal(err)
	}
	// A hash changed in the meantime (for example a password change) must not be overwritten.
	if err := repo.RehashPassword(t.Context(), user.ID, "old-hash", "stale-upgrade"); err != nil {
		t.Fatal(err)
	}
	stored, err := repo.UserByID(t.Context(), user.ID)
	if err != nil || stored.PasswordHash != "new-hash" || stored.TokenVersion != 3 {
		t.Fatalf("stored = %#v, err %v", stored, err)
	}
}
