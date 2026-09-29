package db

import (
	"sync"
	"testing"
	"time"
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
