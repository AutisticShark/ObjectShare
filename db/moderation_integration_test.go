package db

import (
	"errors"
	"sync"
	"testing"
)

func TestPostgresModerationMigrationPreservesAccounts(t *testing.T) {
	repo := creditTestRepository(t)
	user := creditTestUser(t, repo, 42)
	if err := repo.connection.Migrator().DropColumn(&User{}, "ModerationStatus"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := repo.connection.AutoMigrate(&User{}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := repo.UserByID(t.Context(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ModerationStatus != ModerationNone || got.Email != user.Email || got.TokenVersion != user.TokenVersion || got.CreditBalance != 42 || !got.Active {
		t.Fatal("migration changed existing account")
	}
}

func TestPostgresModerationLifecycle(t *testing.T) {
	repo := creditTestRepository(t)
	user := creditTestUser(t, repo, 42)
	if user.ModerationStatus != ModerationNone {
		t.Fatal("new account is moderated")
	}
	version := user.TokenVersion
	for _, step := range []struct {
		status    string
		increment int
	}{
		{ModerationShadowbanned, 0}, {ModerationShadowbanned, 0}, {ModerationNone, 0},
		{ModerationBanned, 1}, {ModerationBanned, 0}, {ModerationShadowbanned, 1}, {ModerationNone, 0},
	} {
		if err := repo.AdminModerateUser(t.Context(), user.ID, step.status); err != nil {
			t.Fatal(err)
		}
		version += step.increment
		got, err := repo.UserByID(t.Context(), user.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.ModerationStatus != step.status || got.TokenVersion != version || got.CreditBalance != 42 || !got.Active || got.Role != RoleUser {
			t.Fatalf("unexpected moderation transition: %#v", got)
		}
	}
	if err := repo.AdminModerateUser(t.Context(), user.ID, "invalid"); !errors.Is(err, ErrInvalidModeration) {
		t.Fatalf("invalid status: %v", err)
	}
	for _, status := range []string{ModerationBanned, ModerationShadowbanned} {
		if err := repo.AdminModerateUser(t.Context(), user.ID, status); err != nil {
			t.Fatal(err)
		}
		if err := repo.DeleteUser(t.Context(), user.ID); !errors.Is(err, ErrModeratedUser) {
			t.Fatalf("deletion bypassed moderation: %v", err)
		}
	}
}

func TestPostgresModerationPreservesLastAdministrator(t *testing.T) {
	repo := creditTestRepository(t)
	one, two := creditTestUser(t, repo, 0), creditTestUser(t, repo, 0)
	for _, user := range []User{one, two} {
		if err := repo.AdminUpdateUser(t.Context(), user.ID, RoleAdmin, true); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i, user := range []User{one, two} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status := ModerationBanned
			if i == 1 {
				status = ModerationShadowbanned
			}
			results <- repo.AdminModerateUser(t.Context(), user.ID, status)
		}()
	}
	wg.Wait()
	close(results)
	success, protected := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrLastAdmin) {
			protected++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || protected != 1 {
		t.Fatalf("concurrent moderation success=%d protected=%d", success, protected)
	}
	users, err := repo.ListUsers(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range users {
		if !user.IsAvailableAdmin() {
			continue
		}
		for _, status := range []string{ModerationBanned, ModerationShadowbanned} {
			if err := repo.AdminModerateUser(t.Context(), user.ID, status); !errors.Is(err, ErrLastAdmin) {
				t.Fatalf("last admin moderation: %v", err)
			}
		}
		if err := repo.AdminUpdateUser(t.Context(), user.ID, RoleUser, true); !errors.Is(err, ErrLastAdmin) {
			t.Fatalf("last admin demotion: %v", err)
		}
		if err := repo.AdminUpdateUser(t.Context(), user.ID, RoleAdmin, false); !errors.Is(err, ErrLastAdmin) {
			t.Fatalf("last admin disabling: %v", err)
		}
		if err := repo.DeleteUser(t.Context(), user.ID); !errors.Is(err, ErrLastAdmin) {
			t.Fatalf("last admin deletion: %v", err)
		}
	}
}
