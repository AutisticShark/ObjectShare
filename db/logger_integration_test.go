package db

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/google/uuid"
)

// GORM's default logger printed failed and slow statements to stdout with
// every bound value, including argon2id hashes and email addresses. Query
// diagnostics must go through the structured logger with placeholders only.
func TestPostgresQueryLogNeverContainsBoundValues(t *testing.T) {
	settings := creditTestSettings(t)
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	repo, err := openPostgres(t.Context(), &config.DatabaseConfig{MaxOpenConns: 2, MaxIdleConns: 1}, settings, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	hash := "$argon2id$v=19$m=65536,t=3,p=4$query-log-test-secret"
	email := "query-log-" + uuid.NewString() + "@example.com"
	user := User{ID: uuid.NewString(), Email: email, PasswordHash: hash, Active: true, TokenVersion: 1}
	if err := repo.connection.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	duplicate := User{ID: uuid.NewString(), Email: email, PasswordHash: hash, Active: true, TokenVersion: 1}
	if err := repo.connection.Create(&duplicate).Error; err == nil {
		t.Fatal("duplicate email was accepted")
	}
	if _, err := repo.UserByID(t.Context(), uuid.NewString()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user: %v", err)
	}
	// Scan records statements through GORM's package-level recorder; make
	// this one slow enough to be logged.
	var count int64
	if err := repo.connection.Raw("SELECT count(*) FROM users WHERE email = ? AND pg_sleep(0.25) IS NOT NULL", email).Scan(&count).Error; err != nil || count != 1 {
		t.Fatalf("slow scan: count %d, err %v", count, err)
	}

	logged := output.String()
	if !strings.Contains(logged, `"SQL executed"`) || !strings.Contains(logged, "$1") {
		t.Fatalf("failed and slow statements were not logged through slog with placeholders:\n%s", logged)
	}
	for _, leaked := range []string{hash, "query-log-test-secret", email, "record not found", "\x1b["} {
		if strings.Contains(logged, leaked) {
			t.Fatalf("query log contains %q:\n%s", leaked, logged)
		}
	}
}
