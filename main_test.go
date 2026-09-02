package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

type memorySettingsRepository struct {
	setting        *db.ApplicationSetting
	initializeRuns int
}

func (repository *memorySettingsRepository) ApplicationSettings(context.Context) (*db.ApplicationSetting, error) {
	if repository.setting == nil {
		return nil, db.ErrNotFound
	}
	copy := *repository.setting
	return &copy, nil
}

func (repository *memorySettingsRepository) InitializeApplicationSettings(_ context.Context, value string) error {
	repository.initializeRuns++
	if repository.setting == nil {
		now := time.Now().UTC()
		repository.setting = &db.ApplicationSetting{Key: "runtime_config", Value: value, UpdatedBy: "bootstrap import", CreatedAt: now, UpdatedAt: now}
	}
	return nil
}

func (repository *memorySettingsRepository) SaveApplicationSettings(context.Context, string, string, string) error {
	return nil
}

func TestDatabaseConfigurationImportsLegacyValuesOnlyOnce(t *testing.T) {
	t.Setenv("OBJECTSHARE_JWT_SECRET", "main-test-jwt-secret-with-at-least-32-bytes")
	t.Setenv("OBJECTSHARE_SETTINGS_KEY", "main-test-settings-key-with-at-least-32-bytes")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repository := &memorySettingsRepository{}

	first, err := config.Load("config.json.example")
	if err != nil {
		t.Fatal(err)
	}
	first.MaxFileSize = 33
	if err := loadDatabaseConfiguration(t.Context(), repository, first, logger); err != nil {
		t.Fatal(err)
	}
	if first.MaxFileSize != 33 || repository.initializeRuns != 1 {
		t.Fatalf("initial import failed: max=%d imports=%d", first.MaxFileSize, repository.initializeRuns)
	}

	second, err := config.Load("config.json.example")
	if err != nil {
		t.Fatal(err)
	}
	// Even an invalid stale operational seed is replaced before full runtime
	// validation once the database row exists.
	second.MaxFileSize = 0
	if err := loadDatabaseConfiguration(t.Context(), repository, second, logger); err != nil {
		t.Fatal(err)
	}
	if second.MaxFileSize != 33 || repository.initializeRuns != 1 {
		t.Fatalf("legacy value overwrote database authority: max=%d imports=%d", second.MaxFileSize, repository.initializeRuns)
	}
}

var _ db.SettingsRepository = (*memorySettingsRepository)(nil)
