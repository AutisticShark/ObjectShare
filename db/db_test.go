package db

import (
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"gorm.io/gorm/schema"
)

func TestUploadQuotaComparisonDoesNotOverflow(t *testing.T) {
	if exceedsQuota(math.MaxInt64-5, 10, math.MaxInt64) != true {
		t.Fatal("overflowing reservation should exceed the quota")
	}
	if exceedsQuota(100, 100, 0) {
		t.Fatal("zero quota should be unlimited")
	}
	err := &UploadQuotaError{Scope: "user", Used: 90, Limit: 100, Requested: 11}
	if !errors.Is(err, ErrUploadQuota) {
		t.Fatal("quota error does not unwrap to ErrUploadQuota")
	}
}

func TestUserUploadQuotaMigrationMetadata(t *testing.T) {
	parsed, err := schema.Parse(&User{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	field := parsed.FieldsByDBName["upload_quota_bytes"]
	if field == nil || !field.NotNull || !field.HasDefaultValue || field.DefaultValueInterface != int64(0) {
		t.Fatalf("unsafe upload quota field metadata: %#v", field)
	}
	check, ok := parsed.ParseCheckConstraints()["chk_users_upload_quota_bytes_nonnegative"]
	if !ok || check.Constraint != "upload_quota_bytes >= 0" {
		t.Fatalf("missing nonnegative quota constraint: %#v", parsed.ParseCheckConstraints())
	}
}

func TestUserDarkModeMigrationMetadata(t *testing.T) {
	parsed, err := schema.Parse(&User{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	field := parsed.FieldsByDBName["dark_mode"]
	if field == nil || !field.NotNull || !field.HasDefaultValue || field.DefaultValueInterface != false {
		t.Fatalf("unsafe dark mode field metadata: %#v", field)
	}
}

func TestApplicationSettingsMigrationMetadata(t *testing.T) {
	parsed, err := schema.Parse(&ApplicationSetting{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.FieldsByDBName["key"] == nil || !parsed.FieldsByDBName["key"].PrimaryKey {
		t.Fatal("application setting key is not a primary key")
	}
	for _, name := range []string{"value", "updated_by"} {
		if parsed.FieldsByDBName[name] == nil || !parsed.FieldsByDBName[name].NotNull {
			t.Fatalf("application setting %s is nullable", name)
		}
	}
}

func TestPostgresConfigPreservesTimeZoneAndCredentials(t *testing.T) {
	cfg := &config.DatabaseConfig{
		Host: "db.example", Port: 5432, User: "objectshare",
		Password: "slash/colon:at@percent%", Database: "objectshare",
		SSLMode: "require", TimeZone: "Asia/Taipei",
		ConnMaxLifetime: config.Duration(30 * time.Minute),
	}
	parsed, location, err := postgresConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.RuntimeParams["timezone"]; got != cfg.TimeZone {
		t.Fatalf("runtime timezone = %q, want %q", got, cfg.TimeZone)
	}
	if location.String() != cfg.TimeZone {
		t.Fatalf("scan timezone = %q, want %q", location, cfg.TimeZone)
	}
	if parsed.Password != cfg.Password {
		t.Fatal("database password was changed while parsing the connection configuration")
	}
}

func TestPostgresConfigRejectsUnknownTimeZone(t *testing.T) {
	cfg := &config.DatabaseConfig{
		Host: "localhost", Port: 5432, User: "objectshare", Database: "objectshare",
		SSLMode: "disable", TimeZone: "Not/A_Real_Zone",
	}
	if _, _, err := postgresConfig(cfg); err == nil {
		t.Fatal("expected an invalid timezone error")
	}
}
