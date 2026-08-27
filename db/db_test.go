package db

import (
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
)

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
