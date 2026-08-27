package config

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDurationAcceptsStringAndLegacySeconds(t *testing.T) {
	for _, test := range []struct {
		input string
		want  time.Duration
	}{
		{`"15s"`, 15 * time.Second}, {`600`, 10 * time.Minute},
	} {
		var duration Duration
		if err := json.Unmarshal([]byte(test.input), &duration); err != nil {
			t.Fatal(err)
		}
		if duration.Duration() != test.want {
			t.Fatalf("%s: got %s, want %s", test.input, duration.Duration(), test.want)
		}
	}
}

func TestDefaultsValidate(t *testing.T) {
	cfg := defaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestExampleConfiguration(t *testing.T) {
	cfg, err := Load("../config.json.example")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Address != ":8080" || cfg.Db.Port != 5432 {
		t.Fatalf("unexpected example configuration: %#v", cfg)
	}
}

func TestEncryptionMemoryLimit(t *testing.T) {
	cfg := defaults()
	cfg.MaxFileSize = 129
	cfg.Encryption.Enabled = true
	cfg.Encryption.Key = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected encrypted upload limit error")
	}
}
