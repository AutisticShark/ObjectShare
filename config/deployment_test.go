package config

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// composeEnvironment returns the app service's environment entries as written.
func composeEnvironment(t *testing.T) map[string]string {
	t.Helper()
	content, err := os.ReadFile("../compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]string{}
	for _, match := range regexp.MustCompile(`(?m)^      (OBJECTSHARE_[A-Z0-9_]+): (.*)$`).FindAllStringSubmatch(strings.ReplaceAll(string(content), "\r\n", "\n"), -1) {
		entries[match[1]] = strings.TrimSpace(match[2])
	}
	if len(entries) < 20 {
		t.Fatalf("only %d app environment entries found in compose.yaml", len(entries))
	}
	return entries
}

// Compose values are fallbacks, not overrides: a non-empty ${VAR:-default}
// would replace the matching value in a mounted config.json at the first
// import. Only the stack's own topology may be fixed by Compose.
func TestComposeForwardsSeedVariablesWithoutDefaults(t *testing.T) {
	topology := map[string]bool{
		"OBJECTSHARE_ADDRESS": true, "OBJECTSHARE_DB_HOST": true, "OBJECTSHARE_DB_PORT": true, "OBJECTSHARE_DB_USER": true,
		"OBJECTSHARE_DB_PASSWORD": true, "OBJECTSHARE_DB_DATABASE": true, "OBJECTSHARE_DB_SSLMODE": true,
		"OBJECTSHARE_REDIS_URL": true, "OBJECTSHARE_REDIS_PASSWORD": true, "OBJECTSHARE_JWT_SECRET": true,
	}
	for name, value := range composeEnvironment(t) {
		if topology[name] {
			continue
		}
		if want := `"${` + name + `:-}"`; value != want {
			t.Errorf("compose.yaml sets %s to %s; forward it as %s so config.json and built-in defaults apply", name, value, want)
		}
	}
}

// The documented zero-configuration Compose install sets only the PostgreSQL
// password, JWT secret, and settings key. Resolve compose.yaml the way Compose
// does for that .env and check that the application still starts with the
// image's volume path and the bundled Redis.
func TestZeroConfigurationComposeEnvironmentLoads(t *testing.T) {
	dockerfile, err := os.ReadFile("../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	for _, match := range regexp.MustCompile(`(?m)^ENV (OBJECTSHARE_[A-Z0-9_]+)=(\S+)`).FindAllStringSubmatch(string(dockerfile), -1) {
		t.Setenv(match[1], match[2])
	}
	interpolation := regexp.MustCompile(`^"?\$\{([A-Z0-9_]+)(:-|-|:\?)([^}]*)\}"?$`)
	for name, value := range composeEnvironment(t) {
		match := interpolation.FindStringSubmatch(value)
		switch {
		case match == nil:
			t.Setenv(name, strings.Trim(value, `"`))
		case match[2] == ":?":
			t.Setenv(name, "compose-test-secret-with-at-least-32-random-bytes")
		default:
			t.Setenv(name, match[3])
		}
	}
	t.Setenv("OBJECTSHARE_SETTINGS_KEY", "compose-test-settings-key-with-at-least-32-bytes")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("zero-configuration Compose environment rejected: %v", err)
	}
	if cfg.StorageService != "filesystem" || cfg.StoragePath != "/var/lib/objectshare/objects" || cfg.Address != ":8080" ||
		cfg.Redis.URL != "redis://redis:6379/0" || cfg.Db.Host != "db" || cfg.Auth.TokenLifetime.Duration().Hours() != 12 {
		t.Fatalf("zero-configuration Compose install changed: storage %q %q address %q redis %q db %q", cfg.StorageService, cfg.StoragePath, cfg.Address, cfg.Redis.URL, cfg.Db.Host)
	}
}

// parsedEnvironmentNames lists every OBJECTSHARE_* variable the parser reads.
func parsedEnvironmentNames(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	lookupEnvironment = func(name string) (string, bool) { seen[name] = true; return "", false }
	t.Cleanup(func() { lookupEnvironment = os.LookupEnv })
	if err := applyEnvironment(testDefaults()); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Every variable the parser reads must be documented in .env.example and
// forwarded by Compose, or setting it in .env silently does nothing.
func TestEveryParsedVariableIsDocumentedAndForwarded(t *testing.T) {
	example, err := os.ReadFile("../.env.example")
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	for _, match := range regexp.MustCompile(`(?m)^(OBJECTSHARE_[A-Z0-9_]+)=`).FindAllStringSubmatch(string(example), -1) {
		documented[match[1]] = true
	}
	compose := composeEnvironment(t)
	// OBJECTSHARE_PORT is Compose's legacy host-port fallback, so the app keeps
	// its fixed container address; Compose owns the database connection.
	notForwarded := map[string]bool{"OBJECTSHARE_PORT": true}
	composeOwned := map[string]bool{
		"OBJECTSHARE_PORT": true, "OBJECTSHARE_ADDRESS": true, "OBJECTSHARE_DB_HOST": true, "OBJECTSHARE_DB_PORT": true,
		"OBJECTSHARE_DB_USER": true, "OBJECTSHARE_DB_PASSWORD": true, "OBJECTSHARE_DB_DATABASE": true, "OBJECTSHARE_DB_SSLMODE": true,
	}
	for _, name := range parsedEnvironmentNames(t) {
		if _, ok := compose[name]; !ok && !notForwarded[name] {
			t.Errorf("compose.yaml does not forward %s", name)
		}
		if !documented[name] && !composeOwned[name] {
			t.Errorf(".env.example does not document %s", name)
		}
	}
	for name := range documented {
		if _, ok := compose[name]; !ok && name != "OBJECTSHARE_HOST_PORT" {
			t.Errorf(".env.example documents %s but compose.yaml does not forward it", name)
		}
	}
}
