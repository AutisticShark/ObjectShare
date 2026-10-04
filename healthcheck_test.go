package main

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestHealthURLUsesTheConfiguredListenAddress(t *testing.T) {
	for address, want := range map[string]string{
		":8080":           "http://127.0.0.1:8080/health/live",
		":9000":           "http://127.0.0.1:9000/health/live",
		"0.0.0.0:9000":    "http://127.0.0.1:9000/health/live",
		"[::]:9000":       "http://[::1]:9000/health/live",
		"127.0.0.1:9000":  "http://127.0.0.1:9000/health/live",
		"[::1]:9000":      "http://[::1]:9000/health/live",
		"10.0.0.5:9000":   "http://10.0.0.5:9000/health/live",
		"localhost:19000": "http://localhost:19000/health/live",
	} {
		if got, err := healthURL(address); err != nil || got != want {
			t.Errorf("healthURL(%q) = %q, %v; want %q", address, got, err, want)
		}
	}
	if _, err := healthURL("9000"); err == nil {
		t.Error("an address without a port was accepted")
	}
}

// The -healthcheck command must probe the configured address, from either
// the environment or config.json, rather than a hard-coded 127.0.0.1:8080.
func TestHealthcheckProbesTheConfiguredAddress(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	_, port, _ := net.SplitHostPort(listener.Addr().String())

	t.Setenv("OBJECTSHARE_HEALTH_URL", "")
	t.Setenv("OBJECTSHARE_ADDRESS", "0.0.0.0:"+port)
	if err := runHealthcheck(""); err != nil {
		t.Fatalf("health check with OBJECTSHARE_ADDRESS: %v", err)
	}

	t.Setenv("OBJECTSHARE_ADDRESS", "")
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"port": `+port+`}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runHealthcheck(path); err != nil {
		t.Fatalf("health check with a config.json port: %v", err)
	}

	t.Setenv("OBJECTSHARE_HEALTH_URL", "http://127.0.0.1:"+port+"/missing")
	if err := runHealthcheck(path); err == nil {
		t.Fatal("OBJECTSHARE_HEALTH_URL override was ignored")
	}
}
