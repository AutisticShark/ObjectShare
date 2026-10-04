package htmx

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestSchemeTrustsForwardedProtoOnlyFromTrustedProxies(t *testing.T) {
	handler := newAuthTestHandler(t, newAuthMemoryRepository(), false)
	var err error
	if handler.trustedProxies, err = parseTrustedProxies([]string{"10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, remote string
		proto        []string
		tls          bool
		want         string
	}{
		{"trusted proxy https", "10.0.0.2:4000", []string{"https"}, false, "https"},
		{"trusted proxy http", "10.0.0.2:4000", []string{"HTTP"}, false, "http"},
		{"trusted proxy overrides the hop to this process", "10.0.0.2:4000", []string{"http"}, true, "http"},
		{"untrusted peer is ignored", "203.0.113.9:4000", []string{"http"}, false, ""},
		{"untrusted peer over TLS", "203.0.113.9:4000", []string{"http"}, true, "https"},
		{"appended list is ambiguous", "10.0.0.2:4000", []string{"http, https"}, false, ""},
		{"repeated header is ambiguous", "10.0.0.2:4000", []string{"https", "http"}, false, ""},
		{"unknown value", "10.0.0.2:4000", []string{"wss"}, false, ""},
		{"trusted proxy without header", "10.0.0.2:4000", nil, false, ""},
		{"plain connection is unknown", "198.51.100.1:4000", nil, false, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/login", nil)
			request.RemoteAddr = test.remote
			for _, value := range test.proto {
				request.Header.Add("X-Forwarded-Proto", value)
			}
			if test.tls {
				request.TLS = &tls.ConnectionState{}
			}
			if got := handler.RequestScheme(request); got != test.want {
				t.Fatalf("RequestScheme = %q, want %q", got, test.want)
			}
		})
	}
}
