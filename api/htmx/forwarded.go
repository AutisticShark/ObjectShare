package htmx

import (
	"net/http"
	"strings"
)

// RequestScheme reports the scheme ("http" or "https") the browser used to
// reach ObjectShare, or "" when it cannot be determined reliably. A single
// X-Forwarded-Proto value is honoured only when the TCP peer is a trusted
// proxy, the same boundary that governs X-Forwarded-For. Otherwise a TLS
// connection to this process means HTTPS. A plain connection says nothing,
// because a TLS-terminating proxy may sit in front of the application.
func (handler *Handler) RequestScheme(request *http.Request) string {
	if remoteIP := parseRemoteIP(request.RemoteAddr); remoteIP != nil && ipInNetworks(remoteIP, handler.trustedProxies) {
		// Several values (a list or repeated headers) mean a proxy appended to
		// a client-supplied header; trusting either end could be spoofed.
		if values := request.Header.Values("X-Forwarded-Proto"); len(values) == 1 {
			switch scheme := strings.ToLower(strings.TrimSpace(values[0])); scheme {
			case "http", "https":
				return scheme
			}
		}
	}
	if request.TLS != nil {
		return "https"
	}
	return ""
}
