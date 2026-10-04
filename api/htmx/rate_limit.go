package htmx

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

type localRateLimitBucket struct {
	windowStarted time.Time
	windowEnds    time.Time
	used          int
}

type localRateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]localRateLimitBucket
	lastPruned time.Time
}

// localRateLimitPruneInterval bounds how often expired buckets are swept. Keys
// are per client and per scope, so without a sweep the map would grow with every
// distinct client for the life of the process.
const localRateLimitPruneInterval = time.Minute

func newLocalRateLimiter() *localRateLimiter {
	return &localRateLimiter{buckets: make(map[string]localRateLimitBucket)}
}

func (limiter *localRateLimiter) consume(key string, limit int, window time.Duration, now time.Time) (bool, time.Time) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.pruneLocked(now)
	bucket, found := limiter.buckets[key]
	if !found || !now.Before(bucket.windowStarted.Add(window)) {
		limiter.buckets[key] = localRateLimitBucket{windowStarted: now, windowEnds: now.Add(window), used: 1}
		return true, time.Time{}
	}
	retryAt := bucket.windowStarted.Add(window)
	if bucket.used >= limit {
		return false, retryAt
	}
	bucket.used++
	limiter.buckets[key] = bucket
	return true, retryAt
}

func (limiter *localRateLimiter) pruneLocked(now time.Time) {
	if now.Sub(limiter.lastPruned) < localRateLimitPruneInterval {
		return
	}
	limiter.lastPruned = now
	for key, bucket := range limiter.buckets {
		if !now.Before(bucket.windowEnds) {
			delete(limiter.buckets, key)
		}
	}
}

func (handler *Handler) RateLimitAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if handler.allowRequest(writer, request, "api", handler.rateLimitSettings().APILimit) {
			next.ServeHTTP(writer, request)
		}
	})
}

func (handler *Handler) allowRequest(writer http.ResponseWriter, request *http.Request, scope string, limit int) bool {
	return handler.allowRequestOr(writer, request, scope, limit, func() {
		http.Error(writer, "Too many requests. Try again later.", http.StatusTooManyRequests)
	})
}

// allowRequestOr consumes the rate limit like allowRequest. When the request is
// limited it sets the rate-limit headers and calls reject, which must write a
// 429 response, so a form can answer with its own page instead of plain text.
func (handler *Handler) allowRequestOr(writer http.ResponseWriter, request *http.Request, scope string, limit int, reject func()) bool {
	settings := handler.rateLimitSettings()
	if !settings.Enabled || limit <= 0 {
		return true
	}
	identityKey := "ip:" + handler.clientNetwork(request)
	if identity := currentIdentity(request); identity != nil && !preAuthRateLimitScopes[scope] {
		identityKey = "user:" + identity.User.ID
	}
	digest := sha256.Sum256([]byte(identityKey))
	keyHash := hex.EncodeToString(digest[:])
	now := time.Now().UTC()
	var allowed bool
	var retryAt time.Time
	var err error
	if handler.rateLimits != nil {
		allowed, retryAt, err = handler.rateLimits.ConsumeRateLimit(request.Context(), scope, keyHash, limit, settings.Window.Duration(), now)
	} else {
		allowed, retryAt = handler.localRateLimits.consume(scope+":"+keyHash, limit, settings.Window.Duration(), now)
	}
	if err != nil {
		handler.internalError(writer, request, "consume request rate limit", err)
		return false
	}
	if allowed {
		return true
	}
	retrySeconds := max(1, int(math.Ceil(time.Until(retryAt).Seconds())))
	writer.Header().Set("Retry-After", fmt.Sprint(retrySeconds))
	writer.Header().Set("X-RateLimit-Limit", fmt.Sprint(limit))
	writer.Header().Set("X-RateLimit-Scope", scope)
	reject()
	return false
}

// preAuthRateLimitScopes guard steps that run before, or instead of, proving
// who the caller is. They are always keyed by client network: a JWT the caller
// already holds (for example one returned by the previous signup) must not open
// a fresh bucket.
var preAuthRateLimitScopes = map[string]bool{
	"login": true, "signup": true, "mfa-verify": true, "mfa-send": true, "email-verify": true,
}

func (handler *Handler) rateLimitSettings() config.RateLimitConfig {
	if handler.config.RateLimit == nil {
		return config.RateLimitConfig{}
	}
	return *handler.config.RateLimit
}

func (handler *Handler) clientIP(request *http.Request) string {
	remoteIP := parseRemoteIP(request.RemoteAddr)
	if remoteIP == nil {
		return "unknown"
	}
	if !ipInNetworks(remoteIP, handler.trustedProxies) {
		return remoteIP.String()
	}
	// A proxy may append its own X-Forwarded-For line after one the client sent,
	// so every line is read in order rather than only the client-controlled first.
	chain := strings.Split(strings.Join(request.Header.Values("X-Forwarded-For"), ","), ",")
	for index := len(chain) - 1; index >= 0; index-- {
		candidate := net.ParseIP(strings.TrimSpace(chain[index]))
		if candidate == nil {
			continue
		}
		if !ipInNetworks(candidate, handler.trustedProxies) {
			return candidate.String()
		}
	}
	return remoteIP.String()
}

// clientNetwork is the client identity for rate-limit and login-throttle keys.
// IPv4 clients (including IPv4-mapped IPv6) are keyed by address. IPv6 clients
// are keyed by their /64, the smallest prefix normally assigned to one
// subscriber, so rotating addresses inside it does not yield fresh buckets.
func (handler *Handler) clientNetwork(request *http.Request) string {
	ip := net.ParseIP(handler.clientIP(request))
	if ip == nil {
		return "unknown"
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		return ipv4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

func parseRemoteIP(value string) net.IP {
	host, _, err := net.SplitHostPort(value)
	if err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(strings.Trim(value, "[]"))
}

func ipInNetworks(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func parseTrustedProxies(values []string) ([]*net.IPNet, error) {
	networks := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, err
		}
		networks = append(networks, network)
	}
	return networks, nil
}

var _ db.RateLimitRepository = (*db.GormRepository)(nil)
