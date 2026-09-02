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
	used          int
}

type localRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]localRateLimitBucket
}

func newLocalRateLimiter() *localRateLimiter {
	return &localRateLimiter{buckets: make(map[string]localRateLimitBucket)}
}

func (limiter *localRateLimiter) consume(key string, limit int, window time.Duration, now time.Time) (bool, time.Time) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	bucket, found := limiter.buckets[key]
	if !found || !now.Before(bucket.windowStarted.Add(window)) {
		limiter.buckets[key] = localRateLimitBucket{windowStarted: now, used: 1}
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

func (handler *Handler) RateLimitAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if handler.allowRequest(writer, request, "api", handler.rateLimitSettings().APILimit) {
			next.ServeHTTP(writer, request)
		}
	})
}

func (handler *Handler) allowRequest(writer http.ResponseWriter, request *http.Request, scope string, limit int) bool {
	settings := handler.rateLimitSettings()
	if !settings.Enabled || limit <= 0 {
		return true
	}
	identityKey := "ip:" + handler.clientIP(request)
	if identity := currentIdentity(request); identity != nil {
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
	http.Error(writer, "Too many requests. Try again later.", http.StatusTooManyRequests)
	return false
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
	chain := strings.Split(request.Header.Get("X-Forwarded-For"), ",")
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
