package htmx

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/AutisticShark/ObjectShare/db"
)

// Guest uploads are owned by whoever holds their owner token. Earlier releases
// stored each token in its own 30-day cookie, so a browser that uploaded many
// guest files sent one cookie per file with every request; around 90 of them
// overflow common reverse-proxy header buffers and run into browser per-site
// cookie limits. A browser now holds a single random owner key instead, and
// each guest upload's token is an HMAC of its file ID under that key. The key
// cookie has the same HttpOnly, Secure, SameSite=Strict, and path settings,
// and stays one size however many files the browser uploads. The per-file
// cookies browsers already hold remain valid, and a per-file cookie is still
// issued when a token cannot be tied to the browser's key (for example when
// another tab replaced the key while this upload was running).

const (
	guestOwnerKeyCookieName  = "objectshare_owner_key"
	guestOwnerCookieLifetime = 30 * 24 * time.Hour
	guestOwnerKeyBytes       = 32
)

type guestOwnerKeyContextKey struct{}

// guestOwnerKey is the owner key used for one request's guest uploads.
type guestOwnerKey struct {
	key        []byte
	fromCookie bool // false when the key was created for this request
}

// requestGuestOwnerKey returns the well-formed owner key the browser sent, if any.
func requestGuestOwnerKey(request *http.Request) []byte {
	cookie, err := request.Cookie(guestOwnerKeyCookieName)
	if err != nil {
		return nil
	}
	key, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || len(key) != guestOwnerKeyBytes {
		return nil
	}
	return key
}

// deriveOwnerToken is the owner token of fileID under a browser's owner key.
func deriveOwnerToken(key []byte, fileID string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("objectshare-guest-owner-v1\x00" + fileID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// withGuestOwnerKey attaches the browser's owner key, or a new one, to a guest
// upload request so every file in it derives its token from the same key.
// Account uploads keep random tokens.
func withGuestOwnerKey(request *http.Request) (*http.Request, error) {
	if currentIdentity(request) != nil {
		return request, nil
	}
	state := &guestOwnerKey{key: requestGuestOwnerKey(request), fromCookie: true}
	if state.key == nil {
		state.key, state.fromCookie = make([]byte, guestOwnerKeyBytes), false
		if _, err := rand.Read(state.key); err != nil {
			return request, err
		}
	}
	return request.WithContext(context.WithValue(request.Context(), guestOwnerKeyContextKey{}, state)), nil
}

func requestGuestOwnerState(request *http.Request) *guestOwnerKey {
	state, _ := request.Context().Value(guestOwnerKeyContextKey{}).(*guestOwnerKey)
	return state
}

// newUploadOwnerToken returns the owner token and its stored hash for a new
// upload: derived from the request's guest owner key, or random otherwise.
func newUploadOwnerToken(request *http.Request, fileID string) (string, string, error) {
	state := requestGuestOwnerState(request)
	if state == nil {
		return newOwnerToken()
	}
	token := deriveOwnerToken(state.key, fileID)
	hash := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(hash[:]), nil
}

func (handler *Handler) guestOwnerKeyCookie(key []byte) *http.Cookie {
	return &http.Cookie{Name: guestOwnerKeyCookieName, Value: base64.RawURLEncoding.EncodeToString(key), Path: "/", HttpOnly: true,
		Secure: handler.config.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: int(guestOwnerCookieLifetime.Seconds())}
}

// issueGuestOwnerKey sends a key created for this request to the browser
// before the upload finishes, so a direct upload's later completion request
// carries it.
func (handler *Handler) issueGuestOwnerKey(writer http.ResponseWriter, request *http.Request) {
	if state := requestGuestOwnerState(request); state != nil && !state.fromCookie {
		setCookieOnce(writer, handler.guestOwnerKeyCookie(state.key))
	}
}

// grantGuestOwnership gives the browser ownership of a finished guest upload.
// When the token derives from the browser's owner key, refreshing that one
// cookie is enough. A key created for this request is also backed by a
// per-file cookie, because a concurrent first upload in another tab may
// replace the key cookie; any other token gets a per-file cookie.
func (handler *Handler) grantGuestOwnership(writer http.ResponseWriter, request *http.Request, fileID, token string) {
	state := requestGuestOwnerState(request)
	if state == nil {
		if key := requestGuestOwnerKey(request); key != nil {
			state = &guestOwnerKey{key: key, fromCookie: true}
		}
	}
	if state != nil && hmac.Equal([]byte(deriveOwnerToken(state.key, fileID)), []byte(token)) {
		setCookieOnce(writer, handler.guestOwnerKeyCookie(state.key))
		if state.fromCookie {
			return
		}
	}
	http.SetCookie(writer, ownerCookie(fileID, token, handler.config.SecureCookies, guestOwnerCookieLifetime))
}

// guestOwnerKeyOwns reports whether the browser's owner key derives the token
// stored for file.
func guestOwnerKeyOwns(request *http.Request, file *db.FileList) bool {
	key := requestGuestOwnerKey(request)
	return key != nil && ownerTokenMatches(file, deriveOwnerToken(key, file.FileID))
}

// setCookieOnce adds cookie unless the response already sets one with its name.
func setCookieOnce(writer http.ResponseWriter, cookie *http.Cookie) {
	for _, value := range writer.Header().Values("Set-Cookie") {
		if strings.HasPrefix(value, cookie.Name+"=") {
			return
		}
	}
	http.SetCookie(writer, cookie)
}
