package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemory  = 64 * 1024
	argonTime    = 3
	argonThreads = 4
	argonKeyLen  = 32
	saltLength   = 16
)

var (
	dummyOnce sync.Once
	dummyHash string
)

// argonGate bounds concurrent Argon2id computations. Each one holds 64 MiB and
// a core for its whole run, so an unbounded burst of login or signup requests
// would otherwise exhaust memory or starve every other request.
var argonGate = newGate(runtime.NumCPU())

type gate chan struct{}

func newGate(size int) gate { return make(gate, max(1, size)) }

func (g gate) acquire() { g <- struct{}{} }
func (g gate) release() { <-g }

func deriveKey(password, salt []byte, iterations, memory uint32, threads uint8, length uint32) []byte {
	argonGate.acquire()
	defer argonGate.release()
	return argon2.IDKey(password, salt, iterations, memory, threads, length)
}

func NormalizeEmail(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || len(value) > 320 || !utf8.ValidString(value) {
		return "", errors.New("Enter a valid email address.")
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value || strings.Count(value, "@") != 1 {
		return "", errors.New("Enter a valid email address.")
	}
	return value, nil
}

func ValidateDisplayName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len([]rune(value)) > 100 || !utf8.ValidString(value) {
		return "", errors.New("Display name must contain 1 to 100 characters.")
	}
	for _, character := range value {
		if UnsafeTextCharacter(character) {
			return "", errors.New("Display name cannot contain control or invisible formatting characters.")
		}
	}
	return value, nil
}

// UnsafeTextCharacter reports characters that must not appear in names shown
// to other people: control characters and invisible format characters (Cf),
// including bidirectional overrides that make "invoice\u202Efdp.exe" display
// as "invoiceexe.pdf". The zero-width non-joiner and joiner stay allowed
// because several scripts and emoji sequences need them.
func UnsafeTextCharacter(character rune) bool {
	if character == '\u200C' || character == '\u200D' {
		return false
	}
	return unicode.IsControl(character) || unicode.Is(unicode.Cf, character)
}

func ValidatePassword(password string) error {
	if !utf8.ValidString(password) || len([]rune(password)) < 12 || len([]rune(password)) > 128 || len(password) > 512 {
		return errors.New("Password must contain 12 to 128 characters.")
	}
	return nil
}

func HashPassword(password string) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	key := deriveKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	version, err := strconv.Atoi(strings.TrimPrefix(parts[2], "v="))
	if err != nil || version != argon2.Version {
		return false
	}
	parameters := strings.Split(parts[3], ",")
	if len(parameters) != 3 || !strings.HasPrefix(parameters[0], "m=") || !strings.HasPrefix(parameters[1], "t=") || !strings.HasPrefix(parameters[2], "p=") {
		return false
	}
	memoryValue, memoryErr := strconv.ParseUint(strings.TrimPrefix(parameters[0], "m="), 10, 32)
	iterationValue, iterationErr := strconv.ParseUint(strings.TrimPrefix(parameters[1], "t="), 10, 32)
	threadValue, threadErr := strconv.ParseUint(strings.TrimPrefix(parameters[2], "p="), 10, 8)
	memory, iterations, threads := uint32(memoryValue), uint32(iterationValue), uint8(threadValue)
	if memoryErr != nil || iterationErr != nil || threadErr != nil || memory < 19*1024 || memory > 256*1024 || iterations == 0 || iterations > 10 || threads == 0 || threads > 16 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) < 16 || len(want) > 64 {
		return false
	}
	got := deriveKey([]byte(password), salt, iterations, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// NeedsRehash reports whether a stored password hash was made with different
// Argon2id parameters than HashPassword uses now, so a successful login can
// upgrade it. Hashes that cannot be parsed report false: they never verify, so
// there is nothing to upgrade.
func NeedsRehash(encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	if parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return true
	}
	return parts[3] != fmt.Sprintf("m=%d,t=%d,p=%d", argonMemory, argonTime, argonThreads)
}

// DummyPasswordHash returns an Argon2id hash of a random, never-disclosed
// password. It gives callers a real verification to run for unknown or
// passwordless accounts so timing does not reveal them. The password is random
// per process: a constant would be a valid credential for every account that
// falls back to this hash.
func DummyPasswordHash() string {
	dummyOnce.Do(func() {
		secret, _, err := NewToken()
		if err == nil {
			dummyHash, err = HashPassword(secret)
		}
		if err != nil {
			panic(fmt.Sprintf("generate dummy password hash: %v", err))
		}
	})
	return dummyHash
}

func NewToken() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	return token, TokenHash(token), nil
}

func TokenHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
