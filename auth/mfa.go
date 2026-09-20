package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // RFC 6238 interoperability with authenticator apps.
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

func NewTOTPSecret() (string, error) {
	key := make([]byte, 20)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key), nil
}

// TOTPCode implements RFC 6238 SHA-1, six digits and a 30-second time step.
func TOTPCode(secret string, step int64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(key) != 20 || step < 0 {
		return "", errors.New("invalid TOTP secret or step")
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000), nil
}

func VerifyTOTP(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	for _, offset := range []int64{0, -1, 1} {
		step := now.Unix()/30 + offset
		want, err := TOTPCode(secret, step)
		if err == nil && step > lastStep && subtle.ConstantTimeCompare([]byte(code), []byte(want)) == 1 {
			return step, true
		}
	}
	return 0, false
}

func NewEmailOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// Keyed hashes prevent offline enumeration of the small email-code space.
func MFAHash(key, context, value string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte("objectshare-mfa-v1\x00" + context + "\x00" + value))
	return hex.EncodeToString(mac.Sum(nil))
}

func NewRecoveryCodes() ([]string, error) {
	codes := make([]string, 10)
	for i := range codes {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		codes[i] = hex.EncodeToString(raw)
	}
	return codes, nil
}

func mfaAEAD(key string) (cipher.AEAD, error) {
	if len(key) < 32 {
		return nil, errors.New("MFA encryption requires a stable settings key")
	}
	hash := sha256.Sum256([]byte("objectshare-mfa-encryption-v1\x00" + key))
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func SealMFASecret(key, userID, secret string) (string, error) {
	aead, err := mfaAEAD(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	return "mfa:v1:" + base64.RawStdEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte(secret), []byte(userID))), nil
}

func OpenMFASecret(key, userID, value string) (string, error) {
	aead, err := mfaAEAD(key)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(value, "mfa:v1:") {
		return "", errors.New("invalid MFA ciphertext")
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "mfa:v1:"))
	if err != nil || len(raw) < aead.NonceSize()+aead.Overhead() {
		return "", errors.New("invalid MFA ciphertext")
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(userID))
	return string(plain), err
}
