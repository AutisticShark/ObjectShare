package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// Two object formats share the same layout (magic || nonce || sealed data).
//
//	v1: the authenticated data is the magic alone, so a ciphertext decrypts
//	    under any object ID.
//	v2: the authenticated data also contains the object ID, so a ciphertext
//	    copied or swapped onto another object fails authentication.
//
// New objects are written as v2 by EncryptFor; v1 objects written by earlier
// releases are still read by DecryptFor. Releases that predate v2 cannot read v2
// objects, so a downgrade needs the objects re-encrypted first.
var (
	magic   = []byte("OBJECTSHARE-AES-GCM-1\x00")
	magicV2 = []byte("OBJECTSHARE-AES-GCM-2\x00")
)

type Cipher struct{ aead cipher.AEAD }

func New(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256 requires a 32-byte key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM cipher: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt writes a v1 object that is not bound to an object ID. Production
// code uses EncryptFor; this remains for callers that have no ID.
func (cipher *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	return cipher.seal(magic, magic, plaintext)
}

// EncryptFor writes a v2 object bound to objectID.
func (cipher *Cipher) EncryptFor(objectID string, plaintext []byte) ([]byte, error) {
	return cipher.seal(magicV2, boundData(objectID), plaintext)
}

func boundData(objectID string) []byte {
	return append(append([]byte(nil), magicV2...), objectID...)
}

func (cipher *Cipher) seal(header, additionalData, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, cipher.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate encryption nonce: %w", err)
	}
	output := make([]byte, 0, len(header)+len(nonce)+len(plaintext)+cipher.aead.Overhead())
	output = append(output, header...)
	output = append(output, nonce...)
	output = cipher.aead.Seal(output, nonce, plaintext, additionalData)
	return output, nil
}

// Decrypt opens a v1 object. A v2 object needs its ID and is refused here.
func (cipher *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	return cipher.open(ciphertext, "", false)
}

// DecryptFor opens a v1 object or a v2 object bound to objectID.
func (cipher *Cipher) DecryptFor(objectID string, ciphertext []byte) ([]byte, error) {
	return cipher.open(ciphertext, objectID, true)
}

func (cipher *Cipher) open(ciphertext []byte, objectID string, allowBound bool) ([]byte, error) {
	minimum := len(magic) + cipher.aead.NonceSize() + cipher.aead.Overhead()
	if len(ciphertext) < minimum {
		return nil, errors.New("invalid encrypted object")
	}
	var additionalData []byte
	switch {
	case bytes.HasPrefix(ciphertext, magic):
		additionalData = magic
	case allowBound && bytes.HasPrefix(ciphertext, magicV2):
		additionalData = boundData(objectID)
	default:
		return nil, errors.New("invalid encrypted object")
	}
	nonceStart := len(magic)
	nonceEnd := nonceStart + cipher.aead.NonceSize()
	plaintext, err := cipher.aead.Open(nil, ciphertext[nonceStart:nonceEnd], ciphertext[nonceEnd:], additionalData)
	if err != nil {
		return nil, errors.New("encrypted object authentication failed")
	}
	return plaintext, nil
}

func (cipher *Cipher) Overhead() int {
	return len(magic) + cipher.aead.NonceSize() + cipher.aead.Overhead()
}
