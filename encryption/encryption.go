package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

var magic = []byte("OBJECTSHARE-AES-GCM-1\x00")

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

func (cipher *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, cipher.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate encryption nonce: %w", err)
	}
	output := make([]byte, 0, len(magic)+len(nonce)+len(plaintext)+cipher.aead.Overhead())
	output = append(output, magic...)
	output = append(output, nonce...)
	output = cipher.aead.Seal(output, nonce, plaintext, magic)
	return output, nil
}

func (cipher *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	minimum := len(magic) + cipher.aead.NonceSize() + cipher.aead.Overhead()
	if len(ciphertext) < minimum || string(ciphertext[:len(magic)]) != string(magic) {
		return nil, errors.New("invalid encrypted object")
	}
	nonceStart := len(magic)
	nonceEnd := nonceStart + cipher.aead.NonceSize()
	plaintext, err := cipher.aead.Open(nil, ciphertext[nonceStart:nonceEnd], ciphertext[nonceEnd:], magic)
	if err != nil {
		return nil, errors.New("encrypted object authentication failed")
	}
	return plaintext, nil
}

func (cipher *Cipher) Overhead() int {
	return len(magic) + cipher.aead.NonceSize() + cipher.aead.Overhead()
}
