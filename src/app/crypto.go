package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"golang.org/x/crypto/argon2"
)

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func GenerateRandomString(n int) (string, error) {
	const chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	bytes, err := GenerateRandomBytes(n)
	if err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = chars[b % byte(len(chars))]
	}
	return string(bytes), nil
}

func HashArgon2(salt []byte, s string) (string, error) {
	hash := argon2.IDKey([]byte(s), salt, 3, 64 * 1024, 2, 32)
	return hex.EncodeToString(hash), nil
}

func HashSHA256(s string) string {
	encBytes := sha256.Sum256([]byte(s))
	return string(encBytes[:])
}

func Encrypt(b []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, b, nil), nil
}

func Decrypt(b []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(b) < nonceSize {
		return nil, err
	}

	nonce, ciphertext := b[:nonceSize], b[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
