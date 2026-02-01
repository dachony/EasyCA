package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	saltSize   = 32
	keySize    = 32 // AES-256
	iterations = 100000
)

// Encrypt encrypts data with a password using AES-256-GCM
func Encrypt(data []byte, password string) (string, error) {
	// Generate random salt
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	// Derive key from password
	key := pbkdf2.Key([]byte(password), salt, iterations, keySize, sha256.New)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	// Combine salt + ciphertext
	result := make([]byte, len(salt)+len(ciphertext))
	copy(result, salt)
	copy(result[len(salt):], ciphertext)

	return base64.StdEncoding.EncodeToString(result), nil
}

// Decrypt decrypts data with a password
func Decrypt(encryptedData string, password string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	if len(data) < saltSize {
		return nil, errors.New("invalid encrypted data")
	}

	// Extract salt
	salt := data[:saltSize]
	ciphertext := data[saltSize:]

	// Derive key from password
	key := pbkdf2.Key([]byte(password), salt, iterations, keySize, sha256.New)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("invalid encrypted data")
	}

	// Extract nonce
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed - wrong password or corrupted data")
	}

	return plaintext, nil
}
