package vault

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/Hussein-Mazeh/PasswordManager/krypto"
)

const (
	entrySaltLen = 16
	entryInfo    = "entry-key-v1"
)

// EncryptEntryPassword encrypts a plaintext password using the MEK and entry context.
func EncryptEntryPassword(mek []byte, website, username, typ, plaintext string) (salt []byte, blob []byte, err error) {
	if len(mek) != 32 {
		return nil, nil, errors.New("invalid MEK length")
	}
	_ = website
	_ = username
	_ = typ

	salt = make([]byte, entrySaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("generate entry salt: %w", err)
	}

	perKey, err := krypto.HKDFSHA256(mek, salt, []byte(entryInfo), 32)
	if err != nil {
		return nil, nil, fmt.Errorf("derive entry key: %w", err)
	}
	defer zeroize(perKey)

	nonce, ciphertext, err := krypto.EncryptAESGCM(perKey, []byte(plaintext), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt entry password: %w", err)
	}

	blob = append(nonce, ciphertext...)
	return salt, blob, nil
}

// DecryptEntryPassword decrypts a stored blob back into the plaintext password.
func DecryptEntryPassword(mek []byte, salt, blob []byte) (string, error) {
	if len(mek) != 32 {
		return "", errors.New("invalid MEK length")
	}
	if len(salt) != entrySaltLen {
		return "", errors.New("invalid entry salt length")
	}
	if len(blob) <= 12 {
		return "", errors.New("encrypted blob too short")
	}

	perKey, err := krypto.HKDFSHA256(mek, salt, []byte(entryInfo), 32)
	if err != nil {
		return "", fmt.Errorf("derive entry key: %w", err)
	}
	defer zeroize(perKey)

	nonce := blob[:12]
	ciphertext := blob[12:]

	plaintext, err := krypto.DecryptAESGCM(perKey, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt entry password: %w", err)
	}

	return string(plaintext), nil
}

func zeroize(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
