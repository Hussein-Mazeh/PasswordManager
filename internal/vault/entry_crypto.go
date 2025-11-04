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
//
// Args:
//
//	mek: 32-byte master encryption key derived from the user's credentials.
//	website: identifier for the credential's site; currently unused but reserved for AAD.
//	username: identifier for the account; currently unused but reserved for AAD.
//	typ: logical credential type (e.g. "password"); currently unused but reserved for AAD.
//	plaintext: secret to encrypt and store in the vault.
//
// Returns:
//
//	salt: random salt used for HKDF key derivation.
//	blob: AES-GCM nonce concatenated with ciphertext.
//	err: non-nil when key derivation or encryption fails.
//
// Behavior:
//  1. Validates the MEK length.
//  2. Generates a per-entry salt and derives an AES-256 key with HKDF-SHA256.
//  3. Encrypts the plaintext with AES-GCM and returns salt plus nonce|ciphertext.
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

// DecryptEntryPassword decrypts and immediately re-encrypts a stored credential.
//
// Args:
//
//	mek: 32-byte master encryption key derived from the user's credentials.
//	website: identifier for the credential's site (passed through to EncryptEntryPassword).
//	username: identifier for the account (passed through to EncryptEntryPassword).
//	typ: logical credential type (passed through to EncryptEntryPassword).
//	salt: per-entry salt originally returned by EncryptEntryPassword.
//	blob: concatenated nonce and ciphertext produced by EncryptEntryPassword.
//
// Returns:
//
//	plaintext: recovered password string when decryption succeeds.
//	newSalt: freshly generated salt produced during re-encryption.
//	newBlob: newly encrypted nonce|ciphertext pair.
//	err: descriptive failure when inputs are malformed or authenticity fails.
//
// Behavior:
//  1. Validates MEK, salt, and blob lengths.
//  2. Recomputes the per-entry AES key via HKDF-SHA256.
//  3. Splits nonce/ciphertext and decrypts with AES-GCM.
//  4. Re-encrypts the plaintext via EncryptEntryPassword to rotate salt and nonce.
func DecryptEntryPassword(mek []byte, website, username, typ string, salt, blob []byte) (plaintext string, newSalt []byte, newBlob []byte, err error) {
	if len(mek) != 32 {
		return "", nil, nil, errors.New("invalid MEK length")
	}
	if len(salt) != entrySaltLen {
		return "", nil, nil, errors.New("invalid entry salt length")
	}
	if len(blob) <= 12 {
		return "", nil, nil, errors.New("encrypted blob too short")
	}

	perKey, err := krypto.HKDFSHA256(mek, salt, []byte(entryInfo), 32)
	if err != nil {
		return "", nil, nil, fmt.Errorf("derive entry key: %w", err)
	}
	defer zeroize(perKey)

	nonce := blob[:12]
	ciphertext := blob[12:]

	ptBytes, err := krypto.DecryptAESGCM(perKey, nonce, ciphertext, nil)
	if err != nil {
		return "", nil, nil, fmt.Errorf("decrypt entry password: %w", err)
	}

	pwd := string(ptBytes)

	rotatedSalt, rotatedBlob, err := EncryptEntryPassword(mek, website, username, typ, pwd)
	if err != nil {
		return "", nil, nil, fmt.Errorf("reencrypt entry password: %w", err)
	}

	return pwd, rotatedSalt, rotatedBlob, nil
}

// zeroize overwrites sensitive byte slices in place to reduce lifetime in memory.
func zeroize(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
