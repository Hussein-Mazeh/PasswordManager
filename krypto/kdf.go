package krypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	// MinSaltBits ensures salts are at least 92 bits (rounded to 12 bytes).
	MinSaltBits = 92
	// SaltLengthBytes is the enforced salt length in bytes.
	SaltLengthBytes = (MinSaltBits + 7) / 8 // 12 bytes
	expectedSaltSz  = SaltLengthBytes
)

// Argon2Params captures tunable parameters for Argon2id.
type Argon2Params struct {
	MemoryMB    uint32
	Time        uint32
	Parallelism uint8
	SaltLen     int
	KeyLen      uint32
}

// DefaultArgon2Params returns sane defaults for deriving a 256-bit key.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		MemoryMB:    64,
		Time:        3,
		Parallelism: 1,
		SaltLen:     expectedSaltSz,
		KeyLen:      32,
	}
}

// DeriveKeyArgon2id derives a key using Argon2id with the provided parameters.
func DeriveKeyArgon2id(password []byte, salt []byte, p Argon2Params) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("password is required")
	}
	if len(salt) == 0 {
		return nil, errors.New("salt is required")
	}
	if len(salt) != expectedSaltSz {
		return nil, fmt.Errorf("salt must be %d bytes (>= %d bits)", expectedSaltSz, MinSaltBits)
	}
	if p.KeyLen == 0 {
		return nil, errors.New("key length must be positive")
	}
	if p.MemoryMB == 0 {
		return nil, errors.New("memory parameter must be positive")
	}
	if p.Time == 0 {
		return nil, errors.New("time parameter must be positive")
	}
	if p.SaltLen <= 0 {
		return nil, errors.New("salt length must be positive")
	}

	memoryKB := p.MemoryMB * 1024
	key := argon2.IDKey(password, salt, p.Time, memoryKB, uint8(p.Parallelism), p.KeyLen)
	if uint32(len(key)) != p.KeyLen {
		return nil, fmt.Errorf("derived key has unexpected length %d", len(key))
	}
	return key, nil
}

// NewRandomSalt returns a cryptographically secure random salt of length n bytes.
func NewRandomSalt(n int) ([]byte, error) {
	if n <= 0 {
		n = expectedSaltSz
	}
	if n != expectedSaltSz {
		n = expectedSaltSz
	}
	salt := make([]byte, n)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}
