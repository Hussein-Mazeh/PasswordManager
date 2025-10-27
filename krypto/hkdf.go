package krypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"hash"
)

// HKDFSHA256 derives key material using HKDF (RFC 5869) with SHA-256.
func HKDFSHA256(key, salt, info []byte, outLen int) ([]byte, error) {
	if outLen <= 0 {
		return nil, errors.New("invalid hkdf length")
	}

	prk := hkdfExtract(salt, key)
	return hkdfExpand(prk, info, outLen), nil
}

func hkdfExtract(salt, inputKeyMaterial []byte) []byte {
	var zeroSalt []byte
	if len(salt) == 0 {
		zeroSalt = make([]byte, sha256.Size)
		salt = zeroSalt
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(inputKeyMaterial)
	return mac.Sum(nil)
}

func hkdfExpand(prk, info []byte, outLen int) []byte {
	var (
		result []byte
		t      []byte
	)

	h := sha256.New
	hashLen := h().Size()
	rounds := (outLen + hashLen - 1) / hashLen

	counter := byte(1)
	for i := 0; i < rounds; i++ {
		mac := hmac.New(func() hash.Hash { return h() }, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		result = append(result, t...)
		counter++
	}

	return result[:outLen]
}
