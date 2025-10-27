# krypto Package

Cryptographic primitives and helpers live here so that application code can
reuse them consistently.

## Files

- `kdf.go` – Argon2id key-derivation helper with enforced salt length and
  parameter defaults for deriving password-derived keys (PDKs).
- `aead.go` – AES-256-GCM encrypt/decrypt helpers for wrapping secrets such as
  the master encryption key (MEK) and per-entry material.
- `hkdf.go` – HKDF-SHA256 helper to derive per-entry keys from the MEK.

These utilities are dependency-free beyond `golang.org/x/crypto/argon2` and the
Go standard library.
