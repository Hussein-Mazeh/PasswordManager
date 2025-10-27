# store Package

The `store` package handles persistence of vault metadata and related
filesystem operations.

## Files

- `vaultfs.go` – reads and writes `header.json`, wraps/unwraps/rewraps the master
  encryption key (MEK), and enforces directory permissions for vault assets.

Typical workflow:

1. Resolve paths for a vault directory.
2. Load or save the header metadata atomically.
3. Use the encryption helpers from `krypto` to protect sensitive fields and
   rewrap the MEK when the primary master password changes.
