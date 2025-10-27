# internal/vault Package

This package wraps lower-level vault functionality: database access, schema
management, header structures, and credential encryption helpers.

## Files

- `db.go` – opens the SQLite database, ensures the passwords table exists, and
  applies basic connection settings.
- `db_test.go` – tests covering database creation and schema bootstrap.
- `header.go` – data structures representing the persisted vault header (KDF
  parameters, timestamps, wrapped MEK metadata).
- `crypto_entries.go` – encrypts and decrypts per-entry secrets using MEK-derived
  keys and AES-GCM.

The package is internal to the module and meant to be consumed via higher-level
store or CLI layers.
