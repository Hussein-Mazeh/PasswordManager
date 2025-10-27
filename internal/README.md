# Internal Packages

Code under `internal/` is intended for use only within this module. It exposes
shared building blocks that higher-level packages depend on.

## Subdirectories

- `vault/` – database access helpers, header structures, and crypto routines
  that support the encrypted vault.
- `db/` – SQLite wrapper used by the CLI session to store and retrieve wrapped
  credentials.

Because these packages live under `internal/`, they cannot be imported by other
Go modules, which keeps the API surface restricted to this project.
