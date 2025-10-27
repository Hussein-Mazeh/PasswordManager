# pm Command

`pm` is the main command-line interface for the password manager.

## Files

- `main.go` – implements the CLI, currently supporting:
  - `pm version` – prints the CLI version.
  - `pm master set --dir <vault-dir> --user <username>` – validates and sets an
    initial primary master password, derives the password-derived key (PDK),
    creates or reuses the master encryption key (MEK), and persists header
    metadata.
  - `pm master change --dir <vault-dir> --user <username>` – verifies the
    existing password, accepts a new one that satisfies policy, and rewraps the
    MEK without touching stored entries.
  - `pm session --dir <vault-dir>` – opens an interactive session that unlocks
    the MEK and lets you add or retrieve encrypted credentials in SQLite.

## Usage

```bash
# Build the CLI binary
go build -o pm ./cmd/pm

# Set an initial master password
./pm master set --dir ./vault-dev --user alice@example.com

# Change the master password (MEK stays intact)
./pm master change --dir ./vault-dev --user alice@example.com

# Start an interactive session to add/get credentials
./pm session --dir ./vault-dev
```
