# `pm` CLI Command Reference

This document summarizes every command exposed by the `pm` CLI (see `cmd/pm/main.go`). Use it as a checklist when manually testing the password manager.

## Global Usage

```sh
pm <command> [<subcommand>] [flags]
```

### Common Flags

- `--dir <vault-dir>`: Absolute or relative path to the vault directory. Required for any command that needs to read or modify vault data.
- `--user <username>`: Vault owner identifier. Required when setting or changing the master password.

The CLI exits with status code `1` on user errors (e.g., bad arguments) and `2` on unexpected internal errors.

## Top-Level Commands

### 1. `pm version`

- Prints the current CLI version (currently `0.1.0`).

### 2. `pm master`

Manages the master password and wrapped MEK.

#### `pm master set --dir <vault-dir> --user <username>`

- Prompts:
  - `Enter master password:`
  - `Confirm master password:`
- Behaviour:
  - Validates password strength (HIBP check enabled, zxcvbn score ≥ 3).
  - Derives Argon2id parameters, generates MEK if needed, wraps and stores it in the vault header.
  - Creates or updates the header file in `<vault-dir>`.
- Errors if the vault directory or user flag is missing, or passwords mismatch.

#### `pm master change --dir <vault-dir> --user <username>`

- Prompts:
  - `Old master password:`
  - `New master password:`
  - `Confirm new master password:`
- Behaviour:
  - Unlocks the existing MEK with the old password.
  - Validates the new password with the same rules as `master set`.
  - Generates a new salt, re-wraps the MEK, and updates the header.
- Errors if the vault header is missing, passwords mismatch, or validation fails.

### 3. `pm session --dir <vault-dir>`

Unlocks the vault and enters an interactive shell for credential CRUD operations.

- Prompts:
  - `Enter master password:` (unless biometric unlock succeeds).
- Behaviour:
  - Optionally authenticates with Touch ID if biometric unlock is enabled.
  - Derives the session key and opens/migrates `vault.db`.
  - Starts a REPL with prompt `pm>`. Type `help` for available commands.
- Exit by typing `exit` or `quit`, or sending EOF (`Ctrl+D`).

Interactive subcommands (`pm>` prompt):

#### `help`

- Lists available session commands.

#### `add --site <website> --user <username> [--type password]`

- Prompts: `Secret:`
- Behaviour:
  - Encrypts the provided secret with the MEK.
  - Stores a new entry; prints the new entry ID.
- Fails if required flags are missing or the secret is empty.

#### `get --site <website> [--user <username>]`

- Behaviour:
  - Without `--user`, prints all credentials for the site.
  - With `--user`, prints only the matching credential.
  - Each credential is decrypted, re-encrypted with fresh salt, and written back to the DB.
- Prints a warning if decryption fails for any entry.

#### `update --site <website> --user <username> [--type password]`

- Prompts: `New secret:`
- Behaviour:
  - Replaces the stored secret (and optionally the credential type) for the specified entry.
- Errors if the credential does not exist or the new secret is empty.

#### `delete --site <website> --user <username>`

- Behaviour:
  - Removes the specified credential entry.
- Prints a warning if the entry is not found.

#### `exit` / `quit`

- Leaves the session REPL.

### 4. `pm bio`

Controls Touch ID (biometric) unlock toggles for macOS builds.

#### `pm bio enable --dir <vault-dir> [--rp <rp-id>] [--origin <origin>]`

- Defaults: `--rp localhost`, `--origin https://localhost`.
- Behaviour:
  - Verifies the vault directory exists.
  - Touch ID prompt: `Touch ID to enable biometric unlock`.
  - Stores WebAuthn configuration so future `pm session` runs can unlock with Touch ID.
- Returns a user error if biometrics are unsupported (non-macOS) or Touch ID authentication fails.

#### `pm bio disable --dir <vault-dir>`

- Behaviour:
  - Confirms the vault directory exists.
  - Touch ID prompt: `Touch ID to disable biometric unlock`.
  - Clears stored WebAuthn configuration.

#### `pm bio status --dir <vault-dir>`

- Behaviour:
  - Reports whether biometric unlock is enabled.
  - When enabled, prints the configured RP ID and origin.

---

## Testing Tips

1. Initialise a fresh vault directory with `pm master set`.
2. Enable biometrics (macOS only) with `pm bio enable`, then verify status and disable.
3. Run `pm session` to exercise `add`, `get`, `update`, `delete`; use `help` to confirm command list.
4. Change the master password with `pm master change` and confirm that the old password no longer works.
5. Run `pm version` to ensure the binary prints the expected version string.

All commands exit with non-zero status on failure; monitor stderr for user-facing error messages.
