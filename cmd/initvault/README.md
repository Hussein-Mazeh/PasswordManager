# initvault Command

`initvault` is a helper binary that ensures the on-disk SQLite database exists.
It opens the vault using the shared database logic, runs `VACUUM` once, and
exits. This is mostly useful during development to create the `vault/vault.db`
file before other components run.

## Files

- `main.go` – minimal entry point that opens the vault and performs the
  database initialisation side effects.

## Usage

```bash
go run ./cmd/initvault
```
