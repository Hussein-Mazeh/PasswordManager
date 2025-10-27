# Vault Data Directory

This directory holds the SQLite database (`vault.db`) and any other
vault-specific artifacts generated at runtime.

## Files

- `vault.db` – encrypted SQLite database created by the application or the
  `initvault` utility. It contains the `passwords` table and any other persisted
  data.

The files in this directory are generated artifacts; keep backups secure and
restrict permissions to the owning user.
