# Command-Line Tools

This directory contains Go modules that build into command-line utilities for
the password manager project.

## Subdirectories

- `initvault/` – helper utility that ensures the SQLite vault database file
  exists and is initialised.
- `pm/` – primary CLI entry point (`pm`) that exposes end-user commands such as
  setting/changing the master password and running an interactive vault session.

Build a subcommand with `go build ./cmd/<name>` or run it in-place with
`go run ./cmd/<name>`.
