package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	_ "modernc.org/sqlite" // SQLite driver
)

// DB wraps the SQLite handle and associated metadata.
type DB struct {
	sql  *sql.DB
	path string
}

// Open initialises a SQLite database at the given path and returns a DB wrapper.
func Open(path string) (*DB, error) {
	if path == "" {
		return nil, fmt.Errorf("database path is required")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}

	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(ON)", path)
	handle, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}

	if err := handle.Ping(); err != nil {
		handle.Close()
		return nil, fmt.Errorf("ping sqlite database: %w", err)
	}

	if err := EnsurePerm0600(path); err != nil {
		handle.Close()
		return nil, err
	}

	return &DB{sql: handle, path: path}, nil
}

// Close releases the database resources.
func Close(d *DB) error {
	if d == nil || d.sql == nil {
		return nil
	}
	return d.sql.Close()
}

// EnsurePerm0600 attempts to set the database file permissions to 0600 on Unix systems(the owner permission).
// Only the current owner of the sqlite db is allowed to read and write (ensured if Unix system)
func EnsurePerm0600(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if err := os.Chmod(path, 0o600); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("chmod database: %w", err)
	}
	return nil
} //Must find a new way to ensure secure database on windows too.

const createPasswordsTable = `
CREATE TABLE IF NOT EXISTS passwords (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	encrypted_pass BLOB    NOT NULL,
	salt           BLOB    NOT NULL,
	website        TEXT    NOT NULL,
	username       TEXT    NOT NULL,
	type           TEXT    NOT NULL DEFAULT 'password',
	created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(website, username)
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_passwords_site_user ON passwords(website, username);
`

// Migrate ensures the passwords table (and index) exist.
func Migrate(d *DB) error {
	if d == nil || d.sql == nil {
		return fmt.Errorf("database handle is nil")
	}
	if _, err := d.sql.Exec(createPasswordsTable); err != nil {
		return fmt.Errorf("migrate schema: %w", err)
	}
	return nil
}
