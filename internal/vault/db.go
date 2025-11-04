package vault

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite" // SQLite driver
)
//This file is about vault provisioning  

// Config describes how the vault database should be opened.
type Config struct {
	// FilePath points to the SQLite database file.
	// If empty, DefaultDatabasePath is used.
	FilePath string
}

// DefaultDatabasePath is the relative path for the vault database file.
const DefaultDatabasePath = "vault/vault.db"

// Open creates (if needed) and opens the SQLite database located in the vault directory.
// It returns a live connection that the caller must Close.
func Open(cfg Config) (*sql.DB, error) {
	dbPath := cfg.FilePath
	if dbPath == "" {
		dbPath = DefaultDatabasePath
	}

	if err := ensureDirectory(dbPath); err != nil {
		return nil, fmt.Errorf("create vault directory: %w", err)
	}

	dsn := fmt.Sprintf("file:%s?_busy_timeout=5000&_foreign_keys=on", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open vault database: %w", err)
	}

	// Prime the connection and ensure the database file is created.
	if err := db.Ping(); err != nil {
		db.Close() // best effort cleanup
		return nil, fmt.Errorf("ping vault database: %w", err)
	}

	if err := ensureSchema(db); err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
}

func ensureDirectory(dbPath string) error {
	dir := filepath.Dir(dbPath)
	if dir == "." || dir == "" {
		return errors.New("database path must include a directory")
	}

	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}

	return nil
}

const createPasswordsTable = `
CREATE TABLE IF NOT EXISTS passwords (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	encrypted_pass BLOB    NOT NULL,
	salt           BLOB    NOT NULL,
	website        TEXT    NOT NULL,
	username       TEXT    NOT NULL,
	type           TEXT    NOT NULL DEFAULT 'password',
	created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);`

func ensureSchema(db *sql.DB) error {
	if _, err := db.Exec(createPasswordsTable); err != nil {
		return fmt.Errorf("ensure passwords table: %w", err)
	}
	return nil
}
