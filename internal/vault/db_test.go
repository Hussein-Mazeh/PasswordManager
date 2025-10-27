package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Hussein-Mazeh/PasswordManager/internal/vault"
)

func TestOpenCreatesDatabaseFile(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "data", "vault.db")

	db, err := vault.Open(vault.Config{FilePath: dbPath})
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
	})

	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("expected database file to exist at %q: %v", dbPath, err)
	}
}

func TestOpenEnsuresPasswordsTable(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "vault.db")

	db, err := vault.Open(vault.Config{FilePath: dbPath})
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
	})

	var tableName string
	err = db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='passwords'`).Scan(&tableName)
	if err != nil {
		t.Fatalf("query table existence: %v", err)
	}
	if tableName != "passwords" {
		t.Fatalf("expected table name 'passwords', got %q", tableName)
	}
}
