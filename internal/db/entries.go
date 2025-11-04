package db

import (
	"database/sql"
	"fmt"
)

// EntryRow represents a credential row retrieved from storage.
type EntryRow struct {
	ID            int64
	EncryptedPass []byte
	Salt          []byte
	Website       string
	Username      string
	Type          string
	CreatedAt     string
	UpdatedAt     string
}

// InsertEntry stores a new credential row and returns its database ID.
func InsertEntry(d *DB, website, username, typ string, salt, enc []byte) (int64, error) {
	if d == nil || d.sql == nil {
		return 0, fmt.Errorf("database handle is nil")
	}

	res, err := d.sql.Exec(
		`INSERT INTO passwords (encrypted_pass, salt, website, username, type) VALUES (?, ?, ?, ?, ?)`,
		enc, salt, website, username, typ,
	)
	if err != nil {
		return 0, fmt.Errorf("insert entry: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("fetch insert id: %w", err)
	}

	return id, nil
}

// UpdateEntryCipher rotates the salt, encrypted blob, and optional type for an existing credential.
func UpdateEntryCipher(d *DB, id int64, typ string, salt, enc []byte) error {
	if d == nil || d.sql == nil {
		return fmt.Errorf("database handle is nil")
	}

	_, err := d.sql.Exec(
		`UPDATE passwords SET encrypted_pass = ?, salt = ?, type = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		enc, salt, typ, id,
	)
	if err != nil {
		return fmt.Errorf("update entry cipher: %w", err)
	}

	return nil
}

// GetEntryByWebsite returns all entries for a given website.
func GetEntryByWebsite(d *DB, website string) ([]EntryRow, error) {
	if d == nil || d.sql == nil {
		return nil, fmt.Errorf("database handle is nil")
	}

	rows, err := d.sql.Query(
		`SELECT id, encrypted_pass, salt, website, username, type, created_at, updated_at
		 FROM passwords
		 WHERE website = ?
		 ORDER BY username`,
		website,
	)
	if err != nil {
		return nil, fmt.Errorf("select entries by website: %w", err)
	}
	defer rows.Close()

	var results []EntryRow
	for rows.Next() {
		var r EntryRow
		if err := rows.Scan(
			&r.ID,
			&r.EncryptedPass,
			&r.Salt,
			&r.Website,
			&r.Username,
			&r.Type,
			&r.CreatedAt,
			&r.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan entry row: %w", err)
		}
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate entry rows: %w", err)
	}

	return results, nil
}

// GetEntryBySiteAndUser returns a single entry matching website and username.
func GetEntryBySiteAndUser(d *DB, website, username string) (*EntryRow, error) {
	if d == nil || d.sql == nil {
		return nil, fmt.Errorf("database handle is nil")
	}

	var r EntryRow
	err := d.sql.QueryRow(
		`SELECT id, encrypted_pass, salt, website, username, type, created_at, updated_at
		 FROM passwords
		 WHERE website = ? AND username = ?`,
		website, username,
	).Scan(
		&r.ID,
		&r.EncryptedPass,
		&r.Salt,
		&r.Website,
		&r.Username,
		&r.Type,
		&r.CreatedAt,
		&r.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, err
		}
		return nil, fmt.Errorf("select entry: %w", err)
	}

	return &r, nil
}

// DeleteEntryBySiteAndUser deletes a credential matching website and username.
// It returns sql.ErrNoRows if nothing was deleted.
func DeleteEntryBySiteAndUser(d *DB, website, username string) error {
	if d == nil || d.sql == nil {
		return fmt.Errorf("database handle is nil")
	}

	res, err := d.sql.Exec(
		`DELETE FROM passwords WHERE website = ? AND username = ?`,
		website, username,
	)
	if err != nil {
		return fmt.Errorf("delete entry: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete rows affected: %w", err)
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
