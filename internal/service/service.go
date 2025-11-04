package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Hussein-Mazeh/PasswordManager/auth"
	"github.com/Hussein-Mazeh/PasswordManager/internal/bio/toggle"
	"github.com/Hussein-Mazeh/PasswordManager/internal/vault"
	"github.com/Hussein-Mazeh/PasswordManager/krypto"
	"github.com/Hussein-Mazeh/PasswordManager/store"
)

// Service exposes high-level vault operations for CLI/GUI.
type Service struct {
	sql   *sql.DB     // sqlite handle (vault/vault.db)
	paths store.Paths // points to vault dir (header.json lives here)
	mek   []byte      // decrypted MEK in memory after Unlock
}

// New returns a ready service bound to a vault directory (where BOTH header.json and vault.db live).
func New(vaultDir string) (*Service, error) {
	if vaultDir == "" {
		vaultDir = "./dev-vault"
	}
	dbPath := filepath.Join(vaultDir, "vault.db")

	db, err := vault.Open(vault.Config{FilePath: dbPath})
	if err != nil {
		return nil, fmt.Errorf("open sqlite (%s): %w", dbPath, err)
	}
	return &Service{
		sql:   db,
		paths: store.Paths{Dir: vaultDir},
	}, nil
}

// Close DB and zeroize MEK.
func (s *Service) Close() {
	if s.sql != nil {
		_ = s.sql.Close()
	}
	wipe(s.mek)
	s.mek = nil
}

func wipe(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
}

func (s *Service) setMEK(mek []byte) {
	if len(mek) == 0 {
		s.mek = nil
		return
	}
	if cap(s.mek) < len(mek) {
		s.mek = make([]byte, len(mek))
	} else {
		s.mek = s.mek[:len(mek)]
	}
	copy(s.mek, mek)
}

// NeedsMasterSetup returns true when the vault header is missing or lacks a wrapped MEK.
func (s *Service) NeedsMasterSetup() (bool, error) {
	hdr, err := store.LoadVaultHeader(s.paths)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return false, fmt.Errorf("load header: %w", err)
	}
	if hdr.WrapNonce == "" || hdr.WrappedMEK == "" {
		return true, nil
	}
	return false, nil
}

// SetMaster initializes the vault header with a new Argon2id KDF configuration and wrapped MEK.
// It must only be called when NeedsMasterSetup reports true.
func (s *Service) SetMaster(user, master string) error {
	user = strings.TrimSpace(user)
	if user == "" {
		return errors.New("username is required")
	}
	if master == "" {
		return errors.New("master password cannot be empty")
	}

	ctx := context.Background()
	opts := auth.DefaultValidateOptions()
	opts.EnableHIBP = true
	opts.MinZXCVBNScore = 3
	if err := auth.ValidateMasterPasswordAdvanced(ctx, master, opts); err != nil {
		return fmt.Errorf("validate master password: %w", err)
	}

	hdr, err := store.LoadVaultHeader(s.paths)
	headerExists := err == nil
	switch {
	case errors.Is(err, os.ErrNotExist):
		hdr = vault.VaultHeader{}
	case err != nil:
		return fmt.Errorf("load header: %w", err)
	}
	if headerExists && hdr.WrapNonce != "" && hdr.WrappedMEK != "" {
		return errors.New("vault already initialised; unlock instead")
	}

	params := krypto.DefaultArgon2Params()
	params.SaltLen = krypto.SaltLengthBytes

	salt, err := krypto.NewRandomSalt(params.SaltLen)
	if err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	hdr.Salt = base64.StdEncoding.EncodeToString(salt)

	masterBytes := []byte(master)
	defer wipe(masterBytes)

	pdk, err := krypto.DeriveKeyArgon2id(masterBytes, salt, params)
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}
	defer wipe(pdk)

	mek := make([]byte, 32)
	if _, err := rand.Read(mek); err != nil {
		return fmt.Errorf("generate mek: %w", err)
	}
	defer wipe(mek)

	hdr.Version = 1
	hdr.User = user
	hdr.KDF = vault.KDFConfig{
		Name:        "argon2id",
		MemoryMB:    params.MemoryMB,
		Time:        params.Time,
		Parallelism: params.Parallelism,
		SaltLen:     krypto.SaltLengthBytes,
		KeyLen:      params.KeyLen,
	}

	now := time.Now().UTC()
	if hdr.CreatedAt.IsZero() {
		hdr.CreatedAt = now
	}
	hdr.UpdatedAt = now

	if err := store.WrapAndSaveMEK(s.paths, hdr, pdk, mek); err != nil {
		return fmt.Errorf("persist header: %w", err)
	}

	s.setMEK(nil)
	return nil
}

// buildKDF pulls Argon2 + salt from the header and decodes the base64 salt.
func buildKDF(hdr vault.VaultHeader) (krypto.Argon2Params, []byte, error) {
	params := krypto.Argon2Params{
		MemoryMB:    hdr.KDF.MemoryMB,
		Time:        hdr.KDF.Time,
		Parallelism: hdr.KDF.Parallelism,
		SaltLen:     hdr.KDF.SaltLen,
		KeyLen:      hdr.KDF.KeyLen,
	}
	salt, err := base64.StdEncoding.DecodeString(hdr.Salt)
	if err != nil {
		return krypto.Argon2Params{}, nil, fmt.Errorf("decode salt: %w", err)
	}
	return params, salt, nil
}

func (s *Service) requireBiometricForUnlock() error {
	status, err := toggle.Status(s.paths.Dir)
	if err != nil {
		if errors.Is(err, toggle.ErrUnsupported) {
			return nil
		}
		return fmt.Errorf("biometric status: %w", err)
	}
	if !status.Enabled {
		return nil
	}
	if err := toggle.Authenticate("Touch ID to unlock the vault"); err != nil {
		if errors.Is(err, toggle.ErrUnsupported) {
			return nil
		}
		return fmt.Errorf("biometric authentication failed: %w", err)
	}
	return nil
}

// Unlock derives the PDK via Argon2id and unwraps the MEK from header.json.
func (s *Service) Unlock(master string) error {
	if err := s.requireBiometricForUnlock(); err != nil {
		return err
	}

	hdr, err := store.LoadVaultHeader(s.paths)
	if err != nil {
		return fmt.Errorf("load header: %w", err)
	}

	params, salt, err := buildKDF(hdr)
	if err != nil {
		return err
	}

	masterBytes := []byte(master)
	defer wipe(masterBytes)

	pdk, err := krypto.DeriveKeyArgon2id(masterBytes, salt, params)
	if err != nil {
		return fmt.Errorf("derive PDK: %w", err)
	}
	defer wipe(pdk)

	mek, _, err := store.LoadAndUnwrapMEK(s.paths, pdk)
	if err != nil {
		return fmt.Errorf("unwrap MEK: %w", err)
	}
	defer wipe(mek)

	s.setMEK(mek)
	return nil
}

// ChangeMaster rewraps the header MEK and validates the new password using auth policy.
func (s *Service) ChangeMaster(oldMaster, newMaster string) error {
	if oldMaster == "" || newMaster == "" {
		return errors.New("old and new master passwords are required")
	}

	ctx := context.Background()
	opts := auth.DefaultValidateOptions()
	opts.EnableHIBP = true
	opts.MinZXCVBNScore = 3
	if err := auth.ValidateMasterPasswordAdvanced(ctx, newMaster, opts); err != nil {
		return fmt.Errorf("validate new master password: %w", err)
	}

	hdr, err := store.LoadVaultHeader(s.paths)
	if err != nil {
		return fmt.Errorf("load header: %w", err)
	}

	params, oldSalt, err := buildKDF(hdr)
	if err != nil {
		return err
	}

	oldBytes := []byte(oldMaster)
	defer wipe(oldBytes)

	oldPDK, err := krypto.DeriveKeyArgon2id(oldBytes, oldSalt, params)
	if err != nil {
		return fmt.Errorf("derive old PDK: %w", err)
	}
	defer wipe(oldPDK)

	mek, hdrCurrent, err := store.LoadAndUnwrapMEK(s.paths, oldPDK)
	if err != nil {
		return fmt.Errorf("verify old master password: %w", err)
	}
	defer wipe(mek)

	newSalt, err := krypto.NewRandomSalt(params.SaltLen)
	if err != nil {
		return fmt.Errorf("generate new salt: %w", err)
	}

	newBytes := []byte(newMaster)
	defer wipe(newBytes)

	newPDK, err := krypto.DeriveKeyArgon2id(newBytes, newSalt, params)
	if err != nil {
		return fmt.Errorf("derive new PDK: %w", err)
	}
	defer wipe(newPDK)

	hdrCurrent.Salt = base64.StdEncoding.EncodeToString(newSalt)
	hdrCurrent.KDF.Name = "argon2id"

	if err := store.RewrapMEK(s.paths, hdrCurrent, newPDK, mek); err != nil {
		return fmt.Errorf("rewrap mek: %w", err)
	}

	s.setMEK(mek)
	return nil
}

// Add stores (website, username, password) encrypted with the current MEK.
func (s *Service) Add(website, username, plaintext string) error {
	if s.mek == nil {
		return errors.New("vault locked")
	}
	if website == "" || username == "" {
		return errors.New("website and username required")
	}
	if plaintext == "" {
		return errors.New("password cannot be empty")
	}

	salt, blob, err := vault.EncryptEntryPassword(s.mek, website, username, "password", plaintext)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	_, err = s.sql.Exec(
		`INSERT INTO passwords (encrypted_pass, salt, website, username, type)
		 VALUES (?, ?, ?, ?, 'password')`,
		blob, salt, website, username,
	)
	if err != nil {
		return fmt.Errorf("insert entry: %w", err)
	}
	return nil
}

// Get returns the decrypted password for (website, username).
func (s *Service) Get(website, username string) (string, error) {
	if s.mek == nil {
		return "", errors.New("vault locked")
	}

	var (
		id   int64
		typ  string
		enc  []byte
		salt []byte
	)

	err := s.sql.QueryRow(
		`SELECT id, encrypted_pass, salt, "type"
           FROM passwords
          WHERE website = ? AND username = ?`,
		website, username,
	).Scan(&id, &enc, &salt, &typ)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("not found")
		}
		return "", fmt.Errorf("select: %w", err)
	}

	plain, newSalt, newBlob, err := vault.DecryptEntryPassword(s.mek, website, username, typ, salt, enc)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	// Rotate-at-read if crypto lib returned updated salt/ciphertext.
	if !bytes.Equal(newSalt, salt) || !bytes.Equal(newBlob, enc) {
		if _, uerr := s.sql.Exec(
			`UPDATE passwords
                SET encrypted_pass = ?, salt = ?, updated_at = CURRENT_TIMESTAMP
              WHERE id = ?`,
			newBlob, newSalt, id,
		); uerr != nil {
			return plain, fmt.Errorf("rotation persisted partially: %w", uerr)
		}
	}

	return plain, nil
}

// Update changes the password and (optionally) the type for a site/user.
// If newType == "", the existing row.Type is kept.
func (s *Service) Update(website, username, newType, newPlaintext string) error {
	if s.mek == nil {
		return errors.New("vault locked")
	}
	if website == "" || username == "" {
		return errors.New("website and username required")
	}
	if newPlaintext == "" {
		return errors.New("new password cannot be empty")
	}

	var id int64
	var curType string
	err := s.sql.QueryRow(
		`SELECT id, "type" FROM passwords WHERE website = ? AND username = ?`,
		website, username,
	).Scan(&id, &curType)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("not found")
		}
		return fmt.Errorf("select: %w", err)
	}

	typ := curType
	if newType != "" {
		typ = newType
	}

	salt, blob, err := vault.EncryptEntryPassword(s.mek, website, username, typ, newPlaintext)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	_, err = s.sql.Exec(
		`UPDATE passwords
		    SET encrypted_pass = ?, salt = ?, "type" = ?, updated_at = CURRENT_TIMESTAMP
		  WHERE id = ?`,
		blob, salt, typ, id,
	)
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	return nil
}

// ListItem is a minimal row for GUI lists.
type ListItem struct {
	ID       int64
	Website  string
	Username string
}

// Delete removes the credential row for (website, username).
func (s *Service) Delete(website, username string) error {
	if s.mek == nil {
		return errors.New("vault locked")
	}
	if website == "" || username == "" {
		return errors.New("website and username required")
	}

	res, err := s.sql.Exec(
		`DELETE FROM passwords WHERE website = ? AND username = ?`,
		website, username,
	)
	if err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("not found")
	}
	return nil
}

// List returns (id, website, username) for all entries.
func (s *Service) List() ([]ListItem, error) {
	if s.mek == nil {
		return nil, errors.New("vault locked")
	}
	rows, err := s.sql.Query(`SELECT id, website, username FROM passwords ORDER BY website, username`)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	var out []ListItem
	for rows.Next() {
		var it ListItem
		if err := rows.Scan(&it.ID, &it.Website, &it.Username); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// EnableBiometrics persists biometric toggle metadata after local auth.
func (s *Service) EnableBiometrics(rpID, origin string) error {
	if err := toggle.Authenticate("Touch ID to enable biometric unlock"); err != nil {
		return err
	}
	if err := toggle.Enable(s.paths.Dir, rpID, origin); err != nil {
		return err
	}
	return nil
}

// DisableBiometrics removes biometric toggle metadata after local auth.
func (s *Service) DisableBiometrics() error {
	if err := toggle.Authenticate("Touch ID to disable biometric unlock"); err != nil {
		return err
	}
	if err := toggle.Disable(s.paths.Dir); err != nil {
		return err
	}
	return nil
}

// BiometricStatus queries the persisted toggle state for the current vault directory.
func (s *Service) BiometricStatus() (toggle.State, error) {
	return toggle.Status(s.paths.Dir)
}

// MekSetUnsafe allows tests to inject an already-derived MEK reference.
func (s *Service) MekSetUnsafe(m []byte) { s.mek = m }
func (s *Service) IsUnlocked() bool      { return s.mek != nil }
