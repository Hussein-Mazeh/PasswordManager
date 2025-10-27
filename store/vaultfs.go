package store

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Hussein-Mazeh/PasswordManager/internal/vault"
	"github.com/Hussein-Mazeh/PasswordManager/krypto"
)

const headerFilename = "header.json"

var (
	// ErrMEKNotWrapped indicates the header does not contain a wrapped MEK.
	ErrMEKNotWrapped = errors.New("wrapped mek not present")

	headerMEKAAD = []byte("header.mek")
)

// Paths locates vault artifacts on disk.
type Paths struct {
	Dir string
}

// HeaderPath resolves the header JSON path.
func (p Paths) HeaderPath() string {
	return filepath.Join(p.Dir, headerFilename)
}

func (p Paths) ensureDir() error {
	if p.Dir == "" {
		return errors.New("vault directory not specified")
	}
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return fmt.Errorf("create vault directory: %w", err)
	}
	return nil
}

// LoadVaultHeader reads header.json from disk.
func LoadVaultHeader(p Paths) (vault.VaultHeader, error) {
	var hdr vault.VaultHeader

	data, err := os.ReadFile(p.HeaderPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return hdr, err
		}
		return hdr, fmt.Errorf("read header: %w", err)
	}

	if err := json.Unmarshal(data, &hdr); err != nil {
		return hdr, fmt.Errorf("decode header: %w", err)
	}

	return hdr, nil
}

// SaveVaultHeader persists header.json atomically with restrictive permissions.
func SaveVaultHeader(p Paths, hdr vault.VaultHeader) error {
	if err := p.ensureDir(); err != nil {
		return err
	}

	data, err := json.MarshalIndent(hdr, "", "  ")
	if err != nil {
		return fmt.Errorf("encode header: %w", err)
	}

	tmp, err := os.CreateTemp(p.Dir, "header-*.json")
	if err != nil {
		return fmt.Errorf("create temp header: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write temp header: %w", err)
	}

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("chmod temp header: %w", err)
	}

	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp header: %w", err)
	}

	if err := os.Rename(tmpPath, p.HeaderPath()); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("replace header: %w", err)
	}

	return nil
}

// WrapAndSaveMEK wraps the MEK using the provided PDK and saves it into header.json.
func WrapAndSaveMEK(p Paths, hdr vault.VaultHeader, pdk []byte, mek []byte) error {
	if len(pdk) != 32 {
		return errors.New("invalid PDK length")
	}
	if len(mek) != 32 {
		return errors.New("invalid MEK length")
	}
	if hdr.Version != 1 {
		return errors.New("unsupported header version")
	}
	if hdr.KDF.Name != "argon2id" {
		return errors.New("unsupported kdf")
	}

	nonce, ciphertext, err := krypto.EncryptAESGCM(pdk, mek, headerMEKAAD)
	if err != nil {
		return fmt.Errorf("wrap mek: %w", err)
	}

	hdr.WrapNonce = base64.StdEncoding.EncodeToString(nonce)
	hdr.WrappedMEK = base64.StdEncoding.EncodeToString(ciphertext)

	now := time.Now().UTC()
	if hdr.CreatedAt.IsZero() {
		hdr.CreatedAt = now
	}
	hdr.UpdatedAt = now

	if err := SaveVaultHeader(p, hdr); err != nil {
		return fmt.Errorf("save header: %w", err)
	}

	return nil
}

// LoadAndUnwrapMEK loads header.json and decrypts the wrapped MEK using the provided PDK.
func LoadAndUnwrapMEK(p Paths, pdk []byte) ([]byte, vault.VaultHeader, error) {
	if len(pdk) != 32 {
		return nil, vault.VaultHeader{}, errors.New("invalid PDK length")
	}

	hdr, err := LoadVaultHeader(p)
	if err != nil {
		return nil, hdr, err
	}

	if hdr.Version != 1 {
		return nil, hdr, errors.New("unsupported header version")
	}
	if hdr.KDF.Name != "argon2id" {
		return nil, hdr, errors.New("unsupported kdf")
	}
	if hdr.WrapNonce == "" || hdr.WrappedMEK == "" {
		return nil, hdr, ErrMEKNotWrapped
	}

	nonce, err := base64.StdEncoding.DecodeString(hdr.WrapNonce)
	if err != nil {
		return nil, hdr, fmt.Errorf("decode wrap nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(hdr.WrappedMEK)
	if err != nil {
		return nil, hdr, fmt.Errorf("decode wrapped mek: %w", err)
	}

	mek, err := krypto.DecryptAESGCM(pdk, nonce, ciphertext, headerMEKAAD)
	if err != nil {
		return nil, hdr, fmt.Errorf("unwrap mek: %w", err)
	}

	return mek, hdr, nil
}

// RewrapMEK replaces the stored wrapped MEK using a newly derived PDK.
func RewrapMEK(p Paths, hdr vault.VaultHeader, newPDK []byte, mek []byte) error {
	if len(newPDK) != 32 {
		return errors.New("invalid PDK length")
	}
	if len(mek) != 32 {
		return errors.New("invalid MEK length")
	}
	if hdr.Version != 1 {
		return errors.New("unsupported header version")
	}
	if hdr.KDF.Name != "argon2id" {
		return errors.New("unsupported kdf")
	}

	nonce, ciphertext, err := krypto.EncryptAESGCM(newPDK, mek, headerMEKAAD)
	if err != nil {
		return fmt.Errorf("rewrap mek: %w", err)
	}

	hdr.WrapNonce = base64.StdEncoding.EncodeToString(nonce)
	hdr.WrappedMEK = base64.StdEncoding.EncodeToString(ciphertext)
	hdr.UpdatedAt = time.Now().UTC()

	if err := SaveVaultHeader(p, hdr); err != nil {
		return fmt.Errorf("save header: %w", err)
	}
	return nil
}
