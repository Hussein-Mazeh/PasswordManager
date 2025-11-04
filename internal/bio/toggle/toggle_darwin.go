//go:build darwin

// Package toggle (darwin) — Biometric toggle storage on macOS Keychain
//
// Why Keychain:
//   - Hardware-backed protection: Using Keychain with `AccessibleWhenUnlockedThisDeviceOnly` keeps
//     data device-local and only readable while the device is unlocked, aligning with Secure Enclave
//     policy where applicable.
//   - OS-enforced access control: The system mediates reads/writes and can prompt the user as needed,
//     reducing the risk of silent exfiltration.
//   - Robustness: Atomic add/update semantics, consistent APIs across macOS versions,
//     and no ad-hoc file format to maintain or defend.
//
// Design:
//   - Each vault directory maps to a single Keychain “account” string equal to the directory’s
//     absolute, symlink-resolved path (stable identifier).
//   - The item is stored under service `keychainService` with a human-readable label.
//   - The payload is a compact JSON-encoded `State` (Enabled, RPID, Origin), not synchronized to iCloud.

package toggle

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	keychain "github.com/keybase/go-keychain"
)

const (
	keychainService = "com.crypto.passman.bio.toggle"
	keychainLabel   = "PassMan biometric toggle"
)

// accountForDirectory validates and canonicalizes(turn the path into a single and unique identifier for that folder) 
// a vault directory path to use as the Keychain account.
//
// Args:
//   directory: Path to the vault directory; may be relative and may include symlinks.
//
// Returns:
//   (string, error): Absolute, symlink-resolved directory path suitable as a unique Keychain account;
//   error if the input is empty, not resolvable, does not exist, or is not a directory.
//
// Behavior:
//   - Rejects blank/whitespace-only input.
//   - Converts to an absolute path and stats it; requires that it is a directory.
//   - Resolves symlinks (when possible) to produce a stable identifier for Keychain storage.
//   - Returns the resolved absolute path (used as the per-vault “account” key).
func accountForDirectory(directory string) (string, error) {
	directory = strings.TrimSpace(directory)
	if directory == "" {
		return "", errors.New("vault directory is required")
	}

	absolutePath, err := filepath.Abs(directory)
	if err != nil {
		return "", fmt.Errorf("resolve directory: %w", err)
	}

	info, err := os.Stat(absolutePath)
	if err != nil {
		return "", fmt.Errorf("stat directory: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("not a directory: %s", absolutePath)
	}

	if resolved, err := filepath.EvalSymlinks(absolutePath); err == nil && resolved != "" {
		absolutePath = resolved
	}

	return absolutePath, nil
}

// storePayload writes the biometric toggle State into the macOS Keychain.
//
// Args:
//   account: The per-vault account string (canonical directory path) used to identify the item.
//   payload: The State to persist (e.g., Enabled, RPID, Origin).
//
// Returns:
//   error: nil on success; wrapped error if JSON encoding, add, or update fails.
//
// Behavior:
//   - JSON-encodes the payload.
//   - Creates a GenericPassword item with:
//       • Service: keychainService
//       • Account: account (canonical directory path)
//       • Label:   keychainLabel
//       • Data:    JSON payload
//   - Security attributes:
//       • SynchronizableNo (device-local; not synced to iCloud)
//       • AccessibleWhenUnlockedThisDeviceOnly (only when device is unlocked; never migrates)
//   - Attempts AddItem; if the item already exists, performs UpdateItem with the new payload.
//
// Notes (Keychain value):
//   - Using Keychain instead of a plaintext or custom-encrypted file leverages OS policy, user session
//     state, and hardware-backed protections, reducing silent tamper risk.
func storePayload(account string, payload State) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode biometric toggle: %w", err)
	}

	item := keychain.NewGenericPassword(keychainService, account, keychainLabel, data, "")
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlockedThisDeviceOnly)

	if err := keychain.AddItem(item); err != nil {
		if err == keychain.ErrorDuplicateItem {
			query := keychain.NewGenericPassword(keychainService, account, "", nil, "")
			update := keychain.NewItem()
			update.SetData(data)
			if err := keychain.UpdateItem(query, update); err != nil {
				return fmt.Errorf("update biometric toggle: %w", err)
			}
			return nil
		}
		return fmt.Errorf("add biometric toggle to keychain: %w", err)
	}
	return nil
}

// Enable stores the biometric toggle metadata for the vault directory.
//
// Args:
//   dir:    Vault directory path to bind the toggle to.
//   rpID:   WebAuthn relying party ID (scope/domain for credentials).
//   origin: Allowed WebAuthn origin (scheme+host[:port]).
//
// Returns:
//   error: nil on success; error if the directory is invalid or Keychain write fails.
//
// Behavior:
//   - Derives the per-vault account (canonical absolute path) via accountForDirectory.
//   - Builds a State with Enabled=true and trimmed RPID/Origin.
//   - Persists the State in Keychain using device-local, “when unlocked” access policy.
//
// Notes:
//   - Storing the “enabled” state in Keychain (device-local, non-synced) avoids easy toggling via file edits
//     and ties reads to the OS’s unlocked state, aligning with biometric policies.
func Enable(dir, rpID, origin string) error {
	account, err := accountForDirectory(dir)
	if err != nil {
		return err
	}
	payload := State{
		Enabled: true,
		RPID:    strings.TrimSpace(rpID),
		Origin:  strings.TrimSpace(origin),
	}
	return storePayload(account, payload)
}

// Disable removes the biometric toggle metadata for the vault directory.
//
// Args:
//   dir: Vault directory whose toggle should be removed.
//
// Returns:
//   error: nil if removed or not found; wrapped error on Keychain failures.
//
// Behavior:
//   - Resolves the directory to the canonical account key.
//   - Issues a Keychain DeleteItem for the {service, account} pair.
//   - Treats ErrorItemNotFound as success for idempotency.
func Disable(dir string) error {
	account, err := accountForDirectory(dir)
	if err != nil {
		return err
	}
	query := keychain.NewGenericPassword(keychainService, account, "", nil, "")
	if err := keychain.DeleteItem(query); err != nil && err != keychain.ErrorItemNotFound {
		return fmt.Errorf("remove biometric toggle from keychain: %w", err)
	}
	return nil
}

// Status returns the biometric toggle metadata for the vault directory.
//
// Args:
//   dir: Vault directory to query.
//
// Returns:
//   (State, error): Decoded State on success; State{Enabled:false} if not present;
//   wrapped error if Keychain read or JSON decoding fails.
//
// Behavior:
//   - Resolves the directory to the canonical account key.
//   - Reads the GenericPassword item from Keychain under keychainService/account.
//   - If no data is present, returns a disabled State.
//   - Otherwise, JSON-decodes and returns the stored State.
func Status(dir string) (State, error) {
	account, err := accountForDirectory(dir)
	if err != nil {
		return State{}, err
	}
	data, err := keychain.GetGenericPassword(keychainService, account, "", "")
	if err != nil {
		return State{}, fmt.Errorf("read biometric toggle: %w", err)
	}
	if len(data) == 0 {
		return State{Enabled: false}, nil
	}

	var payload State
	if err := json.Unmarshal(data, &payload); err != nil {
		return State{}, fmt.Errorf("decode biometric toggle: %w", err)
	}
	return payload, nil
}
