package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Hussein-Mazeh/PasswordManager/internal/bio/toggle"
)

func runBio(args []string) error {
	if len(args) == 0 {
		return userError{msg: "missing bio subcommand"}
	}

	switch args[0] {
	case "enable":
		return runBioEnable(args[1:])
	case "disable":
		return runBioDisable(args[1:])
	case "status":
		return runBioStatus(args[1:])
	default:
		return userError{msg: "unknown bio subcommand"}
	}
}

// runBioEnable enables biometric unlock for a given vault directory.
//
// Args:
//   args: CLI arguments slice to parse for this subcommand.
//         Supported flags:
//           --dir     (string, required): Vault directory path.
//           --rp      (string, default "localhost"): WebAuthn relying party ID (RP ID).
//           --origin  (string, default "https://localhost"): Allowed WebAuthn origin.
//
// Returns:
//   error: nil on success; a user-facing error for invalid input or unsupported platform;
//          a wrapped error for parsing, filesystem, authentication, or enable failures.
//
// Behavior:
//   - Creates a dedicated flag.FlagSet ("bio enable") with ContinueOnError and silences its output.
//   - Binds and parses flags from args; rejects unexpected positional arguments.
//   - Requires --dir and verifies the vault directory via ensureVaultDir.
//   - Performs a live biometric authentication prompt (Touch ID) to confirm user presence/consent.
//       • If biometrics are unsupported, returns a userError indicating macOS-only support.
//   - Calls toggle.Enable(dir, rpID, origin) to persist enrollment/credentials bound to RP ID and origin.
//       • If unsupported, returns a userError indicating macOS-only support.
//   - On success, prints a confirmation including the normalized vault path and RP ID.
//
// Notes:
//   - Biometric authentication is performed *before* enabling to prevent silent enrollment,
//     bind Secure Enclave/Keychain policy to a recent user verification, and fail fast on
//     unsupported configurations.
func runBioEnable(args []string) error {
	fs := flag.NewFlagSet("bio enable", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var dir string
	var rpID string
	var origin string

	fs.StringVar(&dir, "dir", "", "vault directory")
	fs.StringVar(&rpID, "rp", "localhost", "WebAuthn relying party ID")
	fs.StringVar(&origin, "origin", "https://localhost", "allowed WebAuthn origin") // You must have one for the UI and other for the extension

	if err := fs.Parse(args); err != nil {
		return userError{msg: "invalid arguments"}
	}
	if fs.NArg() != 0 {
		return userError{msg: "unexpected positional arguments"}
	}
	if dir == "" {
		return userError{msg: "missing required flag: --dir"}
	}
	if err := ensureVaultDir(dir); err != nil {
		return err
	}

	if err := toggle.Authenticate("Touch ID to enable biometric unlock"); err != nil {
		if errors.Is(err, toggle.ErrUnsupported) {
			return userError{msg: "biometric unlock is only supported on macOS"}
		}
		return fmt.Errorf("biometric authentication failed: %w", err)
	}
	if err := toggle.Enable(dir, rpID, origin); err != nil {
		if errors.Is(err, toggle.ErrUnsupported) {
			return userError{msg: "biometric unlock is only supported on macOS"}
		}
		return fmt.Errorf("enable biometric unlock: %w", err)
	}

	fmt.Printf("Biometric unlock enabled for %s (rpId=%s)\n", filepath.Clean(dir), rpID)
	return nil
}

func runBioDisable(args []string) error {
	fs := flag.NewFlagSet("bio disable", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var dir string
	fs.StringVar(&dir, "dir", "", "vault directory")

	if err := fs.Parse(args); err != nil {
		return userError{msg: "invalid arguments"}
	}
	if dir == "" {
		return userError{msg: "missing required flag: --dir"}
	}
	if fs.NArg() != 0 {
		return userError{msg: "unexpected positional arguments"}
	}
	if err := ensureVaultDir(dir); err != nil {
		return err
	}

	if err := toggle.Authenticate("Touch ID to disable biometric unlock"); err != nil {
		if errors.Is(err, toggle.ErrUnsupported) {
			return userError{msg: "biometric unlock is only supported on macOS"}
		}
		return fmt.Errorf("biometric authentication failed: %w", err)
	}
	if err := toggle.Disable(dir); err != nil {
		if errors.Is(err, toggle.ErrUnsupported) {
			return userError{msg: "biometric unlock is only supported on macOS"}
		}
		return fmt.Errorf("disable biometric unlock: %w", err)
	}

	fmt.Printf("Biometric unlock disabled for %s\n", filepath.Clean(dir))
	return nil
}

func runBioStatus(args []string) error {
	fs := flag.NewFlagSet("bio status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var dir string
	fs.StringVar(&dir, "dir", "", "vault directory")

	if err := fs.Parse(args); err != nil {
		return userError{msg: "invalid arguments"}
	}
	if dir == "" {
		return userError{msg: "missing required flag: --dir"}
	}
	if fs.NArg() != 0 {
		return userError{msg: "unexpected positional arguments"}
	}
	if err := ensureVaultDir(dir); err != nil {
		return err
	}

	status, err := toggle.Status(dir)
	if err != nil {
		if errors.Is(err, toggle.ErrUnsupported) {
			return userError{msg: "biometric unlock is only supported on macOS"}
		}
		return fmt.Errorf("read biometric status: %w", err)
	}

	if status.Enabled {
		fmt.Printf("Biometric unlock: enabled (rpId=%s, origin=%s)\n", status.RPID, status.Origin)
	} else {
		fmt.Println("Biometric unlock: disabled")
	}
	return nil
}

func ensureVaultDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return userError{msg: fmt.Sprintf("vault directory not found: %s", dir)}
		}
		return fmt.Errorf("stat vault directory: %w", err)
	}
	if !info.IsDir() {
		return userError{msg: fmt.Sprintf("expected directory: %s", dir)}
	}
	return nil
}
