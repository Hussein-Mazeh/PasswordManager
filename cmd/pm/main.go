package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/Hussein-Mazeh/PasswordManager/auth"
	dbpkg "github.com/Hussein-Mazeh/PasswordManager/internal/db"
	"github.com/Hussein-Mazeh/PasswordManager/internal/vault"
	"github.com/Hussein-Mazeh/PasswordManager/krypto"
	"github.com/Hussein-Mazeh/PasswordManager/store"
)

const cliVersion = "0.1.0"

type userError struct {
	msg string
}

func (e userError) Error() string { return e.msg }

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version":
		fmt.Println(cliVersion)
	case "master":
		if len(os.Args) < 3 {
			printMasterUsage()
			os.Exit(1)
		}
		switch os.Args[2] {
		case "set":
			if err := runMasterSet(os.Args[3:]); err != nil {
				handleError(err)
			}
		case "change":
			if err := runMasterChange(os.Args[3:]); err != nil {
				handleError(err)
			}
		default:
			printMasterUsage()
			os.Exit(1)
		}
	case "session":
		if err := runSession(os.Args[2:]); err != nil {
			handleError(err)
		}
	default:
		printUsage()
		os.Exit(1)
	}
}

func handleError(err error) {
	if err == nil {
		return
	}

	var uerr userError
	if errors.As(err, &uerr) {
		fmt.Fprintln(os.Stderr, uerr.Error())
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "unexpected error: %v\n", err)
	os.Exit(2)
}

func runMasterSet(args []string) error {
	fs := flag.NewFlagSet("master set", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var dir string
	var user string
	fs.StringVar(&dir, "dir", "", "vault directory")
	fs.StringVar(&user, "user", "", "vault username")

	if err := fs.Parse(args); err != nil {
		return userError{msg: "invalid arguments"}
	}
	if dir == "" || user == "" {
		return userError{msg: "missing required flags: --dir and --user"}
	}
	if fs.NArg() != 0 {
		return userError{msg: "unexpected positional arguments"}
	}

	pw, err := promptPassword("Enter master password: ")
	if err != nil {
		return fmt.Errorf("read master password: %w", err)
	}
	defer zeroBytes(pw)

	confirm, err := promptPassword("Confirm master password: ")
	if err != nil {
		return fmt.Errorf("read confirmation password: %w", err)
	}
	defer zeroBytes(confirm)

	if !bytes.Equal(pw, confirm) {
		return userError{msg: "passwords do not match"}
	}

	if err := auth.ValidateMasterPassword(string(pw)); err != nil {
		return userError{msg: "password does not meet policy requirements"}
	}

	paths := store.Paths{Dir: dir}

	params := krypto.DefaultArgon2Params()
	params.SaltLen = krypto.SaltLengthBytes
	hdr, err := store.LoadVaultHeader(paths)
	headerExists := err == nil
	saltReplaced := false
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			hdr = vault.VaultHeader{}
			headerExists = false
		} else {
			return fmt.Errorf("load header: %w", err)
		}
	}

	var salt []byte
	if hdr.Salt != "" {
		salt, err = base64.StdEncoding.DecodeString(hdr.Salt)
		if err != nil {
			return fmt.Errorf("decode header salt: %w", err)
		}
		if len(salt) != krypto.SaltLengthBytes {
			saltReplaced = true
		}
	} else {
		salt, err = krypto.NewRandomSalt(params.SaltLen)
		if err != nil {
			return fmt.Errorf("generate salt: %w", err)
		}
		hdr.Salt = base64.StdEncoding.EncodeToString(salt)
	}

	if saltReplaced {
		salt, err = krypto.NewRandomSalt(krypto.SaltLengthBytes)
		if err != nil {
			return fmt.Errorf("regenerate salt: %w", err)
		}
		hdr.Salt = base64.StdEncoding.EncodeToString(salt)
	}

	pdk, err := krypto.DeriveKeyArgon2id(pw, salt, params)
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}
	defer zeroBytes(pdk)

	var mek []byte
	if headerExists && !saltReplaced && hdr.Version == 1 && hdr.KDF.Name == "argon2id" {
		existingMEK, loadedHdr, err := store.LoadAndUnwrapMEK(paths, pdk)
		switch {
		case err == nil:
			mek = existingMEK
			hdr = loadedHdr
		case errors.Is(err, store.ErrMEKNotWrapped):
			// No wrapped MEK yet; generate below.
		case errors.Is(err, os.ErrNotExist):
			headerExists = false
		default:
			return fmt.Errorf("load existing mek: %w", err)
		}
	}

	if len(mek) == 0 {
		mek = make([]byte, 32)
		if _, err := rand.Read(mek); err != nil {
			return fmt.Errorf("generate mek: %w", err)
		}
	}
	defer zeroBytes(mek)

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

	if err := store.WrapAndSaveMEK(paths, hdr, pdk, mek); err != nil {
		return fmt.Errorf("persist header: %w", err)
	}

	fmt.Printf("master password set for user %s; MEK is wrapped\n", user)
	return nil
}

func runSession(args []string) error {
	fs := flag.NewFlagSet("session", flag.ContinueOnError)
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

	paths := store.Paths{Dir: dir}
	hdr, err := store.LoadVaultHeader(paths)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return userError{msg: "vault header not found; run pm master set first"}
		}
		return fmt.Errorf("load header: %w", err)
	}
	if hdr.KDF.Name != "argon2id" || hdr.Salt == "" {
		return userError{msg: "vault header missing required fields"}
	}

	salt, err := base64.StdEncoding.DecodeString(hdr.Salt)
	if err != nil {
		return fmt.Errorf("decode header salt: %w", err)
	}

	params := krypto.Argon2Params{
		MemoryMB:    hdr.KDF.MemoryMB,
		Time:        hdr.KDF.Time,
		Parallelism: hdr.KDF.Parallelism,
		SaltLen:     hdr.KDF.SaltLen,
		KeyLen:      hdr.KDF.KeyLen,
	}

	pw, err := promptPassword("Enter master password: ")
	if err != nil {
		return fmt.Errorf("read master password: %w", err)
	}
	defer zeroBytes(pw)

	pdk, err := krypto.DeriveKeyArgon2id(pw, salt, params)
	if err != nil {
		return userError{msg: "failed to unlock vault"}
	}
	defer zeroBytes(pdk)

	mek, _, err := store.LoadAndUnwrapMEK(paths, pdk)
	if err != nil {
		if errors.Is(err, store.ErrMEKNotWrapped) {
			return userError{msg: "vault is not initialised with a master key"}
		}
		return userError{msg: "failed to unlock vault"}
	}
	defer zeroBytes(mek)

	dbPath := filepath.Join(dir, "vault.db")
	database, err := dbpkg.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open vault database: %w", err)
	}
	defer dbpkg.Close(database)

	if err := dbpkg.Migrate(database); err != nil {
		return fmt.Errorf("initialise vault database: %w", err)
	}

	fmt.Println("session unlocked; type 'help' for commands")
	return sessionLoop(database, mek)
}

func sessionLoop(database *dbpkg.DB, mek []byte) error {
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("pm> ")
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("read input: %w", err)
			}
			fmt.Println()
			return nil
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		cmd := fields[0]
		args := fields[1:]

		switch cmd {
		case "help":
			printSessionHelp()
		case "add":
			if err := sessionAdd(database, mek, args); err != nil {
				handleSessionError(err)
			}
		case "get":
			if err := sessionGet(database, mek, args); err != nil {
				handleSessionError(err)
			}
		case "exit", "quit":
			return nil
		default:
			fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		}
	}
}

func sessionAdd(database *dbpkg.DB, mek []byte, args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var site string
	var user string
	var typ string
	fs.StringVar(&site, "site", "", "website identifier")
	fs.StringVar(&user, "user", "", "username")
	fs.StringVar(&typ, "type", "password", "credential type")

	if err := fs.Parse(args); err != nil {
		return userError{msg: "invalid add arguments"}
	}
	if site == "" || user == "" {
		return userError{msg: "add requires --site and --user"}
	}
	if fs.NArg() != 0 {
		return userError{msg: "unexpected positional arguments"}
	}

	secret, err := promptPassword("Secret: ")
	if err != nil {
		return fmt.Errorf("read secret: %w", err)
	}
	defer zeroBytes(secret)

	confirm, err := promptPassword("Confirm: ")
	if err != nil {
		return fmt.Errorf("read confirmation: %w", err)
	}
	defer zeroBytes(confirm)

	if !bytes.Equal(secret, confirm) {
		return userError{msg: "secrets do not match"}
	}

	entrySalt, blob, err := vault.EncryptEntryPassword(mek, site, user, typ, string(secret))
	if err != nil {
		return fmt.Errorf("encrypt credential: %w", err)
	}

	id, err := dbpkg.InsertEntry(database, site, user, typ, entrySalt, blob)
	if err != nil {
		return fmt.Errorf("store credential: %w", err)
	}

	fmt.Printf("stored credential for %s/%s (id=%d)\n", site, user, id)
	return nil
}

func sessionGet(database *dbpkg.DB, mek []byte, args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var site string
	var user string
	fs.StringVar(&site, "site", "", "website identifier")
	fs.StringVar(&user, "user", "", "username")

	if err := fs.Parse(args); err != nil {
		return userError{msg: "invalid get arguments"}
	}
	if site == "" {
		return userError{msg: "get requires --site"}
	}
	if fs.NArg() != 0 {
		return userError{msg: "unexpected positional arguments"}
	}

	if user != "" {
		row, err := dbpkg.GetEntryBySiteAndUser(database, site, user)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				fmt.Fprintf(os.Stderr, "no credential found for %s/%s\n", site, user)
				return nil
			}
			return fmt.Errorf("fetch credential: %w", err)
		}
		plaintext, err := vault.DecryptEntryPassword(mek, row.Salt, row.EncryptedPass)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to decrypt credential for %s/%s\n", row.Website, row.Username)
			return nil
		}
		fmt.Printf("%s %s: %s\n", row.Website, row.Username, plaintext)
		return nil
	}

	rows, err := dbpkg.GetEntryByWebsite(database, site)
	if err != nil {
		return fmt.Errorf("fetch credentials: %w", err)
	}
	if len(rows) == 0 {
		fmt.Fprintf(os.Stderr, "no credentials found for %s\n", site)
		return nil
	}
	for _, row := range rows {
		plaintext, err := vault.DecryptEntryPassword(mek, row.Salt, row.EncryptedPass)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to decrypt credential for %s/%s\n", row.Website, row.Username)
			continue
		}
		fmt.Printf("%s %s: %s\n", row.Website, row.Username, plaintext)
	}
	return nil
}

func handleSessionError(err error) {
	if err == nil {
		return
	}

	var uerr userError
	if errors.As(err, &uerr) {
		fmt.Fprintln(os.Stderr, uerr.Error())
		return
	}

	fmt.Fprintf(os.Stderr, "error: %v\n", err)
}

func promptPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	return pw, nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: pm <command>")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  version")
	fmt.Fprintln(os.Stderr, "  master set --dir <vault-dir> --user <username>")
	fmt.Fprintln(os.Stderr, "  master change --dir <vault-dir> --user <username>")
	fmt.Fprintln(os.Stderr, "  session --dir <vault-dir>")
}

func printMasterUsage() {
	fmt.Fprintln(os.Stderr, "Usage: pm master <set|change> --dir <vault-dir> --user <username>")
}

func printSessionHelp() {
	fmt.Println("Commands:")
	fmt.Println("  add --site <website> --user <username> [--type password]")
	fmt.Println("  get --site <website> [--user <username>]")
	fmt.Println("  exit | quit")
}

func runMasterChange(args []string) error {
	fs := flag.NewFlagSet("master change", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var dir string
	var user string
	fs.StringVar(&dir, "dir", "", "vault directory")
	fs.StringVar(&user, "user", "", "vault username")

	if err := fs.Parse(args); err != nil {
		return userError{msg: "invalid arguments"}
	}
	if dir == "" || user == "" {
		return userError{msg: "missing required flags: --dir and --user"}
	}
	if fs.NArg() != 0 {
		return userError{msg: "unexpected positional arguments"}
	}

	paths := store.Paths{Dir: dir}
	hdr, err := store.LoadVaultHeader(paths)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return userError{msg: "vault header not found; run pm master set first"}
		}
		return fmt.Errorf("load header: %w", err)
	}
	if hdr.KDF.Name != "argon2id" || hdr.Salt == "" {
		return userError{msg: "vault header missing required fields"}
	}

	oldSalt, err := base64.StdEncoding.DecodeString(hdr.Salt)
	if err != nil {
		return fmt.Errorf("decode header salt: %w", err)
	}

	params := krypto.Argon2Params{
		MemoryMB:    hdr.KDF.MemoryMB,
		Time:        hdr.KDF.Time,
		Parallelism: hdr.KDF.Parallelism,
		SaltLen:     hdr.KDF.SaltLen,
		KeyLen:      hdr.KDF.KeyLen,
	}

	oldPw, err := promptPassword("Old master password: ")
	if err != nil {
		return fmt.Errorf("read old master password: %w", err)
	}
	defer zeroBytes(oldPw)

	oldPDK, err := krypto.DeriveKeyArgon2id(oldPw, oldSalt, params)
	if err != nil {
		return userError{msg: "failed to verify existing password"}
	}
	defer zeroBytes(oldPDK)

	mek, hdrCurrent, err := store.LoadAndUnwrapMEK(paths, oldPDK)
	if err != nil {
		if errors.Is(err, store.ErrMEKNotWrapped) {
			return userError{msg: "vault is not initialised with a master key"}
		}
		return userError{msg: "failed to verify existing password"}
	}
	defer zeroBytes(mek)

	newPw, err := promptPassword("New master password: ")
	if err != nil {
		return fmt.Errorf("read new master password: %w", err)
	}
	defer zeroBytes(newPw)

	confirmPw, err := promptPassword("Confirm new master password: ")
	if err != nil {
		return fmt.Errorf("read confirmation password: %w", err)
	}
	defer zeroBytes(confirmPw)

	if !bytes.Equal(newPw, confirmPw) {
		return userError{msg: "passwords do not match"}
	}

	if err := auth.ValidateMasterPassword(string(newPw)); err != nil {
		return userError{msg: "password does not meet policy requirements"}
	}

	newSalt, err := krypto.NewRandomSalt(params.SaltLen)
	if err != nil {
		return fmt.Errorf("generate new salt: %w", err)
	}

	newPDK, err := krypto.DeriveKeyArgon2id(newPw, newSalt, params)
	if err != nil {
		return fmt.Errorf("derive new key: %w", err)
	}
	defer zeroBytes(newPDK)

	hdrCurrent.Salt = base64.StdEncoding.EncodeToString(newSalt)
	hdrCurrent.KDF.Name = "argon2id"

	if err := store.RewrapMEK(paths, hdrCurrent, newPDK, mek); err != nil {
		return fmt.Errorf("rewrap mek: %w", err)
	}

	fmt.Printf("master password changed for user %s; MEK rewrapped\n", user)
	return nil
}
