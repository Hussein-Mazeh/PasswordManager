package main

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	dbpkg "github.com/Hussein-Mazeh/PasswordManager/internal/db"
	"github.com/Hussein-Mazeh/PasswordManager/internal/vault"
	"github.com/Hussein-Mazeh/PasswordManager/krypto"
	"github.com/Hussein-Mazeh/PasswordManager/store"

	"github.com/Hussein-Mazeh/PasswordManager/native-host/domaincheck"
)

const (
	version      = "0.1.0"
	unlockTTL    = 10 * time.Minute
	bufferSize   = 1 << 16
	maxFrameSize = 1 << 20
)

var (
	errUnauthorized  = errors.New("unauthorized")
	errExpired       = errors.New("expired")
	errInvalidState  = errors.New("invalid state")
	errNonceReplayed = errors.New("nonce_replayed")
)

type sessionState struct {
	mutex    sync.Mutex //To avoid race conditions
	token    string
	mek      []byte
	expires  time.Time
	dir      string
	nonces   map[string]struct{}
	ownerUID string
}

// establish replaces any prior unlocked session with the provided MEK and metadata.
//
// Args:
//
//	dir: absolute path to the unlocked vault directory.
//	mek: decrypted master encryption key to cache.
//
// Returns:
//
//	string: newly generated session token.
//	int: token lifetime in seconds.
//	error: non-nil when token generation or state initialization fails.
//
// Behavior:
//  1. Locks the session mutex and clears any existing state.
//  2. Copies the MEK, generates a crypto-random token, and records directory/expiry.
//  3. On failure, zeroizes partial state before returning the error.
func (s *sessionState) establish(dir string, mek []byte) (string, int, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.clearLockedUnsafe()

	s.mek = make([]byte, len(mek))
	copy(s.mek, mek)

	token, err := generateToken()
	if err != nil {
		s.clearLockedUnsafe()
		return "", 0, err
	}

	s.token = token
	s.dir = dir
	s.expires = time.Now().Add(unlockTTL)
	s.nonces = make(map[string]struct{})
	s.ownerUID = currentUserIdentifier()

	return token, int(unlockTTL / time.Second), nil
}

// validateRequest confirms session authenticity and checks replay-protection nonce.
//
// Args:
//
//	token: session token presented by the caller.
//	nonce: per-request nonce to enforce uniqueness.
//
// Returns:
//
//	[]byte: copy of the cached MEK when authorization succeeds.
//	string: associated vault directory path.
//	error: non-nil for missing, expired, mismatched, or replayed requests.
//
// Behavior:
//  1. Locks the session mutex and ensures stored and supplied tokens/nonces are present.
//  2. Rejects expired sessions or unexpected MEK lengths, clearing state when detected.
//  3. Validates the caller's OS identity matches the session owner (when available).
//  4. Enforces nonce uniqueness per session to prevent replayed requests.
//  5. Extends the expiry window on successful validation and returns MEK/dir copies.
func (s *sessionState) validateRequest(token, nonce string) ([]byte, string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.token == "" || token == "" || nonce == "" {
		return nil, "", errUnauthorized
	}
	if time.Now().After(s.expires) {
		s.clearLockedUnsafe()
		return nil, "", errExpired
	}
	if subtle.ConstantTimeCompare([]byte(s.token), []byte(token)) != 1 {
		return nil, "", errUnauthorized
	}
	if owner := s.ownerUID; owner != "" {
		if current := currentUserIdentifier(); current != "" && current != owner {
			return nil, "", errUnauthorized
		}
	}
	if len(s.mek) != 32 {
		s.clearLockedUnsafe()
		return nil, "", errInvalidState
	}
	if s.nonces == nil {
		s.nonces = make(map[string]struct{})
	}
	if _, exists := s.nonces[nonce]; exists {
		return nil, "", errNonceReplayed
	}
	s.nonces[nonce] = struct{}{}

	s.expires = time.Now().Add(unlockTTL)

	mekCopy := make([]byte, len(s.mek))
	copy(mekCopy, s.mek)
	return mekCopy, s.dir, nil
}

// clear zeroizes and removes the active session.
//
// Args:
//
//	None.
//
// Returns:
//
//	None.
//
// Behavior:
//  1. Locks the session mutex.
//  2. Calls clearLockedUnsafe to wipe MEK, token, directory, and expiry timestamp.
func (s *sessionState) clear() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.clearLockedUnsafe()
}

func (s *sessionState) clearLockedUnsafe() {
	if len(s.mek) > 0 {
		zeroize(s.mek)
	}
	s.mek = nil
	s.token = ""
	s.dir = ""
	s.expires = time.Time{}
	s.nonces = nil
	s.ownerUID = ""
}

var sess sessionState

// Behavior:
//  1. Installs signal handlers that clear session state before exiting.
//  2. Wraps stdin/stdout with buffered I/O for Chrome's native messaging frames.
//  3. Loops reading requests, dispatching them via handleRequest, and writing responses.
func main() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		sess.clear()
		os.Exit(0)
	}()

	reader := bufio.NewReaderSize(os.Stdin, bufferSize)
	writer := bufio.NewWriterSize(os.Stdout, bufferSize)

	for {
		payload, err := readFrame(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			fmt.Fprintf(os.Stderr, "passwordmanager-host: read error: %v\n", err)
			return
		}

		resp := handleRequest(payload)

		if err := writeFrame(writer, resp); err != nil {
			fmt.Fprintf(os.Stderr, "passwordmanager-host: write error: %v\n", err)
			return
		}
	}
}

type envelope struct {
	Type string `json:"type"`
}

type unlockRequest struct {
	Type           string `json:"type"`
	Dir            string `json:"dir"`
	MasterPassword string `json:"masterPassword"`
}

type sessionRequest struct {
	Type         string `json:"type"`
	SessionToken string `json:"sessionToken"`
	Nonce        string `json:"nonce"`
}

type getCredentialsRequest struct {
	sessionRequest
	DomainETLD1      string `json:"domainEtld1"`
	ExactHost        string `json:"exactHost"`
	Username         string `json:"username"`
	RequireExactHost bool   `json:"requireExactHost"`
}

type saveCredentialRequest struct {
	sessionRequest
	DomainETLD1      string `json:"domainEtld1"`
	ExactHost        string `json:"exactHost"`
	Username         string `json:"username"`
	Password         string `json:"password"`
	RequireExactHost bool   `json:"requireExactHost"`
}

type response struct {
	OK      bool   `json:"ok"`
	Data    any    `json:"data,omitempty"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

type unlockData struct {
	Token      string `json:"token"`
	TTLSeconds int    `json:"ttlSeconds"`
}

// handleRequest routes an inbound payload to the appropriate handler according to the envelope type.
//
// Args:
//
//	payload: JSON-encoded request received from the browser.
//
// Returns:
//
//	response: structured result indicating success and data or failure details.
//
// Behavior:
//  1. Parses the envelope to determine the command type, returning BAD_JSON on failure.
//  2. Unmarshals into the typed request and delegates to command-specific handlers.
//  3. Emits UNSUPPORTED responses for unknown commands without mutating global state.
func handleRequest(payload []byte) response {
	var env envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return response{OK: false, Code: "BAD_JSON", Message: "invalid json"}
	}

	switch env.Type {
	case "health":
		return response{OK: true, Data: map[string]string{"version": version}}
	case "unlock":
		var req unlockRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return response{OK: false, Code: "BAD_JSON", Message: "invalid json"}
		}
		return handleUnlock(req)
	case "lock":
		var req sessionRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return response{OK: false, Code: "BAD_JSON", Message: "invalid json"}
		}
		if mek, _, err := sess.validateRequest(req.SessionToken, req.Nonce); err != nil {
			return sessionErrorResponse(err)
		} else {
			zeroize(mek)
		}
		sess.clear()
		return response{OK: true}
	case "getCredentials":
		var req getCredentialsRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return response{OK: false, Code: "BAD_JSON", Message: "invalid json"}
		}
		return handleGetCredentials(req)
	case "saveCredential":
		var req saveCredentialRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return response{OK: false, Code: "BAD_JSON", Message: "invalid json"}
		}
		return handleSaveCredential(req)
	case "phishingCheck":
		var req phishingCheckRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return response{OK: false, Code: "BAD_JSON", Message: "invalid json"}
		}
		return handlePhishingCheck(req)
	default:
		return response{OK: false, Code: "UNSUPPORTED", Message: "unsupported command"}
	}
}

func sessionErrorResponse(err error) response {
	if errors.Is(err, errNonceReplayed) {
		return response{OK: false, Code: "NONCE_REPLAY"}
	}
	if errors.Is(err, errExpired) {
		return response{OK: false, Code: "SESSION_EXPIRED"}
	}
	if errors.Is(err, errInvalidState) {
		return response{OK: false, Code: "INVALID_STATE"}
	}
	return response{OK: false, Code: "UNAUTHORIZED"}
}

// handleUnlock derives the vault key from the submitted master password and opens a session.
//
// Args:
//
//	req: unlock request containing vault directory and master password.
//
// Returns:
//
//	response: success contains a session token and TTL; failure surfaces a descriptive code.
//
// Behavior:
//  1. Validates request fields and resolves the vault directory path.
//  2. Loads the vault header, derives the PDK via Argon2id, and unwraps the MEK.
//  3. Establishes the session while zeroizing sensitive buffers throughout.
func handleUnlock(req unlockRequest) response {
	if strings.TrimSpace(req.Dir) == "" {
		return response{OK: false, Code: "BAD_REQUEST", Message: "vault directory required"}
	}

	sess.clear()

	pwBytes := []byte(req.MasterPassword)
	defer zeroize(pwBytes)
	defer zeroizeString(&req.MasterPassword)
	if len(pwBytes) == 0 {
		return response{OK: false, Code: "BAD_REQUEST", Message: "master password required"}
	}

	dir, err := filepath.Abs(req.Dir)
	if err != nil {
		dir = req.Dir
	}

	paths := store.Paths{Dir: dir}
	hdr, err := store.LoadVaultHeader(paths)
	if err != nil {
		return response{OK: false, Code: "UNLOCK_FAILED", Message: "unlock failed"}
	}

	if hdr.KDF.Name != "argon2id" || hdr.Salt == "" {
		return response{OK: false, Code: "UNLOCK_FAILED", Message: "unlock failed"}
	}

	salt, err := base64.StdEncoding.DecodeString(hdr.Salt)
	if err != nil {
		return response{OK: false, Code: "UNLOCK_FAILED", Message: "unlock failed"}
	}
	defer zeroize(salt)

	params := krypto.Argon2Params{
		MemoryMB:    hdr.KDF.MemoryMB,
		Time:        hdr.KDF.Time,
		Parallelism: hdr.KDF.Parallelism,
		SaltLen:     hdr.KDF.SaltLen,
		KeyLen:      hdr.KDF.KeyLen,
	}

	pdk, err := krypto.DeriveKeyArgon2id(pwBytes, salt, params)
	if err != nil {
		return response{OK: false, Code: "UNLOCK_FAILED", Message: "unlock failed"}
	}
	defer zeroize(pdk)

	mek, _, err := store.LoadAndUnwrapMEK(paths, pdk)
	if err != nil {
		zeroize(mek)
		return response{OK: false, Code: "UNLOCK_FAILED", Message: "unlock failed"}
	}

	token, ttlSeconds, err := sess.establish(dir, mek)
	zeroize(mek)
	if err != nil {
		return response{OK: false, Code: "INTERNAL", Message: "unlock failed"}
	}

	return response{OK: true, Data: unlockData{Token: token, TTLSeconds: ttlSeconds}}
}

// handleGetCredentials decrypts and returns stored credentials for a site/user.
//
// Args:
//
//	req: request containing session token, eTLD+1, host, and optional username.
//
// Returns:
//
//	response: success includes an array of credential maps; errors describe the failure.
//
// Behavior:
//  1. Validates the session token and checks domain policy for the requested host.
//  2. Opens/migrates the SQLite database and loads matching rows.
//  3. Decrypts rows via decryptRow, refreshing ciphertext when needed, and returns results.
func handleGetCredentials(req getCredentialsRequest) response {
	mek, dir, err := sess.validateRequest(req.SessionToken, req.Nonce)
	if err != nil {
		return sessionErrorResponse(err)
	}
	defer zeroize(mek)

	if req.DomainETLD1 == "" || req.ExactHost == "" {
		return response{OK: false, Code: "BAD_REQUEST"}
	}

	if !domaincheck.AllowAutofill(req.DomainETLD1, req.ExactHost, req.RequireExactHost, req.ExactHost) {
		return response{OK: false, Code: "ETLD_MISMATCH"}
	}

	dbPath := filepath.Join(dir, "vault.db")
	database, err := dbpkg.Open(dbPath)
	if err != nil {
		return response{OK: false, Code: "DB_ERROR", Message: "database unavailable"}
	}
	defer dbpkg.Close(database)
	if err := dbpkg.Migrate(database); err != nil {
		return response{OK: false, Code: "DB_ERROR", Message: "database unavailable"}
	}

	result := make([]map[string]string, 0)

	if strings.TrimSpace(req.Username) != "" {
		row, err := dbpkg.GetEntryBySiteAndUser(database, req.DomainETLD1, req.Username)
		if err == nil && row != nil {
			if item, ok := decryptRow(database, mek, row); ok {
				result = append(result, item)
			}
		}
	} else {
		rows, err := dbpkg.GetEntryByWebsite(database, req.DomainETLD1)
		if err == nil {
			for _, row := range rows {
				if item, ok := decryptRow(database, mek, &row); ok {
					result = append(result, item)
					break
				}
			}
		}
	}

	return response{OK: true, Data: map[string]any{"items": result}}
}

// decryptRow unwraps a database credential row and materializes plaintext fields.
//
// Args:
//
//	database: open SQLite handle used for optional ciphertext rotation.
//	mek: master encryption key supporting decryption.
//	row: credential row retrieved from the passwords table.
//
// Returns:
//
//	map[string]string: decrypted username/password pair when successful.
//	bool: false when decryption fails and the row should be skipped.
//
// Behavior:
//  1. Decrypts the entry via vault.DecryptEntryPassword to obtain plaintext and new blobs.
//  2. Updates stored ciphertext when rotation material is provided, zeroizing buffers afterward.
//  3. Returns the plaintext credential map while zeroizing temporary copies.
func decryptRow(database *dbpkg.DB, mek []byte, row *dbpkg.EntryRow) (map[string]string, bool) {
	plaintext, newSalt, newBlob, err := vault.DecryptEntryPassword(mek, row.Website, row.Username, row.Type, row.Salt, row.EncryptedPass)
	if err != nil {
		return nil, false
	}

	if len(newSalt) > 0 && len(newBlob) > 0 {
		_ = dbpkg.UpdateEntryCipher(database, row.ID, row.Type, newSalt, newBlob)
	}
	if len(newSalt) > 0 {
		zeroize(newSalt)
	}
	if len(newBlob) > 0 {
		zeroize(newBlob)
	}

	item := map[string]string{
		"username": row.Username,
		"password": plaintext,
	}
	zeroizeString(&plaintext)
	return item, true
}

// handleSaveCredential encrypts and persists a new credential entry.
//
// Args:
//
//	req: request containing session token, site metadata, username, and plaintext password.
//
// Returns:
//
//	response: success includes saved status and database row ID; errors report failure details.
//
// Behavior:
//  1. Validates the session token and enforces domain policy requirements.
//  2. Encrypts the plaintext password with the MEK to produce salt/ciphertext blobs.
//  3. Inserts the credential into SQLite while zeroizing sensitive buffers regardless of outcome.
func handleSaveCredential(req saveCredentialRequest) response {
	mek, dir, err := sess.validateRequest(req.SessionToken, req.Nonce)
	if err != nil {
		return sessionErrorResponse(err)
	}
	defer zeroize(mek)

	if req.DomainETLD1 == "" || req.ExactHost == "" || strings.TrimSpace(req.Username) == "" || req.Password == "" {
		return response{OK: false, Code: "BAD_REQUEST"}
	}

	if !domaincheck.AllowAutofill(req.DomainETLD1, req.ExactHost, req.RequireExactHost, req.ExactHost) {
		return response{OK: false, Code: "ETLD_MISMATCH"}
	}

	passwordBytes := []byte(req.Password)
	defer zeroize(passwordBytes)
	defer zeroizeString(&req.Password)

	dbPath := filepath.Join(dir, "vault.db")
	database, err := dbpkg.Open(dbPath)
	if err != nil {
		return response{OK: false, Code: "DB_ERROR", Message: "database unavailable"}
	}
	defer dbpkg.Close(database)
	if err := dbpkg.Migrate(database); err != nil {
		return response{OK: false, Code: "DB_ERROR", Message: "database unavailable"}
	}

	salt, blob, err := vault.EncryptEntryPassword(mek, req.DomainETLD1, req.Username, "password", req.Password)
	if err != nil {
		return response{OK: false, Code: "ENCRYPT_FAILED"}
	}

	id, err := dbpkg.InsertEntry(database, req.DomainETLD1, req.Username, "password", salt, blob)
	if err != nil {
		return response{OK: false, Code: "DB_ERROR", Message: "database unavailable"}
	}

	zeroize(salt)
	zeroize(blob)

	return response{OK: true, Data: map[string]any{"saved": true, "id": id}}
}

// readFrame consumes a native messaging frame from stdin.
//
// Args:
//
//	r: buffered reader connected to stdin.
//
// Returns:
//
//	[]byte: decoded JSON payload from the frame.
//	error: non-nil when reading fails or the frame exceeds maxFrameSize.
//
// Behavior:
//  1. Reads the 4-byte little-endian length prefix.
//  2. Validates the declared length and allocates a payload buffer.
//  3. Reads the full payload into memory and returns it.
func readFrame(r *bufio.Reader) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	length := binary.LittleEndian.Uint32(lenBuf)
	if length > maxFrameSize {
		return nil, fmt.Errorf("frame too large: %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func currentUserIdentifier() string {
	if usr, err := user.Current(); err == nil && usr != nil {
		if usr.Uid != "" {
			return usr.Uid
		}
		if usr.Username != "" {
			return usr.Username
		}
	}
	if val := os.Getenv("USER"); val != "" {
		return val
	}
	if val := os.Getenv("USERNAME"); val != "" {
		return val
	}
	return ""
}

// writeFrame emits a response using Chrome's native messaging framing.
//
// Args:
//
//	w: buffered writer connected to stdout.
//	resp: response object to serialize.
//
// Returns:
//
//	error: non-nil if JSON marshaling or writing fails.
//
// Behavior:
//  1. Marshals the response to JSON and prefixes it with a 4-byte length field.
//  2. Writes the length and payload sequentially to the writer.
//  3. Flushes the buffer so Chrome receives the complete frame.
func writeFrame(w *bufio.Writer, resp response) error {
	encoded, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(encoded)))
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	if _, err := w.Write(encoded); err != nil {
		return err
	}
	return w.Flush()
}

// generateToken creates a cryptographically secure session token.
//
// Args:
//
//	None.
//
// Returns:
//
//	string: base64-encoded 256-bit token.
//	error: non-nil when the random source fails.
//
// Behavior:
//  1. Allocates a 32-byte buffer.
//  2. Fills the buffer using crypto/rand.Read.
//  3. Base64-encodes the buffer for JSON-safe transport.
func generateToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil //Encode it into ascii to avoid encoding issues in json responses
}

func zeroize(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

func zeroizeString(s *string) {
	if s == nil {
		return
	}
	b := []byte(*s)
	zeroize(b)
	*s = ""
}
