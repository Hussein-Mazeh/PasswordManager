package toggle

import "errors"

// State captures the biometric toggle state for a vault directory.
type State struct {
	Enabled bool   `json:"enabled"`
	RPID    string `json:"rpId,omitempty"` //WebAuthn Relying party ID / WebAuthn Domain (for local use it is just the local host)
	Origin  string `json:"origin,omitempty"` //URL of a web origin (used with https://localhost)
}

// ErrUnsupported signals that biometric toggling is not available on this platform.
var ErrUnsupported = errors.New("biometric toggle not supported on this platform")
