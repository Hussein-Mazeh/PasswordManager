//go:build !darwin

package toggle

// Enable is unavailable on non-macOS platforms.
func Enable(dir, rpID, origin string) error {
	return ErrUnsupported
}

// Disable is unavailable on non-macOS platforms.
func Disable(dir string) error {
	return ErrUnsupported
}

// Status always reports disabled when biometrics are unsupported.
func Status(dir string) (State, error) {
	return State{Enabled: false}, ErrUnsupported
}

// Authenticate is unavailable on non-macOS platforms.
func Authenticate(reason string) error {
	return ErrUnsupported
}
