package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/nbutton23/zxcvbn-go"
)

const specialChars = "!\"#$%&'()*+,-./:;<=>?@[\\]^_{|}~`"

var hibpLookupFn = CheckHIBP

// ValidateOptions configures password policy requirements.
type ValidateOptions struct {
	EnableHIBP     bool
	MinZXCVBNScore int
	MinLength      int
	RequireLUDS    bool
}

// DefaultValidateOptions returns the standard validation policy.
func DefaultValidateOptions() ValidateOptions {
	return ValidateOptions{
		EnableHIBP:     true,
		MinZXCVBNScore: 3,
		MinLength:      12,
		RequireLUDS:    true, //LowerCase, UpperCase, Digit, Special
	}
}

// ValidateMasterPassword validates a password using the default policy.
//
// Args:
//   pw: password candidate to check against the default policy.
//
// Returns:
//   error: nil when the password passes validation; descriptive error otherwise.
//
// Behavior:
//   - Uses context.Background and DefaultValidateOptions.
//   - Delegates to ValidateMasterPasswordAdvanced for the actual checks.
func ValidateMasterPassword(pw string) error {
	return ValidateMasterPasswordAdvanced(context.Background(), pw, DefaultValidateOptions())
}

// ValidateMasterPasswordAdvanced applies the supplied validation policy.
//
// Args:
//   ctx: controls cancellation, deadlines, and metadata for downstream checks such as HIBP.
//   pw: password candidate to check.
//   opts: validation policy; zero values are filled with DefaultValidateOptions.
//
// Returns:
//   error: nil when the password satisfies the policy; descriptive error otherwise.
//
// Behavior:
//   1) Normalizes opts to ensure sensible minimums.
//   2) Verifies length, optional LUDS composition, and zxcvbn score.
//   3) Optionally performs a Have I Been Pwned lookup via the provided context.
//   4) Surfaces actionable, non-leaking error messages for each failing condition.
func ValidateMasterPasswordAdvanced(ctx context.Context, pw string, opts ValidateOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}

	defaults := DefaultValidateOptions()
	opts.MinLength = defaults.MinLength
	opts.MinZXCVBNScore = defaults.MinZXCVBNScore
	if opts.MinZXCVBNScore > 4 {
		opts.MinZXCVBNScore = 4
	}

	if len(pw) < opts.MinLength {
		return errors.New("password too short")
	}
	if opts.RequireLUDS {
		if !hasUpper(pw) {
			return errors.New("password must include an uppercase letter")
		}
		if !hasDigit(pw) {
			return errors.New("password must include a digit")
		}
		if !hasSpecial(pw) {
			return errors.New("password must include a special character")
		}
	}

	strength := zxcvbn.PasswordStrength(pw, nil)
	if strength.Score < opts.MinZXCVBNScore {
		return errors.New("password too weak")
	}

	if opts.EnableHIBP {
		res, err := hibpLookupFn(ctx, pw)
		if err != nil {
			return fmt.Errorf("hibp lookup failed: %w", err)
		}
		if res.Found {
			return errors.New("password appears in known breach lists")
		}
	}

	return nil
}

func hasUpper(s string) bool {
	for _, r := range s {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

func hasDigit(s string) bool {
	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

func hasSpecial(s string) bool {
	for _, r := range s {
		if strings.ContainsRune(specialChars, r) {
			return true
		}
	}
	return false
}
