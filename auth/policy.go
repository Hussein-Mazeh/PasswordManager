package auth

import (
	"errors"
	"strings"
	"unicode"
)

const specialChars = "!\"#$%&'()*+,-./:;<=>?@[\\]^_{|}~`"

// ValidateMasterPassword applies the master password policy requirements.
func ValidateMasterPassword(pw string) error {
	if len(pw) < 12 {
		return errors.New("password must be at least 12 characters long")
	}
	if !hasUpper(pw) {
		return errors.New("password must include an uppercase letter")
	}
	if !hasDigit(pw) {
		return errors.New("password must include a digit")
	}
	if !hasSpecial(pw) {
		return errors.New("password must include a special character")
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
