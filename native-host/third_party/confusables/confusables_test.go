package confusables_test

// The following website is useful for inspecting the contents of Unicode strings:
// https://apps.timwhitlock.info/unicode/inspect

// The following website is useful for creating characters with diacritics (accents):
// https://onlineunicodetools.com/add-combining-characters

import (
	"errors"
	"testing"

	"github.com/Zamiell/confusables"
)

func TestContainsHomoglyphsBasic(t *testing.T) {
	username := "Alice" // Uses all ASCII characters, like you would naively expect ("A" is 0x41)
	if confusables.ContainsHomoglyphs(username) {
		t.Error("username of \"" + username + "\" should not contain homoglyphs")
	}
}

func TestContainsHomoglyphsGreek(t *testing.T) {
	username := "Αlice" // Uses a Greek letter A (0x391)
	if !confusables.ContainsHomoglyphs(username) {
		t.Error("username of \"" + username + "\" should contain homoglyphs")
	}
}

func TestNormalizeGreek(t *testing.T) {
	username1 := "Alice" // Uses all ASCII characters, like you would naively expect ("A" is 0x41)
	username2 := "Αlice" // Uses a Greek letter A (0x391)

	if err := NormalizeTestEqual(username1, username2); err != nil {
		t.Error(err)
	}
}

func TestNormalizeDiacriticAndNoDiacritic(t *testing.T) {
	username1 := "Alice" // Uses all ASCII characters, like you would naively expect ("e" is 0x65)
	username2 := "Alicé" // Uses an e-acute (0xe9)

	// Characters with diacritics (accents) do not count as being confusing,
	// at least according to "confusables.txt".
	if err := NormalizeTestNotEqual(username1, username2); err != nil {
		t.Error(err)
	}
}

func TestNormalizeDiacritic(t *testing.T) {
	username1 := "Àlice" // Uses a normal A (0x41) with a grave (0x300)
	username2 := "Ὰlice" // Uses a Greek letter A (0x391) with a grave (0x300)

	if err := NormalizeTestEqual(username1, username2); err != nil {
		t.Error(err)
	}
}

func TestNormalizeNFD(t *testing.T) {
	username1 := "Alicé"  // Uses an e-acute (0xe9).
	username2 := "Alicé" // Uses an normal e followed by an acute accent (0x301).

	// This will fail unless the "Normalize()" function performs some kind of Unicode normalization.
	// https://blog.golang.org/normalization
	if err := NormalizeTestEqual(username1, username2); err != nil {
		t.Error(err)
	}
}

// TestNormalizeDiacriticAndNFD is a combination of TestNormalizeDiacritic and TestNormalizeNFD.
func TestNormalizeDiacriticAndNFD(t *testing.T) {
	username1 := "Alicé"  // Uses an e-acute (0xe9).
	username2 := "Alicе́" // Uses a Cyrillic small letter e (0x435) followed by an acute accent (0x301).

	if err := NormalizeTestEqual(username1, username2); err != nil {
		t.Error(err)
	}
}

/*
	Testing subroutines
*/

func NormalizeTestEqual(s1 string, s2 string) error {
	if s1 == s2 {
		return errors.New("\"" + s1 + "\" and \"" + s2 + "\" are equal before normalization")
	}

	if confusables.Normalize(s1) != confusables.Normalize(s2) {
		return errors.New("normalization did not make \"" + s1 + "\" and \"" + s2 + "\" equal")
	}

	return nil
}

func NormalizeTestNotEqual(s1 string, s2 string) error {
	if s1 == s2 {
		return errors.New("\"" + s1 + "\" and \"" + s2 + "\" are equal before normalization")
	}

	if confusables.Normalize(s1) == confusables.Normalize(s2) {
		return errors.New("normalization made \"" + s1 + "\" and \"" + s2 + "\" equal")
	}

	return nil
}
