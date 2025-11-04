package confusables

import (
	_ "embed"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode"

	"github.com/pkg/errors"
	"golang.org/x/text/unicode/norm"
)

const (
	ConfusablesFileName = "confusables.txt"
)

var (
	confusableMap map[rune]string
)

//go:embed assets/confusables.txt
var confusablesTXT string

// When this package is initialized, parse the "confusables.txt" file provided by The Unicode
// Consortium and turn it into a map. Keep it in memory for subsequent use.
func init() {
	if v, err := makeConfusableMap(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	} else {
		confusableMap = v
	}
}

func makeConfusableMap() (map[rune]string, error) {
	if strings.TrimSpace(confusablesTXT) == "" {
		return nil, errors.New("confusables asset is empty")
	}
	confusableLines := strings.Split(confusablesTXT, "\n")

	newConfusableMap := make(map[rune]string)

	for i, line := range confusableLines {
		// Ignore the first line, which should just be a comment of "# confusables.txt". This line
		// will also start with an invisible byte order mark to signify that this text file contains
		// Unicode.
		// https://en.wikipedia.org/wiki/Byte_order_mark
		lineNumber := i + 1
		if lineNumber == 1 {
			continue
		}

		// Ignore empty lines.
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Ignore comments.
		if strings.HasPrefix(line, "#") {
			continue
		}

		// The format used in the confusables file is:
		// 1D5A4 ;	0045 ;	MA	# ( 𝖤 → E ) MATHEMATICAL SANS-SERIF CAPITAL E → LATIN CAPITAL LETTER E	#
		mapping := strings.Split(line, ";")

		// Get the first character (e.g. the confusing character). This is represented as a hex
		// string (e.g. "2FA1D"). It is always one rune, so we don't have to worry about splitting
		// on spaces.
		char1String := "0x" + strings.TrimSpace(mapping[0])
		var char1Int int64
		if v, err := strconv.ParseInt(char1String, 0, 64); err != nil {
			msg := "Failed to convert \"" + char1String + "\" to an integer on line " +
				strconv.Itoa(lineNumber) + ":"
			return nil, errors.Wrap(err, msg)
		} else {
			char1Int = v
		}
		char1 := rune(char1Int)

		// We ignore confusing ASCII characters
		// For example, "confusables.txt" contains the following line:
		// 006D ;	0072 006E ;	MA	# ( m → rn ) LATIN SMALL LETTER M → LATIN SMALL LETTER R, LATIN SMALL LETTER N	#
		if char1 <= unicode.MaxASCII {
			continue
		}

		// Get the second character (e.g. the character that the confusing character looks like).
		// This is represented as one or more hex strings (e.g. "2A600", "0028 0072 006E 0029").
		char2String := strings.TrimSpace(mapping[1])
		char2StringArray := strings.Split(char2String, " ")
		char2Array := make([]rune, 0)
		for _, hexStr := range char2StringArray {
			hexStr = "0x" + hexStr
			var charInt int64
			if v, err := strconv.ParseInt(hexStr, 0, 64); err != nil {
				msg := "Failed to convert \"" + hexStr + "\" to an integer on line " +
					strconv.Itoa(lineNumber) + ":"
				return nil, errors.Wrap(err, msg)
			} else {
				charInt = v
			}
			char2Array = append(char2Array, rune(charInt))
		}
		char2 := string(char2Array)

		// See: https://staticcheck.io/docs/checks#S1036
		if _, ok := newConfusableMap[char1]; ok {
			msg := "Failed to parse \"" + ConfusablesFileName + "\". There is a duplicate rune " +
				"on line " + strconv.Itoa(lineNumber) + "."
			err := errors.New(msg)
			return nil, errors.Wrap(err, msg)
		}
		newConfusableMap[char1] = char2
	}

	return newConfusableMap, nil
}

func ContainsHomoglyphs(s string) bool {
	// See the comment in the "Normalize()" function below.
	s = norm.NFD.String(s)

	for _, r := range s {
		if _, ok := confusableMap[r]; ok {
			return true
		}
	}

	return false
}

func IndexOfFirstHomoglyph(s string) int {
	// See the comment in the "Normalize()" function below.
	s = norm.NFD.String(s)

	for i, r := range s {
		if _, ok := confusableMap[r]; ok {
			return i
		}
	}

	return -1
}

// Normalize returns a copy of a string that is:
// 1) Normalized with Normalization Form Canonical Decomposition (NFD).
// 2) Has common Unicode homoglyphs replaced with their more-standard versions.
func Normalize(s string) string {
	// First, normalize the string with NFD.
	// https://blog.golang.org/normalization
	// We need to use NFD instead of NFC because we need to separate diacritics (accents) from the
	// base character. Otherwise, we wouldn't be able to find the match in "confusables.txt". For an
	// example of this, see "TestNormalizeDiacriticAndNFD()".
	s = norm.NFD.String(s)

	// Second, replace homoglyphs (as reported by "confusables.txt")
	s2 := s // Make a copy before iterating over it
	for _, r := range s {
		if replacement, ok := confusableMap[r]; ok {
			s2 = strings.ReplaceAll(s2, string(r), replacement)
		}
	}

	return s2
}
