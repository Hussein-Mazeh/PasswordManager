package main

import (
	"net/url"
	"strings"
	"unicode"

	"github.com/Zamiell/confusables"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

type phishingCheckRequest struct {
	Type       string `json:"type"`
	URL        string `json:"url"`
	SavedETLD1 string `json:"savedEtld1"`
	ExactHost  string `json:"exactHost"`
}

type phishingVerdict struct {
	OK      bool     `json:"ok"`
	Reasons []string `json:"reasons"`
	ETLD1   string   `json:"etld1,omitempty"`
}

// handlePhishingCheck evaluates a URL for phishing indicators.
//
// Args:
//
//	req: native messaging payload containing the URL under inspection and stored site metadata.
//
// Returns:
//
//	response: JSON-serializable envelope containing the phishingVerdict.
//
// Behavior:
//  1. Delegates to evaluatePhishingCheck with the supplied parameters.
//  2. Wraps the resulting verdict in a successful response for the caller.
func handlePhishingCheck(req phishingCheckRequest) response {
	verdict := evaluatePhishingCheck(req.URL, req.SavedETLD1, req.ExactHost)
	return response{OK: true, Data: verdict}
}

// evaluatePhishingCheck inspects URL and stored metadata for XSS attacks.
//
// Args:
//
//	rawURL: full URL of the page requesting autofill.
//	savedETLD1: stored effective TLD+1 associated with the credential entry.
//	exactHost: stored host value when exact match enforcement is enabled.
//
// Returns:
//
//	phishingVerdict: outcome combining allow/deny decision, reasons, and resolved eTLD+1.
//
// Behavior:
//  1. Parses the URL, capturing eTLD+1 via IDNA and publicsuffix helpers.
//  2. Records reasons for failure (HTTP, eTLD mismatch, host mismatch, punycode, mixed scripts, confusables).
//  3. Returns a verdict where OK is true only when no reasons were recorded.
func evaluatePhishingCheck(rawURL, savedETLD1, exactHost string) phishingVerdict {
	var reasons []string

	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" {
		return phishingVerdict{
			OK:      false,
			Reasons: []string{"URL_PARSE_ERROR"},
		}
	}

	if !strings.EqualFold(parsed.Scheme, "https") {
		reasons = append(reasons, "HTTP")
	}

	host := parsed.Hostname()
	hostLower := strings.ToLower(host)

	asciiHost := hostLower
	if converted, err := idna.Lookup.ToASCII(hostLower); err == nil && converted != "" {
		asciiHost = converted
	}

	unicodeHost := hostLower
	if converted, err := idna.Lookup.ToUnicode(hostLower); err == nil && converted != "" {
		unicodeHost = converted
	}

	var etld1 string
	if asciiHost != "" {
		if value, err := publicsuffix.EffectiveTLDPlusOne(asciiHost); err == nil {
			etld1 = strings.ToLower(value)
		}
	}
	if etld1 == "" && unicodeHost != "" {
		if value, err := publicsuffix.EffectiveTLDPlusOne(unicodeHost); err == nil {
			etld1 = strings.ToLower(value)
		}
	}

	if etld1 == "" {
		reasons = append(reasons, "ETLD_INVALID")
	}

	saved := strings.ToLower(strings.TrimSpace(savedETLD1))
	if saved != "" && etld1 != "" && !strings.EqualFold(saved, etld1) {
		reasons = append(reasons, "ETLD_MISMATCH")
	}

	if exactHost = strings.TrimSpace(exactHost); exactHost != "" && hostLower != "" && !strings.EqualFold(exactHost, hostLower) {
		reasons = append(reasons, "HOST_MISMATCH")
	}

	if strings.Contains(hostLower, "xn--") {
		reasons = append(reasons, "PUNYCODE")
	}

	if hasMixedScript(unicodeHost) {
		reasons = append(reasons, "MIXED_SCRIPT")
	}

	if saved != "" && etld1 != "" && looksConfusable(saved, etld1) {
		reasons = append(reasons, "CONFUSABLE")
	}

	ok := len(reasons) == 0

	return phishingVerdict{
		OK:      ok,
		Reasons: reasons,
		ETLD1:   etld1,
	}
}

// hasMixedScript reports whether a host contains characters from multiple scripts.
//
// Args:
//
//	host: Unicode hostname to analyze.
//
// Returns:
//
//	bool: true when two or more distinct Unicode scripts are detected.
//
// Behavior:
//  1. Splits the host into labels and iterates each rune.
//  2. Detects the script category for each rune via detectScript.
//  3. Tracks unique scripts and returns true as soon as two or more are observed.
func hasMixedScript(host string) bool {
	if host == "" {
		return false
	}
	scripts := make(map[string]struct{})
	labels := strings.Split(host, ".")
	for _, label := range labels {
		for _, r := range label {
			script := detectScript(r)
			if script == "" {
				continue
			}
			scripts[script] = struct{}{}
			if len(scripts) >= 2 {
				return true
			}
		}
	}
	return false
}

// detectScript categorizes a rune by its Unicode script grouping.
//
// Args:
//
//	r: rune to classify.
//
// Returns:
//
//	string: lowercase script name (latin, cyrillic, etc.) or empty string when unrecognized.
//
// Behavior:
//  1. Checks membership against selected Unicode script tables.
//  2. Returns the first matching script identifier, or empty when none match.
func detectScript(r rune) string {
	switch {
	case unicode.In(r, unicode.Latin):
		return "latin"
	case unicode.In(r, unicode.Cyrillic):
		return "cyrillic"
	case unicode.In(r, unicode.Greek):
		return "greek"
	case unicode.In(r, unicode.Hiragana):
		return "hiragana"
	case unicode.In(r, unicode.Katakana):
		return "katakana"
	case unicode.In(r, unicode.Han):
		return "han"
	default:
		return ""
	}
}

// looksConfusable determines whether two hostnames are visually confusable.
//
// Args:
//
//	target: stored eTLD+1 reference.
//	candidate: eTLD+1 derived from the inspected URL.
//
// Returns:
//
//	bool: true when normalized strings match and at least one contains homoglyphs.
//
// Behavior:
//  1. Trims/normalizes strings and exits early for empty/identical inputs.
//  2. Compares confusables-normalized lowercased forms for equality.
//  3. Uses homoglyph detection to confirm visual ambiguity before returning true.
func looksConfusable(target, candidate string) bool {
	target = strings.TrimSpace(target)
	candidate = strings.TrimSpace(candidate)
	if target == "" || candidate == "" || target == candidate {
		return false
	}
	normalizedTarget := strings.ToLower(confusables.Normalize(target))
	normalizedCandidate := strings.ToLower(confusables.Normalize(candidate))
	if normalizedTarget != normalizedCandidate {
		return false
	}
	if confusables.ContainsHomoglyphs(target) || confusables.ContainsHomoglyphs(candidate) {
		return true
	}
	return false
}
