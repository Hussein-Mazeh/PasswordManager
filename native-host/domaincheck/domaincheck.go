package domaincheck

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// ETLDPlusOne resolves the effective top-level domain plus one label for the supplied host.
//
// Args:
//
//	host: raw host or host:port string captured from the browser.
//
// Returns:
//
//	string: eTLD+1 suitable for credential matching.
//	error: non-nil when publicsuffix cannot classify the host (e.g., IPs, invalid names).
//
// Behavior:
//  1. Normalizes the host via sanitizeHost to trim whitespace, lowercase, and drop ports.
//  2. Delegates to publicsuffix.EffectiveTLDPlusOne to compute the registrable domain.
//  3. Bubbles up any error from the publicsuffix resolver to the caller.
func ETLDPlusOne(host string) (string, error) {
	canonical := sanitizeHost(host)
	return publicsuffix.EffectiveTLDPlusOne(canonical)
}

// AllowAutofill decides whether saved credentials may be used for the given host.
//
// Args:
//
//	savedETLD1: eTLD+1 that was stored alongside the credential entry.
//	host: runtime host extracted from the active tab.
//	requireExactHost: when true, enforce full hostname equality in addition to eTLD+1.
//	exactHost: stored hostname (often the page hostname at save time) used for strict checks.
//
// Returns:
//
//	bool: true when the runtime host satisfies stored domain constraints; false otherwise.
//
// Behavior:
//  1. Computes the runtime host’s eTLD+1; failures (IPs, malformed hosts) deny autofill.
//  2. Compares eTLD+1 values case-insensitively, rejecting mismatches as potential phishing.
//  3. When requireExactHost is set, ensures both stored and runtime hosts match after sanitization.
func AllowAutofill(savedETLD1, host string, requireExactHost bool, exactHost string) bool {
	hostETLD1, err := ETLDPlusOne(host)
	if err != nil {
		return false
	}
	if !strings.EqualFold(hostETLD1, savedETLD1) {
		return false
	}
	if requireExactHost {
		if exactHost == "" {
			return false
		}
		if !strings.EqualFold(sanitizeHost(host), sanitizeHost(exactHost)) {
			return false
		}
	}
	return true
}

// sanitizeHost normalizes host strings for consistent comparisons.
//
// Args:
//
//	host: potentially mixed-case host, optionally containing whitespace, trailing dots, or ports.
//
// Returns:
//
//	string: lowercase host with surrounding whitespace removed, ports stripped, and no trailing dot.
//
// Behavior:
//  1. Trims leading/trailing whitespace and a single trailing dot commonly found in FQDNs.
//  2. Removes any :port suffix to ensure only the hostname is compared.
//  3. Lowercases the result to allow case-insensitive host matching upstream.
func sanitizeHost(host string) string {
	clean := strings.TrimSpace(host)
	clean = strings.TrimSuffix(clean, ".")
	if colon := strings.Index(clean, ":"); colon >= 0 {
		clean = clean[:colon]
	}
	return strings.ToLower(clean)
}
