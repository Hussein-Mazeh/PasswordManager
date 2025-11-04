package auth

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	hibpRangeURL  = "https://api.pwnedpasswords.com/range/"
	hibpUserAgent = "go-passman/0.1"
)

var hibpHTTPClient = &http.Client{
	Timeout: 4 * time.Second,
}

// HIBPResult captures whether a password hash suffix was found in the HIBP dataset.
type HIBPResult struct {
	Found bool
	Count int
}

// CheckHIBP queries the HIBP range API using k-anonymity.
// It never sends the full password; only a 5-hex prefix of SHA1(pw).
// On network/HTTP errors, return a wrapped error (caller may decide to fail closed or open).
// Behavior:
//   - Computes SHA-1 of the password, upper-cases its hex, splits into:
//       - prefix = first 5 hex chars (sent to HIBP)
//       - suffix = last 35 hex chars (kept locally)
//   - Performs GET https://api.pwnedpasswords.com/range/{prefix} with a short timeout and UA.
//   - Streams the response line-by-line (“SUFFIX:COUNT”), case-insensitively matches our suffix,
//     parses COUNT, and returns Found/Count immediately on match.
//   - If no match is found, returns Found=false, Count=0 with nil error.
//   - Wraps and returns errors for request build, HTTP call, non-200 status, or scan/parse failures.
func CheckHIBP(ctx context.Context, pw string) (HIBPResult, error) {
	var result HIBPResult

	sum := sha1.Sum([]byte(pw))
	hashHex := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix := hashHex[:5]
	suffix := hashHex[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hibpRangeURL+prefix, nil)
	if err != nil {
		return result, fmt.Errorf("hibp request: %w", err)
	}
	req.Header.Set("User-Agent", hibpUserAgent)

	resp, err := hibpHTTPClient.Do(req)
	if err != nil {
		return result, fmt.Errorf("hibp query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("hibp query: unexpected status %s", resp.Status)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		partIdx := strings.IndexByte(line, ':')
		if partIdx == -1 {
			continue
		}

		lineSuffix := line[:partIdx]
		countStr := strings.TrimSpace(line[partIdx+1:])
		if !strings.EqualFold(lineSuffix, suffix) {
			continue
		}

		count, err := strconv.Atoi(countStr)
		if err != nil {
			return result, fmt.Errorf("hibp parse count: %w", err)
		}

		result.Found = true
		result.Count = count
		return result, nil
	}

	if err := scanner.Err(); err != nil {
		return result, fmt.Errorf("hibp read response: %w", err)
	}

	return result, nil
}
