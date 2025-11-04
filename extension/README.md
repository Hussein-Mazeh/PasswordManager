# PassMan Browser Extension – Phase 1

PassMan is a Manifest V3 browser extension that talks to a native Go helper via Chrome/Firefox Native Messaging. This MVP keeps the surface minimal and prepares for deeper integration with the existing Go CLI.

## Architecture

- **Background service worker** (`src/background/index.ts`) holds ephemeral session state, proxies Native Messaging calls, and coordinates auto-lock policies.
- **Native Messaging bridge** (`src/background/messaging.ts`) opens a host connection per request. Phase 2 will reuse a long-lived port.
- **Session management** (`src/background/session.ts`) keeps the unlock token in memory only, with idle auto-lock.
- **Phishing heuristics** (`src/background/phishing.ts`) currently implements a lightweight eTLD+1 comparison. TODO: replace with a PSL-backed parser.
- **Content script** (`src/content/autofill.ts`) requests credentials when it detects password fields. Filling is stubbed until Phase 2 wiring.
- **Popup UI** (`src/popup`) shows lock state and provides manual lock/unlock controls.
- **Options page** (`src/options`) stores configuration in `chrome.storage.sync` for future use.

All HTML documents ship with strict Content Security Policy meta tags:

```
default-src 'none';
script-src 'self';
style-src 'self';
img-src 'self';
connect-src 'none';
object-src 'none';
```

No inline scripts or remote assets are used.

## Phase 1 Limitations

- Native host commands are stubbed to `health`, `unlock`, and `lock` only.
- Background returns placeholder data for autofill requests.
- Phishing protection is a simple domain match.
- Host permissions cover all URLs; we will scope them as site support lands.

## Building / Running

1. Install TypeScript dependencies (e.g. `npm install --save-dev typescript`) and runtime libraries (`npm install tldts`).
2. Compile the extension scripts (example: `npx tsc --project tsconfig.json`). Ensure `.js` files land next to the `.ts` sources as referenced in the manifest.
3. Load the `extension/` directory as an unpacked extension in Chrome (Developer Mode) or Firefox (about:debugging).
4. Register the Native Messaging host using the manifests in `../native-host/`.

See `../native-host/README.md` for host installation details.

## Anti-Phishing Core

Phase 2 introduces layered gates before any autofill:

- **PSL / eTLD+1 enforcement:** `tldts` (ICANN build) mirrors the Mozilla Public Suffix List to ensure we only match registrable domains. References: [publicsuffix.org](https://publicsuffix.org), [`tldts`](https://github.com/remusao/tldts).
- **IDN + homograph heuristics:** Inspired by Unicode Technical Standard #39 and Unicode Technical Report #36. Punycode hostnames, mixed-script labels, or obvious confusables (e.g., `rn` vs `m`, `0` vs `o`) are blocked from silent autofill.
- **Optional reputation checks:** When enabled, the background worker queries Google Safe Browsing v4 for malware or social-engineering hits. The feature is opt-in to respect privacy/quotas and uses the Lookup API as documented by Google.

These checks run before any credential request reaches the native host, and the host reiterates the eTLD+1 validation to defend-in-depth.

## Phase 3 Wiring & Security

- The native host now unwraps the vault MEK on unlock, keeps it in RAM only, and wipes it on lock or expiry. Session tokens expire after 10 minutes and are validated for every request.
- Autofill/fill/save operations flow through Native Messaging (`getCredentials`, `saveCredential`) so the background service never stores secrets persistently; tokens remain in memory within the service worker.
- The host re-verifies eTLD+1 for every operation and refuses mismatches before touching the vault. Plaintext passwords are decrypted on demand, refreshed with new salts, and zeroized where feasible.
- The content script captures form data only when asked, never persists it, and the background forwards passwords directly to the host without writing them to storage.

Manual tests:

1. Unlock from popup; wait beyond TTL to ensure auto-lock fires.
2. Save credentials on a test page and confirm the entry via CLI (`pm pass get`).
3. Autofill on a matching HTTPS domain populates fields without submitting.
4. HTTP, iframe, punycode, or mismatched eTLD pages are blocked with `PHISHING_BLOCK`.
5. Safe Browsing enabled + flagged URL returns `REPUTATION_BLOCK`.
6. Expired or invalid session token returns `UNAUTHORIZED` and forces a relock.

## Phase 4 Hardening

- No analytics or telemetry are collected. The only optional outbound call remains Google Safe Browsing, which is disabled by default and governed by user settings.
- Auto-lock triggers include browser idle (idle/locked states), service-worker suspension (`onSuspend`), and TTL expiry managed entirely in memory.
- Unlock always rotates the native host token; only a single active session is allowed per browser profile.
- A red badge (`!`) signals that autofill was blocked; a page banner explains phishing reasons until cleared.
- Permissions are restricted to HTTPS pages, and all extension pages obey a strict Content Security Policy without inline scripts or remote code.
