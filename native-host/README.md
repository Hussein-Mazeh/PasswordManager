# PassMan Native Host

This Go binary implements the Native Messaging endpoint used by the PassMan browser extension. Phase 3 keeps secrets in RAM only, unwraps the vault MEK on demand, and exposes credential accessors guarded by eTLD+1 revalidation.

## Supported Commands

- `health` – returns the host version.
- `unlock` – derives the PDK from the supplied master password, unwraps the MEK, stores it in memory, and returns a session token with a 10-minute TTL.
- `lock` – zeroizes the MEK and invalidates the current session token immediately.
- `getCredentials` – validates the session token and domain, decrypts matching credentials, rotates salts, and returns the plaintext username/password pair.
- `saveCredential` – validates the session and domain, encrypts a new credential, and stores it in the SQLite vault database.

## Building

```
go build -o passman-host
```

The resulting executable path must match the `path` property in the browser-specific manifests.

## Installing The Host

### Chrome / Edge

1. Copy `host.chrome.json` to the appropriate Native Messaging directory:
   - **macOS:** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`
   - **Linux:** `~/.config/google-chrome/NativeMessagingHosts/`
   - **Windows:** `HKEY_CURRENT_USER\Software\Google\Chrome\NativeMessagingHosts`
2. Update the `path` to the absolute location of `passman-host` and set the extension ID.

### Firefox

1. Copy `host.firefox.json` to:
   - **macOS:** `~/Library/Application Support/Mozilla/NativeMessagingHosts/`
   - **Linux:** `~/.mozilla/native-messaging-hosts/`
   - **Windows:** `HKEY_CURRENT_USER\Software\Mozilla\NativeMessagingHosts`
2. Update `path` and the `allowed_extensions` entry.

Refer to the official browser documentation for system-wide install locations and policies.

## Testing

Quick health probe once the host is built:

```
printf '\x07\x00\x00\x00{"type":"health"}' | ./passman-host | hexdump -C
```

```
printf '\x1f\x00\x00\x00{"type":"unlock","dir":"vault-dev","masterPassword":"example"}' | ./passman-host
```

The unlock command returns a `token` and `ttlSeconds` when the supplied master password unwraps the MEK successfully.

## Notes

- The host re-verifies eTLD+1 (via `golang.org/x/net/publicsuffix`) before decrypting or storing credentials.
- Session tokens expire automatically; the MEK is wiped on lock or expiry.
- No secrets are logged or persisted outside the SQLite vault.
