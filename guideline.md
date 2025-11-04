# PassMan Developer Guideline

This walkthrough assumes a fresh clone of the repository at `~/PasswordManager`. Adapt the paths if you keep the project elsewhere.

## 1. Prerequisites
- Go 1.22+ (the module targets 1.25; Go 1.22 or newer works today).
- Node.js 18+ with npm (for the browser extension build).
- Google Chrome (or Chromium/Edge) with Developer Mode enabled for unpacked extensions.
- macOS or Linux shell tools (`bash`, `printf`, `mkdir`, etc.).

## 2. Clone and Module Downloads
```bash
git clone https://github.com/Hussein-Mazeh/PasswordManager.git
cd PasswordManager
go mod download          # grabs top-level Go deps
cd native-host
go mod download          # grabs native-host specific deps (confusables, etc.)
cd ..
```

## 3. Vault Directory Layout
- The default vault directory is the project-relative folder `vault/`.  
- The native host expects a SQLite database named `vault.db` inside that folder (`vault/vault.db`).  
- If you need seed data, copy one of the files from `vault-dev/` into `vault/` and rename it to `vault.db`, or run the CLI to initialise a new vault.

## 4. Build the Go Binaries
```bash
# Native messaging host (invoked by the browser)
go build -o native-host/passman-host ./native-host

# Optional: CLI / GUI helpers
go build -o bin/pm ./cmd/pm
go build -o bin/passman-gui ./cmd/gui

# Optional: run the Go test suite
go test ./...
```

Keep the `native-host/passman-host` path handy; the Chrome manifest must point to this absolute location.

## 5. Browser Extension Setup
```bash
cd extension
npm install      # installs TypeScript + runtime deps
npm run build    # emits .js files next to the TypeScript sources
cd ..
```

Load the extension in Chrome:
1. Visit `chrome://extensions`, enable **Developer mode**.
2. Click **Load unpacked** and select the `extension/` directory (not `src/`).
3. Note the generated extension ID; you will need it for the native host manifest.

## 6. Native Messaging Host Registration (Chrome on macOS/Linux)
1. Copy `native-host/com.crypto.passwordmanager.json` to your browser’s Native Messaging directory:
   - **macOS:** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.crypto.passwordmanager.json`
   - **Linux:** `~/.config/google-chrome/NativeMessagingHosts/com.crypto.passwordmanager.json`
   (Create the directory if it does not exist.)
2. Edit the copied manifest:
   - Update `path` to the absolute path of the compiled `passman-host` binary (e.g. `/Users/you/PasswordManager/native-host/passman-host`).
   - Replace the `allowed_origins` entry with your extension ID, e.g. `"chrome-extension://<your-extension-id>/"`.
3. Repeat the same steps for other Chromium profiles (e.g. Brave) if needed. For Firefox, place the manifest in `~/Library/Application Support/Mozilla/NativeMessagingHosts/` (macOS) or `~/.mozilla/native-messaging-hosts/` (Linux) and adjust `allowed_extensions`.

## 7. Extension Configuration
- Open the extension’s Options page and confirm the **Vault directory** field shows `vault`. If you relocate the vault, update the absolute path here so the host can find `vault.db`.
- The background service unlocks the vault when you submit your master password; it auto-locks on idle, browser suspend, or TTL expiry.

## 8. Smoke Tests
```bash
# Check host health
printf '\x07\x00\x00\x00{"type":"health"}' | native-host/passman-host | hexdump -C

# Unlock against the default vault (replace password as needed)
printf '\x1f\x00\x00\x00{"type":"unlock","dir":"vault","masterPassword":"example"}' | native-host/passman-host
```

- From the extension popup, click **Unlock**, supply the master password for `vault/vault.db`, and visit a test site to confirm autofill.
- Watch Chrome’s background console (`chrome://extensions` → **Service Worker**) for logs if something fails; the native host logs to stderr (check `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/NativeMessagingHosts.log` on macOS).

## 9. Recap & Housekeeping
- `native-host/vendor/` and other generated artifacts stay out of git thanks to the updated `.gitignore`.
- Re-run `npm run build` after modifying any `.ts` files so the checked-in `.js` stays in sync.
- When upgrading Go or npm dependencies, run the commands in sections 2 and 5 to refresh module caches.
- Commit only source changes; binaries (`passman-host`, `bin/pm`, etc.) should remain untracked.
