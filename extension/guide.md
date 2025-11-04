# PassMan Extension – Developer Test Guide

This guide walks through setting up the browser extension TypeScript toolchain, resolving the common editor errors (`chrome` global, `tldts` module), building the Javascript artifacts, loading the unpacked extension in Chrome, wiring the native messaging host, and executing a manual test plan that covers unlock, save, autofill, and phishing defences. A short security checklist is included at the end.

---

## 1. Prerequisites

- **Node.js 18+** and **npm** (or pnpm/yarn if you prefer). Check with `node --version`.
- **Go 1.21+** (matches the native host’s `go.mod`) to build the native messaging bridge.
- **Google Chrome** (or Chromium/Edge) with developer mode enabled.
- macOS/Linux users: access to `~/Library/Application Support` (Chrome’s native messaging location). Windows users need access to the registry hive documented below.
- Optional: `python3` (or any static file server) to host throwaway login pages during manual testing.

> Tip: run `npm --version` and `go version` once to ensure your PATH resolves the toolchains before continuing.

---

## 2. One-Time TypeScript & Dependency Setup

1. Initialise a package manifest inside the `extension/` folder (run once):
   ```sh
   cd extension
   npm init -y
   ```

2. Install the dependencies and type definitions that the editors/TypeScript compiler expect:
   ```sh
   npm install tldts
   npm install --save-dev typescript @types/chrome
   ```
   - `tldts` ships its own TypeScript declarations, so no extra `@types/...` package is needed.
   - `@types/chrome` fixes the “Cannot find name 'chrome'” errors throughout the background, popup, and content scripts.

3. Generate a `tsconfig.json` (you can start from this tuned configuration):
   ```jsonc
   {
     "compilerOptions": {
       "target": "ES2021",
       "module": "ESNext",
       "moduleResolution": "Bundler",
       "lib": ["DOM", "DOM.Iterable", "ES2021"],
       "types": ["chrome"],
       "strict": true,
       "skipLibCheck": true,
       "resolveJsonModule": true,
       "esModuleInterop": true,
       "forceConsistentCasingInFileNames": true,
       "noEmitOnError": true
     },
     "include": ["src/**/*.ts"]
   }
   ```
   - `moduleResolution: "Bundler"` preserves the native ESM import paths that MV3 service workers expect (`import "./messaging.js"` at runtime).
   - `types: ["chrome"]` loads the global namespace definitions for developer tooling.
   - Feel free to add `compilerOptions.outDir` (e.g., `"outDir": "dist"`) if you prefer keeping the compiled `.js` files separate. Update the manifest paths accordingly if you do.

4. (Until the real Safe Browsing integration lands) create a stub for `src/background/reputation.ts` so the build succeeds:
   ```ts
   // extension/src/background/reputation.ts
   export async function checkSafeBrowsing(_url: string): Promise<"SAFE" | "UNSAFE"> {
     return "SAFE";
   }
   ```
   Replace this with the actual API implementation when you wire up reputation checks.

5. Add helpful npm scripts to `package.json`:
   ```jsonc
   {
     "scripts": {
       "build": "tsc",
       "check": "tsc --noEmit",
       "watch": "tsc --watch --preserveWatchOutput"
     }
   }
   ```

---

## 3. Building & Watching

- **One-off build**  
  ```sh
  npm run build
  ```  
  This emits `.js` files next to their `.ts` counterparts (or to `dist/` if you set `outDir`). Ensure that every file referenced in `manifest.json` (`src/background/index.js`, `src/content/autofill.js`, `src/popup/popup.js`, `src/options/options.js`) exists after the build.

- **Incremental rebuilds while developing**  
  ```sh
  npm run watch
  ```  
  Keep this running in a terminal; Chrome will need a manual reload (`chrome://extensions` → Reload) after each emit.

- **Type-only verification**  
  ```sh
  npm run check
  ```  
  Useful on CI or before packaging to ensure no type regressions are introduced.

If the compiler still reports `Cannot find name 'chrome'`, re-open the workspace so the editor picks up the new `node_modules/@types/chrome` declarations. Missing-module errors for `tldts` disappear after the install in step 2.

---

## 4. Native Messaging Host

The browser only talks to binaries that are registered as *native messaging hosts*. Creating one is a two-part job: build the executable and drop a manifest in Chrome’s NativeMessagingHosts directory. The steps below assume you want to keep the default host name `com.yourorg.passman`; feel free to pick another name, just update the places called out in **bold**.

1. **Pick a host name** (reverse-DNS style, e.g. `com.example.passman`).  
   - Update `extension/src/background/messaging.ts` → `HOST_NAME` if you choose something other than `com.yourorg.passman`.  
   - Update the `"name"` field in `native-host/host.chrome.json` to match. The file name you install later must also match this value.

2. **Build the Go binary**:
   ```sh
   cd native-host
   go build -o passman-host
   ```
   The compiled binary can live anywhere, but the manifest must reference its *absolute* path.

3. **Create a manifest for your host name.**  
   Start from `native-host/host.chrome.json`:
   ```jsonc
  {
    "name": "com.crypto.passwordmanager",      // host names must stay lowercase
     "description": "Password Manager Native Host",
     "path": "/ABSOLUTE/PATH/TO/passman-host",
     "type": "stdio",
     "allowed_origins": [
       "chrome-extension://<EXTENSION_ID>/"
     ]
   }
   ```
   Replace:
   - `"path"` with the full path to the `passman-host` binary you built in step 2.
   - `<EXTENSION_ID>` with the ID shown on the PassMan card in `chrome://extensions`. If the ID changes (e.g. on another machine), copy the manifest again with the new value.

4. **Install the manifest in the Native Messaging directory.**

   | Platform | Command |
   |----------|---------|
  | macOS | ```sh mkdir -p ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts cp native-host/com.crypto.passwordmanager.json ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/com.crypto.passwordmanager.json ``` |
   | Linux | ```sh mkdir -p ~/.config/google-chrome/NativeMessagingHosts cp native-host/host.chrome.json ~/.config/google-chrome/NativeMessagingHosts/com.yourorg.passman.json ``` |
   | Windows | Copy the JSON to `%LOCALAPPDATA%\Google\Chrome\User Data\NativeMessagingHosts\com.yourorg.passman.json` or create `HKEY_CURRENT_USER\Software\Google\Chrome\NativeMessagingHosts\com.yourorg.passman` with a `Default` string pointing to the JSON. |

  Replace `com.yourorg.passman`/`com.crypto.passwordmanager` in the destination path with your chosen host name if you changed it.

5. **Verify the registration** (optional but recommended):
   ```sh
   python3 - <<'PY' | ./native-host/passman-host
   import json, struct, sys
   payload = json.dumps({"type": "health"}).encode()
   sys.stdout.buffer.write(struct.pack("<I", len(payload)))
   sys.stdout.buffer.write(payload)
   PY
   ```
   You should receive `{"ok":true,"data":{"version":"0.1.0"}}`. If you get “host not found” from Chrome, re-check the manifest path and extension ID.

6. **Restart Chrome** (or close all Chrome processes) so it re-reads the manifest directory, then reload the extension.

Once the manifest and binary are in place, the background worker in `index.ts` can call into the Go host (`unlock`, `lock`, `getCredentials`, `saveCredential`) transparently.

> **Important:** `com.crypto.passwordmanager.json` must be edited before copying so its `"path"` field points to the absolute location of your `passman-host` binary on *this* machine, and `"allowed_origins"` lists the extension ID assigned on this Chrome profile.

Ensure the vault the host points at (`vault-dev` by default) exists and contains the expected `header.json`/`vault.db`. You can inspect entries with the CLI in `pm/` or the helper in `test/view_passwords.go`. Refer to `native-host/README.md` for Firefox-specific instructions and deeper operational notes.

---

## 5. Loading The Extension In Chrome (Developer Mode)

1. Run a build (`npm run build`) so Chrome can find the compiled JavaScript files.
2. Open `chrome://extensions/`, toggle **Developer mode**, and click **Load unpacked**.
3. Select the repository’s `extension/` directory.
4. Chrome will assign an extension ID—copy it into `native-host/host.chrome.json`.
5. On code changes, rebuild (or let the watch task emit) and press **Reload** on the extension card. Keep the DevTools console for background and content scripts open to catch runtime logs/errors.

---

## 6. Manual Test Plan

| Area | Goal | Steps |
|------|------|-------|
| **Native host reachability** | Background detects host and handles errors | Open the popup, click **Unlock**, and observe that the status changes to “Unlocking…” then “Vault state: unlocked”. If you see “Native host unreachable”, revisit the manifest path/ID. |
| **Session lifecycle** | Idle/TTL lock works | Unlock, wait for >10 minutes or set `chrome.idle.setDetectionInterval` to a low value in DevTools, confirm the popup reports “Vault state: locked” without manual input. |
| **Credential save** | `SAVE_CREDENTIAL` pipeline stores data | 1. Serve a local login form (e.g. `python3 -m http.server` in a folder that contains `login.html`).<br>2. Unlock via popup.<br>3. Fill the form with new credentials.<br>4. With the tab focused, click **Save** in the popup.<br>5. Confirm success in popup status and check the vault (`pm pass list` or `go run test/view_passwords.go`). |
| **Autofill happy path** | Matching HTTPS domain auto-fills | 1. Visit the same domain with the saved credentials.<br>2. Ensure the page is served over `https://` (self-signed dev certs work).<br>3. Reload; when the content script runs you should see the username/password fields populate after the background `REQUEST_FILL` call completes. |
| **Phishing defences** | Blocks suspicious contexts | Repeat the autofill test on: (a) `http://` URL, (b) iframe-embedded login form, (c) domain with Punycode/mixed scripts (e.g. `https://www.xn--pple-43d.com`). The popup badge should show `!`, the banner should appear, and the popup status should surface `PHISHING_BLOCK`. |
| **Badge clearing** | Banner resets on safe pages | After a block, navigate back to a safe page and click the popup. The badge should clear and the banner disappear (covered by `CLEAR_BADGE`). |
| **Lock / unlock** | Manual controls work | Use **Lock** in the popup; background should send `nmLock()` and zero the session token. Autocomplete should fail with `LOCKED` until you unlock again. |
| **Error handling** | Graceful failures | Temporarily stop the native host, attempt a save/fill, confirm `NATIVE_ERROR` surfaces and the popup doesn’t crash. Resume the host and ensure the extension recovers. |

> For quick test pages, create `login.html` with a vanilla `<form>` plus username/password inputs. Chromium allows loading `file://` pages for this purpose, but serving via `https://localhost` better mirrors production and exercises the HTTPS requirement.

---

## 7. Security Review Checklist

- **Transport:** Confirm credentials are only exchanged over `chrome.runtime.connectNative` and verify the host refuses HTTP or mismatched eTLD+1 domains (check both extension logs and host logs).
- **Storage:** Inspect `chrome.storage.sync`—only non-secret configuration should appear. Secrets should remain confined to the native host’s RAM.
- **Content security policy:** All extension HTML already ships with strict CSP. After builds, ensure no inline scripts were accidentally emitted.
- **Phishing heuristics:** Check that Punycode (`xn--`), mixed-script domains, and homograph lookalikes raise `CONFUSABLE` or `MIXED_SCRIPT` reasons before autofill/save proceeds.
- **Idle & suspension hooks:** Validate that locking triggers on browser idle/lock and `onSuspend` (background service worker). Simulate by closing the extension DevTools and waiting for the worker to suspend.
- **Native host hardening:** Ensure the host binary permissions are limited, the path in `host.chrome.json` is absolute, and the manifest lists only the PassMan extension ID under `allowed_origins`.
- **Dependencies:** Run `npm audit --production` and `go list -m -u all` periodically to monitor for library CVEs. Because the extension stays offline, keep the dependency surface minimal.

---

## 8. Troubleshooting

- **`Cannot find name 'chrome'`:** Install `@types/chrome`, restart the TS language server, and ensure `types: ["chrome"]` is present in `tsconfig.json`.
- **`Cannot find module 'tldts'`:** Run `npm install tldts` from the `extension/` folder. For older editors you may need to reload the workspace.
- **`Cannot find module './reputation'`:** Add the stub in §2 step 4 until the Safe Browsing integration is implemented.
- **No `.js` output:** Double-check `npm run build` logs; compilation stops if there’s a type error due to `noEmitOnError`.
- **Chrome loads stale code:** The extension doesn’t auto-reload. Always click **Reload** in `chrome://extensions` after the watcher emits or use the “auto-reload” devtools extension if you prefer.

---

With the environment set up and the above test plan, you can iterate quickly on autofill, phishing detection, and the native host handshake while keeping a security-first posture. Keep the DevTools consoles open (background service worker, popup, content script) to spot runtime violations early, and expand the checklist as new features land.
