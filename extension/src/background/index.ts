import { nmGet, nmHealth, nmSave } from "./messaging.js";
import * as session from "./session.js";
import * as phishing from "./phishing.js";
import { DEFAULT_VAULT_DIR } from "../config/defaults.js";

type Settings = {
  requireExactHost: boolean;
  vaultDir: string;
};

const settings: Settings = {
  requireExactHost: false,
  vaultDir: DEFAULT_VAULT_DIR,
};

type ScrapedCredential = {
  username: string;
  password: string;
  url: string;
  hostname: string;
  strategy: string;
  capturedAt: number;
};

const scrapedCredentialCache = new Map<number, ScrapedCredential>();

const SAFE_BROWSING_NOTIFICATION_ID = "passman-safe-browsing";
const SAFE_BROWSING_WARNING_TITLE = "PassMan requires Safe Browsing";

const CACHE_TTL_MS = 60 * 1000;
setInterval(() => {
  const now = Date.now();
  for (const [tabId, entry] of scrapedCredentialCache) {
    if (now - entry.capturedAt > CACHE_TTL_MS) {
      scrapedCredentialCache.delete(tabId);
    }
  }
}, 30 * 1000);

function getSafeBrowsingSetting(): chrome.types.ChromeSetting<boolean> | undefined {
  return chrome.privacy?.services?.safeBrowsingEnabled;
}

function getExtensionIcon(): string {
  try {
    return chrome.runtime.getURL("assets/icon-128.jpg");
  } catch {
    return "assets/icon-128.jpg";
  }
}

async function readSafeBrowsingEnabled(): Promise<boolean> {
  const setting = getSafeBrowsingSetting();
  if (!setting) {
    console.warn("PassMan Safe Browsing enforcement unavailable: chrome.privacy API missing");
    return true;
  }
  return new Promise((resolve) => {
    try {
      setting.get({ incognito: false }, (details: chrome.types.ChromeSettingGetResult<boolean>) => {
        if (chrome.runtime.lastError) {
          console.warn("PassMan Safe Browsing → get failed", chrome.runtime.lastError.message);
          resolve(false);
          return;
        }
        resolve(details?.value === true);
      });
    } catch (err) {
      console.error("PassMan Safe Browsing → get threw", err);
      resolve(false);
    }
  });
}

async function setSafeBrowsingEnabledTrue(): Promise<boolean> {
  const setting = getSafeBrowsingSetting();
  if (!setting) {
    return true;
  }
  return new Promise((resolve) => {
    try {
      setting.set({ value: true }, () => {
        if (chrome.runtime.lastError) {
          console.warn("PassMan Safe Browsing → set failed", chrome.runtime.lastError.message);
          resolve(false);
          return;
        }
        setting.get({ incognito: false }, (details: chrome.types.ChromeSettingGetResult<boolean>) => {
          if (chrome.runtime.lastError) {
            console.warn("PassMan Safe Browsing → verification failed", chrome.runtime.lastError.message);
            resolve(false);
            return;
          }
          resolve(details?.value === true);
        });
      });
    } catch (err) {
      console.error("PassMan Safe Browsing → set threw", err);
      resolve(false);
    }
  });
}

async function ensureSafeBrowsingEnabled(): Promise<boolean> {
  const currentlyEnabled = await readSafeBrowsingEnabled();
  if (currentlyEnabled) {
    return true;
  }
  return setSafeBrowsingEnabledTrue();
}

async function showSafeBrowsingWarning(message: string): Promise<void> {
  if (!chrome.notifications?.create) {
    console.warn("PassMan Safe Browsing →", message);
    return;
  }
  return new Promise((resolve) => {
    chrome.notifications.create(
      SAFE_BROWSING_NOTIFICATION_ID,
      {
        type: "basic",
        iconUrl: getExtensionIcon(),
        title: SAFE_BROWSING_WARNING_TITLE,
        message,
        priority: 2,
      },
      () => {
        if (chrome.runtime.lastError) {
          console.warn("PassMan Safe Browsing → notification error", chrome.runtime.lastError.message);
        }
        resolve();
      }
    );
  });
}

async function handleSafeBrowsingDisabled(): Promise<void> {
  const restored = await setSafeBrowsingEnabledTrue();
  if (restored) {
    await showSafeBrowsingWarning(
      "Chrome Safe Browsing is required for PassMan. It was turned off and has been re-enabled."
    );
  } else {
    await showSafeBrowsingWarning(
      "Chrome Safe Browsing is required for PassMan, but it could not be re-enabled automatically. Please enable it."
    );
  }
}

function initializeSafeBrowsingEnforcement(): void {
  const setting = getSafeBrowsingSetting();
  if (!setting) {
    return;
  }
  setting.onChange.addListener((details: chrome.types.ChromeSettingOnChangeDetails<boolean>) => {
    if (details.value === false) {
      void handleSafeBrowsingDisabled();
    }
  });
  void ensureSafeBrowsingEnabled().then((enabled) => {
    if (!enabled) {
      void showSafeBrowsingWarning(
        "Chrome Safe Browsing must be enabled for PassMan to operate. Please enable it in Chrome settings."
      );
    }
  });
}

initializeSafeBrowsingEnforcement();

async function loadSettings(): Promise<void> {
  const stored = await chrome.storage.sync.get({
    requireExactHost: false,
    vaultDir: DEFAULT_VAULT_DIR,
  });
  settings.requireExactHost = !!stored.requireExactHost;
  settings.vaultDir = typeof stored.vaultDir === "string" && stored.vaultDir.trim() !== ""
    ? stored.vaultDir.trim()
    : DEFAULT_VAULT_DIR;
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "sync") {
    return;
  }
  if (Object.prototype.hasOwnProperty.call(changes, "requireExactHost")) {
    settings.requireExactHost = !!changes.requireExactHost?.newValue;
  }
  if (Object.prototype.hasOwnProperty.call(changes, "vaultDir")) {
    const val = changes.vaultDir?.newValue;
    if (typeof val === "string" && val.trim() !== "") {
      settings.vaultDir = val.trim();
    }
  }
});

function setPhishingAlert(tabId: number | undefined, reasons: string[]): void {
  void chrome.action.setBadgeBackgroundColor({ color: "#d93025" });
  void chrome.action.setBadgeText({ text: "!" });
  if (tabId === undefined) {
    return;
  }
  void chrome.tabs
    .sendMessage(tabId, { type: "PHISHING_BANNER", reasons })
    .catch(() => undefined);
}

function clearPhishingAlert(tabId: number | undefined): void {
  void chrome.action.setBadgeText({ text: "" });
  if (tabId === undefined) {
    return;
  }
  void chrome.tabs
    .sendMessage(tabId, { type: "PHISHING_CLEAR" })
    .catch(() => undefined);
}

chrome.runtime.onInstalled.addListener(() => {
  void loadSettings();
  session.startIdleWatch();
  session.onSuspendLock();
  void chrome.action.setBadgeText({ text: "" });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    if (!message || typeof message.type !== "string") {
      sendResponse({ ok: false, code: "BAD_REQUEST" });
      return;
    }

    switch (message.type) {
      case "PING": {
        sendResponse({ ok: true, data: "PONG" });
        return;
      }
      case "SCRAPED_CREDENTIALS": {
        const tabId = sender?.tab?.id;
        const { username, password, url, hostname, strategy } = message ?? {};
        if (
          typeof tabId !== "number" ||
          typeof username !== "string" ||
          typeof password !== "string" ||
          username.trim() === "" ||
          password === "" ||
          typeof url !== "string" ||
          typeof hostname !== "string" ||
          typeof strategy !== "string"
        ) {
          sendResponse({ ok: false });
          return;
        }
        scrapedCredentialCache.set(tabId, {
          username,
          password,
          url,
          hostname,
          strategy,
          capturedAt: Date.now(),
        });
        sendResponse({ ok: true });
        return;
      }
      case "LOCK_STATE": {
        sendResponse({ ok: true, data: { locked: session.isLocked() } });
        return;
      }
      case "UNLOCK": {
  try {
    const dir = typeof message.dir === "string" && message.dir.trim() !== ""
      ? message.dir.trim()
      : settings.vaultDir;
    console.log("PassMan UNLOCK → start", { dir });

    const masterPassword = typeof message.masterPassword === "string"
      ? message.masterPassword
      : undefined;
    if (!masterPassword || masterPassword.trim() === "") {
      console.warn("PassMan UNLOCK → missing master password");
      sendResponse({ ok: false, code: "BAD_REQUEST" });
      return;
    }

    await session.unlock(dir, masterPassword);
    console.log("PassMan UNLOCK → success");

    clearPhishingAlert(sender?.tab?.id);
    void chrome.action.setBadgeText({ text: "" });
    if (masterPassword) {
      message.masterPassword = "";
    }
    sendResponse({ ok: true });
  } catch (err) {
    const code = (err as any)?.code || "UNLOCK_FAILED";
    console.error("PassMan UNLOCK → failed", code, err);
    sendResponse({ ok: false, code, message: (err as Error).message });
  } finally {
    if (typeof message.masterPassword === "string") message.masterPassword = "";
  }
  return;
}

      case "LOCK": {
        try {
          await session.lock();
          clearPhishingAlert(sender?.tab?.id);
          void chrome.action.setBadgeText({ text: "" });
          sendResponse({ ok: true });
        } catch (err) {
          sendResponse({ ok: false, message: (err as Error).message });
        }
        return;
      }
      case "CLEAR_BADGE": {
        const originTabId = sender?.tab?.id;
        clearPhishingAlert(originTabId);
        if (originTabId === undefined) {
          void chrome.tabs
            .query({ active: true, currentWindow: true })
            .then((tabs) => {
              const tab = tabs && tabs.length > 0 ? tabs[0] : undefined;
              if (tab && tab.id !== undefined) {
                clearPhishingAlert(tab.id);
              }
            })
            .catch(() => undefined);
        }
        sendResponse({ ok: true });
        return;
      }
      case "REQUEST_FILL": {
        const { url, usernameHint } = message;
        const tabId = sender?.tab?.id;
        if (!url || typeof url !== "string") {
          sendResponse({ ok: false, code: "BAD_REQUEST" });
          return;
        }

        try {
          session.requireUnlocked();
        } catch (err) {
          sendResponse({ ok: false, code: "LOCKED" });
          return;
        }

        try {
          phishing.setFrameContext(sender?.tab?.id, sender?.frameId);
          const pageUrl = new URL(url);
          const safeBrowsingOk = await ensureSafeBrowsingEnabled();
          if (!safeBrowsingOk) {
            await showSafeBrowsingWarning(
              "Chrome Safe Browsing must remain enabled for PassMan to autofill passwords."
            );
            sendResponse({ ok: false, code: "SAFE_BROWSING_REQUIRED" });
            return;
          }

          const verdict = await phishing.evaluatePageForAutofill(url, undefined, pageUrl.hostname);
          if (!verdict.ok) {
            console.warn("PassMan REQUEST_FILL → phishing verdict blocked", {
              tabId,
              url,
              reasons: verdict.reasons,
              etld1: verdict.etld1 ?? null,
            });
            setPhishingAlert(tabId, verdict.reasons);
            sendResponse({ ok: false, code: "PHISHING_BLOCK", data: { reasons: verdict.reasons, etld1: verdict.etld1 ?? null } });
            return;
          }
          if (!verdict.etld1) {
            sendResponse({ ok: false, code: "ETLD_INVALID" });
            return;
          }

          const data = await nmGet(verdict.etld1, pageUrl.hostname, usernameHint, settings.requireExactHost);
          if (!data.items || data.items.length === 0) {
            sendResponse({ ok: false, code: "NO_CREDENTIALS" });
            return;
          }
          clearPhishingAlert(tabId);
          session.touch();
          sendResponse({ ok: true, data: data.items[0] });
        } catch (err) {
          const code = (err as any)?.code || "NATIVE_ERROR";
          if (code === "UNAUTHORIZED" || code === "SESSION_EXPIRED" || code === "NONCE_REPLAY") {
            await session.lock();
            void chrome.action.setBadgeText({ text: "" });
            clearPhishingAlert(tabId);
          }
          sendResponse({ ok: false, code, message: (err as Error).message });
        } finally {
          phishing.setFrameContext(undefined, undefined);
        }
        return;
      }
      case "SAVE_CREDENTIAL": {
        const { tabId, url, username, password } = message;
        if (typeof tabId !== "number") {
          console.warn("PassMan SAVE_CREDENTIAL → missing tabId", message);
          sendResponse({ ok: false, code: "NO_TAB" });
          return;
        }

        try {
          session.requireUnlocked();
        } catch (err) {
          sendResponse({ ok: false, code: "LOCKED" });
          return;
        }

        let pageUrlString = typeof url === "string" && url !== "" ? url : undefined;
        if (!pageUrlString) {
          try {
            const tab = await chrome.tabs.get(tabId);
            if (tab.url) {
              pageUrlString = tab.url;
            }
          } catch {
            // ignore
          }
        }
        if (!pageUrlString) {
          console.warn("PassMan SAVE_CREDENTIAL → no URL available", { tabId });
          sendResponse({ ok: false, code: "NO_URL" });
          return;
        }

        const cached = scrapedCredentialCache.get(tabId);
        phishing.setFrameContext(tabId, 0);

        let user = typeof username === "string" ? username : "";
        let pass = typeof password === "string" ? password : "";

        if (cached && Date.now() - cached.capturedAt < 5 * 60 * 1000 && cached.url === pageUrlString) {
          if (!user) {
            user = cached.username;
          }
          if (!pass) {
            pass = cached.password;
          }
        }

        if (!user || !pass) {
          try {
            const context = phishing.getFrameContext();
            const frameId = typeof context?.frameId === "number" ? context.frameId : undefined;
            const scraped = frameId !== undefined
              ? await chrome.tabs.sendMessage(tabId, { type: "SCRAPE_ACTIVE_FORM" }, { frameId })
              : await chrome.tabs.sendMessage(tabId, { type: "SCRAPE_ACTIVE_FORM" });
            if (scraped) {
              if (!user && typeof scraped.username === "string") {
                user = scraped.username;
              }
              if (!pass && typeof scraped.password === "string") {
                pass = scraped.password;
              }
            }
          } catch {
            // ignore; content script may not respond
          }
        }

        if (!user || !pass) {
          console.warn("PassMan SAVE_CREDENTIAL → no form data", { tabId });
          sendResponse({ ok: false, code: "NO_FORM_DATA" });
          return;
        }

        try {
          const pageUrl = new URL(pageUrlString);
          const safeBrowsingOk = await ensureSafeBrowsingEnabled();
          if (!safeBrowsingOk) {
            await showSafeBrowsingWarning(
              "Chrome Safe Browsing must remain enabled for PassMan to save credentials."
            );
            sendResponse({ ok: false, code: "SAFE_BROWSING_REQUIRED" });
            return;
          }

          const verdict = await phishing.evaluatePageForAutofill(pageUrlString, undefined, pageUrl.hostname);
          if (!verdict.ok) {
            console.warn("PassMan SAVE_CREDENTIAL → phishing verdict blocked", {
              tabId,
              reasons: verdict.reasons,
              etld1: verdict.etld1 ?? null,
            });
            setPhishingAlert(tabId, verdict.reasons);
            sendResponse({ ok: false, code: "PHISHING_BLOCK", data: { reasons: verdict.reasons, etld1: verdict.etld1 ?? null } });
            return;
          }
          if (!verdict.etld1) {
            console.warn("PassMan SAVE_CREDENTIAL → missing etld1 from verdict", { tabId });
            sendResponse({ ok: false, code: "ETLD_INVALID" });
            return;
          }

          await nmSave(verdict.etld1, pageUrl.hostname, user, pass, settings.requireExactHost);
          session.touch();
          clearPhishingAlert(tabId);
          scrapedCredentialCache.delete(tabId);
          sendResponse({ ok: true });
          user = "";
          pass = "";
        } catch (err) {
          const code = (err as any)?.code || "NATIVE_ERROR";
          if (code === "UNAUTHORIZED" || code === "SESSION_EXPIRED" || code === "NONCE_REPLAY") {
            await session.lock();
            void chrome.action.setBadgeText({ text: "" });
            clearPhishingAlert(tabId);
          }
          console.error("PassMan SAVE_CREDENTIAL → error", {
            tabId,
            code,
            message: (err as Error).message,
          });
          sendResponse({ ok: false, code, message: (err as Error).message });
          user = "";
          pass = "";
        } finally {
          phishing.setFrameContext(undefined, undefined);
        }
        return;
      }
      default:
        sendResponse({ ok: false, code: "UNKNOWN_TYPE" });
        return;
    }
  })();
  return true;
});

void loadSettings();
session.startIdleWatch();
session.onSuspendLock();
void chrome.action.setBadgeText({ text: "" });

void nmHealth().catch(() => {
  // best-effort connectivity probe
});

chrome.tabs.onRemoved.addListener((tabId) => {
  scrapedCredentialCache.delete(tabId);
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    scrapedCredentialCache.delete(tabId);
  }
});
