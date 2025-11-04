import { nmLock, nmUnlock, resetNativeConnection } from "./messaging.js";
import { DEFAULT_VAULT_DIR } from "../config/defaults.js";

let sessionToken: string | null = null;
let expiresAt: number | null = null;
let ttlSeconds = 600;
let lockTimer: ReturnType<typeof setTimeout> | null = null;
let idleWatchStarted = false;
let suspendListenerAttached = false;

function clearLockTimer(): void {
  if (lockTimer !== null) {
    clearTimeout(lockTimer);
    lockTimer = null;
  }
}

function scheduleLockCountdown(): void {
  clearLockTimer();
  if (!sessionToken || !expiresAt) {
    return;
  }
  const remaining = expiresAt - Date.now();
  if (remaining <= 0) {
    void lock();
    return;
  }
  lockTimer = setTimeout(() => {
    void lock();
  }, remaining);
}

export async function unlock(dir?: string, masterPassword?: string): Promise<void> {
  if (sessionToken) {
    try {
      await nmLock();
    } catch {
      // ignore and continue rotating token
      resetNativeConnection();
    }
  }

  sessionToken = null;
  expiresAt = null;
  clearLockTimer();

  const payloadDir = dir ?? DEFAULT_VAULT_DIR;
  const inputPassword = masterPassword ?? "";

  try {
    const { token, ttlSeconds: ttl } = await nmUnlock(payloadDir, inputPassword);
    ttlSeconds = Number.isFinite(ttl) && ttl > 0 ? ttl : 600;
    sessionToken = token;
    expiresAt = Date.now() + ttlSeconds * 1000;
    scheduleLockCountdown();
  } finally {
    if (masterPassword) {
      masterPassword = "";
    }
  }
}

export async function lock(): Promise<void> {
  const hadToken = sessionToken !== null;
  try {
    if (hadToken) {
      await nmLock();
    }
  } catch {
    // swallowing to ensure state cleared locally
  } finally {
    sessionToken = null;
    expiresAt = null;
    clearLockTimer();
  }
}

export function getToken(): string | null {
  return sessionToken;
}

export function isLocked(): boolean {
  if (!sessionToken || !expiresAt) {
    return true;
  }
  if (Date.now() >= expiresAt) {
    void lock();
    return true;
  }
  return false;
}

export function requireUnlocked(): void {
  if (isLocked()) {
    const err = new Error("vault locked");
    (err as any).code = "LOCKED";
    throw err;
  }
}

export function touch(): void {
  if (!sessionToken || ttlSeconds <= 0) {
    return;
  }
  expiresAt = Date.now() + ttlSeconds * 1000;
  scheduleLockCountdown();
}

export function startIdleWatch(): void {
  if (idleWatchStarted) {
    return;
  }
  chrome.idle.setDetectionInterval(60);
  chrome.idle.onStateChanged.addListener(async (state) => {
    if (state === "idle" || state === "locked") {
      await lock();
    }
  });
  idleWatchStarted = true;
}

export function onSuspendLock(): void {
  if (suspendListenerAttached) {
    return;
  }
  chrome.runtime.onSuspend.addListener(() => {
    void lock();
  });
  suspendListenerAttached = true;
}
