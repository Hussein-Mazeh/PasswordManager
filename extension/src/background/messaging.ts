import { getToken } from "./session.js";

type NativeResponse<T> = {
  ok: boolean;
  data?: T;
  code?: string;
  message?: string;
};

const HOST_NAME = "com.crypto.passwordmanager";

export type NativePhishingVerdict = {
  ok: boolean;
  reasons: string[];
  etld1?: string | null;
};

type SendOptions = {
  transient?: boolean;
  closeAfter?: boolean;
};

let persistentPort: chrome.runtime.Port | null = null;
let connectPromise: Promise<chrome.runtime.Port> | null = null;
let lastCall: Promise<unknown> = Promise.resolve();
let persistentInFlight = false;

function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  // btoa is safe here because the string only contains bytes in [0,255]
  return btoa(binary);
}

function generateNonce(): string {
  const buf = new Uint8Array(16);
  crypto.getRandomValues(buf);
  return encodeBase64(buf);
}

function requireSessionToken(): string {
  const token = getToken();
  if (!token) {
    const err = new Error("Session locked");
    (err as any).code = "LOCKED";
    throw err;
  }
  return token;
}

function createNativeError(): Error {
  return chrome.runtime.lastError
    ? new Error(`${chrome.runtime.lastError.message} (host: ${HOST_NAME})`)
    : new Error(`Native host disconnected (host: ${HOST_NAME})`);
}

async function ensurePersistentPort(): Promise<chrome.runtime.Port> {
  if (persistentPort) {
    return persistentPort;
  }
  if (connectPromise) {
    return connectPromise;
  }
  connectPromise = new Promise<chrome.runtime.Port>((resolve, reject) => {
    try {
      console.debug("PassMan native connect → establishing persistent host", HOST_NAME);
      const port = chrome.runtime.connectNative(HOST_NAME);
      const handleDisconnect = () => {
        if (persistentPort === port) {
          persistentPort = null;
        }
        port.onDisconnect.removeListener(handleDisconnect);
      };
      port.onDisconnect.addListener(handleDisconnect);
      persistentPort = port;
      connectPromise = null;
      resolve(port);
    } catch (err) {
      connectPromise = null;
      reject(err);
    }
  });
  return connectPromise;
}

function disconnectPersistentPort(): void {
  if (!persistentPort) {
    return;
  }
  try {
    persistentPort.disconnect();
  } catch {
    /* ignore */
  } finally {
    persistentPort = null;
    lastCall = Promise.resolve();
  }
}

export function resetNativeConnection(): void {
  disconnectPersistentPort();
}

function sendTransientNative<T>(payload: Record<string, unknown>): Promise<NativeResponse<T>> {
  return new Promise((resolve, reject) => {
    let settled = false;

    try {
      console.debug("PassMan native connect → transient request", HOST_NAME, payload.type);
      const port = chrome.runtime.connectNative(HOST_NAME);

      const cleanup = () => {
        port.onMessage.removeListener(handleMessage);
        port.onDisconnect.removeListener(handleDisconnect);
      };

      const handleMessage = (response: unknown) => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        resolve((response ?? {}) as NativeResponse<T>);
        port.disconnect();
      };

      const handleDisconnect = () => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        reject(createNativeError());
      };

      port.onMessage.addListener(handleMessage);
      port.onDisconnect.addListener(handleDisconnect);
      port.postMessage(payload);
    } catch (err) {
      reject(err);
    }
  });
}

async function sendPersistentNative<T>(
  payload: Record<string, unknown>,
  closeAfter: boolean
): Promise<NativeResponse<T>> {
  const port = await ensurePersistentPort();
  if (persistentInFlight) {
    return Promise.reject(new Error("native request already in flight"));
  }
  persistentInFlight = true;
  return new Promise((resolve, reject) => {
    let settled = false;

    const finalize = (disconnect: boolean) => {
      port.onMessage.removeListener(handleMessage);
      port.onDisconnect.removeListener(handleDisconnect);
      persistentInFlight = false;
      if (disconnect) {
        if (persistentPort === port) {
          persistentPort = null;
        }
        try {
          port.disconnect();
        } catch {
          /* ignore */
        }
      }
    };

    const handleMessage = (response: unknown) => {
      if (settled) {
        return;
      }
      settled = true;
      finalize(closeAfter);
      resolve((response ?? {}) as NativeResponse<T>);
    };

    const handleDisconnect = () => {
      if (settled) {
        if (persistentPort === port) {
          persistentPort = null;
        }
        persistentInFlight = false;
        return;
      }
      settled = true;
      finalize(false);
      if (persistentPort === port) {
        persistentPort = null;
      }
      reject(createNativeError());
    };

    try {
      port.onMessage.addListener(handleMessage);
      port.onDisconnect.addListener(handleDisconnect);
      port.postMessage(payload);
    } catch (err) {
      settled = true;
      finalize(false);
      if (persistentPort === port) {
        persistentPort = null;
      }
      try {
        port.disconnect();
      } catch {
        /* ignore */
      }
      lastCall = Promise.resolve();
      reject(err);
    }
  });
}

function sendNative<T>(payload: Record<string, unknown>, options: SendOptions = {}): Promise<NativeResponse<T>> {
  if (options.transient) {
    return sendTransientNative<T>(payload);
  }

  const run = () => sendPersistentNative<T>(payload, !!options.closeAfter);
  const runWithRetry = async () => {
    let retried = false;
    while (true) {
      try {
        return await run();
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        const recoverable =
          msg.includes("disconnected port") ||
          msg.includes("Native host disconnected") ||
          msg.includes("No such native application") ||
          msg.includes("chrome.runtime.lastError");
        if (!recoverable || retried) {
          throw err;
        }
        retried = true;
      }
    }
  };

  const next = lastCall
    .catch(() => undefined)
    .then(runWithRetry);
  lastCall = next.catch(() => undefined);
  return next;
}

function assertOk<T>(response: NativeResponse<T>): T {
  if (!response || !response.ok) {
    const code = response?.code || "NATIVE_ERROR";
    const message = response?.message || "Native host rejected request";
    throw Object.assign(new Error(message), { code });
  }
  return (response.data ?? {}) as T;
}

export async function nmUnlock(dir: string, masterPassword?: string): Promise<{ token: string; ttlSeconds: number }> {
  const payload: Record<string, unknown> = { type: "unlock", dir };
  if (masterPassword) {
    payload.masterPassword = masterPassword;
  }
  const response = await sendNative<{ token: string; ttlSeconds: number }>(payload);
  return assertOk(response);
}

export async function nmLock(): Promise<void> {
  const token = getToken();
  if (!token) {
    return;
  }
  try {
    // Keep the persistent native port alive; the host clears its session on lock.
    const response = await sendNative<unknown>({
      type: "lock",
      sessionToken: token,
      nonce: generateNonce(),
    });
    assertOk(response);
  } catch (err) {
    disconnectPersistentPort();
    throw err;
  }
}

export async function nmPhishingCheck(
  url: string,
  savedEtld1?: string | null,
  exactHost?: string
): Promise<NativePhishingVerdict> {
  const payload: Record<string, unknown> = { type: "phishingCheck", url };
  if (savedEtld1) {
    payload.savedEtld1 = savedEtld1;
  }
  if (exactHost) {
    payload.exactHost = exactHost;
  }
  const response = await sendNative<NativePhishingVerdict>(payload, { transient: true });
  return assertOk(response);
}

export async function nmGet(
  domainEtld1: string,
  exactHost: string,
  username?: string,
  requireExactHost?: boolean
): Promise<{ items: { username: string; password: string }[] }> {
  const token = requireSessionToken();
  const payload: Record<string, unknown> = {
    type: "getCredentials",
    sessionToken: token,
    nonce: generateNonce(),
    domainEtld1,
    exactHost,
    requireExactHost: !!requireExactHost,
  };
  if (username) {
    payload.username = username;
  }
  const response = await sendNative<{ items: { username: string; password: string }[] }>(payload);
  return assertOk(response);
}

export async function nmSave(
  domainEtld1: string,
  exactHost: string,
  username: string,
  password: string,
  requireExactHost?: boolean
): Promise<{ saved: boolean; id?: number }> {
  const token = requireSessionToken();
  const payload: Record<string, unknown> = {
    type: "saveCredential",
    sessionToken: token,
    nonce: generateNonce(),
    domainEtld1,
    exactHost,
    username,
    password,
    requireExactHost: !!requireExactHost,
  };
  const response = await sendNative<{ saved: boolean; id?: number }>(payload);
  return assertOk(response);
}

export async function nmHealth(): Promise<{ version?: string }> {
  const response = await sendNative<{ version?: string }>({ type: "health" }, { transient: true });
  return assertOk(response);
}
