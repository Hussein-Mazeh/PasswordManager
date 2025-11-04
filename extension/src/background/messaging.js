import { getToken } from "./session.js";
const HOST_NAME = "com.crypto.passwordmanager";
let persistentPort = null;
let connectPromise = null;
let lastCall = Promise.resolve();
let persistentInFlight = false;
function encodeBase64(bytes) {
    let binary = "";
    bytes.forEach((b) => {
        binary += String.fromCharCode(b);
    });
    // btoa is safe here because the string only contains bytes in [0,255]
    return btoa(binary);
}
function generateNonce() {
    const buf = new Uint8Array(16);
    crypto.getRandomValues(buf);
    return encodeBase64(buf);
}
function requireSessionToken() {
    const token = getToken();
    if (!token) {
        const err = new Error("Session locked");
        err.code = "LOCKED";
        throw err;
    }
    return token;
}
function createNativeError() {
    return chrome.runtime.lastError
        ? new Error(`${chrome.runtime.lastError.message} (host: ${HOST_NAME})`)
        : new Error(`Native host disconnected (host: ${HOST_NAME})`);
}
async function ensurePersistentPort() {
    if (persistentPort) {
        return persistentPort;
    }
    if (connectPromise) {
        return connectPromise;
    }
    connectPromise = new Promise((resolve, reject) => {
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
        }
        catch (err) {
            connectPromise = null;
            reject(err);
        }
    });
    return connectPromise;
}
function disconnectPersistentPort() {
    if (!persistentPort) {
        return;
    }
    try {
        persistentPort.disconnect();
    }
    catch {
        /* ignore */
    }
    finally {
        persistentPort = null;
        lastCall = Promise.resolve();
    }
}
export function resetNativeConnection() {
    disconnectPersistentPort();
}
function sendTransientNative(payload) {
    return new Promise((resolve, reject) => {
        let settled = false;
        try {
            console.debug("PassMan native connect → transient request", HOST_NAME, payload.type);
            const port = chrome.runtime.connectNative(HOST_NAME);
            const cleanup = () => {
                port.onMessage.removeListener(handleMessage);
                port.onDisconnect.removeListener(handleDisconnect);
            };
            const handleMessage = (response) => {
                if (settled) {
                    return;
                }
                settled = true;
                cleanup();
                resolve((response ?? {}));
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
        }
        catch (err) {
            reject(err);
        }
    });
}
async function sendPersistentNative(payload, closeAfter) {
    const port = await ensurePersistentPort();
    if (persistentInFlight) {
        return Promise.reject(new Error("native request already in flight"));
    }
    persistentInFlight = true;
    return new Promise((resolve, reject) => {
        let settled = false;
        const finalize = (disconnect) => {
            port.onMessage.removeListener(handleMessage);
            port.onDisconnect.removeListener(handleDisconnect);
            persistentInFlight = false;
            if (disconnect) {
                if (persistentPort === port) {
                    persistentPort = null;
                }
                try {
                    port.disconnect();
                }
                catch {
                    /* ignore */
                }
            }
        };
        const handleMessage = (response) => {
            if (settled) {
                return;
            }
            settled = true;
            finalize(closeAfter);
            resolve((response ?? {}));
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
        }
        catch (err) {
            settled = true;
            finalize(false);
            if (persistentPort === port) {
                persistentPort = null;
            }
            try {
                port.disconnect();
            }
            catch {
                /* ignore */
            }
            lastCall = Promise.resolve();
            reject(err);
        }
    });
}
function sendNative(payload, options = {}) {
    if (options.transient) {
        return sendTransientNative(payload);
    }
    const run = () => sendPersistentNative(payload, !!options.closeAfter);
    const runWithRetry = async () => {
        let retried = false;
        while (true) {
            try {
                return await run();
            }
            catch (err) {
                const msg = err instanceof Error ? err.message : String(err);
                const recoverable = msg.includes("disconnected port") ||
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
function assertOk(response) {
    if (!response || !response.ok) {
        const code = response?.code || "NATIVE_ERROR";
        const message = response?.message || "Native host rejected request";
        throw Object.assign(new Error(message), { code });
    }
    return (response.data ?? {});
}
export async function nmUnlock(dir, masterPassword) {
    const payload = { type: "unlock", dir };
    if (masterPassword) {
        payload.masterPassword = masterPassword;
    }
    const response = await sendNative(payload);
    return assertOk(response);
}
export async function nmLock() {
    const token = getToken();
    if (!token) {
        return;
    }
    try {
        // Keep the persistent native port alive; the host clears its session on lock.
        const response = await sendNative({
            type: "lock",
            sessionToken: token,
            nonce: generateNonce(),
        });
        assertOk(response);
    }
    catch (err) {
        disconnectPersistentPort();
        throw err;
    }
}
export async function nmPhishingCheck(url, savedEtld1, exactHost) {
    const payload = { type: "phishingCheck", url };
    if (savedEtld1) {
        payload.savedEtld1 = savedEtld1;
    }
    if (exactHost) {
        payload.exactHost = exactHost;
    }
    const response = await sendNative(payload, { transient: true });
    return assertOk(response);
}
export async function nmGet(domainEtld1, exactHost, username, requireExactHost) {
    const token = requireSessionToken();
    const payload = {
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
    const response = await sendNative(payload);
    return assertOk(response);
}
export async function nmSave(domainEtld1, exactHost, username, password, requireExactHost) {
    const token = requireSessionToken();
    const payload = {
        type: "saveCredential",
        sessionToken: token,
        nonce: generateNonce(),
        domainEtld1,
        exactHost,
        username,
        password,
        requireExactHost: !!requireExactHost,
    };
    const response = await sendNative(payload);
    return assertOk(response);
}
export async function nmHealth() {
    const response = await sendNative({ type: "health" }, { transient: true });
    return assertOk(response);
}
