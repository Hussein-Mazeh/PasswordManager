(() => {
    const statusEl = document.getElementById("status");
    const unlockBtn = document.getElementById("unlock");
    const lockBtn = document.getElementById("lock");
    const saveBtn = document.getElementById("save");
    function setStatus(text) {
        if (statusEl) {
            statusEl.textContent = text;
        }
    }
    async function refreshLockState() {
        try {
            const response = await chrome.runtime.sendMessage({ type: "LOCK_STATE" });
            if (response && response.ok && response.data) {
                const locked = !!response.data.locked;
                setStatus(`Vault state: ${locked ? "locked" : "unlocked"}`);
            }
            else {
                setStatus("Vault state: unknown");
            }
        }
        catch {
            setStatus("Vault state: unknown");
        }
    }
    if (unlockBtn) {
        unlockBtn.addEventListener("click", async () => {
            let masterPassword = window.prompt("Enter master password");
            if (masterPassword === null) {
                return;
            }
            setStatus("Unlocking...");
            try {
                const res = await chrome.runtime.sendMessage({ type: "UNLOCK", masterPassword });
                if (res && res.ok) {
                    await chrome.runtime.sendMessage({ type: "CLEAR_BADGE" });
                    console.error("PassMan popup → UNLOCK lastError", chrome.runtime.lastError);
                    await refreshLockState();
                }
                else {
                    console.log("PassMan popup → UNLOCK response", res);
                    setStatus("Unlock failed");
                }
            }
            catch {
                setStatus("Unlock failed");
            }
            finally {
                masterPassword = "";
            }
        });
    }
    if (lockBtn) {
        lockBtn.addEventListener("click", async () => {
            setStatus("Locking...");
            try {
                const res = await chrome.runtime.sendMessage({ type: "LOCK" });
                if (res && res.ok) {
                    await chrome.runtime.sendMessage({ type: "CLEAR_BADGE" });
                    await refreshLockState();
                }
                else {
                    setStatus("Lock failed");
                }
            }
            catch {
                setStatus("Lock failed");
            }
        });
    }
    if (saveBtn) {
        saveBtn.addEventListener("click", async () => {
            setStatus("Saving...");
            try {
                const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
                if (!tab || tab.id === undefined || !tab.url) {
                    setStatus("No active tab");
                    return;
                }
                const res = await chrome.runtime.sendMessage({
                    type: "SAVE_CREDENTIAL",
                    tabId: tab.id,
                    url: tab.url,
                });
                console.log("PassMan popup → SAVE_CREDENTIAL response", res);
                if (chrome.runtime.lastError) {
                    console.error("PassMan popup → SAVE_CREDENTIAL lastError", chrome.runtime.lastError);
                }
                if (res && res.ok) {
                    setStatus("Saved credential");
                }
                else {
                    const code = res?.code || "Save failed";
                    setStatus(code);
                }
            }
            catch {
                setStatus("Save failed");
            }
        });
    }
    chrome.runtime.sendMessage({ type: "PING" }).then((res) => {
        if (!res || !res.ok) {
            setStatus("Native host unreachable");
        }
    });
    void refreshLockState();
})();
