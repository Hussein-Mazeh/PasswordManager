import { DEFAULT_VAULT_DIR } from "../config/defaults.js";
(() => {
    const form = document.getElementById("options-form");
    const hostInput = document.getElementById("host");
    const vaultDirInput = document.getElementById("vault-dir");
    const idleInput = document.getElementById("idle");
    const statusEl = document.getElementById("status");
    const requireExactEl = document.getElementById("require-exact");
    function setStatus(text) {
        if (statusEl) {
            statusEl.textContent = text;
        }
    }
    async function load() {
        const { hostName, vaultDir, idleMinutes, requireExactHost, } = await chrome.storage.sync.get({
            hostName: "com.yourorg.passman",
            vaultDir: DEFAULT_VAULT_DIR,
            idleMinutes: 10,
            requireExactHost: false,
        });
        if (hostInput)
            hostInput.value = hostName;
        if (vaultDirInput)
            vaultDirInput.value = vaultDir;
        if (idleInput)
            idleInput.value = String(idleMinutes);
        if (requireExactEl)
            requireExactEl.checked = !!requireExactHost;
    }
    async function save(event) {
        event.preventDefault();
        if (!hostInput || !idleInput || !vaultDirInput) {
            return;
        }
        const hostName = hostInput.value.trim() || "com.yourorg.passman";
        const vaultDir = vaultDirInput.value.trim() || DEFAULT_VAULT_DIR;
        const idleMinutes = Math.max(1, Number(idleInput.value) || 10);
        const requireExactHost = !!requireExactEl?.checked;
        await chrome.storage.sync.set({
            hostName,
            vaultDir,
            idleMinutes,
            requireExactHost,
        });
        setStatus("Saved");
        // TODO: Notify background to reload settings in Phase 4 when we add messaging channel.
    }
    if (form) {
        form.addEventListener("submit", (event) => {
            void save(event);
        });
    }
    void load();
})();
