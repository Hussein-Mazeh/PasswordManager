import { DEFAULT_VAULT_DIR } from "../config/defaults.js";

(() => {
  const form = document.getElementById("options-form") as HTMLFormElement | null;
  const hostInput = document.getElementById("host") as HTMLInputElement | null;
  const vaultDirInput = document.getElementById("vault-dir") as HTMLInputElement | null;
  const idleInput = document.getElementById("idle") as HTMLInputElement | null;
  const statusEl = document.getElementById("status") as HTMLSpanElement | null;
  const requireExactEl = document.getElementById("require-exact") as HTMLInputElement | null;

  function setStatus(text: string): void {
    if (statusEl) {
      statusEl.textContent = text;
    }
  }

  async function load(): Promise<void> {
    const {
      hostName,
      vaultDir,
      idleMinutes,
      requireExactHost,
    } = await chrome.storage.sync.get({
      hostName: "com.yourorg.passman",
      vaultDir: DEFAULT_VAULT_DIR,
      idleMinutes: 10,
      requireExactHost: false,
    });

    if (hostInput) hostInput.value = hostName;
    if (vaultDirInput) vaultDirInput.value = vaultDir;
    if (idleInput) idleInput.value = String(idleMinutes);
    if (requireExactEl) requireExactEl.checked = !!requireExactHost;
  }

  async function save(event: SubmitEvent): Promise<void> {
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
