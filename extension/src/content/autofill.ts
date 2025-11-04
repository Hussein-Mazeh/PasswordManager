let bannerHostEl: HTMLElement | null = null;
let bannerShadowRoot: ShadowRoot | null = null;

function showWarningBanner(reasons: string[]): void {
  if (!document || !document.body) {
    return;
  }

  removeBanner();

  bannerHostEl = document.createElement("div");
  bannerHostEl.style.position = "fixed";
  bannerHostEl.style.top = "0";
  bannerHostEl.style.left = "0";
  bannerHostEl.style.right = "0";
  bannerHostEl.style.zIndex = "2147483647";
  bannerHostEl.style.pointerEvents = "none";

  bannerShadowRoot = bannerHostEl.attachShadow({ mode: "open" });

  const style = document.createElement("style");
  style.textContent = `
    .banner {
      box-sizing: border-box;
      width: 100%;
      padding: 10px 16px;
      background: #d93025;
      color: #fff;
      font: 13px/1.4 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      pointer-events: auto;
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.25);
    }
    .message {
      margin: 0;
      flex: 1;
    }
    button {
      border: none;
      background: rgba(255, 255, 255, 0.2);
      color: #fff;
      border-radius: 3px;
      padding: 4px 8px;
      font: inherit;
      cursor: pointer;
    }
    button:hover {
      background: rgba(255, 255, 255, 0.35);
    }
  `;

  const container = document.createElement("div");
  container.className = "banner";

  const message = document.createElement("p");
  message.className = "message";
  const reasonText = Array.isArray(reasons) && reasons.length > 0 ? reasons.join(", ") : "unknown";
  message.textContent = `Autofill blocked for your safety: ${reasonText}. Open the PassMan popup to proceed.`;

  const closeButton = document.createElement("button");
  closeButton.type = "button";
  closeButton.textContent = "Dismiss";
  closeButton.addEventListener("click", () => {
    removeBanner();
  });

  container.appendChild(message);
  container.appendChild(closeButton);

  bannerShadowRoot.appendChild(style);
  bannerShadowRoot.appendChild(container);

  document.body.appendChild(bannerHostEl);
}

function removeBanner(): void {
  if (bannerShadowRoot) {
    while (bannerShadowRoot.firstChild) {
      bannerShadowRoot.removeChild(bannerShadowRoot.firstChild);
    }
    bannerShadowRoot = null;
  }
  if (bannerHostEl && bannerHostEl.parentElement) {
    bannerHostEl.parentElement.removeChild(bannerHostEl);
  }
  bannerHostEl = null;
}

(function runAutofill(): void {
  function locateFields(): {
    username: HTMLInputElement | null;
    password: HTMLInputElement;
  } | null {
    const password = document.querySelector<HTMLInputElement>('input[type="password"]');
    if (!password) {
      return null;
    }

    let username: HTMLInputElement | null = null;
    const form = password.form;
    if (form) {
      const candidates = Array.from(
        form.querySelectorAll<HTMLInputElement>(
          'input[type="text"], input[type="email"], input[type="username"], input[name*="user" i], input[name*="email" i]'
        )
      );
      username = candidates.find((input) => input !== password) ?? null;
    }
    if (!username) {
      const allInputs = Array.from(document.querySelectorAll<HTMLInputElement>('input'));
      for (const input of allInputs) {
        if (input === password) continue;
        if (input.type === "password") continue;
        if (input.type === "hidden") continue;
        username = input;
        break;
      }
    }

    return { username, password };
  }

  function fillFields(username?: string, password?: string): void {
    const fields = locateFields();
    if (!fields) {
      return;
    }
    if (username && fields.username) {
      fields.username.value = username;
      fields.username.dispatchEvent(new Event("input", { bubbles: true }));
    }
    if (password) {
      fields.password.value = password;
      fields.password.dispatchEvent(new Event("input", { bubbles: true }));
    }
  }

  const initialFields = locateFields();
  if (!initialFields) {
    return;
  }

  const hints: Record<string, string> = {};
  if (initialFields.username?.value) {
    hints.username = initialFields.username.value;
  }

  chrome.runtime.sendMessage(
    {
      type: "REQUEST_FILL",
      url: window.location.href,
      hints,
      usernameHint: hints.username || "",
    },
    (response) => {
      if (!response || !response.ok || !response.data) {
        return;
      }
      const data = response.data as { username?: string; password?: string };
      fillFields(data.username, data.password);
    }
  );

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg && msg.type === "PHISHING_BANNER" && Array.isArray(msg.reasons)) {
      showWarningBanner(msg.reasons as string[]);
      return false;
    }
    if (msg && msg.type === "PHISHING_CLEAR") {
      removeBanner();
      return false;
    }
    if (msg && msg.type === "SCRAPE_ACTIVE_FORM") {
      const fresh = locateFields();
      sendResponse({
        username: fresh?.username?.value || "",
        password: fresh?.password?.value || "",
      });
      return false;
    }
    return undefined;
  });
})();
