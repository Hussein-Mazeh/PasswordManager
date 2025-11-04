type Strategy =
  | "form-submit"
  | "beforeunload"
  | "button-click"
  | "manual-request"
  | "input-change"
  | "shadow-form";

type Binding = {
  username: HTMLInputElement | null;
  password: HTMLInputElement | null;
  form: HTMLFormElement | null;
  cleanup: Array<() => void>;
};

const DISQUALIFY_USER_PATTERNS = [/otp/i, /code/i, /2fa/i, /pin/i, /token/i];
const USER_CANDIDATE_SELECTORS = [
  "input[autocomplete='username']",
  "input[autocomplete='email']",
  "input[type='email']",
  "input[name*='user' i]",
  "input[name*='login' i]",
  "input[name*='email' i]",
  "input[id*='user' i]",
  "input[id*='email' i]",
];
const SUBMIT_BUTTON_SELECTORS = [
  "button[type='submit']",
  "input[type='submit']",
  "button[name*='login' i]",
  "button[id*='login' i]",
];

const SEND_DEBOUNCE_MS = 1000;

let currentBinding: Binding = { username: null, password: null, form: null, cleanup: [] };
let usernameValue = "";
let passwordValue = "";
let lastSentAt = 0;
let lastSentUrl = "";
const observedShadows = new Set<ShadowRoot>();
const SHOULD_RUN = window === window.top && location.protocol === "https:";
const DEBUG_LOGGING = true;

function debugLog(message: string, detail?: Record<string, unknown>): void {
  if (!DEBUG_LOGGING) {
    return;
  }
  if (detail) {
    console.debug("PassMan scraper → " + message, detail);
  } else {
    console.debug("PassMan scraper → " + message);
  }
}

if (!SHOULD_RUN) {
  debugLog("skipping content script execution", {
    topFrame: window === window.top,
    protocol: location.protocol,
  });
}

function isVisible(el: Element | null): boolean {
  if (!el) return false;
  if (el instanceof HTMLElement) {
    if (el.hidden) return false;
  }
  const style = window.getComputedStyle(el);
  if (style.visibility === "hidden" || style.display === "none" || style.opacity === "0") {
    return false;
  }
  if (el instanceof HTMLElement) {
    if (!el.offsetParent && style.position !== "fixed") {
      return false;
    }
  }
  return true;
}

function isLikelyPassword(input: HTMLInputElement): boolean {
  return (
    input.type === "password" &&
    !input.readOnly &&
    !input.disabled &&
    input.getAttribute("aria-hidden") !== "true" &&
    isVisible(input)
  );
}

function isLikelyUsername(input: HTMLInputElement): boolean {
  if (input.disabled || input.readOnly || !isVisible(input)) return false;
  if (input.type === "password") return false;
  const signature = `${input.name ?? ""} ${input.id ?? ""}`;
  for (const pattern of DISQUALIFY_USER_PATTERNS) {
    if (pattern.test(signature)) {
      return false;
    }
  }
  return true;
}

function scoreUsernameCandidate(input: HTMLInputElement): number {
  let score = 0;
  if (input.type === "email") score += 6;
  if (input.getAttribute("autocomplete") === "username") score += 6;
  if (input.getAttribute("autocomplete") === "email") score += 5;
  if (/user|login|email/i.test(input.name ?? "")) score += 4;
  if (/user|login|email/i.test(input.id ?? "")) score += 4;
  if (input.type === "text") score += 1;
  if (/phone|tel/i.test((input.name ?? "") + (input.id ?? ""))) score -= 2;
  return score;
}

function nearestForm(el: Element | null): HTMLFormElement | null {
  if (!el) return null;
  if (el instanceof HTMLInputElement && el.form) {
    return el.form;
  }
  let cursor: Element | null = el;
  while (cursor) {
    if (cursor instanceof HTMLFormElement) {
      return cursor;
    }
    cursor = cursor.parentElement;
  }
  return null;
}

function collectInputs(root: Document | ShadowRoot, bucket: HTMLInputElement[], seen: Set<Node>): void {
  if (seen.has(root)) return;
  seen.add(root);
  debugLog("collectInputs scanning root", {
    rootType: root instanceof Document ? "document" : "shadow",
    bucketSizeBefore: bucket.length,
  });

  const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
  let node = walker.currentNode as Element | null;
  while (node) {
    if (node instanceof HTMLInputElement) {
      bucket.push(node);
    }
    const shadow = (node as HTMLElement).shadowRoot;
    if (shadow && shadow.mode === "open" && !observedShadows.has(shadow)) {
      observedShadows.add(shadow);
      collectInputs(shadow, bucket, seen);
      observeRoot(shadow);
    }
    node = walker.nextNode() as Element | null;
  }
  debugLog("collectInputs completed root", {
    rootType: root instanceof Document ? "document" : "shadow",
    bucketSizeAfter: bucket.length,
  });
}

function findUsernameForPassword(password: HTMLInputElement, inputs: HTMLInputElement[]): HTMLInputElement | null {
  const candidates: HTMLInputElement[] = [];
  const form = nearestForm(password);
  debugLog("findUsernameForPassword start", {
    password: describeNode(password),
    totalInputs: inputs.length,
    hasForm: !!form,
  });

  const consider = (input: HTMLInputElement) => {
    if (input === password) return;
    if (!isLikelyUsername(input)) return;
    candidates.push(input);
  };

  if (form) {
    Array.from(form.elements).forEach((el) => {
    if (el instanceof HTMLInputElement) consider(el);
    });
  }

  if (candidates.length === 0) {
    const selectors = USER_CANDIDATE_SELECTORS.join(",");
    const withinForm = form ? form.querySelectorAll<HTMLInputElement>(selectors) : [];
    withinForm.forEach(consider);
  }

  if (candidates.length === 0) {
    const container = password.closest("div") ?? password.parentElement;
    if (container) {
      const textInputs = container.querySelectorAll<HTMLInputElement>("input[type='text']");
      textInputs.forEach(consider);
    }
  }

  if (candidates.length === 0) {
    inputs.forEach((input) => {
      if (input.type === "email") consider(input);
    });
  }

  if (candidates.length === 0) {
    debugLog("findUsernameForPassword no candidates found", {});
    return null;
  }

  candidates.sort((a, b) => scoreUsernameCandidate(b) - scoreUsernameCandidate(a));
  const winner = candidates[0];
  debugLog("findUsernameForPassword selected candidate", {
    username: describeNode(winner),
    score: scoreUsernameCandidate(winner),
    totalCandidates: candidates.length,
  });
  return candidates[0];
}

function readUsernameField(input: HTMLInputElement | null): string {
  if (!input) return "";
  return input.value.trim();
}

function readPasswordField(input: HTMLInputElement | null): string {
  if (!input) return "";
  return input.value;
}

function cleanupBinding(): void {
  debugLog("cleanupBinding invoked", {
    hadUsername: !!currentBinding.username,
    hadPassword: !!currentBinding.password,
  });
  currentBinding.cleanup.forEach((fn) => {
    try {
      fn();
    } catch {
      /* ignore */
    }
  });
  currentBinding = { username: null, password: null, form: null, cleanup: [] };
  usernameValue = "";
  passwordValue = "";
}

function bindInputs(username: HTMLInputElement | null, password: HTMLInputElement | null, strategy: Strategy): void {
  if (currentBinding.username === username && currentBinding.password === password) {
    debugLog("bindInputs unchanged binding", {
      username: username ? describeNode(username) : null,
      password: password ? describeNode(password) : null,
      strategy,
    });
    return;
  }

  debugLog("bindInputs establishing binding", {
    username: username ? describeNode(username) : null,
    password: password ? describeNode(password) : null,
    strategy,
  });
  cleanupBinding();

  if (!password) {
    debugLog("bindInputs aborted (no password candidate)", {});
    return;
  }

  currentBinding.username = username;
  currentBinding.password = password;
  currentBinding.form = nearestForm(password);

  usernameValue = readUsernameField(username);
  passwordValue = readPasswordField(password);

  const userListener = () => {
    usernameValue = readUsernameField(username);
  };
  const passListener = () => {
    passwordValue = readPasswordField(password);
    if (usernameValue && passwordValue) {
      sendIfReady("input-change");
    }
  };

  if (username) {
    username.addEventListener("input", userListener, { passive: true });
    username.addEventListener("change", userListener, { passive: true });
    currentBinding.cleanup.push(() => {
      username.removeEventListener("input", userListener);
      username.removeEventListener("change", userListener);
    });
  }

  password.addEventListener("input", passListener, { passive: true });
  password.addEventListener("change", passListener, { passive: true });
  currentBinding.cleanup.push(() => {
    password.removeEventListener("input", passListener);
    password.removeEventListener("change", passListener);
  });
  debugLog("bindInputs listeners attached", {
    usernameInitial: usernameValue,
    passwordLength: passwordValue.length,
    formPresent: !!currentBinding.form,
  });

  const submitHandler = () => sendIfReady("form-submit");
  const beforeUnloadHandler = () => sendIfReady("beforeunload");

  window.addEventListener("beforeunload", beforeUnloadHandler, true);
  currentBinding.cleanup.push(() => window.removeEventListener("beforeunload", beforeUnloadHandler, true));

  if (currentBinding.form) {
    currentBinding.form.addEventListener("submit", submitHandler, { capture: true });
    currentBinding.cleanup.push(() => currentBinding.form?.removeEventListener("submit", submitHandler, { capture: true } as any));

    const buttons = currentBinding.form.querySelectorAll<HTMLButtonElement | HTMLInputElement>(
      SUBMIT_BUTTON_SELECTORS.join(",")
    );
    buttons.forEach((btn) => {
      const clickHandler = () => sendIfReady("button-click");
      btn.addEventListener("click", clickHandler, { capture: true });
      currentBinding.cleanup.push(() => btn.removeEventListener("click", clickHandler, { capture: true } as any));
    });
  }
}

function sendIfReady(strategy: Strategy): void {
  const username = readUsernameField(currentBinding.username);
  const password = readPasswordField(currentBinding.password);

  if (!username || !password) {
    debugLog("sendIfReady skipped (missing fields)", {
      hasUsername: !!username,
      hasPassword: !!password,
      strategy,
    });
    return;
  }

  const now = Date.now();
  if (lastSentUrl === location.href && now - lastSentAt < SEND_DEBOUNCE_MS) {
    debugLog("sendIfReady skipped (debounced)", {
      strategy,
      lastSentUrl,
      elapsed: now - lastSentAt,
    });
    return;
  }

  lastSentUrl = location.href;
  lastSentAt = now;

  const payload = {
    type: "SCRAPED_CREDENTIALS",
    url: location.href,
    hostname: location.hostname,
    username,
    password,
    strategy,
  };
  debugLog("sendIfReady dispatching message", {
    strategy,
    usernameLength: username.length,
    passwordLength: password.length,
    url: location.href,
  });
  void chrome.runtime
    .sendMessage(payload)
    .then(() => debugLog("sendIfReady message acknowledged", {}))
    .catch((err) =>
      debugLog("sendIfReady message failed", {
        error: err instanceof Error ? err.message : String(err),
      })
    );
}

function discoverCandidates(): void {
  const inputs: HTMLInputElement[] = [];
  collectInputs(document, inputs, new Set());
  debugLog("discoverCandidates collected inputs", {
    totalInputs: inputs.length,
    url: location.href,
  });

  const passwordCandidates = inputs.filter(isLikelyPassword);
  if (passwordCandidates.length === 0) {
    debugLog("discoverCandidates no password candidates", {});
    bindInputs(null, null, "input-change");
    return;
  }

  const password = passwordCandidates[0];
  const username = findUsernameForPassword(password, inputs);
  const strategy: Strategy = observedShadows.has(password.getRootNode() as ShadowRoot) ? "shadow-form" : "input-change";
  debugLog("discoverCandidates resolved binding", {
    password: describeNode(password),
    username: username ? describeNode(username) : null,
    strategy,
  });
  bindInputs(username, password, strategy);
}

function respondToScrapeRequest(sendResponse: (response: unknown) => void): void {
  const username = readUsernameField(currentBinding.username);
  const password = readPasswordField(currentBinding.password);
  if (username && password) {
    debugLog("respondToScrapeRequest returning credentials", {
      usernameLength: username.length,
      passwordLength: password.length,
    });
    sendResponse({ ok: true, username, password });
  } else {
    debugLog("respondToScrapeRequest unable to provide credentials", {
      hasUsername: !!username,
      hasPassword: !!password,
    });
    sendResponse({ ok: false });
  }
}

function observeRoot(root: Document | ShadowRoot): void {
  debugLog("observeRoot attaching observer", {
    rootType: root instanceof Document ? "document" : "shadow",
  });
  const observer = new MutationObserver(() => {
    debugLog("observeRoot mutation triggered", {
      hasPassword: !!currentBinding.password,
      passwordConnected: currentBinding.password?.isConnected ?? false,
      hasUsername: !!currentBinding.username,
      usernameConnected: currentBinding.username?.isConnected ?? false,
    });
    const password = currentBinding.password;
    if (!password || !password.isConnected || !currentBinding.username?.isConnected) {
      discoverCandidates();
    }
  });
  observer.observe(root, { childList: true, subtree: true });
}

function resetForNavigation(): void {
  debugLog("resetForNavigation invoked", {});
  cleanupBinding();
  lastSentAt = 0;
  lastSentUrl = "";
  discoverCandidates();
}

function bootstrap(): void {
  debugLog("bootstrap starting", { url: location.href });
  observeRoot(document);
  discoverCandidates();
}

if (SHOULD_RUN) {
  if (document.readyState === "complete" || document.readyState === "interactive") {
    debugLog("document ready, running bootstrap immediately", {});
    bootstrap();
  } else {
    document.addEventListener(
      "DOMContentLoaded",
      () => {
        debugLog("DOMContentLoaded fired, running bootstrap", {});
        bootstrap();
      },
      { once: true }
    );
  }

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    debugLog("runtime message received", { type: msg?.type });
    if (msg?.type === "SCRAPE_ACTIVE_FORM") {
      respondToScrapeRequest(sendResponse);
      return true;
    }
    return false;
  });

  window.addEventListener("popstate", resetForNavigation);
  window.addEventListener("hashchange", resetForNavigation);
}

function _debugForceDiscover(): { usernameSel?: string; passwordSel?: string } {
  if (!SHOULD_RUN) {
    return {};
  }
  discoverCandidates();
  return {
    usernameSel: currentBinding.username ? describeNode(currentBinding.username) : undefined,
    passwordSel: currentBinding.password ? describeNode(currentBinding.password) : undefined,
  };
}

function _debugRead(): { username?: string; password?: string } {
  if (!SHOULD_RUN) {
    return {};
  }
  const username = readUsernameField(currentBinding.username);
  const password = readPasswordField(currentBinding.password);
  return {
    username: username || undefined,
    password: password || undefined,
  };
}

if (typeof window !== "undefined") {
  const globalWindow = window as typeof window & {
    PassManScraperDebug?: {
      forceDiscover: typeof _debugForceDiscover;
      read: typeof _debugRead;
    };
  };
  globalWindow.PassManScraperDebug = {
    forceDiscover: _debugForceDiscover,
    read: _debugRead,
  };
}

function describeNode(node: Element): string {
  const parts: string[] = [node.tagName.toLowerCase()];
  if (node.id) parts.push(`#${node.id}`);
  if (node.classList.length) parts.push(`.${Array.from(node.classList).join(".")}`);
  return parts.join("");
}
