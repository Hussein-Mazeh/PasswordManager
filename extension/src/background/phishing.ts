import { nmPhishingCheck, NativePhishingVerdict } from "./messaging.js";

type FrameContext = {
  tabId?: number;
  frameId?: number;
};

let currentFrameContext: FrameContext | null = null;

export type PhishingVerdict = {
  ok: boolean;
  reasons: string[];
  etld1?: string | null;
};

export function setFrameContext(tabId?: number, frameId?: number): void {
  if (tabId === undefined && frameId === undefined) {
    currentFrameContext = null;
    return;
  }
  currentFrameContext = { tabId, frameId };
}

export function getFrameContext(): FrameContext | null {
  if (!currentFrameContext) {
    return null;
  }
  return { ...currentFrameContext };
}

export async function isTopLevelFrame(): Promise<boolean> {
  if (!currentFrameContext) {
    return false;
  }
  const frameId = currentFrameContext.frameId ?? 0;
  return frameId === 0;
}

export async function evaluatePageForAutofill(
  url: string,
  savedEtld1?: string | null,
  exactHost?: string
): Promise<PhishingVerdict> {
  const frameReasons: string[] = [];
  if (!(await isTopLevelFrame())) {
    frameReasons.push("IFRAME");
  }

  let baseVerdict: NativePhishingVerdict;
  try {
    baseVerdict = await nmPhishingCheck(url, savedEtld1 ?? null, exactHost);
  } catch (err) {
    console.error("PassMan phishing → native check failed", {
      url,
      savedEtld1: savedEtld1 ?? null,
      exactHost: exactHost ?? null,
      error: err instanceof Error ? err.message : err,
    });
    return {
      ok: false,
      reasons: [...frameReasons, "PHISHING_CHECK_FAILED"],
      etld1: null,
    };
  }

  const reasons = baseVerdict.reasons ? [...baseVerdict.reasons] : [];
  if (frameReasons.length > 0) {
    reasons.push(...frameReasons);
  }

  const ok = (baseVerdict.ok ?? false) && frameReasons.length === 0;
  return {
    ok,
    reasons,
    etld1: baseVerdict.etld1 ?? null,
  };
}
