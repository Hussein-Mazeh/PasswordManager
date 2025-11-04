import { nmPhishingCheck } from "./messaging.js";
let currentFrameContext = null;
export function setFrameContext(tabId, frameId) {
    if (tabId === undefined && frameId === undefined) {
        currentFrameContext = null;
        return;
    }
    currentFrameContext = { tabId, frameId };
}
export function getFrameContext() {
    if (!currentFrameContext) {
        return null;
    }
    return { ...currentFrameContext };
}
export async function isTopLevelFrame() {
    if (!currentFrameContext) {
        return false;
    }
    const frameId = currentFrameContext.frameId ?? 0;
    return frameId === 0;
}
export async function evaluatePageForAutofill(url, savedEtld1, exactHost) {
    const frameReasons = [];
    if (!(await isTopLevelFrame())) {
        frameReasons.push("IFRAME");
    }
    let baseVerdict;
    try {
        baseVerdict = await nmPhishingCheck(url, savedEtld1 ?? null, exactHost);
    }
    catch (err) {
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
