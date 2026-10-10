/* ShadowTrace service worker: backend health badge + install note. */

const BACKEND = "http://127.0.0.1:8137";

async function alive() {
  try {
    const r = await fetch(`${BACKEND}/api/health`);
    return r.ok;
  } catch {
    return false;
  }
}

async function refresh() {
  const ok = await alive();
  chrome.action.setBadgeText({ text: ok ? "" : "!" });
  if (!ok) {
    chrome.action.setBadgeBackgroundColor({ color: "#000000" });
    chrome.action.setTitle({ title: "ShadowTrace: backend unreachable (start it: python scripts/serve.py)" });
  } else {
    chrome.action.setTitle({ title: "ShadowTrace: local backend connected" });
  }
}

chrome.runtime.onInstalled.addListener(async () => {
  await chrome.storage.local.set({ method: "generalize", rung_shift: 0 });
  await refresh();
});

chrome.runtime.onStartup.addListener(refresh);
chrome.alarms?.create("st-health", { periodInMinutes: 2 });
chrome.alarms?.onAlarm.addListener(refresh);
