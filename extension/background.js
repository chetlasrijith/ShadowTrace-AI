/* ShadowTrace service worker: backend health badge + install note. */

const BACKEND = "https://shadowtrace-ai-gwho.onrender.com";

const DEFAULT_BACKEND = BACKEND;

async function backendURL() {
  const d = await chrome.storage.local.get({ backend_url: DEFAULT_BACKEND });
  return String(d.backend_url || DEFAULT_BACKEND).replace(/\/+$/, "");
}

async function alive(base) {
  try {
    const r = await fetch(`${base}/api/health`);
    return r.ok;
  } catch {
    return false;
  }
}

async function refresh() {
  const base = await backendURL();
  const ok = await alive(base);
  chrome.action.setBadgeText({ text: ok ? "" : "!" });
  if (!ok) {
    chrome.action.setBadgeBackgroundColor({ color: "#000000" });
    chrome.action.setTitle({ title: `ShadowTrace: backend unreachable (${base})` });
  } else {
    chrome.action.setTitle({ title: `ShadowTrace: connected (${base})` });
  }
}

chrome.runtime.onInstalled.addListener(async () => {
  await chrome.storage.local.set({ method: "generalize", rung_shift: 0 });
  await refresh();
});

chrome.runtime.onStartup.addListener(refresh);
chrome.alarms?.create("st-health", { periodInMinutes: 2 });
chrome.alarms?.onAlarm.addListener(refresh);

/* --------- backend proxy for content scripts ----------
 * Content-script fetches to http://localhost from an https:// tab can be
 * refused as mixed content (Edge is strict here). The worker has no page
 * context, so it makes the calls and messages the result back. The page
 * never talks to the network directly. */
async function postJSON(path, body) {
  const base = await backendURL();
  const r = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const t = await r.text().catch(() => "");
    throw new Error(`backend ${r.status} ${t.slice(0, 120)}`);
  }
  return r.json();
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    if (msg?.type === "st-health") {
      try {
        const base = await backendURL();
        const r = await fetch(`${base}/api/health`);
        if (!r.ok) throw new Error(`backend ${r.status}`);
        sendResponse({ ok: true, data: await r.json(), base });
      } catch (e) {
        sendResponse({ ok: false, error: String(e?.message || e) });
      }
    } else if (msg?.type === "st-sanitize") {
      try {
        const data = await postJSON("/api/sanitize", {
          text: msg.text, method: msg.method, rung_shift: msg.rung_shift,
        });
        sendResponse({ ok: true, data });
      } catch (e) {
        sendResponse({ ok: false, error: String(e?.message || e) });
      }
    } else {
      sendResponse({ ok: false, error: "unknown message" });
    }
  })();
  return true; // async response
});
