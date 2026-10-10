/* ShadowTrace content script: intercept → sanitize → confirm → release.
 *
 * Design rules:
 * - The page never sees raw interception logic beyond a captured key/click.
 * - Kill every submit event SYNCHRONOUSLY, then investigate async. An await
 *   before preventDefault() lets the original through (then approval sends
 *   a duplicate). Approved submits return as fresh programmatic events
 *   covered by a one-shot bypass.
 * - The original text lives only in this isolated world + the localhost
 *   backend. Nothing is sent to any third party by this script.
 * - The panel renders inside Shadow DOM: page CSS cannot touch it.
 */

(() => {
  "use strict";

  const DEFAULT_BACKEND = "https://shadowtrace-ai-gwho.onrender.com";
  const HOST = location.hostname;

  /* ---------------- site adapters: allowlist, expect maintenance ------ */
  const ADAPTERS = [
    {
      host: /(^|\.)chatgpt\.com$|(^|\.)chat\.openai\.com$/,
      site: "chatgpt",
      composer: ["#prompt-textarea", "div#prompt-textarea[contenteditable='true']",
                 "form div[contenteditable='true']", "div[contenteditable='true'][id*='prompt']"],
      send: ['[data-testid="send-button"]', 'button[data-testid="send-button"]',
             'button[aria-label="Send message"]', "form button[type='submit']"],
    },
    {
      host: /(^|\.)claude\.ai$/,
      site: "claude",
      composer: ["div.ProseMirror[contenteditable='true']", "div[contenteditable='true']",
                 "form div[contenteditable='true']"],
      send: ['button[aria-label="Send message"]', 'button[aria-label^="Send"]',
             "form button[type='submit']"],
    },
    {
      host: /(^|\.)gemini\.google\.com$/,
      site: "gemini",
      composer: ["div[contenteditable='true'].ql-editor", "div[contenteditable='true']",
                 "form div[contenteditable='true']"],
      send: ['button[aria-label="Send message"]', 'button[aria-label^="Send"]',
             "form button[type='submit']"],
    },
  ];

  const adapter = ADAPTERS.find((a) => a.host.test(HOST));
  if (!adapter) return;

  // Injection marker, visible from the page's own console/Elements panel:
  // <html data-shadowtrace-injected="chatgpt">. If this attribute is absent,
  // the content script never loaded in this tab (matches/Edge issue). If it
  // is present but interception still misses, the composer selectors are
  // stale (site changed its DOM) — not an injection problem.
  try {
    document.documentElement.dataset.shadowtraceInjected = adapter.site;
    console.log(`[shadowtrace] injected on ${adapter.site} (${HOST})`);
  } catch { /* headless DOM, ignore */ }

  const $ = (sels, root = document) => {
    for (const s of sels) {
      try {
        const el = root.querySelector(s);
        if (el && el.offsetParent !== null) return el;
      } catch { /* bad selector, try next */ }
    }
    return null;
  };

  // Last-resort composer discovery: the largest visible contenteditable or
  // textarea on the page. Chat pages have exactly one real composer; a
  // wrong guess here only misfires the lookup, never sends anything.
  function findComposerFallback() {
    const cands = [
      ...document.querySelectorAll("div[contenteditable='true'], textarea"),
    ].filter((el) => el.offsetParent !== null);
    if (!cands.length) return null;
    // prefer the one closest to the viewport bottom (chat composers live there)
    cands.sort((a, b) => b.getBoundingClientRect().top - a.getBoundingClientRect().top);
    return cands[0];
  }

  function findComposer() {
    return $(adapter.composer) || findComposerFallback();
  }

  /* ---------------- composer IO -------------------------------------- */
  function getText(el) {
    if (!el) return "";
    if (el.tagName === "TEXTAREA" || el.tagName === "INPUT") return el.value;
    return el.innerText || el.textContent || "";
  }

  function setText(el, text) {
    el.focus();
    if (el.tagName === "TEXTAREA" || el.tagName === "INPUT") {
      el.value = text;
      el.dispatchEvent(new Event("input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
      return true;
    }
    // contenteditable: ONLY execCommand, never textContent assignment.
    // Setting textContent changes pixels but desyncs framework editor state
    // (ProseMirror/TipTap-style), so submit would send the STALE text.
    // execCommand generates real beforeinput/input events the editor honors.
    const sel = window.getSelection();
    try {
      sel.selectAllChildren(el);
      if (document.execCommand("insertText", false, text)) {
        sel.collapseToEnd();
        return true;
      }
      // retry after clearing: some editors reject replacement but take insert
      document.execCommand("delete", false, null);
      if (document.execCommand("insertText", false, text)) {
        sel.collapseToEnd();
        return true;
      }
    } catch { /* fall through to failure */ }
    return false;
  }

  /* ---------------- audit log (metadata only) ------------------------ */
  let backendHost = "shadowtrace-ai-gwho.onrender.com"; // updated by getSettings
  function audit(entry) {
    try {
      const rec = {
        ts: new Date().toISOString(),
        site: adapter.site,
        backend: backendHost,
        ...entry, // {action, method, entityTypes, spansFound, held}
        // never: raw text, surfaces, or substitutions
      };
      chrome.storage.local.get({ shadowtrace_audit: [] }, (d) => {
        const log = d.shadowtrace_audit;
        log.push(rec);
        chrome.storage.local.set({ shadowtrace_audit: log.slice(-500) });
      });
    } catch { /* storage is best-effort */ }
  }

  /* ---------------- backend ------------------------------------------ */
  async function getSettings() {
    const d = await chrome.storage.local.get(
      { method: "generalize", rung_shift: 0, backend_url: DEFAULT_BACKEND });
    d.backend_url = String(d.backend_url || DEFAULT_BACKEND).replace(/\/+$/, "");
    try {
      d.backend_host = new URL(d.backend_url).host;
    } catch {
      d.backend_host = d.backend_url;
    }
    backendHost = d.backend_host;
    return d;
  }

  function bgMessage(msg) {
    return new Promise((resolve, reject) => {
      try {
        chrome.runtime.sendMessage(msg, (resp) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          resolve(resp);
        });
      } catch (e) {
        reject(e);
      }
    });
  }

  async function sanitize(text, method, rung_shift) {
    const resp = await bgMessage({ type: "st-sanitize", text, method, rung_shift });
    if (!resp || !resp.ok) throw new Error((resp && resp.error) || "backend unreachable");
    return resp.data;
  }

  async function backendAlive() {
    try {
      const resp = await bgMessage({ type: "st-health" });
      return !!(resp && resp.ok);
    } catch { return false; }
  }

  /* ---------------- intercept ----------------------------------------
   * The golden rule lives here: the decision to kill an event must be
   * SYNCHRONOUS. An `await` before preventDefault() lets the event finish
   * propagating (the original submits, the panel opens anyway, and approval
   * sends a duplicate). So every handler below kills the event first and
   * asks questions afterward; approved submits go back through as fresh
   * programmatic events covered by the one-shot bypass. */
  let busy = false;
  let bypassOnce = false;

  async function handleSubmit(composer, text, anchor) {
    // event already dead on arrival; busy was set synchronously by caller.
    // `text` is the intercepted original; `anchor` is the node that held it.
    try {
      const { method, rung_shift, backend_url, backend_host } = await getSettings();
      if (!(await backendAlive())) {
        toast(`ShadowTrace backend unreachable (${backend_host}). Submit blocked — the backend may be waking up (Render sleeps when idle); wait a minute and press Enter again.`);
        audit({ action: "blocked_no_backend", method: "?", entityTypes: [], spansFound: 0 });
        return;
      }
      const res = await sanitize(text, method, rung_shift);
      const sensCount = res.spans.filter((s) => s.sensitive).length;
      if (sensCount === 0 && !res.held) {
        audit({ action: "passthrough_clean", method, entityTypes: [], spansFound: 0 });
        release(anchor || composer, text, text, method); // re-submit untouched
        return;
      }
      openPanel(anchor || composer, text, res, method, backend_url, backend_host);
      audit({
        action: "panel_shown", method,
        entityTypes: [...new Set(res.spans.filter((s) => s.sensitive).map((s) => s.etype))],
        spansFound: sensCount, held: res.held,
      });
    } catch (e) {
      toast(`ShadowTrace error: ${e.message}. Submit blocked.`);
      audit({ action: "blocked_error", method: "?", entityTypes: [], spansFound: 0 });
    } finally {
      busy = false;
    }
  }

  function hook() {
    // Enter key in the composer. e.target is ground truth: real keystrokes
    // land on the LIVE node, so it becomes the anchor for release.
    document.addEventListener("keydown", (e) => {
      if (e.key !== "Enter" || e.shiftKey || e.isComposing) return;
      const composer = findComposer();
      if (!composer || !composer.contains(e.target)) return;
      if (bypassOnce) { bypassOnce = false; return; } // approved: let it fly
      if (busy) { e.preventDefault(); e.stopPropagation(); return; } // panel open: swallow
      const text = getText(composer).trim();
      if (!text) return; // empty: let it fall through
      e.preventDefault();
      e.stopPropagation();
      busy = true;
      const anchor = (e.target instanceof Element)
        ? (e.target.closest("div[contenteditable='true'],textarea,input") || null)
        : null;
      void handleSubmit(composer, text, anchor || composer);
    }, true);

    // send-button clicks (same synchronous-kill rule as Enter above)
    document.addEventListener("click", (e) => {
      if (bypassOnce) {
        // approved re-submit clicks the real button: let this one fly.
        // (Checked before the target test so a re-rendered button still passes.)
        bypassOnce = false;
        return;
      }
      const btn = $(adapter.send);
      if (!btn || !(e.target instanceof Element)) return;
      if (!btn.contains(e.target) && e.target !== btn) return;
      if (busy) { e.preventDefault(); e.stopPropagation(); return; }
      const composer = findComposer();
      const text = composer ? getText(composer).trim() : "";
      if (!composer || !text) return;
      e.preventDefault();
      e.stopPropagation();
      busy = true;
      void handleSubmit(composer, text, composer);
    }, true);
  }

  function describe(el) {
    if (!el) return "null";
    return `<${el.tagName || "?"} id="${el.id || ""}" class="${(el.className || "").toString().slice(0, 40)}" connected=${el.isConnected}>`;
  }

  const normWs = (s) => s.replace(/\s+/g, " ").trim();
  const headMatch = (a, b) => {
    // tolerant prefix overlap: editors normalize whitespace and entities
    const x = normWs(a).slice(0, 60), y = normWs(b).slice(0, 60);
    return !!x && !!y && (x.startsWith(y.slice(0, 20)) || y.startsWith(x.slice(0, 20)));
  };

  function candidateComposers(anchorEl) {
    // EVERY plausible composer node, because ChatGPT keeps decoys: the node
    // we write must be the node the app submits, and DOM order lies.
    const out = [], seen = new Set();
    const push = (el) => {
      if (el && el.isConnected && !seen.has(el)) { seen.add(el); out.push(el); }
    };
    push(anchorEl);
    for (const a of ADAPTERS) {
      for (const s of a.composer) {
        try { document.querySelectorAll(s).forEach(push); } catch { /* bad selector */ }
      }
    }
    document.querySelectorAll("div[contenteditable='true'],textarea").forEach(push);
    return out;
  }

  function rankComposer(anchorEl, heads) {
    // heads[0] = most expected content (original pre-write, approved later).
    // Content match outranks DOM order and the anchor: a connected anchor
    // holding NEITHER text is a ghost and must lose.
    let best = null, bestScore = -1;
    for (const el of candidateComposers(anchorEl)) {
      const t = normWs(getText(el));
      let score = 0;
      heads.forEach((h, i) => { if (h && t.includes(normWs(h).slice(0, 40))) score += 10 - i; });
      if (el === anchorEl && score === 0) score = 0; // ghost anchor: no pity points
      else if (el === anchorEl) score += 1;
      if (score > bestScore) { bestScore = score; best = el; }
    }
    return bestScore > 0 ? best : null;
  }

  async function clipboardFallback(text, toastMsg, action, method) {
    try { await navigator.clipboard?.writeText(text); } catch { /* best-effort */ }
    toast(toastMsg);
    audit({ action, method, entityTypes: [], spansFound: 0 });
  }

  async function writeVerified(composer, approvedText, method) {
    // Returns the node now holding approvedText, or null (already complained).
    if (!setText(composer, approvedText)) {
      await clipboardFallback(approvedText,
        "Chat refused the rewrite — sanitized text copied, paste it with Ctrl+V and send.",
        "settext_failed_clipboard", method);
      return null;
    }
    try { window.getSelection()?.collapseToEnd(); } catch { /* caret best-effort */ }
    const got = normWs(getText(composer)).slice(0, 60);
    console.log("[shadowtrace] read-back on", describe(composer), JSON.stringify(got));
    if (!headMatch(got, approvedText)) {
      await clipboardFallback(approvedText,
        "Rewrite didn't stick — sanitized text copied, paste it with Ctrl+V and send.",
        "readback_mismatch", method);
      return null;
    }
    return composer;
  }

  async function release(anchorEl, approvedText, originalText, method) {
    const origHead = normWs(originalText).slice(0, 40);
    const apprHead = normWs(approvedText).slice(0, 40);
    // Attempt 1: the box should still hold the original (nothing written yet).
    // Attempt 2: if attempt 1 wrote a ghost, the live box still holds the
    // original while the ghost holds approved — ranking by content finds live.
    for (let attempt = 1; attempt <= 2; attempt++) {
      const composer = rankComposer(anchorEl, [origHead, apprHead]);
      console.log("[shadowtrace] release attempt", attempt, describe(composer));
      if (!composer) break;
      const ready = await writeVerified(composer, approvedText, method);
      if (ready) {
        pollForSend(ready, approvedText, method, anchorEl, Date.now());
        return;
      }
    }
    await clipboardFallback(approvedText,
      "Couldn't rewrite the chat box — sanitized text copied, paste it with Ctrl+V and send.",
      "release_exhausted", method);
  }

  function pollForSend(composer, approvedText, method, anchorEl, t0) {
    // Frameworks enable the send button a beat after the input event.
    // Poll briefly instead of assuming 60ms is enough.
    const btn = $(adapter.send);
    const ready = btn && !btn.disabled &&
      btn.getAttribute("aria-disabled") !== "true" &&
      btn.offsetParent !== null;
    if (ready) {
      // Re-resolve at click time: prefer the node we verified, but if it no
      // longer holds approved text, re-rank (original should be gone by now,
      // so approved-head leads) and rewrite there instead of clicking blind.
      let live = composer;
      if (!headMatch(getText(composer), approvedText)) {
        live = rankComposer(anchorEl, [normWs(approvedText).slice(0, 40)]);
        console.log("[shadowtrace] click-time re-resolve:", describe(live));
        if (!live) {
          clipboardFallback(approvedText,
            "Chat box changed under us — sanitized text copied, paste it with Ctrl+V and send.",
            "click_time_mismatch", method);
          return;
        }
        setText(live, approvedText);
        if (!headMatch(getText(live), approvedText)) {
          clipboardFallback(approvedText,
            "Chat box changed under us — sanitized text copied, paste it with Ctrl+V and send.",
            "click_time_rewrite_failed", method);
          return;
        }
      }
      bypassOnce = true;
      console.log("[shadowtrace] clicking send:", describe(btn), "for box:", describe(live));
      btn.click();
      // Verify on the CLICK node: a real submit clears it (optimistic UI).
      // If text is still there, the click died — reset bypass so a manual
      // Enter re-runs sanitize instead of leaking on a stale approval.
      setTimeout(() => {
        const now = normWs(getText(live.isConnected ? live : (findComposer() || live)));
        console.log("[shadowtrace] post-click box len:", now.length,
          JSON.stringify(now.slice(0, 50)));
        if (now) {
          bypassOnce = false;
          toast("Send didn't go through — press Enter to retry (sanitize re-runs).");
        }
      }, 1500);
      return;
    }
    if (Date.now() - t0 > 2500) {
      clipboardFallback(approvedText,
        "Send button never enabled — sanitized text copied, paste it with Ctrl+V and send.",
        "send_never_ready", method);
      return;
    }
    setTimeout(() => pollForSend(composer, approvedText, method, anchorEl, t0), 120);
  }

  /* ---------------- panel (Shadow DOM) ------------------------------- */
  const CSS = `
    :host { all: initial; }
    .st-overlay { position: fixed; inset: 0; z-index: 2147483647; background: rgba(0,0,0,0.45);
      display: flex; align-items: center; justify-content: center; font-family: Inter, system-ui, sans-serif; }
    .st-card { background: #fff; color: #000; width: min(680px, 92vw); max-height: 86vh; overflow: auto;
      border: 1px solid #000; }
    .st-head { padding: 16px 22px; border-bottom: 1px solid #000; display: flex;
      justify-content: space-between; align-items: center; }
    .st-head b { font-size: 11px; letter-spacing: 0.22em; font-weight: 400; }
    .st-x { border: 0; background: none; font-size: 18px; cursor: pointer; color: #000; }
    .st-sec { padding: 16px 22px; border-bottom: 1px solid #e4e4e4; }
    .st-sec h4 { font-size: 11px; letter-spacing: 0.22em; font-weight: 400; color: #6d6d6d; margin: 0 0 10px; }
    .st-cols { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
    @media (max-width: 560px) { .st-cols { grid-template-columns: 1fr; } }
    .st-box { font-size: 13px; line-height: 1.65; white-space: pre-wrap; word-break: break-word; }
    .st-box mark.e { background: #000; color: #fff; padding: 0 4px; }
    .st-box mark.r { border-bottom: 1px solid #000; background: none; color: #000; }
    .st-sub { font-size: 12px; padding: 7px 0; border-bottom: 1px dotted #e4e4e4; }
    .st-sub:last-child { border-bottom: 0; }
    .st-sub .arrow { color: #6d6d6d; }
    .st-sub label { display: flex; gap: 8px; align-items: baseline; cursor: pointer; }
    .st-sub code { font-family: ui-monospace, Menlo, monospace; font-size: 12px; }
    .st-sub .why { color: #6d6d6d; display: block; margin-left: 24px; }
    .st-kv { display: flex; justify-content: space-between; font-size: 13px; padding: 4px 0; }
    .st-kv span:first-child { color: #6d6d6d; }
    .st-hold { background: #000; color: #fff; padding: 12px 14px; font-size: 13px; }
    .st-actions { padding: 16px 22px; display: flex; gap: 10px; flex-wrap: wrap; }
    .st-btn { font-size: 14px; padding: 10px 26px; border-radius: 75px; cursor: pointer;
      border: 1px solid #000; background: #fff; color: #000; }
    .st-btn.primary { background: #000; color: #fff; }
    .st-btn.danger { border-color: #000; }
    .st-note { padding: 0 22px 16px; font-size: 11px; color: #6d6d6d; letter-spacing: 0.04em; }
    .st-edit { width: 100%; min-height: 90px; font: inherit; font-size: 13px; padding: 10px;
      border: 1px solid #000; border-radius: 0; resize: vertical; }
  `;

  function esc(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function markSpans(text, spans) {
    let out = "", cur = 0;
    const ord = [...spans].sort((a, b) => a.start - b.start);
    for (const s of ord) {
      if (s.start < cur) continue;
      out += esc(text.slice(cur, s.start));
      out += `<mark class="e" title="${esc(s.etype)}">${esc(text.slice(s.start, s.end))}</mark>`;
      cur = s.end;
    }
    return out + esc(text.slice(cur));
  }

  function markSubs(text, subs, reverted) {
    let out = esc(text);
    const ord = [...subs].sort((a, b) => b.replacement.length - a.replacement.length);
    for (const s of ord) {
      if (reverted.has(s.eid)) continue;
      const n = esc(s.replacement);
      if (n) out = out.split(n).join(`<mark class="r" title="${esc(s.etype)} · depth ${s.depth}">${n}</mark>`);
    }
    return out;
  }

  function openPanel(anchorEl, original, res, method, backendUrl, backendHost) {
    closePanel();
    const host = document.createElement("div");
    host.id = "shadowtrace-panel-host";
    document.documentElement.appendChild(host);
    const root = host.attachShadow({ mode: "closed" });
    const reverted = new Set();
    const remote = backendHost && !/^(127\.0\.0\.1|localhost)/.test(backendHost);

    const sensSubs = res.substitutions;
    const subRows = sensSubs.map((s) => `
      <div class="st-sub"><label>
        <input type="checkbox" data-eid="${esc(s.eid)}" ${reverted.has(s.eid) ? "checked" : ""}>
        <span><code>${esc(s.surface)}</code> <span class="arrow">→</span> ${esc(s.replacement)}
        <span class="why">${esc(s.etype)} · rung depth ${s.depth} · ${s.reveal && s.reveal.length ? "reveals " + esc(s.reveal.join(", ")) : "reveals nothing"} · ${s.restorable ? "restorable on your device" : "not restorable"}</span></span>
      </label></div>`).join("");

    const atk = res.attack;
    root.innerHTML = `<style>${CSS}</style>
      <div class="st-overlay"><div class="st-card" role="dialog" aria-label="ShadowTrace review">
        <div class="st-head"><b>SHADOWTRACE — REVIEW BEFORE SENDING</b><button class="st-x" data-act="cancel">✕</button></div>
        ${res.held ? `<div class="st-sec"><div class="st-hold">HELD — ${esc(res.hold_reason)}. Sending the original requires explicit confirmation below.</div></div>` : ""}
        <div class="st-sec"><h4>01 — WHAT WAS FOUND · ${res.spans.filter((s) => s.sensitive).length} SENSITIVE</h4>
          <div class="st-box">${markSpans(res.normalized, res.spans.filter((s) => s.sensitive))}</div></div>
        <div class="st-sec"><h4>02 — WHAT WOULD BE SENT · ${esc((res.method || method).toUpperCase())}</h4>
          <div class="st-box" data-role="preview">${markSubs(res.sanitized, sensSubs, reverted)}</div>
          <div style="margin-top:10px">${subRows || '<div class="st-sub">Text unchanged.</div>'}</div>
          <div style="margin-top:10px"><button class="st-btn" data-act="edit">Edit text manually</button></div>
          <div data-role="editor" style="display:none;margin-top:10px">
            <textarea class="st-edit" data-role="editbox">${esc(res.sanitized)}</textarea>
          </div></div>
        <div class="st-sec"><h4>03 — LEAKAGE LEDGER</h4>
          <div class="st-kv"><span>Span survival</span><span>${(res.leakage.span.rate * 100).toFixed(1)}%</span></div>
          <div class="st-kv"><span>Attribute disclosure</span><span>${(res.leakage.attribute.mean * 100).toFixed(1)}%</span></div>
          <div class="st-kv"><span>Attacker credit (N=${atk ? atk.n : "—"})</span><span>${atk ? (atk.rate * 100).toFixed(1) + "%" : "—"}</span></div>
          <div class="st-kv"><span>Restorable on device</span><span>${(res.leakage.restorable_frac * 100).toFixed(1)}%</span></div></div>
        <div class="st-actions">
          <button class="st-btn primary" data-act="send">Send sanitized →</button>
          <button class="st-btn" data-act="cancel">Cancel</button>
          <button class="st-btn danger" data-act="original">Send original anyway</button>
        </div>
        <div class="st-note">DETECTION + REWRITE RAN ON ${esc(backendHost || "this device")}${remote ? " OVER TLS — YOUR ORIGINAL TEXT LEAVES THIS DEVICE FOR SANITIZATION" : " (YOUR ORIGINAL NEVER LEFT THIS DEVICE)"}. UNTICK A CHANGE TO KEEP THE ORIGINAL VALUE. SENDING THE ORIGINAL IS LOGGED LOCALLY.</div>
      </div></div>`;

    const q = (sel) => root.querySelector(sel);
    const preview = q('[data-role="preview"]');
    const editbox = q('[data-role="editbox"]');
    let manualEdit = null;

    root.addEventListener("change", (e) => {
      const cb = e.target.closest("input[type=checkbox][data-eid]");
      if (!cb) return;
      if (cb.checked) reverted.add(cb.dataset.eid); else reverted.delete(cb.dataset.eid);
      preview.innerHTML = markSubs(currentText(), sensSubs, reverted);
    });

    function currentText() {
      if (manualEdit !== null) return manualEdit;
      // apply reverts to the sanitized text: swap replacements back to surfaces
      let t = res.sanitized;
      for (const s of sensSubs) {
        if (reverted.has(s.eid) && s.replacement) t = t.split(s.replacement).join(s.surface);
      }
      return t;
    }

    root.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-act]");
      if (!btn) return;
      const act = btn.dataset.act;
      if (act === "cancel") {
        audit({ action: "cancelled", method, entityTypes: types(), spansFound: counts() });
        closePanel();
      } else if (act === "edit") {
        const ed = q('[data-role="editor"]');
        const open = ed.style.display !== "none";
        ed.style.display = open ? "none" : "block";
        if (!open) { q("[data-role='editbox']").value = currentText(); q("[data-role='editbox']").focus(); }
      } else if (act === "send") {
        if (q('[data-role="editor"]').style.display !== "none") manualEdit = q("[data-role='editbox']").value;
        const finalText = currentText();
        audit({ action: "sent_sanitized", method, entityTypes: types(), spansFound: counts(), reverted: reverted.size, edited: manualEdit !== null });
        closePanel();
        release(anchorEl, finalText, original, method);
      } else if (act === "original") {
        if (!btn.dataset.armed) {
          btn.dataset.armed = "1";
          btn.textContent = "Confirm: send original with secrets?";
          return;
        }
        audit({ action: "sent_original_confirmed", method, entityTypes: types(), spansFound: counts() });
        closePanel();
        release(anchorEl, original, original, method);
      }
    });

    document.addEventListener("keydown", function escClose(e) {
      if (e.key === "Escape") { closePanel(); document.removeEventListener("keydown", escClose); }
    });

    function types() {
      return [...new Set(res.spans.filter((s) => s.sensitive).map((s) => s.etype))];
    }
    function counts() { return res.spans.filter((s) => s.sensitive).length; }
  }

  function closePanel() {
    document.getElementById("shadowtrace-panel-host")?.remove();
  }

  function toast(msg) {
    closePanel();
    const host = document.createElement("div");
    host.id = "shadowtrace-panel-host";
    document.documentElement.appendChild(host);
    const root = host.attachShadow({ mode: "closed" });
    root.innerHTML = `<style>${CSS}</style><div class="st-overlay" style="background:transparent;align-items:flex-end;justify-content:center;padding-bottom:40px">
      <div class="st-card" style="width:auto;max-width:92vw;padding:12px 26px;border-radius:75px;font-size:13px">${esc(msg)}</div></div>`;
    setTimeout(closePanel, 5000);
  }

  hook();
})();
