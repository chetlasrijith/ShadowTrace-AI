/* ShadowTrace content script: intercept → sanitize → confirm → release.
 *
 * Design rules:
 * - The page never sees raw interception logic beyond a captured key/click.
 * - The original text lives only in this isolated world + the localhost
 *   backend. Nothing is sent to any third party by this script.
 * - Every submit path funnels through maybeIntercept(); programmatic
 *   re-submit after approval sets bypassOnce so we never loop.
 * - The panel renders inside Shadow DOM: page CSS cannot touch it.
 */

(() => {
  "use strict";

  const BACKEND = "http://127.0.0.1:8137";
  const HOST = location.hostname;

  /* ---------------- site adapters: allowlist, expect maintenance ------ */
  const ADAPTERS = [
    {
      host: /(^|\.)chatgpt\.com$|(^|\.)chat\.openai\.com$/,
      site: "chatgpt",
      composer: ["#prompt-textarea", "div[contenteditable='true']#prompt-textarea"],
      send: ['[data-testid="send-button"]', 'button[data-testid="send-button"]'],
    },
    {
      host: /(^|\.)claude\.ai$/,
      site: "claude",
      composer: ["div.ProseMirror[contenteditable='true']", "div[contenteditable='true']"],
      send: ['button[aria-label="Send message"]', 'button[aria-label^="Send"]'],
    },
    {
      host: /(^|\.)gemini\.google\.com$/,
      site: "gemini",
      composer: ["div[contenteditable='true'].ql-editor", "div[contenteditable='true']"],
      send: ['button[aria-label="Send message"]', 'button[aria-label^="Send"]'],
    },
  ];

  const adapter = ADAPTERS.find((a) => a.host.test(HOST));
  if (!adapter) return;

  const $ = (sels, root = document) => {
    for (const s of sels) {
      const el = root.querySelector(s);
      if (el && el.offsetParent !== null) return el;
    }
    return null;
  };

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
      return;
    }
    // contenteditable: select-all + insertText keeps framework bindings alive
    const sel = window.getSelection();
    sel.selectAllChildren(el);
    if (!document.execCommand("insertText", false, text)) {
      el.textContent = text;
      el.dispatchEvent(new InputEvent("input", { bubbles: true, data: text }));
    }
  }

  /* ---------------- audit log (metadata only) ------------------------ */
  function audit(entry) {
    try {
      const rec = {
        ts: new Date().toISOString(),
        site: adapter.site,
        backend: BACKEND,
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
    const d = await chrome.storage.local.get({ method: "generalize", rung_shift: 0 });
    return d;
  }

  async function sanitize(text, method, rung_shift) {
    const r = await fetch(`${BACKEND}/api/sanitize`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, method, rung_shift }),
    });
    if (!r.ok) throw new Error(`backend ${r.status}`);
    return r.json();
  }

  async function backendAlive() {
    try {
      const r = await fetch(`${BACKEND}/api/health`);
      return r.ok;
    } catch { return false; }
  }

  /* ---------------- intercept ---------------------------------------- */
  let busy = false;
  let bypassOnce = false;

  async function maybeIntercept(kind) {
    if (busy || bypassOnce) { bypassOnce = false; return false; }
    const composer = $(adapter.composer);
    if (!composer) return false;
    const text = getText(composer).trim();
    if (!text) return false; // let empty submits fall through

    busy = true;
    try {
      if (!(await backendAlive())) {
        toast("ShadowTrace backend unreachable (127.0.0.1:8137). Submit blocked — start the server or disable the extension.");
        audit({ action: "blocked_no_backend", method: "?", entityTypes: [], spansFound: 0 });
        return true;
      }
      const { method, rung_shift } = await getSettings();
      const res = await sanitize(text, method, rung_shift);
      const sensCount = res.spans.filter((s) => s.sensitive).length;
      if (sensCount === 0 && !res.held) {
        audit({ action: "passthrough_clean", method, entityTypes: [], spansFound: 0 });
        return false; // nothing sensitive: release the submit untouched
      }
      openPanel(composer, text, res, method);
      audit({
        action: "panel_shown", method,
        entityTypes: [...new Set(res.spans.filter((s) => s.sensitive).map((s) => s.etype))],
        spansFound: sensCount, held: res.held,
      });
      return true;
    } catch (e) {
      toast(`ShadowTrace error: ${e.message}. Submit blocked.`);
      audit({ action: "blocked_error", method: "?", entityTypes: [], spansFound: 0 });
      return true;
    } finally {
      busy = false;
    }
  }

  function hook() {
    // Enter key in the composer
    document.addEventListener("keydown", async (e) => {
      if (e.key !== "Enter" || e.shiftKey || e.isComposing) return;
      const composer = $(adapter.composer);
      if (!composer || !composer.contains(e.target)) return;
      if (await maybeIntercept("enter")) { e.preventDefault(); e.stopPropagation(); }
    }, true);

    // send-button clicks
    document.addEventListener("click", async (e) => {
      const btn = $(adapter.send);
      if (!btn || !(e.target instanceof Element)) return;
      if (!btn.contains(e.target) && e.target !== btn) return;
      if (await maybeIntercept("click")) { e.preventDefault(); e.stopPropagation(); }
    }, true);
  }

  function release(composer, text) {
    bypassOnce = true;
    setText(composer, text);
    // let frameworks settle, then click the real send button
    setTimeout(() => {
      const btn = $(adapter.send);
      if (btn && !btn.disabled && btn.getAttribute("aria-disabled") !== "true") {
        btn.click();
      } else {
        // fallback: synthesize Enter
        composer.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
      }
    }, 60);
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

  function openPanel(composer, original, res, method) {
    closePanel();
    const host = document.createElement("div");
    host.id = "shadowtrace-panel-host";
    document.documentElement.appendChild(host);
    const root = host.attachShadow({ mode: "closed" });
    const reverted = new Set();

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
        <div class="st-note">DETECTION + REWRITE RAN ON YOUR MACHINE (127.0.0.1). UNTICK A CHANGE TO KEEP THE ORIGINAL VALUE. SENDING THE ORIGINAL IS LOGGED LOCALLY.</div>
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
        release(composer, finalText);
      } else if (act === "original") {
        if (!btn.dataset.armed) {
          btn.dataset.armed = "1";
          btn.textContent = "Confirm: send original with secrets?";
          return;
        }
        audit({ action: "sent_original_confirmed", method, entityTypes: types(), spansFound: counts() });
        closePanel();
        release(composer, original);
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
