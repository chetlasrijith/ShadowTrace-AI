/* ShadowTrace simulation client. No framework, no build. */

const $ = (sel) => document.querySelector(sel);

/* Split deployment: Vercel serves this file, Render answers the API.
   window.SHADOWTRACE_API_BASE is injected by static/api-config.js
   (same-origin default ""). All API calls go through api(). */
const API_BASE = (window.SHADOWTRACE_API_BASE || "").replace(/\/+$/, "");
const api = (path) => API_BASE + path;
const state = { method: "generalize", rungShift: 0, busy: false };

const SHIFT_LABELS = { "-2": "near-exact", "-1": "shallow", "0": "default", "1": "deep", "2": "near-placeholder" };

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(t._h);
  t._h = setTimeout(() => t.classList.remove("show"), 4200);
}

function esc(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/* ---------- nav ---------- */
function navTheme() {
  const nav = $("#nav");
  nav.classList.toggle("on-dark", window.scrollY < window.innerHeight - 80);
  nav.classList.toggle("on-light", window.scrollY >= window.innerHeight - 80);
}
window.addEventListener("scroll", navTheme, { passive: true });

async function health() {
  try {
    const r = await fetch(api("/api/health"));
    const j = await r.json();
    $("#navStatusText").textContent = "CONNECTED · " + j.entities + " ENTITIES";
    $("#navStatus").classList.add("live");
  } catch {
    $("#navStatusText").textContent = "SERVER UNREACHABLE";
  }
}

/* ---------- method switch ---------- */
document.querySelectorAll(".tag-pill[data-method]").forEach((b) => {
  b.addEventListener("click", () => {
    document.querySelectorAll(".tag-pill[data-method]").forEach((x) => x.setAttribute("aria-pressed", "false"));
    b.setAttribute("aria-pressed", "true");
    state.method = b.dataset.method;
    $("#inspMethod").textContent = state.method.toUpperCase();
  });
});
$("#rungShift").addEventListener("input", (e) => {
  state.rungShift = parseInt(e.target.value, 10);
  $("#rungShiftLabel").textContent = SHIFT_LABELS[String(state.rungShift)];
});

/* ---------- samples ---------- */
async function loadSamples() {
  try {
    const r = await fetch(api("/api/samples"));
    const j = await r.json();
    const wrap = $("#samples");
    j.samples.forEach((s) => {
      const b = document.createElement("button");
      b.className = "tag-pill";
      b.textContent = s.family + " · " + s.pid;
      b.title = s.text.slice(0, 120) + "…";
      b.addEventListener("click", () => { $("#composer").value = s.text; $("#composer").focus(); });
      wrap.appendChild(b);
    });
  } catch { /* samples are a convenience, not a requirement */ }
}

/* ---------- highlight helpers ---------- */
function highlightSpans(text, spans) {
  // spans: [{start, end, sensitive}] on the same text. Escape, then mark.
  const parts = [];
  let cur = 0;
  const ordered = [...spans].sort((a, b) => a.start - b.start);
  for (const s of ordered) {
    if (s.start < cur) continue; // overlap: first wins
    parts.push(esc(text.slice(cur, s.start)));
    const cls = s.sensitive ? "ent" : "ent neg";
    const title = s.sensitive ? `${s.etype} · sensitive` : "non-sensitive";
    parts.push(`<mark class="${cls}" title="${esc(title)}">${esc(text.slice(s.start, s.end))}</mark>`);
    cur = s.end;
  }
  parts.push(esc(text.slice(cur)));
  return parts.join("");
}

function highlightSubs(text, subs) {
  let out = esc(text);
  const ordered = [...subs].sort((a, b) => b.replacement.length - a.replacement.length);
  for (const s of ordered) {
    const needle = esc(s.replacement);
    if (!needle || out.indexOf(needle) < 0) continue;
    const title = `${s.etype} · depth ${s.depth}` + (s.restorable ? " · restorable" : " · not restorable");
    out = out.split(needle).join(`<mark class="rep" title="${esc(title)}">${needle}</mark>`);
  }
  return out;
}

/* ---------- code fence rendering ---------- */
function renderAnswer(text) {
  const fence = text.match(/```(\w*)\n?([\s\S]*?)```/);
  if (fence) {
    const before = esc(text.slice(0, fence.index)).trim();
    const code = esc(fence[2].trim());
    const after = esc(text.slice(fence.index + fence[0].length)).trim();
    return (before ? `<p>${before}</p>` : "") + `<pre>${code}</pre>` + (after ? `<p style="margin-top:12px">${after}</p>` : "");
  }
  return `<p>${esc(text)}</p>`;
}

/* ---------- inspector ---------- */
function renderInspector(d) {
  const el = $("#inspector");
  const sens = d.spans.filter((s) => s.sensitive);
  const nons = d.spans.filter((s) => !s.sensitive);

  const chips = sens.map((s) => `<span class="chip">${esc(s.surface)} <small>${s.etype.toUpperCase()}</small></span>`).join("") +
    nons.map((s) => `<span class="chip neg">${esc(s.surface)} <small>NOT SENSITIVE</small></span>`).join("");

  const subs = d.substitutions.map((s) =>
    `<div class="sub-row"><code>${esc(s.surface)}</code> <span class="arrow">→</span> ${esc(s.replacement)} <span class="arrow">· depth ${s.depth} · ${s.reveal.length ? "reveals " + esc(s.reveal.join(", ")) : "reveals nothing"}</span> <span class="${s.restorable ? "flag-ok" : "flag-bad"}">${s.restorable ? "· restorable" : "· ambiguous ×" + s.ambiguity_k}</span></div>`
  ).join("");

  const atk = d.attack;
  const atkRows = atk ? (
    `<div class="kv"><span class="k">Attacker N</span><span class="v">${atk.n} (chance ${(atk.chance * 100).toFixed(1)}%)</span></div>` +
    `<div class="kv"><span class="k">Mean credit</span><span class="v">${(atk.rate * 100).toFixed(1)}%</span></div>` +
    atk.results.slice(0, 4).map((r) =>
      `<div class="kv"><span class="k">${esc(r.eid_true)}</span><span class="v">→ ${esc(r.eid_pred || "—")} · ${(r.credit * 100).toFixed(0)}%</span></div>`
    ).join("")
  ) : `<p class="empty-note">No sensitive entities — nothing to attack.</p>`;

  el.innerHTML = `
    <div class="insp-head"><span>PIPELINE INSPECTOR</span><span>${esc(d.method.toUpperCase())}</span></div>
    ${d.held ? `<div class="stage"><div class="hold-banner">HELD — ${esc(d.hold_reason)}. Nothing was forwarded.</div></div>` : ""}
    <div class="stage"><div class="stage-title"><span class="n">01</span> — DETECTED · ${sens.length} SENSITIVE${nons.length ? ` · ${nons.length} NON-SENSITIVE LEFT ALONE` : ""}</div>
      <div class="chips">${chips || '<p class="empty-note">No known entities. Unknown names are invisible to this detector — a stated limitation.</p>'}</div></div>
    <div class="stage"><div class="stage-title"><span class="n">02</span> — SANITIZED · ${d.substitutions.length} SUBSTITUTIONS${d.missed_eids.length ? ` · ${d.missed_eids.length} MISSED` : ""}</div>
      <div class="sanitized-text">${highlightSubs(d.sanitized, d.substitutions)}</div>
      <div style="margin-top:12px">${subs || '<p class="empty-note">Text unchanged.</p>'}</div></div>
    <div class="stage"><div class="stage-title"><span class="n">03</span> — LEAKAGE LEDGER</div>
      <div class="kv"><span class="k">Span survival</span><span class="v">${(d.leakage.span.rate * 100).toFixed(1)}%${d.leakage.span.survivors.length ? " · " + esc(d.leakage.span.survivors.slice(0, 3).join(", ")) : ""}</span></div>
      <div class="kv"><span class="k">Attribute disclosure</span><span class="v">${(d.leakage.attribute.mean * 100).toFixed(1)}%</span></div>
      <div class="kv"><span class="k">Restorable</span><span class="v">${(d.leakage.restorable_frac * 100).toFixed(1)}%</span></div></div>
    <div class="stage"><div class="stage-title"><span class="n">04</span> — ATTACKER · CLOSED CANDIDATE SET</div>${atkRows}</div>`;
}

/* ---------- send ---------- */
async function send() {
  if (state.busy) return;
  const text = $("#composer").value.trim();
  if (!text) { toast("Write a prompt first — or pick a sample."); return; }
  state.busy = true;
  $("#sendBtn").disabled = true;
  $("#composerHint").innerHTML = '<span class="spinner"></span>&nbsp; DETECTING → REWRITING → ANSWERING';

  // user message first (unhighlighted until detection returns)
  const thread = $("#thread");
  const userMsg = document.createElement("div");
  userMsg.className = "msg";
  userMsg.innerHTML = `<div class="msg-role">YOU · VIA ${esc(state.method.toUpperCase())}</div><div class="msg-body">${esc(text)}</div>`;
  thread.appendChild(userMsg);
  userMsg.scrollIntoView({ behavior: "smooth", block: "nearest" });

  const pending = document.createElement("div");
  pending.className = "msg";
  pending.innerHTML = `<div class="msg-role">SHADOWTRACE</div><div class="msg-body"><span class="spinner"></span>&nbsp; running the local pipeline…</div>`;
  thread.appendChild(pending);

  try {
    const r = await fetch(api("/api/chat"), {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, method: state.method, rung_shift: state.rungShift }),
    });
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      throw new Error(err.detail || ("HTTP " + r.status));
    }
    const d = await r.json();
    // highlight detected entities in the user message now that spans are known
    userMsg.querySelector(".msg-body").innerHTML = highlightSpans(d.normalized, d.spans);
    pending.innerHTML = `<div class="msg-role">ANSWER · ${esc(d.answer.model)} · SANITIZED INPUT ONLY</div>
      <div class="msg-body answer">${renderAnswer(d.answer.text)}</div>
      <div class="msg-meta">${d.answer.latency_s}s · TRANSFORM ${esc(d.method.toUpperCase())} · ${d.elapsed_s}s END-TO-END</div>`;
    renderInspector(d);
  } catch (e) {
    pending.innerHTML = `<div class="msg-role">SHADOWTRACE</div><div class="msg-body">Pipeline failed: ${esc(e.message)}</div>`;
    toast(e.message);
  } finally {
    state.busy = false;
    $("#sendBtn").disabled = false;
    $("#composerHint").textContent = "DETECTION + REWRITE ARE LOCAL";
    $("#composer").value = "";
  }
}

$("#sendBtn").addEventListener("click", send);
$("#composer").addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "Enter") send();
});

/* ---------- benchmark ---------- */
async function loadBenchmark() {
  const wrap = $("#benchWrap");
  try {
    const r = await fetch(api("/api/benchmark"));
    const j = await r.json();
    if (!j.available) { wrap.innerHTML = `<p class="empty-note" style="margin-top:28px">No measurements yet — run the pilot first.</p>`; return; }
    const rows = j.rows;
    const order = { noop: 0, generalize: 1, chain: 2, redact: 3 };
    rows.sort((a, b) => (order[a.method] ?? 9) - (order[b.method] ?? 9));
    const fmt = (m) => `${m.mean.toFixed(3)} [${m.lo.toFixed(3)}, ${m.hi.toFixed(3)}]`;
    wrap.innerHTML = `<table class="bench-table"><thead><tr>
      <th>METHOD</th><th>N</th><th>TASK SUCCESS</th><th>SPAN LEAK</th><th>ATTR LEAK</th><th>RE-ID (CHANCE 0.10)</th><th>RESTORABLE</th>
      </tr></thead><tbody>` + rows.map((x) =>
      `<tr><td>${esc(x.method)}</td><td>${x.n}</td><td>${fmt(x.task_success)}</td><td>${fmt(x.span_leakage)}</td><td>${fmt(x.attribute_leakage)}</td><td>${fmt(x.reid_rate)}</td><td>${fmt(x.restorable_frac)}</td></tr>`
    ).join("") + `</tbody></table>`;
    const m = j.meta || {};
    $("#benchCaption").textContent =
      `Answer model ${m.answer_model || "—"} · repeats ${m.repeats ?? "—"} · ${m.n_prompts || "?"} prompts · ${m.n_entities || "?"} entities. ` +
      `Code family reads 0.000 for every method including noop: the 1.5B model cannot write the helpers at all — a capability floor, not a sanitization finding. ` +
      `Intervals are bootstrap 95% over prompts; overlapping intervals settle nothing.`;
    drawPareto(rows);
  } catch {
    wrap.innerHTML = `<p class="empty-note" style="margin-top:28px">Measurements unavailable.</p>`;
  }
}

function drawPareto(rows) {
  const svg = $("#pareto");
  const W = 560, H = 360, P = 56;
  const get = (r, k) => r[k].mean;
  const xs = rows.map((r) => get(r, "reid_rate"));
  const ys = rows.map((r) => get(r, "task_success"));
  const xMax = Math.max(1.0, ...xs) * 1.02, yMax = 1.02;
  const X = (v) => P + (v / xMax) * (W - 2 * P);
  const Y = (v) => H - P - v * (H - 2 * P) / yMax;
  const chance = rows.length ? (rows[0].reid_chance ?? 0.1) : 0.1;
  let s = `<line x1="${P}" y1="${H - P}" x2="${W - 20}" y2="${H - P}" stroke="#000" stroke-width="1"/>
    <line x1="${P}" y1="${H - P}" x2="${P}" y2="16" stroke="#000" stroke-width="1"/>
    <line x1="${X(chance)}" y1="${H - P}" x2="${X(chance)}" y2="16" stroke="#9a9a9a" stroke-width="1" stroke-dasharray="5 5"/>
    <text x="${X(chance) + 6}" y="30" font-size="11" fill="#6d6d6d" letter-spacing="2">CHANCE</text>
    <text x="${W - 20}" y="${H - P + 22}" font-size="11" fill="#6d6d6d" text-anchor="end" letter-spacing="2">RE-IDENTIFICATION →</text>
    <text x="12" y="24" font-size="11" fill="#6d6d6d" letter-spacing="2">TASK SUCCESS</text>`;
  for (const r of rows) {
    const cx = X(get(r, "reid_rate")), cy = Y(get(r, "task_success"));
    const lo = Y(r.task_success.hi), hi = Y(r.task_success.lo);
    s += `<line x1="${cx}" y1="${lo}" x2="${cx}" y2="${hi}" stroke="#000" stroke-width="1"/>`;
    s += `<circle cx="${cx}" cy="${cy}" r="7" fill="${r.method === "noop" ? "#000" : "#fff"}" stroke="#000" stroke-width="1.5"/>`;
    s += `<text x="${cx + 12}" y="${cy + 4}" font-size="12" fill="#000">${esc(r.method)}</text>`;
  }
  svg.innerHTML = s;
}

/* ---------- ladders ---------- */
async function loadLadders() {
  try {
    const r = await fetch(api("/api/ladders"));
    const j = await r.json();
    $("#ladder").innerHTML = Object.entries(j.ladders).map(([etype, rungs]) => `
      <div class="ladder-type"><div class="etype">${esc(etype.toUpperCase())} · DEFAULT DEPTH ${j.default_depth[etype] ?? "—"}</div>
      <h3>${esc(etype)} ladder</h3>
      ${rungs.map((x) => `<div class="rung"><span class="depth">DEPTH ${x.depth}</span><code>${esc(x.template)}</code><span class="reveal">${x.reveal.length ? "reveals " + esc(x.reveal.join(" · ")) : "reveals nothing"}</span></div>`).join("")}
      </div>`).join("");
  } catch { $("#ladder").innerHTML = `<p class="empty-note">Ladder config unavailable.</p>`; }
}

/* ---------- init ---------- */
navTheme();
health();
loadSamples();
loadBenchmark();
loadLadders();
