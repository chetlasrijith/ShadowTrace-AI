/* ShadowTrace popup: default method, abstraction shift, backend status. */
const LABELS = { "-2": "near-exact", "-1": "shallow", "0": "default", "1": "deep", "2": "near-placeholder" };

async function init() {
  const d = await chrome.storage.local.get({ method: "generalize", rung_shift: 0, shadowtrace_audit: [] });
  const method = document.getElementById("method");
  const shift = document.getElementById("shift");
  method.value = d.method;
  shift.value = String(d.rung_shift);
  document.getElementById("shiftLabel").textContent = LABELS[String(d.rung_shift)] || "default";

  method.addEventListener("change", () => chrome.storage.local.set({ method: method.value }));
  shift.addEventListener("input", () => {
    const v = parseInt(shift.value, 10);
    document.getElementById("shiftLabel").textContent = LABELS[String(v)];
    chrome.storage.local.set({ rung_shift: v });
  });

  try {
    const r = await fetch("http://127.0.0.1:8137/api/health");
    const j = await r.json();
    document.getElementById("status").textContent =
      `BACKEND CONNECTED · ${j.entities} ENTITIES · LADDERS v${j.ladders_version}`;
  } catch {
    document.getElementById("status").textContent =
      "BACKEND UNREACHABLE — run: python scripts/serve.py";
  }

  const n = (d.shadowtrace_audit || []).length;
  document.getElementById("audit").textContent =
    `${n} local audit entr${n === 1 ? "y" : "ies"} (metadata only, this device)`;

  document.getElementById("clearAudit").addEventListener("click", async () => {
    await chrome.storage.local.set({ shadowtrace_audit: [] });
    document.getElementById("audit").textContent = "0 local audit entries (metadata only, this device)";
  });
}

init();
