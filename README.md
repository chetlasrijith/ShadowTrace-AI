# Shadow AI Leak Detector — Pilot Prototype

First experimental prototype for the research question: **can entity
generalization preserve task utility better than placeholder redaction
without increasing re-identification risk?**

Status: pre-pilot. Every number is a measurement of the current code, not a
claim. See the plan (`../plan.md`) for the full research design.

## What this is

- A synthetic benchmark of 50 fictional enterprise prompts (SQL, code,
  extraction, document Q&A, drafting) with labeled entities, executable
  checkers, and a fixed train/test split.
- Three transforms: `noop` (A, unprotected), `redact` (B, placeholders),
  `generalize` (D, ladder rungs), plus `chain` (generalize → redact → hold).
- Three leakage axes: span survival, attacker-independent attribute
  distance, and closed-set re-identification (N-way choice over the
  registry, chance = 1/N).
- Utility from execution or exact match. Drafting gets structural proxies
  only, reported separately, never pooled.

## What this is not

- Not a product, not a Chrome extension (demo comes after the pilot gate).
- The registry-match detector measures *transforms*, not real-world NER.
- The lexical attacker is a *lower bound*. H2 is not settled by this pilot.
- No differential privacy, no formal guarantees, no real data anywhere.

## Run it

```bash
pip install pyyaml requests pytest fastapi uvicorn   # pandas optional
python -m pytest tests/ -q           # 32 unit tests
python scripts/run_pilot.py --mode selftest        # harness calibration
ollama pull qwen2.5:1.5b-instruct-q4_K_M           # or any instruct model
python scripts/run_pilot.py --mode real --model qwen2.5:1.5b-instruct-q4_K_M
```

## Try it (simulation UI)

```bash
python scripts/serve.py              # localhost only → http://127.0.0.1:8137
```

A monochrome chat simulation wired to the real pipeline: type a prompt,
pick Original / Redact / Generalize / Chain plus an abstraction shift, and
watch detection spans, the sanitized rewrite with rung depths, the local
model's answer, and the leakage ledger (span survival, attribute
disclosure, closed-set attacker credit, restorability). Same page shows the
measured benchmark table, the Pareto frontier, and the public ladder
codebook. Detection, rewriting, and answering all stay on this machine.

Chat input gets a second detector the benchmark does not use: ad-hoc PII
shapes (emails, phones, passwords, employee IDs, API keys, Luhn-validated
cards) are found by pattern plus context cue, minted per-text entities, and
run through the same transforms and leakage ledger. Passwords and API keys
generalize straight to placeholders — a secret has no safe descriptive
middle. Registry dictionary behavior is unchanged; the pilot numbers are
unaffected.

## Extension (demo)

`extension/` is a Manifest V3 demo for ChatGPT, Claude, and Gemini. It does
not sanitize by itself: on submit it captures the composer text, calls the
local backend (`POST /api/sanitize`), and shows a review panel — diff with
per-change reasons, untick-to-revert, manual edit, send-sanitized, cancel,
or send-original (double-confirm, logged locally). Clean prompts pass
through untouched. Detection and rewriting run on your machine; the chat
site only ever receives what you approve.

Install:

```bash
python scripts/serve.py              # backend must be up first
```

1. Open `chrome://extensions`, enable Developer mode, Load unpacked →
   select `extension/`.
2. Pin ShadowTrace, open its popup: set the default method, confirm the
   backend shows connected.
3. Type in any supported chat box and press Enter: the review panel appears.

Limits, stated plainly: three sites on an allowlist (selectors break, expect
maintenance); no coverage of API calls, other apps, or personal devices; a
motivated user can disable it; reply re-hydration is off. Audit log holds
metadata only (action, method, entity types) on the device.

`selftest` uses a deterministic ceiling oracle: it proves the checkers
(all noop ceilings must read 1.0) and labels every table NOT RESULTS.
Only `--mode real` numbers may be reported, and only with the limitations
block attached.

Useful flags: `--limit N`, `--methods noop,redact`, `--families sql,extract`,
`--repeats R`, `--config configs/pilot.yaml`.

## Answer models: local default, free hosted options

Ollama stays the default — private, reproducible, and the only option the
privacy story leans on. For machines that can't run it, `--model` takes a
provider spec (keys from the environment, never the repo):

```bash
python scripts/run_pilot.py --mode real --model groq:llama-3.3-70b-versatile
#   needs GROQ_API_KEY — free tier, printed per-model limits, fastest

python scripts/run_pilot.py --mode real --model openrouter:meta-llama/llama-3.3-70b-instruct:free
#   needs OPENROUTER_API_KEY — 28+ :free models, no card, one key

python scripts/run_pilot.py --mode real --model gemini:gemini-2.5-flash
#   needs GEMINI_API_KEY — AI Studio free tier, volatile limits, check dashboard
```

Same spec works for the UI/chat server with no code change:

```bash
SHADOWTRACE_MODEL="groq:llama-3.3-70b-versatile" python scripts/serve.py
```

Privacy contract, read before using any hosted model: the chat/sanitize
paths send only **sanitized** text outward — that is the product thesis, and
it is what makes a hosted answer model acceptable here. The pilot's `noop`
baseline sends synthetic originals, fictional by construction and disclosed
in every report. Free-tier data-use terms vary by provider and change often;
check the current policy, and never point a hosted model at real secrets.
The attacker stays local code under all options. Cached responses are keyed
by model name, so switching providers never collides with old results.

## Layout

```
configs/   ladders.yaml (public codebook), pilot.yaml, depth_policy.yaml (later)
data/      universe/registry.jsonl, prompts/pilot.jsonl  (generated, committed)
src/shadowtrace/
  universe.py        fictional registry + ground-truth attributes
  prompts.py         benchmark construction in canonical token space
  detect/            normalize, checksum rules, registry dictionary match
  transform/         ladders, noop/redact/generalize/chain, verify
  checkers/          sqlite, sandboxed code, exact text, structural proxies
  evaluate/          leakage, closed-set attacker, answer models + cache,
                     utility dispatch, drafting proxy, bootstrap metrics
  report/            text + JSON rendering
scripts/run_pilot.py the one command · scripts/serve.py the UI command
server/    app.py (localhost FastAPI) + static/ (zero-dependency UI)
tests/               32 unit tests
results/             cache.jsonl, run.json, report.txt (generated)
```

## Reading the report

- `task_success` is absolute, per method, per family. Compare against the
  `noop` ceiling printed at the top, not against 1.0.
- `reid_rate` is mean fractional attacker credit; `chance` is 1/N.
  Redact on code/sql sits above chance because task prose names the system
  function ("billing service") — prose evidence, not transform leakage.
- `restorable_frac` is the share of substitutions whose original identifier
  is unambiguously recoverable. Placeholders never restore.
- Interval widths are the finding at n=50. Overlapping intervals settle nothing.
