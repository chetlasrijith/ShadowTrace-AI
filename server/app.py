"""ShadowTrace simulation server.

Localhost only. Every endpoint reuses the research package, so the UI
demonstrates the measured pipeline rather than a mock of it:

- detection: registry dictionary match over normalized text
- transform: noop / redact / generalize / chain from configs/ladders.yaml
- leakage: span survival, attribute distance, closed-set attacker
- answer: local Ollama model on the SANITIZED text only

Nothing leaves the machine. The answer model never sees the original.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

import sys

sys.path.insert(0, str(SRC))

from shadowtrace.detect.normalize import normalize  # noqa: E402
from shadowtrace.detect.registry import detect_all, surface_forms  # noqa: E402
from shadowtrace.evaluate.attacker import attack_all_substitutions  # noqa: E402
from shadowtrace.evaluate.answers import (  # noqa: E402
    CachedModel, ResponseCache, build_answer_model,
)
from shadowtrace.evaluate.leakage import (  # noqa: E402
    attribute_leakage, false_positive_rate, span_leakage,
)
from shadowtrace.prompts import load_prompts  # noqa: E402
from shadowtrace.transform.ladders import Ladders  # noqa: E402
from shadowtrace.transform.transforms import (  # noqa: E402
    transform_chain, transform_generalize, transform_noop, transform_redact,
)
from shadowtrace.transform.verify import count_survivors  # noqa: E402
from shadowtrace.universe import Registry  # noqa: E402

APP_TITLE = "ShadowTrace — simulation"
# Answer model spec; override without code changes, e.g.
#   SHADOWTRACE_MODEL="groq:llama-3.3-70b-versatile" python scripts/serve.py
# Ollama (local, private) is the default. Hosted specs send only sanitized
# text through the chat/sanitize paths; see answers.py privacy contract.
CHAT_MODEL = os.environ.get("SHADOWTRACE_MODEL", "qwen2.5:1.5b-instruct-q4_K_M")
CHAT_TEMPERATURE = 0.7

registry = Registry.load(ROOT / "data" / "universe" / "registry.jsonl")
ladders = Ladders.load(ROOT / "configs" / "ladders.yaml")
try:
    samples = load_prompts(ROOT / "data" / "prompts" / "pilot.jsonl")
except FileNotFoundError:
    samples = []

answer_cache = ResponseCache(ROOT / "results" / "chat_cache.jsonl")

app = FastAPI(title=APP_TITLE)


# ---------------------------------------------------------------- models

class ChatRequest(BaseModel):
    text: str = Field(min_length=1, max_length=4000)
    method: Literal["noop", "redact", "generalize", "chain"] = "generalize"
    rung_shift: int = Field(default=0, ge=-2, le=2,
                            description="-2 toward exact, +2 toward placeholder")
    attacker_n: int = Field(default=10, ge=2, le=50)


class DetectRequest(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


# ---------------------------------------------------------------- helpers

def run_detect(text: str) -> tuple[str, list[dict], list]:
    """Unified detection: registry spans plus ad-hoc PII spans.

    Returns (normalized_text, span_dicts, ad_hoc_entities). The entities
    travel with the request so transforms, leakage, and the attacker resolve
    ad-hoc eids without touching the global registry.
    """
    normed = normalize(text)
    spans, entities = detect_all(normed, registry)
    return normed, [s.to_dict() for s in spans], entities


def run_transform(normed: str, spans_raw, entities, method: str, rung_shift: int):
    from shadowtrace.detect.registry import Span

    spans = [Span(**s) for s in spans_raw]
    by_eid = {e.eid: e for e in registry.entities}
    for e in entities:
        by_eid.setdefault(e.eid, e)
    overrides: dict[str, int] = {}
    if rung_shift:
        for s in spans:
            if not s.sensitive:
                continue
            ent = by_eid.get(s.eid)
            if ent is None:
                continue
            base = ladders.depth_for(ent.etype, "chat")
            if rung_shift < 0:
                overrides[s.eid] = max(0, base + rung_shift)
            else:
                overrides[s.eid] = min(ladders.max_depth(ent.etype), base + rung_shift)
    if method == "noop":
        return transform_noop(normed)
    if method == "redact":
        return transform_redact(normed, spans, registry)
    if method == "chain":
        return transform_chain(normed, spans, registry, ladders, "chat",
                               depth_overrides=overrides or None,
                               entities=entities)
    return transform_generalize(normed, spans, registry, ladders, "chat",
                                depth_overrides=overrides or None,
                                entities=entities)


def eval_records(prompt_eids: list[str], tr, entities) -> tuple[list[dict], list[str]]:
    by_eid = {e.eid: e for e in registry.entities}
    for e in entities:
        by_eid.setdefault(e.eid, e)
    have = {s["eid"]: s for s in tr.substitutions}
    records, missed = [], []
    for eid in prompt_eids:
        ent = by_eid.get(eid)
        if ent is None or not ent.sensitive:
            continue
        if eid in have:
            records.append(have[eid])
        else:
            forms = [ent.canonical, ent.name, *ent.aliases] if not eid.startswith("ADHOC_") else [ent.canonical]
            records.append({
                "eid": eid, "etype": ent.etype, "surface": ent.canonical,
                "depth": 0, "replacement": " ".join(forms),
                "reveal": [], "restorable": True, "ambiguity_k": 1,
                "missed_by_transform": True,
            })
            missed.append(eid)
    return records, missed


def answer_model() -> CachedModel:
    return CachedModel(
        build_answer_model(CHAT_MODEL, temperature=CHAT_TEMPERATURE, seed=7),
        answer_cache,
    )


# ---------------------------------------------------------------- routes

@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "entities": len(registry.entities),
            "model": CHAT_MODEL, "ladders_version": ladders.raw.get("version")}


@app.get("/api/ladders")
def get_ladders() -> dict:
    out: dict[str, Any] = {"version": ladders.raw.get("version"),
                           "default_depth": ladders.default_depth, "ladders": {}}
    for etype, rungs in ladders.ladders.items():
        out["ladders"][etype] = [
            {"depth": r.depth, "template": r.template, "reveal": list(r.reveal)}
            for r in rungs
        ]
    return out


@app.get("/api/samples")
def get_samples() -> dict:
    picks = []
    for fam in ("sql", "extract", "docqa", "code", "drafting"):
        for p in samples:
            if p.family == fam and p.split == "train":
                picks.append({"pid": p.pid, "family": fam, "text": p.text})
                break
    return {"samples": picks}


@app.post("/api/detect")
def api_detect(req: DetectRequest) -> dict:
    normed, spans, _ = run_detect(req.text)
    return {"normalized": normed, "spans": spans}


class SanitizeRequest(BaseModel):
    text: str = Field(min_length=1, max_length=8000)
    method: Literal["noop", "redact", "generalize", "chain"] = "generalize"
    rung_shift: int = Field(default=0, ge=-2, le=2)


@app.post("/api/sanitize")
def api_sanitize(req: SanitizeRequest) -> dict:
    """Detect + rewrite only, for the browser extension.

    Unlike /api/chat this never touches an answer model: the chat site
    itself answers. Returns the sanitized text, the substitution map, and
    the leakage ledger so the extension panel can show a diff with reasons.
    """
    normed, span_dicts, entities = run_detect(req.text)
    tr = run_transform(normed, span_dicts, entities, req.method, req.rung_shift)

    by_eid = {e.eid: e for e in registry.entities}
    for e in entities:
        by_eid.setdefault(e.eid, e)
    eids = [s["eid"] for s in span_dicts if s["sensitive"] and s["eid"] in by_eid]

    def _forms(eid: str) -> list[str]:
        ent = by_eid[eid]
        if eid.startswith("ADHOC_"):
            return [ent.canonical]
        return surface_forms(ent)

    surfaces = sorted({f for eid in eids for f in _forms(eid)})
    eval_subs, missed = eval_records(eids, tr, entities)
    span = span_leakage(tr.text, normed, surfaces)
    attr = attribute_leakage(eval_subs, registry, entities)
    attack = attack_all_substitutions(tr.text, eval_subs, registry, ladders,
                                      10, 777, entities=entities) if eval_subs else None
    n_subs = len(eval_subs)
    restorable = (sum(1 for s in eval_subs if s.get("restorable")) / n_subs
                  if n_subs else 1.0)
    return {
        "method": tr.method,
        "held": tr.held,
        "hold_reason": tr.hold_reason,
        "normalized": normed,
        "spans": span_dicts,
        "sanitized": tr.text,
        "substitutions": tr.substitutions,
        "missed_eids": missed,
        "leakage": {
            "span": span,
            "attribute": attr,
            "restorable_frac": round(restorable, 3),
        },
        "attack": attack,
    }


@app.post("/api/chat")
def api_chat(req: ChatRequest) -> dict:
    t0 = time.time()
    normed, span_dicts, entities = run_detect(req.text)
    tr = run_transform(normed, span_dicts, entities, req.method, req.rung_shift)

    by_eid = {e.eid: e for e in registry.entities}
    for e in entities:
        by_eid.setdefault(e.eid, e)
    eids = [s["eid"] for s in span_dicts if s["sensitive"] and s["eid"] in by_eid]

    def _forms(eid: str) -> list[str]:
        ent = by_eid[eid]
        if eid.startswith("ADHOC_"):
            return [ent.canonical]  # the value is its only surface
        return surface_forms(ent)

    surfaces = sorted({f for eid in eids for f in _forms(eid)})

    eval_subs, missed = eval_records(eids, tr, entities)
    span = span_leakage(tr.text, normed, surfaces)
    attr = attribute_leakage(eval_subs, registry, entities)
    attack = attack_all_substitutions(tr.text, eval_subs, registry, ladders,
                                      req.attacker_n, 777,
                                      entities=entities) if eval_subs else None
    n_subs = len(eval_subs)
    restorable = (sum(1 for s in eval_subs if s.get("restorable")) / n_subs
                  if n_subs else 1.0)

    try:
        model = answer_model()
        t1 = time.time()
        answer = model.complete(tr.text)
        latency = round(time.time() - t1, 1)
        model_name = model.name
    except Exception as e:  # noqa: BLE001 - surfaced to the UI as a plain error
        raise HTTPException(status_code=503,
                            detail=f"answer model unreachable ({type(e).__name__}: {e}). "
                                   f"Is Ollama running with {CHAT_MODEL} pulled?")

    return {
        "method": tr.method,
        "held": tr.held,
        "hold_reason": tr.hold_reason,
        "normalized": normed,
        "spans": span_dicts,
        "sanitized": tr.text,
        "substitutions": tr.substitutions,
        "missed_eids": missed,
        "leakage": {
            "span": span,
            "attribute": attr,
            "restorable_frac": round(restorable, 3),
        },
        "attack": attack,
        "answer": {"text": answer, "model": model_name, "latency_s": latency},
        "elapsed_s": round(time.time() - t0, 1),
    }


@app.get("/api/benchmark")
def api_benchmark() -> dict:
    path = ROOT / "results" / "run.json"
    if not path.exists():
        return {"available": False}
    run = json.loads(path.read_text(encoding="utf-8"))
    return {
        "available": True,
        "meta": run.get("meta"),
        "ceilings": run.get("ceilings"),
        "rows": [r for r in run.get("rows_executable", []) if "family" not in r],
    }


app.mount("/static", StaticFiles(directory=ROOT / "server" / "static"), name="static")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(ROOT / "server" / "static" / "index.html")
