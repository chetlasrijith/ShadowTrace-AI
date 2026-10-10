"""One command to run the pilot end to end.

    python scripts/run_pilot.py [--mode selftest|real] [--model NAME]
                                [--limit N] [--methods noop,redact,...]
                                [--families sql,extract] [--repeats R]

selftest (default) uses the deterministic stub: validates the harness,
writes results with the selftest flag, and labels every table as NOT
results. real requires --model and a reachable Ollama host; only its
numbers may be reported.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import yaml  # noqa: E402

from shadowtrace.detect.normalize import normalize  # noqa: E402
from shadowtrace.detect.registry import detect  # noqa: E402
from shadowtrace.evaluate.answers import (  # noqa: E402
    CachedModel, ResponseCache, StubAnswerModel, build_answer_model,
)
from shadowtrace.evaluate.attacker import attack_all_substitutions  # noqa: E402
from shadowtrace.evaluate.leakage import (  # noqa: E402
    attribute_leakage, false_positive_rate, span_leakage,
)
from shadowtrace.evaluate.metrics import aggregate  # noqa: E402
from shadowtrace.evaluate.utility import is_executable, score_answer  # noqa: E402
from shadowtrace.prompts import build_prompts, build_warehouse, load_prompts, save_prompts  # noqa: E402
from shadowtrace.report.render import render_report, save_run  # noqa: E402
from shadowtrace.transform.ladders import Ladders  # noqa: E402
from shadowtrace.transform.transforms import (  # noqa: E402
    transform_chain, transform_generalize, transform_noop, transform_redact,
)
from shadowtrace.transform.verify import count_survivors  # noqa: E402
from shadowtrace.universe import Registry, build_registry  # noqa: E402


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="ShadowTrace pilot runner")
    ap.add_argument("--mode", choices=["selftest", "real"], default=None)
    ap.add_argument("--model", default=None, help="Ollama model for --mode real")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--methods", default=None)
    ap.add_argument("--families", default=None)
    ap.add_argument("--repeats", type=int, default=None)
    ap.add_argument("--config", default=str(ROOT / "configs" / "pilot.yaml"))
    return ap.parse_args(argv)


def ground_truth_surfaces(prompt: Prompt, registry: Registry) -> dict[str, list[str]]:
    """All labeled sensitive surfaces per entity, from ground truth.

    Leakage is scored against these, never against detected spans. Scoring
    against detections hides the worst failures: an entity the detector
    missed would count as unleaked. Plan 8: span leakage is over LABELED
    spans.
    """
    from shadowtrace.detect.registry import surface_forms

    by_eid = {e.eid: e for e in registry.entities}
    out: dict[str, list[str]] = {}
    for eid in prompt.entities:
        ent = by_eid.get(eid)
        if ent is not None and ent.sensitive:
            out[eid] = surface_forms(ent)
    return out


def eval_substitutions(
    prompt: Prompt, registry: Registry,
    substitutions: list[dict],
) -> tuple[list[dict], list[str]]:
    """Substitution records for every ground-truth entity.

    Entities the transform never touched (detection miss, or noop) get a
    pseudo-record marking them fully present: their surfaces survive in the
    text, identity is known, restoration is trivial. Without this, missed
    entities vanish from every leakage number.
    Returns (records, missed_eids).
    """
    from shadowtrace.detect.registry import surface_forms

    by_eid = {e.eid: e for e in registry.entities}
    have = {s["eid"]: s for s in substitutions}
    records, missed = [], []
    for eid in prompt.entities:
        ent = by_eid.get(eid)
        if ent is None or not ent.sensitive:
            continue
        if eid in have:
            records.append(have[eid])
        else:
            forms = surface_forms(ent)
            records.append({
                "eid": eid, "etype": ent.etype, "surface": ent.canonical,
                "depth": 0, "replacement": " ".join(forms),
                "reveal": [], "restorable": True, "ambiguity_k": 1,
                "missed_by_transform": True,
            })
            missed.append(eid)
    return records, missed


def main(argv=None) -> int:
    args = parse_args(argv)
    with open(args.config, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)

    mode = args.mode or cfg.get("mode", "selftest")
    repeats = args.repeats or cfg.get("repeats", 1)
    methods = (args.methods.split(",") if args.methods
               else cfg.get("methods", ["noop", "redact", "generalize", "chain"]))
    families = set(args.families.split(",")) if args.families else None
    attacker_ns = cfg.get("attacker_n", [10])
    seed = cfg.get("seed", 11)

    if mode == "real" and not args.model:
        print("ERROR: --mode real requires --model <ollama-model>", file=sys.stderr)
        return 2
    model_name = args.model or cfg.get("answer_model", "stub-oracle-v1")

    t0 = time.time()
    paths = {k: ROOT / v for k, v in cfg["paths"].items()}

    # -- build -------------------------------------------------------------
    registry = build_registry(cfg.get("registry_seed", 20260101))
    registry.save(paths["registry"])
    prompts_all = build_prompts(registry, seed)
    save_prompts(prompts_all, paths["prompts"])
    warehouse = build_warehouse(registry, cfg.get("warehouse_seed", 7))
    ladders = Ladders.load(ROOT / "configs" / "ladders.yaml")

    if families:
        prompts_all = [p for p in prompts_all if p.family in families]
    if args.limit:
        prompts_all = prompts_all[:args.limit]

    # -- answer model ------------------------------------------------------
    if mode == "real":
        inner = build_answer_model(
            model_name, temperature=cfg.get("temperature", 0.0),
            seed=cfg.get("model_seed", 42))
    else:
        inner = StubAnswerModel()
    cache = ResponseCache(paths["cache"])
    model = CachedModel(inner, cache)

    # -- run ---------------------------------------------------------------
    records: list[dict] = []
    transform_failures = 0
    for prompt in prompts_all:
        normed = normalize(prompt.text)
        spans = detect(normed, registry)
        for method in methods:
            if method == "noop":
                tr = transform_noop(normed)
            elif method == "redact":
                tr = transform_redact(normed, spans, registry)
            elif method == "generalize":
                tr = transform_generalize(normed, spans, registry, ladders, prompt.family)
            elif method == "chain":
                tr = transform_chain(normed, spans, registry, ladders, prompt.family)
            else:
                raise ValueError(f"unknown method {method}")
            if tr.held:
                transform_failures += 1

            gt = ground_truth_surfaces(prompt, registry)
            sens_surfaces = sorted({s for forms in gt.values() for s in forms})
            eval_subs, missed = eval_substitutions(prompt, registry, tr.substitutions)
            span = span_leakage(tr.text, normed, sens_surfaces)
            attr = attribute_leakage(eval_subs, registry)
            fpr = false_positive_rate(spans, tr.text)

            # closed-set attacker at each N; primary N is the first listed
            reid_primary = attack_all_substitutions(
                tr.text, eval_subs, registry, ladders,
                attacker_ns[0], cfg.get("attacker_seed", 777))
            reid_extra = {}
            for n in attacker_ns[1:]:
                r = attack_all_substitutions(
                    tr.text, eval_subs, registry, ladders,
                    n, cfg.get("attacker_seed", 777))
                reid_extra[n] = {"rate": r["rate"], "correct": r["correct"],
                                 "total": r["total"], "chance": r["chance"]}

            for rep in range(repeats):
                answer = model.complete(tr.text, prompt, registry, ladders)
                util = score_answer(prompt, answer, registry, ladders,
                                    warehouse, tr.substitutions)
                n_subs = len(eval_subs)
                restorable = (sum(1 for s in eval_subs if s.get("restorable")) / n_subs
                              if n_subs else 1.0)
                # keep the full utility record minus large blobs: raw-vs-restored
                # success is the restoration-recovery comparison (plan 7.1.1)
                detail = {k: v for k, v in util.items()
                          if k not in ("model_sql", "code", "test_log", "gold_rows", "model_rows")}
                records.append({
                    "pid": prompt.pid, "family": prompt.family, "split": prompt.split,
                    "method": method, "rep": rep,
                    "executable": is_executable(prompt),
                    "task_success": util.get("task_success"),
                    "structural_valid": util.get("structural_valid"),
                    "scored_by": util.get("scored_by"),
                    "utility_detail": detail,
                    "span_leak": span["rate"],
                    "attr_leak": attr["mean"],
                    "reid_rate_item": (reid_primary["rate"]
                                       if reid_primary["total"] else None),
                    "reid_chance": reid_primary["chance"],
                    "reid_extra": reid_extra,
                    "reid_entities": reid_primary["results"],
                    "restorable_frac": restorable,
                    "fpr": fpr["rate"],
                    "held": tr.held,
                    "spans_found": tr.spans_found,
                    "n_substitutions": len(tr.substitutions),
                    "n_missed": len(missed),
                    "missed_eids": missed,
                    "survivors": count_survivors(tr.text, set(sens_surfaces)),
                })

    exec_recs = [r for r in records if r["executable"]]
    draft_recs = [r for r in records if not r["executable"]]
    rows_exec = aggregate(exec_recs, ["method", "family"])
    rows_exec_all = aggregate(exec_recs, ["method"])
    rows_draft = aggregate(draft_recs, ["method"])

    ceilings: dict = {}
    for fam in sorted({p.family for p in prompts_all}):
        base = [r for r in records if r["family"] == fam and r["method"] == "noop"
                and r.get("task_success") is not None]
        ceilings[fam] = {
            "n": len(base),
            "success": (sum(1 for r in base if r["task_success"]) / len(base)) if base else 0.0,
        }

    failures = [
        f"transform holds (both rewrite and redact failed checks): {transform_failures} prompt-method pairs",
        f"repeats={repeats} (plan asks >=3; single-repeat variance is unmeasured)",
        f"attacker N values run: {attacker_ns}; small type pools fall back to full-pool candidacy",
        "code sandbox has no network firewall; imports rejected pre-execution instead",
    ]
    meta = {
        "mode": mode, "answer_model": model.name, "repeats": repeats,
        "attacker_n": attacker_ns, "n_entities": len(registry.entities),
        "n_prompts": len(prompts_all), "seed": seed,
        "methods": methods, "cache_hits": model.hits, "cache_misses": model.misses,
        "elapsed_s": round(time.time() - t0, 1),
    }
    report = render_report(rows_exec_all + rows_exec, rows_draft, meta, ceilings, failures)
    print(report)
    paths["report"].write_text(report, encoding="utf-8")
    save_run(paths["run"], records, rows_exec_all + rows_exec, rows_draft, meta, ceilings)
    print(f"\nwrote {paths['report']} and {paths['run']} "
          f"(cache hits={model.hits} misses={model.misses}, {meta['elapsed_s']}s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
