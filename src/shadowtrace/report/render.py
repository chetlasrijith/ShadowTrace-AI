"""Text and JSON reporting.

Two outputs: a human-readable report.txt with per-method, per-family tables
and an explicit limitations block, and a machine-readable run.json with
every per-item record. Drafting appears only in its own section, headed
with the warning that its numbers are structural proxies, not utility.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _fmt(m: dict) -> str:
    return f"{m['mean']:.3f} [{m['lo']:.3f}, {m['hi']:.3f}]"


def _fmt_util(r: dict) -> str:
    if not r.get("n_utility"):
        return "n/a (proxy, not utility)"
    return _fmt(r["task_success"])


def render_table(rows: list[dict], title: str) -> str:
    lines = [title, "=" * len(title)]
    header = (f"{'method':<12}{'family':<10}{'n':>4}  "
              f"{'task_success':<26}{'struct_valid':<26}  "
              f"{'span_leak':<26}{'attr_leak':<26}  "
              f"{'reid_rate':<26}{'restorable':<26}  {'fpr':<14}{'held':>5}")
    lines.append(header)
    lines.append("-" * len(header))
    for r in rows:
        lines.append(
            f"{r.get('method',''):<12}{r.get('family',''):<10}{r['n']:>4}  "
            f"{_fmt_util(r):<26}{_fmt(r['structural_valid']):<26}  "
            f"{_fmt(r['span_leakage']):<26}{_fmt(r['attribute_leakage']):<26}  "
            f"{_fmt(r['reid_rate']):<26}{_fmt(r['restorable_frac']):<26}  "
            f"{_fmt(r['fpr']):<14}{r['held']:>5}"
        )
    chance = {r.get("reid_chance") for r in rows if r.get("reid_chance") is not None}
    if chance:
        lines.append(f"(closed-set attacker chance rate: {sorted(chance)})")
    return "\n".join(lines)


def render_report(
    rows_exec: list[dict], rows_draft: list[dict], meta: dict,
    ceilings: dict, failures: list[str],
) -> str:
    parts = []
    parts.append("SHADOW AI LEAK DETECTOR -- PILOT REPORT")
    parts.append(f"mode: {meta.get('mode')} | answer model: {meta.get('answer_model')} | "
                 f"repeats: {meta.get('repeats')} | attacker N: {meta.get('attacker_n')}")
    parts.append(f"registry: {meta.get('n_entities')} entities | "
                 f"prompts: {meta.get('n_prompts')} | seed: {meta.get('seed')}")
    parts.append("")
    if meta.get("mode") == "selftest":
        parts.append("!!! SELFTEST MODE: stub answer model. These numbers validate the")
        parts.append("!!! harness only. They are NOT results and must not be quoted.")
        parts.append("")
    parts.append("ORIGINAL-PROMPT CEILINGS (absolute task success, unprotected baseline)")
    for fam, c in sorted(ceilings.items()):
        parts.append(f"  {fam:<10} n={c['n']:>3}  success={c['success']:.3f}")
    parts.append("")
    parts.append(render_table(rows_exec, "EXECUTABLE FAMILIES (sql, code, extract, docqa)"))
    parts.append("")
    if rows_draft:
        parts.append(render_table(rows_draft, "DRAFTING -- STRUCTURAL PROXIES, NOT UTILITY. "
                                              "Do not compare with the table above."))
        parts.append("")
    parts.append("LIMITATIONS")
    for f in failures:
        parts.append(f"  - {f}")
    parts.append("  - attacker is lexical only: every re-id rate is a lower bound.")
    parts.append("  - registry-match detection measures transforms, not real NER.")
    parts.append("  - pilot n is small; interval widths above are the finding.")
    return "\n".join(parts)


def save_run(path: Path, records: list[dict], rows_exec: list[dict],
             rows_draft: list[dict], meta: dict, ceilings: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump({
            "meta": meta, "ceilings": ceilings,
            "rows_executable": rows_exec, "rows_drafting": rows_draft,
            "records": records,
        }, fh, indent=1)
