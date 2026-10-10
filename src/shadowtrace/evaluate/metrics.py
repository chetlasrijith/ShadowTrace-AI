"""Aggregation with bootstrap confidence intervals.

Every rate is reported as (point estimate, 95% percentile interval) over
prompts, seed fixed. With ~50 pilot prompts the intervals will be wide; the
report prints their widths as a headline limitation and refuses to claim
significance from an overlap (plan 8.2).

Absolute task success is the primary utility axis. The original-prompt
ceiling is reported per family, and the sanitized/original ratio appears
only as a secondary column with the denominator printed next to it (8.1).
"""

from __future__ import annotations

import random
from typing import Any

BOOTSTRAP_B = 2000
BOOTSTRAP_SEED = 20260202


def bootstrap_ci(values: list[float], b: int = BOOTSTRAP_B,
                 seed: int = BOOTSTRAP_SEED) -> tuple[float, float, float]:
    """Return (mean, lo, hi) 95% percentile interval. Empty -> (0,0,0)."""
    if not values:
        return 0.0, 0.0, 0.0
    rng = random.Random(seed)
    n = len(values)
    stats = []
    for _ in range(b):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        stats.append(sum(sample) / n)
    stats.sort()
    lo = stats[int(0.025 * b)]
    hi = stats[int(0.975 * b)]
    return sum(values) / n, lo, hi


def mean_ci(pairs: list[tuple[float, float, float]]) -> dict:
    mean, lo, hi = pairs[0] if pairs else (0.0, 0.0, 0.0)
    return {"mean": round(mean, 3), "lo": round(lo, 3), "hi": round(hi, 3),
            "width": round(hi - lo, 3)}


def aggregate(records: list[dict], group_keys: list[str]) -> list[dict]:
    """Aggregate per-item records into grouped rows with CIs.

    Each record carries: method, family, split, executable (bool),
    task_success (bool|None), structural_valid, span_leak (float),
    attr_leak (float), reid_correct (bool|None), reid_chance,
    restorable_frac, fpr, held (bool).
    """
    groups: dict[tuple, list[dict]] = {}
    for r in records:
        key = tuple(r[k] for k in group_keys)
        groups.setdefault(key, []).append(r)
    rows = []
    for key, rs in sorted(groups.items(), key=lambda kv: str(kv[0])):
        row: dict[str, Any] = dict(zip(group_keys, key))
        row["n"] = len(rs)
        succ = [1.0 if r["task_success"] else 0.0 for r in rs
                if r.get("task_success") is not None]
        row["task_success"] = mean_ci([bootstrap_ci(succ)])
        row["n_utility"] = len(succ)
        struct = [1.0 if r.get("structural_valid") else 0.0 for r in rs]
        row["structural_valid"] = mean_ci([bootstrap_ci(struct)])
        row["span_leakage"] = mean_ci([bootstrap_ci([r["span_leak"] for r in rs])])
        row["attribute_leakage"] = mean_ci([bootstrap_ci([r["attr_leak"] for r in rs])])
        reid = [float(r["reid_rate_item"]) for r in rs
                if r.get("reid_rate_item") is not None]
        row["reid_rate"] = mean_ci([bootstrap_ci(reid)])
        chances = [r.get("reid_chance") for r in rs if r.get("reid_chance")]
        row["reid_chance"] = round(sum(chances) / len(chances), 3) if chances else None
        rest = [r.get("restorable_frac", 0.0) for r in rs]
        row["restorable_frac"] = mean_ci([bootstrap_ci(rest)])
        row["fpr"] = mean_ci([bootstrap_ci([r.get("fpr", 0.0) for r in rs])])
        row["held"] = sum(1 for r in rs if r.get("held"))
        rows.append(row)
    return rows
