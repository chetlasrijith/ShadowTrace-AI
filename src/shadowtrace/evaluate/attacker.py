"""Closed-set re-identification attacker. Plan 5.1.

The attacker receives the sanitized text and a candidate set of N entities of
the same type drawn from the registry, always including the truth. It scores
each candidate by surface and attribute evidence visible in the text and
picks the argmax with deterministic tie-breaking.

This is deliberately a weak, fully reproducible attacker: lexical evidence,
no embeddings, no background knowledge beyond the registry. Every number it
produces is therefore a LOWER BOUND on what a stronger attacker could do.
The H2 claim "generalization does not make re-identification easier than
placeholders" is not settled until a stronger attacker exists, and the
report must say so. What this attacker does settle is the comparison between
methods under identical, disclosed conditions.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..transform.ladders import Ladders, context_for
from ..universe import Entity, Registry


@dataclass
class AttackResult:
    eid_true: str
    eid_pred: str | None
    correct: bool
    credit: float  # fractional credit: 1/k on a k-way tie for top, else 0
    n_candidates: int
    chance: float
    scores_top3: list[tuple[str, float]]

    def to_dict(self) -> dict:
        return {
            "eid_true": self.eid_true, "eid_pred": self.eid_pred,
            "correct": self.correct, "credit": self.credit,
            "n_candidates": self.n_candidates,
            "chance": self.chance, "scores_top3": self.scores_top3,
        }


def _evidence(text: str, ent: Entity, ladders: Ladders) -> float:
    """Lexical score: how much of this entity is visible in the text?"""
    t = text.lower()
    score = 0.0
    if ent.canonical.lower() in t:
        score += 4.0  # exact token survives: game over
    if ent.name.lower() in t and len(ent.name) >= 4:
        score += 4.0
    for a in ent.aliases:
        if len(a) >= 4 and a.lower() in t:
            score += 2.0
    for key, val in context_for(ent).items():
        if key == "canonical" or not val:
            continue
        sval = str(val).lower()
        if len(sval) >= 3 and sval in t:
            score += 1.0
    # ladder renderings: the attacker has read the config (plan 6.2.1)
    for depth in range(0, ladders.max_depth(ent.etype) + 1):
        rendered = ladders.render(ent, depth).lower()
        if len(rendered) >= 4 and rendered in t:
            score += 1.5
    return score


def attack(
    text: str, truth: Entity, candidates: list[Entity],
    registry: Registry, ladders: Ladders, seed: int = 0,
) -> AttackResult:
    import random

    order = list(candidates)
    random.Random(seed).shuffle(order)  # deterministic pick for the record
    scored = [(c.eid, _evidence(text, c, ladders)) for c in order]
    best_eid, best_score = scored[0]
    for eid, score in scored[1:]:
        if score > best_score:
            best_eid, best_score = eid, score
    # fractional credit: the unbiased value of a random tie-break, without
    # the variance of actually breaking ties. k-way tie for top (including
    # a tie that contains the truth) scores 1/k.
    top = [eid for eid, s in scored if s == best_score]
    credit = (1.0 / len(top)) if truth.eid in top else 0.0
    scored.sort(key=lambda kv: (-kv[1], kv[0]))
    return AttackResult(
        eid_true=truth.eid, eid_pred=best_eid,
        correct=(best_eid == truth.eid), credit=round(credit, 4),
        n_candidates=len(candidates),
        chance=1.0 / len(candidates) if candidates else 0.0,
        scores_top3=[(eid, round(s, 2)) for eid, s in scored[:3]],
    )


def attack_all_substitutions(
    text: str, substitutions: list[dict], registry: Registry,
    ladders: Ladders, n: int, seed: int,
    entities: list[Entity] | None = None,
) -> dict:
    """Run the closed-set attack for every substituted entity.

    Substitutions with no surviving truth in the registry are skipped and
    counted, never silently dropped.

    `entities` carries ad-hoc entities minted for this text (chat path).
    Ad-hoc values have no universe to choose from, so they are scored
    directly: credit 1.0 when the exact value survives in the text, 0.0
    when the rewrite removed it. Chance is reported as 1.0 (n=1) so the
    number reads as survival, not identification.
    """
    by_eid = {e.eid: e for e in registry.entities}
    if entities:
        for e in entities:
            by_eid.setdefault(e.eid, e)
    results, skipped = [], 0
    for idx, sub in enumerate(substitutions):
        truth = by_eid.get(sub["eid"])
        if truth is None:
            skipped += 1
            continue
        if sub["eid"].startswith("ADHOC_"):
            survived = sub["surface"].lower() in text.lower()
            results.append({
                "eid_true": truth.eid, "eid_pred": truth.eid if survived else None,
                "correct": survived, "credit": 1.0 if survived else 0.0,
                "n_candidates": 1, "chance": 1.0,
                "scores_top3": [(truth.eid, 4.0 if survived else 0.0)],
                "ad_hoc": True,
            })
            continue
        cands = registry.candidate_set(truth.etype, n, seed + idx, exclude_eid=truth.eid)
        results.append(attack(text, truth, cands, registry, ladders, seed + idx).to_dict())
    correct = sum(1 for r in results if r["correct"])
    credit = sum(r["credit"] for r in results)
    n_res = len(results)
    rate = credit / n_res if n_res else 0.0  # mean fractional credit
    # mean per-result chance: equals 1/n when every candidate set is full,
    # and stays honest under small-pool fallback or ad-hoc n=1 results
    chance = sum(r["chance"] for r in results) / n_res if n_res else 0.0
    return {
        "n": n, "rate": rate, "credit": credit, "correct": correct,
        "total": n_res, "skipped": skipped,
        "chance": chance,
        "results": results,
    }