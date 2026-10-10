"""Ladder loading, rendering, and the restoration test.

The restoration test is the part that distinguishes generalization from
redaction. A descriptive rung can be mapped back to the original entity only if
its rendering is unique among all entities of that type. If several entities
share the rendering, the system genuinely does not know which one was meant and
the correct product behavior is to ask the user. Redaction never restores,
because a placeholder carries no attributes at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..universe import Entity, Registry

PLACEHOLDER_DEPTH = -1  # sentinel: behave like a placeholder


@dataclass(frozen=True)
class Rung:
    depth: int
    template: str
    reveal: tuple[str, ...]


class Ladders:
    def __init__(self, config: dict):
        self.raw = config
        self.ladders: dict[str, list[Rung]] = {}
        for etype, rungs in config.get("ladders", {}).items():
            self.ladders[etype] = [
                Rung(r["depth"], r["template"], tuple(r.get("reveal", [])))
                for r in sorted(rungs, key=lambda r: r["depth"])
            ]
        self.default_depth: dict[str, int] = config.get("default_depth", {})
        self.policy: dict[tuple[str, str], int] = {}
        p = config.get("fitted_policy")
        if p:
            for key, depth in p.items():
                etype, family = key.split("|")
                self.policy[(etype, family)] = depth

    @classmethod
    def load(cls, path: str | Path) -> "Ladders":
        with Path(path).open(encoding="utf-8") as fh:
            return cls(yaml.safe_load(fh))

    # -- rendering ---------------------------------------------------------

    def max_depth(self, etype: str) -> int:
        return max(r.depth for r in self.ladders.get(etype, []))

    def depth_for(self, etype: str, family: str, budget: float | None = None) -> int:
        """Resolve the generalization depth for one entity."""
        if etype not in self.ladders:
            return PLACEHOLDER_DEPTH
        key = (etype, family)
        if key in self.policy:
            depth = self.policy[key]
        else:
            depth = self.default_depth.get(etype, 1)
        if budget is not None:
            # sweep parameter: budget is the maximum number of attributes
            # allowed to be disclosed on the utility-safe rung
            allowed = self._depth_within_budget(etype, budget)
            depth = min(depth, allowed)
        return min(depth, self.max_depth(etype))

    def _depth_within_budget(self, etype: str, budget: float) -> int:
        for rung in self.ladders[etype]:
            if len(rung.reveal) <= budget:
                return rung.depth
        return self.max_depth(etype)

    def render(self, ent: Entity, depth: int) -> str:
        """Render one entity at one rung."""
        rungs = self.ladders.get(ent.etype)
        if not rungs:
            return f"[{ent.etype.upper()}]"
        if 0 <= depth <= self.max_depth(ent.etype):
            chosen = next(r for r in rungs if r.depth == depth)
        else:
            chosen = rungs[-1]  # unknown depth or placeholder sentinel: safest rung
        return chosen.template.format(**context_for(ent))

    def rung(self, ent: Entity, depth: int) -> Rung:
        rungs = self.ladders.get(ent.etype)
        if not rungs:
            return Rung(depth, "[{etype}]", ())
        if 0 <= depth <= self.max_depth(ent.etype):
            return next(r for r in rungs if r.depth == depth)
        return rungs[-1]

    # -- restoration -------------------------------------------------------

    def restore_candidates(self, registry: Registry, ent: Entity, depth: int) -> list[Entity]:
        """Entities whose rendering at `depth` is identical to this one's.

        Length 1 means restorable. Length > 1 is the ambiguity class.
        """
        target = self.render(ent, depth).lower()
        out = []
        for cand in registry.of_type(ent.etype):
            if not cand.sensitive:
                continue
            if self.render(cand, depth).lower() == target:
                out.append(cand)
        return out

    def is_restorable(self, registry: Registry, ent: Entity, depth: int) -> bool:
        return len(self.restore_candidates(registry, ent, depth)) == 1

    def ambiguity_class(self, registry: Registry, ent: Entity, depth: int) -> int:
        return len(self.restore_candidates(registry, ent, depth))

    def vocabulary_size(self, etype: str, depth: int) -> int:
        """Number of distinct strings this rung can produce. Plan 6.2.1."""
        return len(self.ladders.get(etype, []))

    def reveal(self, ent: Entity, depth: int) -> tuple[str, ...]:
        return self.rung(ent, depth).reveal


def context_for(ent: Entity) -> dict[str, Any]:
    """Template rendering context for one entity."""
    a = ent.attributes
    ctx: dict[str, Any] = {"canonical": ent.canonical}
    for k in ("industry", "size", "region", "function", "department"):
        ctx[k] = a.get(k, "")
    ctx["magnitude"] = a.get("magnitude", "")
    value = a.get("value")
    if value is not None:
        ctx["value"] = value
        ctx["value_rounded"] = _round_value(value)
    # ad-hoc PII attributes (absent on registry entities: default "")
    for k in ("domain", "user", "last4", "value_kind", "scheme"):
        ctx[k] = a.get(k, "")
    ctx["secret_len"] = len(ent.canonical)
    if "-" in ent.canonical:
        parts = ent.canonical.split("-")
        ctx["id_prefix"] = parts[0]
        ctx["id_suffix"] = parts[-1]
    return ctx


def _round_value(value: int) -> str:
    step = 100_000 if value >= 1_000_000 else 10_000
    rounded = (value // step) * step
    return f"{rounded:,}"