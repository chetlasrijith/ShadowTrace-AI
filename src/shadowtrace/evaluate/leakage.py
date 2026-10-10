"""Leakage measures. Plan 5 and 8.

Three independent axes, reported separately because they disagree in
informative ways:

- span_leakage: fraction of sensitive surfaces still present verbatim.
  Catches depth-0 passthrough and broken transforms. Misses descriptive
  leakage by construction.
- attribute_leakage: fraction of ground-truth attributes disclosed per
  entity, averaged. Attacker-independent: computed from the substitution
  record against the registry, no model in the loop. The pseudo-attribute
  "identity" is disclosed exactly when the exact surface survives, so a
  depth-0 render scores 1.0 and a placeholder scores 0.0.
- re-identification: lives in attacker.py, closed candidate set.

False positives are measured here too: a non-sensitive span that disappears
from the rewrite is an over-fire, whether the detector or the transform is
at fault.
"""

from __future__ import annotations

from ..universe import Entity, Registry

IDENTITY = "identity"

# reveal entries that are not literal attribute keys
REVEAL_ALIASES = {"exact_value": "value"}


def _entity_attributes(ent: Entity) -> dict:
    return {k: v for k, v in ent.attributes.items() if v not in (None, "", "n/a")}


def _normalise_reveal(reveal: list[str]) -> set[str]:
    return {REVEAL_ALIASES.get(r, r) for r in reveal}


def attribute_leakage_for_sub(sub: dict, ent: Entity) -> float:
    """Fraction of this entity's attribute information disclosed [0, 1]."""
    attrs = _entity_attributes(ent)
    total = len(attrs) + 1  # + identity
    surface_survives = sub["surface"].lower() in sub["replacement"].lower()
    disclosed = set(_normalise_reveal(sub.get("reveal", [])))
    if surface_survives:
        disclosed = set(attrs) | {IDENTITY}  # identity known => everything known
    disclosed = {d for d in disclosed if d in set(attrs) | {IDENTITY}}
    return len(disclosed) / total if total else 0.0


def attribute_leakage(
    substitutions: list[dict], registry: Registry,
    entities: list[Entity] | None = None,
) -> dict:
    by_eid = {e.eid: e for e in registry.entities}
    if entities:
        for e in entities:
            by_eid.setdefault(e.eid, e)
    per_entity = []
    for s in substitutions:
        ent = by_eid.get(s["eid"])
        if ent is None:
            continue
        per_entity.append({
            "eid": s["eid"], "etype": ent.etype, "depth": s.get("depth"),
            "leakage": attribute_leakage_for_sub(s, ent),
            "ambiguity_k": s.get("ambiguity_k", -1),
            "restorable": s.get("restorable", False),
        })
    mean = sum(p["leakage"] for p in per_entity) / len(per_entity) if per_entity else 0.0
    return {"mean": mean, "per_entity": per_entity, "n": len(per_entity)}


def span_leakage(transformed: str, original: str, sensitive_surfaces: list[str]) -> dict:
    """Fraction of labeled sensitive spans still present.

    The denominator is surfaces present in the ORIGINAL text, not every
    surface the entity could take. An alias that never appeared cannot leak,
    and counting it would push every rate down, including noop below 1.0.
    """
    present = sorted({s for s in set(sensitive_surfaces) if s and s.lower() in original.lower()})
    lowered = transformed.lower()
    survivors = sorted({s for s in present if s.lower() in lowered})
    rate = len(survivors) / len(present) if present else 0.0
    return {"rate": rate, "survivors": survivors,
            "n_sensitive": len(present), "n_forms": len(set(sensitive_surfaces))}


def false_positive_rate(original_spans: list, transformed_text: str) -> dict:
    """Fraction of non-sensitive detected spans altered by the transform."""
    lowered = transformed_text.lower()
    nonsens = [s for s in original_spans if not s.sensitive]
    altered = [s.surface for s in nonsens if s.surface.lower() not in lowered]
    rate = len(altered) / len(nonsens) if nonsens else 0.0
    return {"rate": rate, "altered": altered, "n_nonsensitive": len(nonsens)}