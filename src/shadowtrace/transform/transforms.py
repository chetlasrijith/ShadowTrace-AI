"""The three transforms under test.

- noop: baseline A, unprotected.
- redact: baseline B, canonical placeholder per entity type.
- generalize: method D, ladder rungs per the configured depth.
- fallback chain: generalize -> redact -> hold, with all failures logged.

Each returns a TransformResult carrying the rewritten text, the substitution
map, and a verdict. The map is what makes restoration-success and H2 scoring
possible downstream.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..universe import Entity, Registry
from .ladders import Ladders

PLACEHOLDERS = {
    "org": "[ORG]", "system": "[SYSTEM]", "person": "[PERSON]",
    "amount": "[AMOUNT]", "identifier": "[ID]", "location": "[LOCATION]",
    "email": "[EMAIL]", "phone": "[PHONE]", "password": "[PASSWORD]",
    "employee_id": "[EMPLOYEE_ID]", "api_key": "[API_KEY]", "card": "[CARD]",
}


@dataclass
class TransformResult:
    method: str
    text: str
    substitutions: list[dict] = field(default_factory=list)
    spans_found: int = 0
    held: bool = False
    hold_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "method": self.method, "text": self.text,
            "substitutions": self.substitutions,
            "spans_found": self.spans_found,
            "held": self.held, "hold_reason": self.hold_reason,
        }


def _placeholder(etype: str) -> str:
    return PLACEHOLDERS.get(etype, f"[{etype.upper()}]")


def _apply(text: str, repls: list[tuple[int, int, str]]) -> str:
    """Apply non-overlapping replacements back to front."""
    out = text
    for start, end, new in sorted(repls, key=lambda r: -r[0]):
        out = out[:start] + new + out[end:]
    return out


def transform_noop(text: str) -> TransformResult:
    return TransformResult(method="noop", text=text)


def transform_redact(
    text: str, spans: list, registry: Registry | None = None,
) -> TransformResult:
    """Replace every sensitive span with its type placeholder."""
    repls, subs = [], []
    for s in spans:
        if not s.sensitive:
            continue
        ph = _placeholder(s.etype)
        repls.append((s.start, s.end, ph))
        subs.append({
            "eid": s.eid, "etype": s.etype, "surface": s.surface,
            "depth": -1, "replacement": ph,
            "reveal": [], "restorable": False, "ambiguity_k": -1,
        })
    return TransformResult(
        method="redact", text=_apply(text, repls),
        substitutions=subs, spans_found=len([s for s in spans if s.sensitive]),
    )


def transform_generalize(
    text: str, spans: list, registry: Registry, ladders: Ladders,
    family: str, depth_overrides: dict | None = None,
    entities: list[Entity] | None = None,
) -> TransformResult:
    """Render every sensitive span at its ladder rung.

    `depth_overrides` maps eid -> depth and is what a per-prompt fitted
    policy would supply. The pilot uses the configured depths.

    `entities` is the per-request lookup for ad-hoc entities minted by
    detect_all (chat path). Registry entities resolve from the registry;
    when omitted, ad-hoc spans are skipped and counted, never dropped.
    """
    repls, subs = [], []
    depth_overrides = depth_overrides or {}
    by_eid = {e.eid: e for e in registry.entities}
    if entities:
        for e in entities:
            by_eid.setdefault(e.eid, e)
    skipped = 0
    for s in spans:
        if not s.sensitive:
            continue
        ent = by_eid.get(s.eid)
        if ent is None:
            skipped += 1
            continue
        depth = depth_overrides.get(s.eid, ladders.depth_for(ent.etype, family))
        replacement = ladders.render(ent, depth)
        repls.append((s.start, s.end, replacement))
        if ent.eid.startswith("ADHOC_"):
            # no universe to be ambiguous in: restoration is against this
            # text's own entity set via the logged substitution map
            same = [e for e in (entities or [])
                    if e.etype == ent.etype
                    and ladders.render(e, depth).lower() == replacement.lower()]
            restorable, ambiguity = len(same) == 1, len(same)
        else:
            restorable = ladders.is_restorable(registry, ent, depth)
            ambiguity = ladders.ambiguity_class(registry, ent, depth)
        subs.append({
            "eid": s.eid, "etype": ent.etype, "surface": s.surface,
            "depth": depth, "replacement": replacement,
            "reveal": list(ladders.reveal(ent, depth)),
            "restorable": restorable,
            "ambiguity_k": ambiguity,
        })
    detected = len([s for s in spans if s.sensitive])
    return TransformResult(
        method="generalize", text=_apply(text, repls),
        substitutions=subs, spans_found=detected,
    )


def transform_chain(
    text: str, spans: list, registry: Registry, ladders: Ladders,
    family: str, depth_overrides: dict | None = None,
    entities: list[Entity] | None = None,
) -> TransformResult:
    """Fallback chain: generalize -> redact -> hold. Plan 6.4."""
    from .verify import verify_no_surviving_spans

    gen = transform_generalize(text, spans, registry, ladders, family,
                               depth_overrides, entities)
    if verify_no_surviving_spans(gen.text, set(s.surface for s in spans if s.sensitive)):
        return gen
    red = transform_redact(text, spans, registry)
    if verify_no_surviving_spans(red.text, set(s.surface for s in spans if s.sensitive)):
        red.method = "generalize_fallback_redact"
        return red
    return TransformResult(
        method="held", text=text, held=True,
        hold_reason="sensitive spans survive both generalize and redact",
        spans_found=len([s for s in spans if s.sensitive]),
    )