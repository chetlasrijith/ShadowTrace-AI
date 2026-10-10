"""Dictionary detection against the synthetic registry.

The detector sees only surface forms. In production this would be Presidio
plus NER plus a tagging model; here the registry stands in for all of them.
The evaluation is therefore a claim about transformation quality, not about
real-world NER accuracy, and plan 9 keeps a detector ablation slot open for
that separate question.

Word-boundary matching. Canonical tokens like ``tbl_7f3a`` and comma
amounts like ``4,825,000`` are matched exactly. Bare digit amounts match only
at five or more digits, so a quantity like ``30`` in a doc never fires while
``4825000`` does.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..universe import Entity, Registry


@dataclass(frozen=True)
class Span:
    eid: str
    etype: str
    surface: str
    start: int
    end: int
    sensitive: bool
    ad_hoc: bool = False  # True when the entity was minted for this text

    def to_dict(self) -> dict:
        return {
            "eid": self.eid, "etype": self.etype, "surface": self.surface,
            "start": self.start, "end": self.end, "sensitive": self.sensitive,
            "ad_hoc": self.ad_hoc,
        }


def _amount_names(ent: Entity) -> list[str]:
    if ent.etype != "amount":
        return []
    # formatted name is the canonical surface; bare digits match long values
    forms = [ent.name]
    if ent.canonical.isdigit() and len(ent.canonical) >= 5:
        forms.append(ent.canonical)
    return forms


def surface_forms(ent: Entity) -> list[str]:
    """Every surface string that identifies this entity."""
    if ent.etype == "amount":
        return _amount_names(ent)
    forms = [ent.canonical, ent.name, *ent.aliases]
    # drop noise aliases that would over-fire (single first names collide)
    forms = [f for f in forms if len(f) >= 4 or "_" in f or "-" in f]
    return sorted(set(forms), key=len, reverse=True)


def build_patterns(registry: Registry) -> list[tuple[re.Pattern, Entity]]:
    patterns: list[tuple[re.Pattern, Entity]] = []
    for ent in registry.entities:
        for form in surface_forms(ent):
            # underscore/dash tokens need a lookahead boundary, not \b
            pat = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(form) + r"(?![A-Za-z0-9_])")
            patterns.append((pat, ent))
    return patterns


def detect(text: str, registry: Registry, normalize_fn=None) -> list[Span]:
    """Return non-overlapping spans, longest match first.

    Registry dictionary only. Unchanged by the ad-hoc PII layer, so the
    benchmark (which contains no ad-hoc shapes) is byte-identical.
    """
    from .normalize import normalize

    norm = (normalize_fn or normalize)(text)
    patterns = build_patterns(registry)
    raw: list[Span] = []
    for pat, ent in patterns:
        for m in pat.finditer(norm):
            raw.append(Span(
                eid=ent.eid, etype=ent.etype, surface=m.group(0),
                start=m.start(), end=m.end(), sensitive=ent.sensitive,
            ))
    # longest match wins on overlap
    raw.sort(key=lambda s: (s.start, -(s.end - s.start)))
    out: list[Span] = []
    for span in raw:
        if any(o.start < span.end and span.start < o.end for o in out):
            continue
        out.append(span)
    out.sort(key=lambda s: s.start)
    return out


def detect_all(
    text: str, registry: Registry, normalize_fn=None,
) -> tuple[list[Span], list[Entity]]:
    """Registry spans plus ad-hoc PII spans for free-form text.

    Returns (spans, ad_hoc_entities). Each ad-hoc entity is minted
    deterministically from its etype + value, so the same value in one text
    always maps to one eid and the substitution map stays consistent.
    Registry spans win ties on overlap (they are ground truth); ad-hoc
    matches must be strictly non-overlapping with them.

    The benchmark path keeps calling detect(); only chat uses detect_all().
    """
    import hashlib

    from .normalize import normalize
    from .pii import scan_pii

    norm = (normalize_fn or normalize)(text)
    reg_spans = detect(norm, registry, normalize_fn=lambda s: s)
    taken = [(s.start, s.end) for s in reg_spans]

    entities: list[Entity] = []
    by_value: dict[tuple[str, str], Entity] = {}
    spans: list[Span] = list(reg_spans)
    for hit in scan_pii(norm):
        if any(a < hit.end and hit.start < b for a, b in taken):
            continue
        key = (hit.etype, hit.value)
        ent = by_value.get(key)
        if ent is None:
            digest = hashlib.sha256(f"{hit.etype}:{hit.value}".encode()).hexdigest()[:8]
            ent = Entity(
                eid=f"ADHOC_{hit.etype.upper()}_{digest}",
                etype=hit.etype,
                canonical=hit.value,
                name=hit.value,
                aliases=(),
                attributes=dict(hit.attributes),
                sensitivity="high",
                sensitive=True,
            )
            by_value[key] = ent
            entities.append(ent)
        spans.append(Span(
            eid=ent.eid, etype=ent.etype, surface=hit.value,
            start=hit.start, end=hit.end, sensitive=True, ad_hoc=True,
        ))
        taken.append((hit.start, hit.end))
    spans.sort(key=lambda s: s.start)
    return spans, entities