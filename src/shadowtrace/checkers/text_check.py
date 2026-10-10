"""Exact-match checkers for extraction and document Q&A.

The resolution rule is what makes these families fair to generalization. A
reference in the answer is accepted when it is either the exact canonical
token or any rendering that maps back to the true entity unambiguously
(registry plus ladders). A placeholder never maps back, so redaction fails
these items, correctly: a placeholder carries no information and nothing
local can restore it.

``resolve_reference`` is the single place this rule lives; both checkers use
it, so the two families cannot drift apart.
"""

from __future__ import annotations

import json
import re

from ..transform.ladders import Ladders
from ..universe import Entity, Registry


def resolve_reference(fragment: str, etype: str, registry: Registry, ladders: Ladders) -> Entity | None:
    """Map an answer fragment to a registry entity, or None.

    Accepts the canonical token, the display name, any alias, or any ladder
    rendering of depth >= 1 that is unique among sensitive entities of that
    type. Ambiguous renderings resolve to None.
    """
    frag = fragment.strip().lower()
    if not frag:
        return None
    for ent in registry.of_type(etype):
        if not ent.sensitive:
            continue
        if frag in {ent.canonical.lower(), ent.name.lower(), *(a.lower() for a in ent.aliases)}:
            return ent
    matches = []
    for ent in registry.of_type(etype):
        if not ent.sensitive:
            continue
        for depth in range(1, ladders.max_depth(ent.etype) + 1):
            if ladders.render(ent, depth).lower() == frag:
                matches.append(ent)
                break
    if len(matches) == 1:
        return matches[0]
    return None


def _extract_json(text: str) -> dict | None:
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None


def _boundary_pat(form: str) -> "re.Pattern":
    return re.compile(r"(?<![A-Za-z0-9_,])" + re.escape(form) + r"(?![A-Za-z0-9_,])")


def _contains_reference(have: str, ent: Entity, registry: Registry, ladders: Ladders) -> bool:
    """Does the answer contain this entity as a standalone span?

    Whole-answer equality is the primary rule; this is the fallback for a
    correct value embedded in conversational prose ("The account code is
    X."). Boundary guards stop "30" matching inside "30,700,000".
    """
    forms = [ent.canonical, ent.name, *ent.aliases]
    forms += [ladders.render(ent, d)
              for d in range(1, ladders.max_depth(ent.etype) + 1)]
    for form in forms:
        if form and _boundary_pat(form).search(have):
            # an ambiguous rendering that also matches a different entity
            # does not count: the reference must identify THIS entity
            if form.lower() in {ent.canonical.lower(), ent.name.lower(),
                                *(a.lower() for a in ent.aliases)}:
                return True
            resolved = resolve_reference(form, ent.etype, registry, ladders)
            if resolved is not None and resolved.eid == ent.eid:
                return True
    return False


def _contains_literal(have: str, want: str) -> bool:
    return bool(_boundary_pat(want).search(have))


def _match_field(want: str, have: str, registry: Registry, ladders: Ladders) -> tuple[bool, str]:
    """Match one answer field: exact, entity-resolved, or case-insensitive."""
    if want == have:
        return True, "exact"
    ent = registry.by_canonical(want)
    if ent is not None:
        resolved = resolve_reference(have, ent.etype, registry, ladders)
        if resolved is not None and resolved.eid == ent.eid:
            return True, "resolved"
        if _contains_reference(have, ent, registry, ladders):
            return True, "contained"
        return False, f"mismatch:{have!r}"
    if want.lower() == have.lower():
        return True, "case-insensitive"
    if _contains_literal(have, want):
        return True, "contained-literal"
    return False, f"mismatch:{have!r}"


def _match_composite(want: str, have: str, registry: Registry, ladders: Ladders) -> dict | None:
    """Field-wise comparison for pipe/comma composite answers. None if shapes differ."""
    if "|" not in want and "," not in want:
        return None
    sep = "|" if "|" in want else ","
    want_fields = [f.strip() for f in want.split(sep)]
    if sep not in have:
        return {"task_success": False, "structural_valid": True,
                "error": f"expected {sep}-separated answer, got {have!r}"}
    got_fields = [f.strip() for f in have.split(sep)]
    if len(got_fields) != len(want_fields):
        return None
    detail = {}
    ok = True
    for w, h in zip(want_fields, got_fields):
        field_ok, how = _match_field(w, h, registry, ladders)
        detail[w] = how
        ok = ok and field_ok
    return {"task_success": ok, "structural_valid": True, "detail": detail}


def score_extract(
    model_output: str, expect: dict, mode: str,
    registry: Registry, ladders: Ladders,
) -> dict:
    """Score one extraction answer against the expected record."""
    if mode == "json":
        got = _extract_json(model_output)
        if got is None:
            return {"task_success": False, "structural_valid": False,
                    "error": "no parseable JSON in output"}
        ok = True
        detail = {}
        for key, want in expect.items():
            have = str(got.get(key, "")).strip()
            field_ok, how = _match_field(str(want), have, registry, ladders)
            detail[key] = how
            ok = ok and field_ok
        return {"task_success": ok, "structural_valid": True, "detail": detail}

    want_line = expect["line"].strip()
    # candidate lines in the output
    lines = [ln.strip() for ln in model_output.strip().splitlines() if ln.strip()]
    for ln in lines:
        if ln == want_line:
            return {"task_success": True, "structural_valid": True, "detail": "exact"}
    # field-wise resolution for pipe/comma lines
    sep = "|" if "|" in want_line else ","
    want_fields = [f.strip() for f in want_line.split(sep)]
    for ln in lines:
        if sep not in ln:
            continue
        got_fields = [f.strip() for f in ln.split(sep)]
        if len(got_fields) != len(want_fields):
            continue
        detail = {}
        ok = True
        for want, have in zip(want_fields, got_fields):
            field_ok, how = _match_field(want, have, registry, ladders)
            detail[want] = how
            ok = ok and field_ok
        if ok:
            return {"task_success": True, "structural_valid": True, "detail": detail}
    return {"task_success": False, "structural_valid": True,
            "error": f"no matching line; expected {want_line!r}"}


def score_docqa(
    model_output: str, expected: str,
    registry: Registry, ladders: Ladders,
) -> dict:
    """Score one document-Q&A answer.

    Non-entity answers (e.g. "30") are compared literally. Entity answers go
    through resolve_reference.
    """
    have = model_output.strip().splitlines()
    have = " ".join(have).strip()
    if have == expected:
        return {"task_success": True, "structural_valid": True, "detail": "exact"}
    composite = _match_composite(expected, have, registry, ladders)
    if composite is not None:
        return composite
    ent = registry.by_canonical(expected)
    if ent is not None:
        resolved = resolve_reference(have, ent.etype, registry, ladders)
        ok = resolved is not None and resolved.eid == ent.eid
        if not ok and _contains_reference(have, ent, registry, ladders):
            return {"task_success": True, "structural_valid": True, "detail": "contained"}
        return {"task_success": ok, "structural_valid": True,
                "detail": "resolved" if ok else f"mismatch:{have!r}"}
    if expected.lower() == have.lower():
        return {"task_success": True, "structural_valid": True, "detail": "case-insensitive"}
    if _contains_literal(have, expected):
        return {"task_success": True, "structural_valid": True, "detail": "contained-literal"}
    return {"task_success": False, "structural_valid": True,
            "error": f"expected {expected!r}, got {have!r}"}