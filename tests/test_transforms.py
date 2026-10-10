"""Ladder rendering, restoration, and transform tests."""

from pathlib import Path

from shadowtrace.detect.registry import detect
from shadowtrace.transform.ladders import Ladders
from shadowtrace.transform.transforms import (
    transform_chain,
    transform_generalize,
    transform_noop,
    transform_redact,
)
from shadowtrace.transform.verify import verify_no_surviving_spans
from shadowtrace.universe import build_registry

LADDERS = Ladders.load(Path(__file__).resolve().parents[1] / "configs" / "ladders.yaml")


def test_render_depths_and_placeholders():
    r = build_registry(1)
    org = r.of_type("org")[0]
    assert LADDERS.render(org, 0) == org.canonical
    mid = LADDERS.render(org, 1)
    assert org.canonical not in mid and len(mid) > len("[ORG]")
    assert LADDERS.render(org, 99) == "[ORG]"
    assert LADDERS.render(org, -1) == "[ORG]"


def test_restoration_flags_ambiguity():
    r = build_registry(1)
    # depth-2 org rung reveals industry+size only: shared by construction
    orgs = r.of_type("org")
    ambiguous = [o for o in orgs
                 if LADDERS.ambiguity_class(r, o, 2) > 1]
    assert ambiguous, "expected at least one ambiguous org rung"
    o = ambiguous[0]
    assert not LADDERS.is_restorable(r, o, 2)
    assert LADDERS.ambiguity_class(r, o, 2) > 1


def test_redact_removes_sensitive_keeps_negative():
    r = build_registry(1)
    org = r.of_type("org")[0]
    text = f"client {org.canonical} filed the public annual report"
    spans = detect(text, r)
    tr = transform_redact(text, spans, r)
    assert org.canonical not in tr.text
    assert "[ORG]" in tr.text
    assert "public annual report" in tr.text  # negative untouched
    assert verify_no_surviving_spans(
        tr.text, {s.surface for s in spans if s.sensitive})


def test_generalize_uses_configured_depth():
    r = build_registry(1)
    org = r.of_type("org")[0]
    text = f"client {org.canonical} owes fees"
    spans = detect(text, r)
    tr = transform_generalize(text, spans, r, LADDERS, "extract")
    assert tr.text != text
    assert org.canonical not in tr.text
    assert tr.substitutions and "reveal" in tr.substitutions[0]


def test_chain_never_silently_forwards():
    r = build_registry(1)
    org = r.of_type("org")[0]
    text = f"client {org.canonical}"
    spans = detect(text, r)
    tr = transform_chain(text, spans, r, LADDERS, "extract")
    assert not tr.held
    assert verify_no_surviving_spans(
        tr.text, {s.surface for s in spans if s.sensitive})


def test_noop_passthrough():
    tr = transform_noop("hello")
    assert tr.text == "hello" and tr.method == "noop"
