"""Detection and normalization tests."""

from shadowtrace.detect.normalize import normalize
from shadowtrace.detect.registry import detect
from shadowtrace.detect.rules import luhn_ok, scan_secrets
from shadowtrace.universe import build_registry


def test_normalize_strips_zero_width_and_folds():
    assert "\u200b" not in normalize("tbl_7f3a\u200b")
    assert normalize("\uff54\uff42\uff4c") == "tbl"  # fullwidth fold
    assert normalize("a\u0430") == "aa"  # cyrillic confusable


def test_registry_detect_finds_canonical_and_name():
    r = build_registry(1)
    org = r.of_type("org")[0]
    sys_ent = r.of_type("system")[0]
    text = f"query {sys_ent.canonical} for client {org.name} please"
    spans = detect(text, r)
    eids = {s.eid for s in spans}
    assert org.eid in eids and sys_ent.eid in eids
    assert all(s.sensitive for s in spans)


def test_amount_matching_threshold():
    r = build_registry(1)
    assert detect("pay in 30 days", r) == [] or all(
        s.etype != "amount" for s in detect("pay in 30 days", r))
    amt = r.of_type("amount")[0]
    spans = detect(f"fee of {amt.name} INR", r)
    assert any(s.eid == amt.eid for s in spans)


def test_hard_negative_detects_as_nonsensitive():
    r = build_registry(1)
    spans = detect("see the public annual report for details", r)
    assert spans and all(not s.sensitive for s in spans)


def test_luhn_accepts_test_card_rejects_noise():
    assert luhn_ok("4111111111111111")
    assert not luhn_ok("4111111111111112")


def test_scan_secrets_finds_validated_card():
    hits = scan_secrets("card 4111 1111 1111 1111 expired")
    assert any(h.scheme == "card" for h in hits)
    hits = scan_secrets("card 4111 1111 1111 1112 expired")
    assert not any(h.scheme == "card" for h in hits)
