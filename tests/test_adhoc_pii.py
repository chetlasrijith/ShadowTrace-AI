"""Ad-hoc PII detection: free-form chat values no registry can enumerate.

Scope contract, locked by these tests:
- detect() is registry-only and byte-identical (benchmark stability).
- detect_all() adds six ad-hoc types; registry spans win overlap ties.
- passwords and API keys default to placeholder (no descriptive middle).
"""

from pathlib import Path

from shadowtrace.detect.pii import _plausible_secret, scan_pii
from shadowtrace.detect.registry import detect, detect_all
from shadowtrace.evaluate.attacker import attack_all_substitutions
from shadowtrace.evaluate.leakage import attribute_leakage, span_leakage
from shadowtrace.transform.ladders import Ladders
from shadowtrace.transform.transforms import transform_generalize, transform_redact
from shadowtrace.universe import Registry

ROOT = Path(__file__).resolve().parents[1]
REG = Registry.load(ROOT / "data" / "universe" / "registry.jsonl")
LAD = Ladders.load(ROOT / "configs" / "ladders.yaml")

CHAT_TEXT = "Client Id is 123893 and client pass is shara@123"


def test_old_detect_finds_nothing_in_chat_text():
    assert detect(CHAT_TEXT, REG) == []


def test_detect_all_finds_id_and_password():
    spans, ents = detect_all(CHAT_TEXT, REG)
    found = {s.surface: s.etype for s in spans}
    assert found.get("123893") == "employee_id"
    assert found.get("shara@123") == "password"
    assert len(ents) == 2
    assert all(e.eid.startswith("ADHOC_") for e in ents)


def test_password_beats_email_for_at_tokens():
    # shara@123 has email SHAPE but a password CUE: cue wins
    hits = {h.value: h.etype for h in scan_pii("client pass is shara@123")}
    assert hits.get("shara@123") == "password"


def test_dotted_email_needs_no_cue():
    hits = {h.value: h.etype for h in scan_pii("mail me at divya.k@example.com soon")}
    assert hits.get("divya.k@example.com") == "email"


def test_short_numbers_do_not_fire():
    assert scan_pii("pay in 30 days, room 404, invoice 77") == []


def test_card_luhn_and_phone_shape():
    hits = {h.value: h.etype for h in scan_pii("card 4111 1111 1111 1111 or call +91 98200 12345")}
    assert hits.get("4111 1111 1111 1111") == "card"
    assert "+91 98200 12345" in hits and hits["+91 98200 12345"] == "phone"


def test_plain_words_are_not_secrets():
    assert not _plausible_secret("password")
    assert not _plausible_secret("hello")
    assert not _plausible_secret("123")
    assert _plausible_secret("shara@123")
    assert _plausible_secret("sk-live-92xQmZ7t precies")


def test_generalize_chat_text_end_to_end():
    spans, ents = detect_all(CHAT_TEXT, REG)
    tr = transform_generalize(CHAT_TEXT, spans, REG, LAD, "chat", entities=ents)
    assert "123893" not in tr.text and "shara@123" not in tr.text
    assert "[PASSWORD]" in tr.text
    assert all(s["restorable"] for s in tr.substitutions)
    span = span_leakage(tr.text, CHAT_TEXT, ["123893", "shara@123"])
    assert span["rate"] == 0.0, span
    attr = attribute_leakage(tr.substitutions, REG, ents)
    assert attr["mean"] < 1.0
    atk = attack_all_substitutions(tr.text, tr.substitutions, REG, LAD, 10, 777,
                                   entities=ents)
    assert atk["rate"] == 0.0 and atk["total"] == 2, atk


def test_noop_chat_text_fully_leaks():
    spans, ents = detect_all(CHAT_TEXT, REG)
    from shadowtrace.transform.transforms import transform_noop
    tr = transform_noop(CHAT_TEXT)
    span = span_leakage(tr.text, CHAT_TEXT, ["123893", "shara@123"])
    assert span["rate"] == 1.0


def test_redact_chat_text():
    spans, ents = detect_all(CHAT_TEXT, REG)
    tr = transform_redact(CHAT_TEXT, spans, REG)
    assert tr.text == "Client Id is [EMPLOYEE_ID] and client pass is [PASSWORD]"


def test_registry_overlap_tie_goes_to_registry():
    spans, ents = detect_all("query tbl_c1ac please", REG)
    assert len(spans) == 1 and not spans[0].ad_hoc and ents == []


def test_ad_hoc_eids_are_deterministic():
    _, e1 = detect_all(CHAT_TEXT, REG)
    _, e2 = detect_all(CHAT_TEXT, REG)
    assert [e.eid for e in e1] == [e.eid for e in e2]
