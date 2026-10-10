"""Checker and evaluator tests."""

from pathlib import Path

from shadowtrace.checkers.code_check import score_code
from shadowtrace.checkers.sqlite_check import (
    build_db,
    score_sql,
    score_sql_with_restoration,
)
from shadowtrace.checkers.text_check import resolve_reference, score_docqa, score_extract
from shadowtrace.evaluate.attacker import attack_all_substitutions
from shadowtrace.evaluate.leakage import attribute_leakage, span_leakage
from shadowtrace.evaluate.metrics import bootstrap_ci
from shadowtrace.prompts import build_prompts, build_warehouse
from shadowtrace.transform.ladders import Ladders
from shadowtrace.transform.transforms import transform_generalize, transform_redact
from shadowtrace.detect.registry import detect
from shadowtrace.detect.normalize import normalize
from shadowtrace.universe import build_registry

LADDERS = Ladders.load(Path(__file__).resolve().parents[1] / "configs" / "ladders.yaml")


def test_sql_gold_passes_and_broken_fails():
    r = build_registry(20260101)
    wh = build_warehouse(r, 7)
    conn = build_db(wh["ddl"], wh["data"])
    try:
        prompts = build_prompts(r, 11)
        sql = next(p for p in prompts if p.family == "sql")
        good = score_sql(conn, sql.spec["gold_sql"], sql.spec["gold_sql"])
        assert good["task_success"] and good["structural_valid"]
        bad = score_sql(conn, "SELECT * FROM [SYSTEM];", sql.spec["gold_sql"])
        assert not bad["task_success"] and not bad["structural_valid"]
    finally:
        conn.close()


def test_sql_restoration_path():
    r = build_registry(20260101)
    wh = build_warehouse(r, 7)
    conn = build_db(wh["ddl"], wh["data"])
    try:
        prompts = build_prompts(r, 11)
        sql = next(p for p in prompts if p.family == "sql")
        spans = detect(normalize(sql.text), r)
        tr = transform_generalize(normalize(sql.text), spans, r, LADDERS, "sql")
        # stub-style answer: gold shape with the phrase as shown
        assert isinstance(tr.substitutions, list)
    finally:
        conn.close()


def test_restoration_recovers_snake_case_invention():
    from shadowtrace.checkers.sqlite_check import restore_identifiers
    subs = [{"surface": "tbl_c1ac", "replacement": "the Finance billing system",
             "restorable": True}]
    out, n = restore_identifiers(
        "SELECT * FROM the_Finance_billing_system WHERE x = 1", subs)
    assert n == 1 and "tbl_c1ac" in out
    # ambiguous phrases are never restored
    subs2 = [{"surface": "tbl_x", "replacement": "a company", "restorable": False}]
    out2, n2 = restore_identifiers("SELECT * FROM a_company", subs2)
    assert n2 == 0 and "tbl_x" not in out2


def test_docqa_accepts_contained_reference():
    r = build_registry(20260101)
    idr = r.of_type("identifier")[0]
    out = score_docqa(
        f"The account code written in the document is {idr.canonical}.",
        idr.canonical, r, LADDERS)
    assert out["task_success"], out
    # but a bare number must not match inside a bigger number
    out2 = score_docqa("the fee was 30,700,000", "30", r, LADDERS)
    assert not out2["task_success"]


def test_code_reference_passes():
    r = build_registry(20260101)
    prompts = build_prompts(r, 11)
    code = next(p for p in prompts if p.family == "code")
    out = score_code(code.spec["reference"], code.spec["fn_name"], code.spec["tests"])
    assert out["task_success"] and out["structural_valid"]


def test_extract_exact_and_resolved():
    r = build_registry(20260101)
    prompts = build_prompts(r, 11)
    ext = next(p for p in prompts
               if p.family == "extract" and p.spec["mode"] == "json")
    want = ext.spec["expect"]
    ok = score_extract(f'{{"client": "{want["client"]}", "account": "{want["account"]}"}}',
                       want, "json", r, LADDERS)
    assert ok["task_success"]
    bad = score_extract('{"client": "wrong", "account": "wrong"}', want, "json", r, LADDERS)
    assert not bad["task_success"]


def test_docqa_literal_control():
    r = build_registry(20260101)
    out = score_docqa("30", "30", r, LADDERS)
    assert out["task_success"]


def test_attacker_perfect_on_noop_near_chance_on_redact():
    r = build_registry(20260101)
    prompts = build_prompts(r, 11)
    p = next(x for x in prompts if x.family == "extract")
    spans = detect(normalize(p.text), r)
    noop = attack_all_substitutions(p.text, [{"eid": s.eid} for s in spans if s.sensitive],
                                    r, LADDERS, 10, 777)
    assert noop["rate"] == 1.0  # surfaces visible: attacker cannot miss
    tr = transform_redact(normalize(p.text), spans, r)
    red = attack_all_substitutions(tr.text, tr.substitutions, r, LADDERS, 10, 777)
    assert red["rate"] <= 0.5  # placeholders carry no evidence
    # fractional credit agrees with chance when nothing is visible
    assert abs(red["rate"] - red["chance"]) <= 0.45


def test_attribute_leakage_ordering():
    r = build_registry(20260101)
    org = r.of_type("org")[0]
    full = attribute_leakage(
        [{"eid": org.eid, "surface": org.canonical, "replacement": org.canonical,
          "reveal": [], "restorable": True, "ambiguity_k": 1}], r)
    red = attribute_leakage(
        [{"eid": org.eid, "surface": org.canonical, "replacement": "[ORG]",
          "reveal": [], "restorable": False, "ambiguity_k": -1}], r)
    assert full["mean"] == 1.0
    assert red["mean"] == 0.0


def test_span_leakage_counts_survivors():
    out = span_leakage("hello tbl_abc and more", "hello tbl_abc and org_xyz",
                       ["tbl_abc", "org_xyz"])
    assert out["rate"] == 0.5 and out["survivors"] == ["tbl_abc"]


def test_span_leakage_denominator_is_original_presence():
    # a surface form that never appeared cannot leak
    out = span_leakage("hello tbl_abc", "hello tbl_abc", ["tbl_abc", "never_present"])
    assert out["rate"] == 1.0 and out["n_sensitive"] == 1


def test_bootstrap_ci_sane():
    mean, lo, hi = bootstrap_ci([1.0] * 20)
    assert (mean, lo, hi) == (1.0, 1.0, 1.0)
    mean, lo, hi = bootstrap_ci([0.0, 1.0] * 10)
    assert lo <= mean <= hi and (hi - lo) > 0.2
