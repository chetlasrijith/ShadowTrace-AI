"""Benchmark integrity tests: the dataset must not contain vacuous items."""

from shadowtrace.checkers.sqlite_check import build_db, run_query
from shadowtrace.prompts import build_prompts, build_warehouse
from shadowtrace.universe import build_registry


def test_no_vacuous_sql_gold():
    r = build_registry(20260101)
    wh = build_warehouse(r, 7)
    conn = build_db(wh["ddl"], wh["data"])
    try:
        sql_prompts = [p for p in build_prompts(r, 11) if p.family == "sql"]
        assert len(sql_prompts) == 14
        for p in sql_prompts:
            rows, err = run_query(conn, p.spec["gold_sql"])
            assert not err, f"{p.pid}: gold fails: {err}"
            assert rows, f"{p.pid}: vacuous gold (empty result set)"
    finally:
        conn.close()


def test_every_prompt_has_sensitive_entities():
    r = build_registry(20260101)
    by_eid = {e.eid: e for e in r.entities}
    for p in build_prompts(r, 11):
        sens = [e for e in p.entities if by_eid[e].sensitive]
        assert sens, f"{p.pid}: no sensitive entities"


def test_split_is_stratified_and_fixed():
    r = build_registry(20260101)
    ps = build_prompts(r, 11)
    for fam in ("sql", "code", "extract", "docqa", "drafting"):
        fam_ps = [p for p in ps if p.family == fam]
        assert any(p.split == "train" for p in fam_ps), fam
        assert any(p.split == "test" for p in fam_ps), fam
    assert [p.split for p in ps] == [p.split for p in build_prompts(r, 11)]
