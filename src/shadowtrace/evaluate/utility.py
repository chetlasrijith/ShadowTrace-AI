"""Utility dispatch: one prompt plus one answer, one score dict.

Executable families (sql, code, extract, docqa) get exact or execution-based
scores. Drafting gets a structural proxy only, explicitly NOT a utility
score, and the report keeps it out of every pooled table (plan 7.3).
"""

from __future__ import annotations

from ..checkers.code_check import score_code
from ..checkers.sqlite_check import build_db, score_sql, score_sql_with_restoration
from ..checkers.text_check import score_docqa, score_extract
from ..prompts import EXECUTABLE_FAMILIES, Prompt
from ..transform.ladders import Ladders
from ..universe import Registry
from .judge import score_drafting_proxy


def score_answer(
    prompt: Prompt, answer: str, registry: Registry, ladders: Ladders,
    warehouse: dict, substitutions: list[dict] | None = None,
) -> dict:
    subs = substitutions or []
    if prompt.family == "sql":
        conn = build_db(warehouse["ddl"], warehouse["data"])
        try:
            if subs:
                out = score_sql_with_restoration(
                    conn, answer, prompt.spec["gold_sql"], subs)
            else:
                out = score_sql(conn, answer, prompt.spec["gold_sql"])
                out["task_success_raw"] = out["task_success"]
                out["restorations_applied"] = 0
        finally:
            conn.close()
        out["scored_by"] = "execution"
        return out
    if prompt.family == "code":
        out = score_code(answer, prompt.spec["fn_name"], prompt.spec["tests"])
        out["scored_by"] = "execution"
        return out
    if prompt.family == "extract":
        out = score_extract(
            answer, prompt.spec["expect"], prompt.spec["mode"], registry, ladders)
        out["scored_by"] = "exact"
        return out
    if prompt.family == "docqa":
        out = score_docqa(answer, prompt.spec["expected"], registry, ladders)
        out["scored_by"] = "exact"
        return out
    if prompt.family == "drafting":
        out = score_drafting_proxy(answer, prompt, registry, ladders)
        out["scored_by"] = "proxy-not-utility"
        return out
    return {"task_success": False, "structural_valid": False,
            "error": f"unknown family {prompt.family}", "scored_by": "none"}


def is_executable(prompt: Prompt) -> bool:
    return prompt.family in EXECUTABLE_FAMILIES