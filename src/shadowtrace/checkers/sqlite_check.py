"""SQLite checker for the SQL family.

The warehouse is built from canonical tokens (prompts.build_warehouse), so
this database contains no real names and the checker runs unmodified on every
variant. Gold answers and model answers are executed and their result sets
compared as multisets of stringified rows.

Structural validity is measured with EXPLAIN against the real schema: a query
that references a placeholder or a descriptive phrase fails with "no such
table", which is exactly the H4 failure mode the plan wants recorded, not
hidden.
"""

from __future__ import annotations

import re
import sqlite3


def build_db(ddl: str, data: dict) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.executescript(ddl)
    for table, rows in data.items():
        if not rows:
            continue
        placeholders = ", ".join("?" * len(rows[0]))
        conn.executemany(f"INSERT INTO {table} VALUES ({placeholders})", rows)
    conn.commit()
    return conn


def extract_sql(text: str) -> str:
    """Pull a SQL statement out of model output (fences or bare)."""
    m = re.search(r"```(?:sql)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
    if m:
        return m.group(1).strip()
    # bare: first SELECT ... up to trailing semicolon
    m = re.search(r"(?is)\bselect\b.*", text)
    if m:
        return m.group(0).strip().rstrip(";") + ";"
    return text.strip()


def explain_ok(conn: sqlite3.Connection, sql: str) -> tuple[bool, str]:
    """Structural validity: does this parse against the real schema?"""
    try:
        conn.execute(f"EXPLAIN {sql}")
        return True, ""
    except Exception as e:  # noqa: BLE001 - surfaced in the report
        return False, f"{type(e).__name__}: {e}"


def run_query(conn: sqlite3.Connection, sql: str):
    """Execute and return (rows_as_sorted_strings, error)."""
    try:
        cur = conn.execute(sql)
        rows = sorted(repr(tuple(r)) for r in cur.fetchall())
        return rows, ""
    except Exception as e:  # noqa: BLE001
        return [], f"{type(e).__name__}: {e}"


def score_sql(conn: sqlite3.Connection, model_output: str, gold_sql: str) -> dict:
    """Score one SQL answer. Result-set equality is the bar."""
    model_sql = extract_sql(model_output)
    gold_sql = gold_sql.strip().rstrip(";") + ";"
    gold_rows, gold_err = run_query(conn, gold_sql)
    if gold_err:
        return {
            "task_success": False, "structural_valid": False,
            "error": f"gold query failed (dataset bug): {gold_err}",
            "model_sql": model_sql,
        }
    valid, valid_err = explain_ok(conn, model_sql)
    model_rows, run_err = run_query(conn, model_sql)
    return {
        "task_success": bool(valid) and not run_err and model_rows == gold_rows,
        "structural_valid": valid,
        "structural_error": valid_err,
        "run_error": run_err,
        "model_sql": model_sql,
        "gold_rows": len(gold_rows),
        "model_rows": len(model_rows),
    }


def _flex_pat(phrase: str) -> "re.Pattern":
    """Match a descriptive phrase ignoring case and _/whitespace differences.

    Models regularly rewrite "the Finance billing system" as
    "the_Finance_billing_system". The words identify the entity either way,
    and restoration must not fail on separators.
    """
    toks = [re.escape(t) for t in phrase.split()]
    return re.compile(r"[\s_]+".join(toks), re.IGNORECASE)


def restore_identifiers(model_output: str, substitutions: list[dict]) -> tuple[str, int]:
    """Map descriptive phrases back to canonical tokens where unambiguous.

    Only substitutions flagged restorable=True are applied. An ambiguous
    phrase is left in place, because the system genuinely cannot know which
    entity was meant (plan 7.1.1). Placeholder replacements ([ORG] etc.) are
    never restorable and are never mapped. Matching is separator-insensitive
    so model-invented snake_case identifiers still restore.

    Returns (restored_text, number_of_applied_restorations).
    """
    out = model_output
    applied = 0
    for s in sorted(substitutions, key=lambda s: -len(s["replacement"])):
        if not s.get("restorable"):
            continue
        phrase, canon = s["replacement"], s["surface"]
        if _flex_pat(phrase).search(out):
            out = _flex_pat(phrase).sub(canon, out)
            applied += 1
    return out, applied


def score_sql_with_restoration(
    conn: sqlite3.Connection, model_output: str, gold_sql: str,
    substitutions: list[dict],
) -> dict:
    """End-to-end SQL score after unambiguous restoration.

    This is the utility number that treats generalization fairly: the model
    wrote the right query modulo naming, and naming was recoverable from the
    logged map. Where restoration is ambiguous the item fails here and the
    ambiguity class size is reported in the substitution record.
    """
    restored, n_restored = restore_identifiers(model_output, substitutions)
    base = score_sql(conn, model_output, gold_sql)
    after = score_sql(conn, restored, gold_sql)
    return {
        **after,
        "task_success_raw": base["task_success"],
        "restorations_applied": n_restored,
        "task_success": after["task_success"],
    }