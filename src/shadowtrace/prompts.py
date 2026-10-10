"""Pilot benchmark construction.

Everything here is written in canonical token space (plan 7.1.1). Prompts, schema
DDL, code stubs and gold answers all reference the same semantics-free tokens,
so a checker runs unmodified on the unprotected baseline and on every
transformed variant. Nothing in this module knows about sanitization; it only
knows about tasks.
"""

from __future__ import annotations

import json
import random
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .universe import Entity, Registry

FAMILIES = ("sql", "code", "extract", "docqa", "drafting")

# families with an executable or exact-match checker (plan 7.3: never pooled
# with judge-scored families)
EXECUTABLE_FAMILIES = ("sql", "code", "extract", "docqa")
JUDGE_FAMILIES = ("drafting",)


def _sens(registry: Registry, etype: str) -> list[Entity]:
    """Sensitive entities only. Non-sensitive hard negatives must never be
    sampled as task entities; they enter prompts exclusively through the
    deliberate hard-negative arms and are recorded in `negatives`."""
    return [e for e in registry.of_type(etype) if e.sensitive]


@dataclass
class Prompt:
    pid: str
    family: str
    split: str
    text: str
    entities: list[str] = field(default_factory=list)     # sensitive eids
    negatives: list[str] = field(default_factory=list)    # non-sensitive eids
    checker: str = "none"
    spec: dict[str, Any] = field(default_factory=dict)
    difficulty: str = "easy"
    style: str = "clean"      # clean | messy
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Prompt":
        return cls(**d)


# ---------------------------------------------------------------------------
# shared SQLite warehouse
# ---------------------------------------------------------------------------

TABLE_SHAPES = {
    "billing": [("invoice_id", "TEXT"), ("customer", "TEXT"), ("amount", "INTEGER"), ("status", "TEXT")],
    "general ledger": [("entry_id", "TEXT"), ("account", "TEXT"), ("debit", "INTEGER"), ("credit", "INTEGER")],
    "CRM": [("account_id", "TEXT"), ("name", "TEXT"), ("region", "TEXT"), ("arr", "INTEGER")],
    "HR records": [("emp_id", "TEXT"), ("name", "TEXT"), ("dept", "TEXT"), ("salary", "INTEGER")],
    "inventory": [("item_id", "TEXT"), ("sku", "TEXT"), ("qty", "INTEGER"), ("warehouse", "TEXT")],
    "telemetry": [("metric_id", "TEXT"), ("host", "TEXT"), ("value", "INTEGER"), ("bucket", "TEXT")],
    "identity": [("user_id", "TEXT"), ("username", "TEXT"), ("role", "TEXT")],
    "claims": [("claim_id", "TEXT"), ("policy_id", "TEXT"), ("amount", "INTEGER"), ("status", "TEXT")],
    "data warehouse": [("row_id", "TEXT"), ("segment", "TEXT"), ("metric", "INTEGER"), ("period", "TEXT")],
    "ticketing": [("ticket_id", "TEXT"), ("subject", "TEXT"), ("priority", "TEXT")],
}

STATUSES = ["paid", "overdue", "pending", "void"]
REGION_VALUES = ["north", "south", "east", "west", "central"]
PRIORITIES = ["P1", "P2", "P3"]
ROLES = ["admin", "analyst", "viewer"]

# deterministic cycles guarantee every queried value is present, so gold
# result sets are never vacuously empty. A checker that compares against an
# empty gold set cannot discriminate a wrong query that also returns empty.
CYCLES = {
    "status": ["overdue", "paid", "pending", "void"],
    "role": ["admin", "analyst", "viewer", "analyst"],
    "region": ["north", "south", "east", "west"],
    "priority": ["P1", "P2", "P3", "P2"],
}


def build_warehouse(registry: Registry, seed: int = 7) -> tuple[dict, str]:
    """Return (ddl, seed data) for the shared canonical warehouse.

    One table per system entity that maps to a table shape. Table names are
    canonical tokens, so the DDL is valid SQL with no real names in it.
    """
    rng = random.Random(seed)
    ddl: list[str] = []
    data: dict[str, list[tuple]] = {}
    for ent in registry.of_type("system"):
        fn = ent.attributes["function"]
        shape = TABLE_SHAPES.get(fn)
        if shape is None:
            continue
        cols = ", ".join(f"{c} {t}" for c, t in shape)
        ddl.append(f"CREATE TABLE {ent.canonical} ({cols});")
        rows = []
        for i in range(12):
            row: list[Any] = []
            for j, (col, coltype) in enumerate(shape):
                if col in CYCLES:
                    row.append(CYCLES[col][i % len(CYCLES[col])])
                elif j == 0:
                    # first (id-like) column carries a known value so that
                    # WHERE <first-col> = 'alpha' is never vacuous
                    row.append("alpha" if i % 3 == 0 else f"row_{i}")
                elif col in ("dept", "account", "warehouse", "host", "segment", "subject", "metric", "bucket", "period"):
                    row.append(rng.choice(["alpha", "beta", "gamma", "delta"]))
                elif col in ("name", "username"):
                    row.append(f"row_{i}")
                else:
                    row.append(i + 1)
            rows.append(tuple(row))
        data[ent.canonical] = rows
    return {"ddl": "\n".join(ddl), "data": data}


# ---------------------------------------------------------------------------
# family builders
# ---------------------------------------------------------------------------

def _messify(text: str, rng: random.Random) -> str:
    """Light realism degradation. Never applied to entity tokens."""
    text = text.replace("? ", "?\n") if rng.random() < 0.5 else text
    if rng.random() < 0.5:
        text = text[0].lower() + text[1:]
    if rng.random() < 0.4:
        text = "  " + text
    if rng.random() < 0.3:
        text = text + "  thanks"
    return text


def _build_sql(registry: Registry, rng: random.Random, count: int, start: int) -> list[Prompt]:
    out = []
    systems = [s for s in registry.of_type("system") if s.attributes["function"] in TABLE_SHAPES]
    orgs = _sens(registry, "org")
    for k in range(count):
        i = start + k
        sys_ent = systems[i % len(systems)]
        org = orgs[(i * 7) % len(orgs)]
        shape = TABLE_SHAPES[sys_ent.attributes["function"]]
        colnames = [c for c, _ in shape]
        pick = colnames[0]

        if "status" in colnames:
            ask = (f"Write a SQLite query against table {sys_ent.canonical} that returns "
                   f"{colnames[0]} and amount for every row where status = 'overdue', "
                   f"ordered by amount descending.")
            gold = (f"SELECT {colnames[0]}, amount FROM {sys_ent.canonical} "
                    f"WHERE status = 'overdue' ORDER BY amount DESC")
        elif "role" in colnames:
            ask = (f"Write a SQLite query against table {sys_ent.canonical} that counts "
                   f"how many users have role = 'admin'.")
            gold = (f"SELECT COUNT(*) FROM {sys_ent.canonical} WHERE role = 'admin'")
        else:
            ask = (f"Write a SQLite query against table {sys_ent.canonical} that returns "
                   f"all rows where {pick} = 'alpha'.")
            gold = f"SELECT * FROM {sys_ent.canonical} WHERE {pick} = 'alpha'"

        text = (
            f"I have a reporting database. The table {sys_ent.canonical} holds "
            f"{sys_ent.attributes['function']} records for our client {org.canonical}.\n\n"
            f"Task: {ask}\n"
            f"Reply with only the SQL statement."
        )
        out.append(Prompt(
            pid=f"sql_{i:03d}", family="sql", split="", text=text,
            entities=[sys_ent.eid, org.eid], checker="sql",
            spec={
                "table": sys_ent.canonical,
                "gold_sql": gold,
                "primary_entities": [sys_ent.eid],
            },
            difficulty="medium" if i % 3 else "easy",
            notes=f"system={sys_ent.eid} org={org.eid}",
        ))
    return out


def _build_code(registry: Registry, rng: random.Random, count: int, start: int) -> list[Prompt]:
    out = []
    systems = [s for s in registry.of_type("system") if s.attributes["function"] in TABLE_SHAPES]
    for k in range(count):
        i = start + k
        sys_ent = systems[(i * 3) % len(systems)]
        fn = sys_ent.attributes["function"]
        fn_name = f"fn_{i:02x}a3"
        if fn == "billing":
            body = ("def total_overdue(rows):\n"
                    "    return sum(r['amount'] for r in rows if r['status'] == 'overdue')")
            tests = ["assert total_overdue([{'amount':5,'status':'overdue'},{'amount':7,'status':'paid'}]) == 5",
                     "assert total_overdue([]) == 0"]
            sig = "rows: list[dict]"
        elif fn == "inventory":
            body = ("def low_stock(rows, threshold=5):\n"
                    "    return [r['sku'] for r in rows if r['qty'] < threshold]")
            tests = ["assert low_stock([{'sku':'a','qty':2},{'sku':'b','qty':9}]) == ['a']"]
            sig = "rows: list[dict], threshold: int = 5"
        else:
            body = ("def count_by(rows, field):\n"
                    "    out = {}\n"
                    "    for r in rows:\n"
                    "        out[r[field]] = out.get(r[field], 0) + 1\n"
                    "    return out")
            tests = ["assert count_by([{'k':'a'},{'k':'a'},{'k':'b'}],'k') == {'a':2,'b':1}"]
            sig = "rows: list[dict], field: str"

        text = (
            f"Our internal {fn} service is called {sys_ent.canonical} in our code base. "
            f"Write a Python function `{fn_name}({sig})` that solves the task below.\n\n"
            f"Task: {fn} helper.\n"
            f"Your function name must be `{fn_name}`.\n"
            f"Reply with only a Python code block."
        )
        # reference implementation carries the required name
        ref_body = re.sub(r"def\s+\w+\s*\(", f"def {fn_name}(", body, count=1)
        ref_tests = [t.replace(body.split("(")[0].split()[-1], fn_name) for t in tests]
        out.append(Prompt(
            pid=f"code_{i:03d}", family="code", split="", text=text,
            entities=[sys_ent.eid], checker="code",
            spec={"fn_name": fn_name, "reference": ref_body, "tests": ref_tests,
                  "primary_entities": [sys_ent.eid]},
            difficulty="medium",
            notes=f"system={sys_ent.eid}",
        ))
    return out


def _build_extract(registry: Registry, rng: random.Random, count: int, start: int) -> list[Prompt]:
    out = []
    orgs = _sens(registry, "org")
    idrs = _sens(registry, "identifier")
    systems = _sens(registry, "system")
    for k in range(count):
        i = start + k
        org = orgs[(i * 5) % len(orgs)]
        idr = idrs[i % len(idrs)]
        sys_ent = systems[(i * 11) % len(systems)]
        block = (
            f"RECORD {i}\n"
            f"client_reference: {org.canonical}\n"
            f"account_code: {idr.canonical}\n"
            f"source_system: {sys_ent.canonical}\n"
            f"renewal_flag: {'yes' if i % 2 else 'no'}\n"
        )
        if i % 3 == 0:
            task = ("Extract the client_reference and account_code from the record. "
                    "Reply as JSON with keys \"client\" and \"account\".")
            expect = {"client": org.canonical, "account": idr.canonical}
        elif i % 3 == 1:
            task = ("Rewrite the record so that account_code is upper-cased and the "
                    "renewal_flag is converted to the word 'true' or 'false'. "
                    "Reply as a single line: CLIENT|ACCOUNT|FLAG")
            expect = {"line": f"{org.canonical}|{idr.canonical.upper()}|{'true' if i % 2 else 'false'}"}
        else:
            task = ("From the record, report only the source_system and the account_code, "
                    "comma separated, in that order, with no extra text.")
            expect = {"line": f"{sys_ent.canonical},{idr.canonical}"}

        out.append(Prompt(
            pid=f"extract_{i:03d}", family="extract", split="", text=f"{block}\nTask: {task}",
            entities=[org.eid, idr.eid, sys_ent.eid], checker="extract",
            spec={"expect": expect, "mode": "json" if i % 3 == 0 else "line",
                  "primary_entities": [org.eid]},
            difficulty="easy", notes=f"org={org.eid} idr={idr.eid}",
        ))
    return out


def _build_docqa(registry: Registry, rng: random.Random, count: int, start: int) -> list[Prompt]:
    out = []
    orgs = _sens(registry, "org")
    idrs = _sens(registry, "identifier")
    amts = _sens(registry, "amount")
    negs = [n for n in registry.entities if not n.sensitive]
    for k in range(count):
        i = start + k
        org = orgs[(i * 13) % len(orgs)]
        idr = idrs[(i * 3) % len(idrs)]
        amt = amts[(i * 2) % len(amts)]
        doc = (
            f"SERVICE SUMMARY {i}\n"
            f"The client {org.canonical} engaged account {idr.canonical} for a total fee of "
            f"{amt.name} INR. Renewals are handled by the account team. "
            f"Payment terms are net 30 from the invoice date."
        )
        if i % 4 == 0:
            # hard negative: a public entity mixed with sensitive ones
            neg = negs[i % len(negs)]
            doc += f" The schedule follows {neg.canonical}."
            q = "Report the total fee stated in the document, in digits only."
            exp = amt.canonical
            negs_used = [neg.eid]
        elif i % 4 == 1:
            q = "Report the account code exactly as written in the document."
            exp = idr.canonical
            negs_used = []
        elif i % 4 == 2:
            q = "What are the payment terms? Answer with the number of days only."
            exp = "30"
            negs_used = []
        else:
            q = "Report the client reference and the total fee, separated by a pipe."
            exp = f"{org.canonical}|{amt.canonical}"
            negs_used = []

        out.append(Prompt(
            pid=f"docqa_{i:03d}", family="docqa", split="", text=f"{doc}\n\nQuestion: {q}",
            entities=[e for e in (org.eid, idr.eid, amt.eid)],
            negatives=negs_used, checker="docqa",
            spec={"expected": exp, "primary_entities": [org.eid]},
            difficulty="easy", notes=f"org={org.eid}",
        ))
    return out


def _build_drafting(registry: Registry, rng: random.Random, count: int, start: int) -> list[Prompt]:
    out = []
    orgs = _sens(registry, "org")
    systems = _sens(registry, "system")
    for k in range(count):
        i = start + k
        org = orgs[(i * 17) % len(orgs)]
        sys_ent = systems[(i * 5) % len(systems)]
        kind = i % 2
        if kind == 0:
            task = "Draft a two-sentence internal note summarising the incident for the engineering team."
            rubric = ["mentions the affected system", "does not invent facts"]
        else:
            task = "Draft a one-paragraph status update for the client."
            rubric = ["addresses the client", "is under four sentences", "does not invent facts"]
        text = (
            f"We had a partial outage in {sys_ent.canonical} affecting {org.canonical}. "
            f"Root cause was a failed nightly job. No data was lost.\n\nTask: {task}"
        )
        out.append(Prompt(
            pid=f"drafting_{i:03d}", family="drafting", split="", text=text,
            entities=[sys_ent.eid, org.eid], checker="judge",
            spec={"rubric": rubric, "primary_entities": [org.eid]},
            difficulty="easy",
            notes="judge-scored, reported separately, never pooled with executable families",
        ))
    return out


def build_prompts(registry: Registry, seed: int = 11) -> list[Prompt]:
    rng = random.Random(seed)
    prompts: list[Prompt] = []
    prompts += _build_sql(registry, rng, 14, 0)
    prompts += _build_code(registry, rng, 8, 0)
    prompts += _build_extract(registry, rng, 12, 0)
    prompts += _build_docqa(registry, rng, 8, 0)
    prompts += _build_drafting(registry, rng, 8, 0)
    assert len(prompts) == 50, len(prompts)

    # messy realism arm: degrade a fifth of the prompts (plan 7.2)
    for p in prompts:
        if int(p.pid.split("_")[1]) % 5 == 0:
            p.style = "messy"
            p.text = _messify(p.text, rng)

    # deterministic stratified split
    for fam in FAMILIES:
        fam_prompts = [p for p in prompts if p.family == fam]
        for idx, p in enumerate(fam_prompts):
            p.split = "test" if idx >= int(len(fam_prompts) * 0.4) else "train"
    return prompts


def save_prompts(prompts: list[Prompt], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for p in prompts:
            fh.write(json.dumps(p.to_dict(), sort_keys=True) + "\n")


def load_prompts(path: Path) -> list[Prompt]:
    out = []
    with Path(path).open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(Prompt.from_dict(json.loads(line)))
    return out