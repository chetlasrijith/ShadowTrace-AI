"""Synthetic entity registry.

Every entity carries ground-truth attributes. That is what makes the
attacker-independent `attribute_distance` leakage measure computable: we know
exactly what the rewrite did and did not reveal, with no model in the loop.

The universe is deliberately fictional. Section 5.1 of the plan explains why
that forces re-identification to be measured against a closed candidate set.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

ENTITY_TYPES = ("org", "system", "person", "amount", "identifier", "location")

CANONICAL_PREFIX = {
    "org": "org",
    "system": "tbl",
    "person": "emp",
    "amount": "amt",
    "identifier": "acc",
    "location": "site",
}

# Invented stems. Combined with suffixes these do not yield real company names,
# which matters because the benchmark is intended to be releasable.
ORG_STEMS = [
    "Vantare", "Korevia", "Zephalon", "Mirath", "Solvane", "Tyrrhen", "Quilara",
    "Obduran", "Fenvik", "Thaldec", "Ruphari", "Cindral", "Norvex", "Zavelli",
    "Belthor", "Arundel", "Calyx", "Drentha", "Eskalon", "Falvind", "Girtona",
    "Halvane", "Istria", "Jorven", "Kaldris", "Luneth", "Marvex", "Norvald",
    "Ostrane", "Pellwin",
]
ORG_SUFFIXES = [
    "Systems", "Logistics", "Labs", "Technologies", "Industries", "Analytics",
    "Networks", "Health", "Capital", "Manufacturing", "Retail Group",
]

INDUSTRIES = [
    "consulting", "logistics", "healthcare", "fintech", "manufacturing",
    "telecom", "retail", "biotech", "insurance", "energy",
]
SIZES = ["small", "mid-market", "large", "enterprise"]
REGIONS = [
    "Hyderabad", "Bengaluru", "Pune", "Chennai", "Mumbai",
    "Delhi NCR", "Kolkata", "Kochi", "Ahmedabad", "Gurugram",
]

SYSTEM_FUNCTIONS = [
    "billing", "general ledger", "CRM", "HR records", "inventory",
    "telemetry", "identity", "claims", "data warehouse", "ticketing",
]
SYSTEM_DEPARTMENTS = [
    "Finance", "Operations", "Engineering", "Sales", "People Ops",
    "Legal", "Customer Support", "Logistics", "Risk", "Data Platform",
]

PERSON_FIRST = [
    "Arun", "Divya", "Kabir", "Meera", "Rohan", "Sana", "Vikram", "Nisha",
    "Aditya", "Priya", "Kiran", "Anita", "Rahul", "Sneha", "Imran", "Tara",
]
PERSON_LAST = [
    "Balakrishnan", "Deshmukh", "Chauhan", "Iyengar", "Nair", "Rao",
    "Malhotra", "Sundaram", "Kulkarni", "Banerjee",
]

AMOUNT_SUFFIX = ["", "", "", " INR", " USD"]

SENSITIVITY = {"org": "high", "system": "high", "person": "high",
               "amount": "medium", "identifier": "high", "location": "low"}


def _short_hash(text: str, n: int = 4) -> str:
    """Deterministic short hex digest. Stable across runs and platforms."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:n]


def canonical_token(etype: str, seed: str) -> str:
    """A syntactically valid SQL/Python identifier carrying no semantics.

    `tbl_7f3a` is a legal table name, so the benchmark can be written directly in
    canonical token space and every checker runs unmodified on every variant.
    """
    return f"{CANONICAL_PREFIX[etype]}_{_short_hash(seed)}"


@dataclass(frozen=True)
class Entity:
    eid: str
    etype: str
    canonical: str
    name: str
    aliases: tuple[str, ...] = ()
    attributes: dict[str, Any] = field(default_factory=dict)
    sensitivity: str = "high"
    sensitive: bool = True

    def attribute_vector(self) -> tuple:
        """Ordered attribute tuple used for k-anonymity and distance scoring."""
        keys = ["industry", "size", "region", "function", "department"]
        return tuple(self.attributes.get(k) for k in keys)


class Registry:
    def __init__(self, entities: Iterable[Entity]):
        self.entities: list[Entity] = list(entities)
        self._by_eid = {e.eid: e for e in self.entities}
        self._by_canonical = {e.canonical: e for e in self.entities}
        self._by_name = {}
        for e in self.entities:
            for form in (e.name, *e.aliases):
                self._by_name.setdefault(form.lower(), e)

    def get(self, eid: str) -> Entity:
        return self._by_eid[eid]

    def by_canonical(self, token: str) -> Entity | None:
        return self._by_canonical.get(token)

    def by_name(self, name: str) -> Entity | None:
        return self._by_name.get(name.lower())

    def of_type(self, etype: str) -> list[Entity]:
        return [e for e in self.entities if e.etype == etype]

    def candidate_set(self, etype: str, n: int, seed: int, exclude_eid: str | None = None) -> list[Entity]:
        """Closed candidate set for the attacker, Section 5.1.

        Always includes the true entity, then samples distractors of the same
        type. Falls back to the whole registry if the type is too small to
        support N, which keeps chance rate honest in the report.

        Sampling uses CRC32, not hash(), because Python string hashing is
        salted per process and would make candidate sets irreproducible
        across runs.
        """
        import random
        import zlib

        pool = [e for e in self.of_type(etype) if e.sensitive and e.eid != exclude_eid]
        rng = random.Random(seed ^ (zlib.crc32(etype.encode("utf-8")) % 10_000))
        k = min(n, len(pool) + 1)
        distractors = pool if k - 1 >= len(pool) else rng.sample(pool, k - 1)
        truth = self.get(exclude_eid) if exclude_eid else None
        cands = list(distractors)
        if truth is not None:
            cands.append(truth)
        else:
            cands.append(rng.choice(pool))
        rng.shuffle(cands)
        return cands

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            for e in self.entities:
                fh.write(json.dumps(_entity_to_dict(e), sort_keys=True) + "\n")

    @classmethod
    def load(cls, path: Path) -> "Registry":
        entities = []
        with Path(path).open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    entities.append(_entity_from_dict(json.loads(line)))
        return cls(entities)


def _entity_to_dict(e: Entity) -> dict:
    d = {
        "eid": e.eid, "etype": e.etype, "canonical": e.canonical, "name": e.name,
        "aliases": list(e.aliases), "attributes": e.attributes,
        "sensitivity": e.sensitivity, "sensitive": e.sensitive,
    }
    return d


def _entity_from_dict(d: dict) -> Entity:
    return Entity(
        eid=d["eid"], etype=d["etype"], canonical=d["canonical"], name=d["name"],
        aliases=tuple(d.get("aliases", [])), attributes=d.get("attributes", {}),
        sensitivity=d.get("sensitivity", "high"), sensitive=d.get("sensitive", True),
    )


def build_registry(seed: int = 20260101) -> Registry:
    """Deterministically construct the fictional universe.

    Attribute tuples are deliberately sometimes duplicated across entities.
    That is not sloppiness: it creates the ambiguity class that makes the
    restoration-success measurement (plan 7.1.1) meaningful, because a
    descriptive rung can fail to invert precisely when several entities share
    its attributes.
    """
    import random

    rng = random.Random(seed)
    entities: list[Entity] = []
    n = 0

    def nid(prefix: str) -> str:
        nonlocal n
        n += 1
        return f"{prefix}_{n:03d}"

    # --- organizations -----------------------------------------------------
    for i in range(30):
        stem = ORG_STEMS[i]
        suffix = ORG_SUFFIXES[i % len(ORG_SUFFIXES)]
        name = f"{stem} {suffix}"
        eid = nid("ORG")
        entities.append(Entity(
            eid=eid, etype="org",
            canonical=canonical_token("org", f"{eid}:{name}"),
            name=name,
            attributes={
                "industry": INDUSTRIES[i % len(INDUSTRIES)],
                "size": SIZES[(i // 3) % len(SIZES)],
                "region": REGIONS[(i * 3) % len(REGIONS)],
            },
            sensitivity="high",
        ))

    # --- internal systems --------------------------------------------------
    for i in range(30):
        fn = SYSTEM_FUNCTIONS[i % len(SYSTEM_FUNCTIONS)]
        dept = SYSTEM_DEPARTMENTS[(i // 3) % len(SYSTEM_DEPARTMENTS)]
        eid = nid("SYS")
        entities.append(Entity(
            eid=eid, etype="system",
            canonical=canonical_token("system", f"{eid}:{fn}:{dept}"),
            name=f"{dept} {fn} system",
            aliases=[f"{fn} system", f"{dept.lower()} {fn}"],
            attributes={"function": fn, "department": dept},
            sensitivity="high",
        ))

    # --- people ------------------------------------------------------------
    for i in range(16):
        first = PERSON_FIRST[i % len(PERSON_FIRST)]
        last = PERSON_LAST[(i // 4) % len(PERSON_LAST)]
        name = f"{first} {last}"
        eid = nid("PER")
        entities.append(Entity(
            eid=eid, etype="person",
            canonical=canonical_token("person", f"{eid}:{name}"),
            name=name, aliases=[first],
            attributes={"region": REGIONS[(i * 5) % len(REGIONS)]},
            sensitivity="high",
        ))

    # --- monetary figures --------------------------------------------------
    for i in range(20):
        value = rng.randrange(250_000, 90_000_000, 50_000)
        eid = nid("AMT")
        entities.append(Entity(
            eid=eid, etype="amount",
            canonical=str(value),
            name=f"{value:,}",
            attributes={"value": value, "magnitude": _magnitude(value)},
            sensitivity="medium",
        ))

    # --- structured identifiers -------------------------------------------
    for i in range(20):
        body = _short_hash(f"IDR{i}", 5).upper()
        eid = nid("IDR")
        entities.append(Entity(
            eid=eid, etype="identifier",
            canonical=f"{body[:3]}-{body[3:]}-KX",
            name=f"{body[:3]}-{body[3:]}-KX",
            aliases=[body],
            attributes={"scheme": "client_account"},
            sensitivity="high",
        ))

    # --- facilities / locations -------------------------------------------
    for i in range(20):
        city = REGIONS[i % len(REGIONS)]
        eid = nid("LOC")
        entities.append(Entity(
            eid=eid, etype="location",
            canonical=canonical_token("location", f"{eid}:{city}"),
            name=f"{city} facility",
            attributes={"region": city},
            sensitivity="low",
        ))

    # --- hard negatives ----------------------------------------------------
    # Not sensitive: public knowledge, or a value that only looks like a
    # secret. These measure false positives (plan 7.2).
    entities.append(Entity(
        eid="NEG_001", etype="location", canonical="public_annual_report",
        name="public annual report", attributes={"region": "n/a"},
        sensitivity="none", sensitive=False,
    ))
    entities.append(Entity(
        eid="NEG_002", etype="org", canonical="the_fruit_apple",
        name="the fruit apple", attributes={"industry": "agriculture"},
        sensitivity="none", sensitive=False,
    ))
    entities.append(Entity(
        eid="NEG_003", etype="amount", canonical="1000",
        name="1000", attributes={"value": 1000, "magnitude": "thousands"},
        sensitivity="none", sensitive=False,
    ))
    entities.append(Entity(
        eid="NEG_004", etype="org", canonical="iso_8601_standard",
        name="the ISO 8601 standard", attributes={"industry": "standards body"},
        sensitivity="none", sensitive=False,
    ))

    return Registry(entities)


def _magnitude(value: int) -> str:
    if value < 1_000:
        return "hundreds"
    if value < 1_000_000:
        return "thousands"
    if value < 10_000_000:
        return "millions"
    return "tens of millions"