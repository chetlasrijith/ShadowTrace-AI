"""Registry and universe tests."""

from shadowtrace.universe import build_registry, canonical_token


def test_registry_builds_and_is_deterministic():
    r1 = build_registry(1)
    r2 = build_registry(1)
    assert len(r1.entities) == len(r2.entities) > 100
    assert [e.canonical for e in r1.entities] == [e.canonical for e in r2.entities]


def test_canonical_tokens_are_valid_identifiers():
    r = build_registry(1)
    for e in r.of_type("system"):
        assert e.canonical.isidentifier(), e.canonical
    for e in r.of_type("org"):
        assert e.canonical.isidentifier(), e.canonical


def test_candidate_set_always_includes_truth():
    r = build_registry(1)
    truth = r.of_type("org")[0]
    cands = r.candidate_set("org", 10, seed=5, exclude_eid=truth.eid)
    assert any(c.eid == truth.eid for c in cands)
    assert len(cands) == 10


def test_candidate_set_falls_back_when_pool_small():
    r = build_registry(1)
    truth = r.of_type("person")[0]
    cands = r.candidate_set("person", 50, seed=5, exclude_eid=truth.eid)
    assert any(c.eid == truth.eid for c in cands)
    assert len(cands) < 50  # pool is smaller than N: honest fallback


def test_fictional_names():
    r = build_registry(1)
    names = " ".join(e.name for e in r.of_type("org")).lower()
    for real in ("infosys", "tcs", "reliance", "google", "microsoft"):
        assert real not in names
