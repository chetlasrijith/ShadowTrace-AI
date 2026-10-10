"""Drafting proxy. Explicitly NOT a utility measure.

Without an LLM judge there is no defensible task-success score for free
text, and the plan (7.3, 8.1) forbids treating a proxy as one. This module
checks only structural properties: the output is prose of reasonable length,
respects the sentence cap, mentions a task keyword, and references at least
one entity from the prompt in any form (canonical, rendering, placeholder).

The report prints these numbers in a separate section headed with the
warning. If they ever look like utility, that is a presentation bug.
"""

from __future__ import annotations

from ..prompts import Prompt
from ..transform.ladders import Ladders
from ..universe import Registry

TASK_KEYWORDS = ("outage", "incident", "status", "update", "system",
                 "client", "root cause", "investigation")


def score_drafting_proxy(
    answer: str, prompt: Prompt, registry: Registry, ladders: Ladders,
) -> dict:
    text = answer.strip()
    words = text.split()
    sentences = [s for s in text.replace("!", ".").replace("?", ".").split(".") if s.strip()]
    checks = {
        "nonempty": len(words) >= 10,
        "not_truncated": len(words) <= 200,
        "sentence_cap": len(sentences) <= 4,
        "task_keyword": any(k in text.lower() for k in TASK_KEYWORDS),
        "entity_reference": _mentions_entity(text, prompt, registry, ladders),
    }
    return {
        "task_success": None,  # no utility claim. ever.
        "is_not_utility": True,
        "structural_valid": all(checks.values()),
        "checks": checks,
        "n_words": len(words),
        "n_sentences": len(sentences),
    }


def _mentions_entity(text: str, prompt: Prompt, registry: Registry, ladders: Ladders) -> bool:
    t = text.lower()
    by_eid = {e.eid: e for e in registry.entities}
    for eid in prompt.entities:
        ent = by_eid.get(eid)
        if ent is None:
            continue
        forms = [ent.canonical.lower(), ent.name.lower(),
                 *(a.lower() for a in ent.aliases)]
        forms += [ladders.render(ent, d).lower()
                  for d in range(1, ladders.max_depth(ent.etype) + 1)]
        if any(f and len(f) >= 3 and f in t for f in forms):
            return True
    return any(ph.lower() in t for ph in
               ("[ORG]", "[SYSTEM]", "[PERSON]", "[AMOUNT]", "[ID]", "[LOCATION]"))