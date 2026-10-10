"""Structured secret rules with checksum validation.

These fire before the registry dictionary match and do not depend on any
entity in the universe. Valid test card numbers are included deliberately:
a detector that flags them is doing its job; a transform that leaves them is
failing it. Luhn validation separates real secrets from random digit noise.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

@dataclass(frozen=True)
class SecretHit:
    start: int
    end: int
    surface: str
    scheme: str

# Test card numbers. Public test data, never real credentials.
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GENERIC_TOKEN_RE = re.compile(r"\b(?:sk|ghp|gho|glpat)-[A-Za-z0-9_-]{12,}\b")
GOVID_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")  # PAN-like pattern


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def luhn_ok(digits: str) -> bool:
    """Luhn checksum. Deterministic, no dependencies."""
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def scan_secrets(text: str) -> list[SecretHit]:
    """Return validated structured-secret spans."""
    hits: list[SecretHit] = []
    for m in AWS_KEY_RE.finditer(text):
        hits.append(SecretHit(m.start(), m.end(), m.group(0), "aws_key"))
    for m in GENERIC_TOKEN_RE.finditer(text):
        hits.append(SecretHit(m.start(), m.end(), m.group(0), "api_token"))
    for m in GOVID_RE.finditer(text):
        hits.append(SecretHit(m.start(), m.end(), m.group(0), "gov_id"))
    for m in CARD_RE.finditer(text):
        digits = _digits(m.group(0))
        if luhn_ok(digits):
            hits.append(SecretHit(m.start(), m.end(), m.group(0), "card"))
    hits.sort(key=lambda h: (h.start, h.end))
    return hits