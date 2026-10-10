"""Ad-hoc PII and secret detection for free-form chat text.

The registry dictionary only fires on synthetic benchmark tokens. Real chat
text contains values no registry can enumerate: email addresses, phone
numbers, passwords, employee IDs, API keys, card numbers. This module finds
those by shape (regex) plus opt-in context cues, deliberately biased toward
recall over precision: in a sanitizer, a false positive costs a placeholder;
a false negative leaks the secret.

Every hit carries the parsed attributes the ladder rungs need (domain, host,
last4, value kind). Nothing here depends on the benchmark universe.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .rules import CARD_RE, luhn_ok


@dataclass(frozen=True)
class AdHoc:
    """One candidate ad-hoc sensitive value found in text."""
    etype: str            # email | phone | password | employee_id | api_key | card
    value: str            # exact surface as written
    start: int
    end: int
    attributes: dict = field(default_factory=dict)
    rule: str = ""        # which pattern fired, for auditability


# ---------------------------------------------------------------------------
# shape patterns (run first; context cues only widen, never narrow)
# ---------------------------------------------------------------------------

# email: local@host.tld — conservative TLD guard so "user@localhost" and
# "a@b" don't fire, but "shara@company" (intranet-style, no dot) DOES fire
# when a password/id cue is nearby (handled in scan_pii).
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
EMAIL_BARE_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+")

# phone: flexible international shapes; digit-count + plausibility validated
PHONE_RE = re.compile(
    r"(?:\+\d{1,3}[\s-]?)?"          # optional country code
    r"(?:\(\d{2,5}\)[\s-]?|\d{2,5}[\s-])"  # area code or first group
    r"\d[\d\s-]{3,13}\d"             # rest; digit-count validated in _phone_ok
)

# password: cue word required (bare "shara@123" alone is ambiguous).
# Captures the token after pass/password/pwd/secret/otp/pin cues, with or
# without = : is delimiters. Value must be non-trivial (see _plausible_secret).
PASS_CUE_RES = [
    re.compile(r"(?i)\b(?:pass(?:word|code|phrase)?|pwd|secret|otp|pin|api[\s_-]?key|token)\b\s*[:=is]*\s*"),
]

# employee / client IDs: cue word + compact token (letters/digits, - _ allowed).
# "Client Id is 123893", "emp id: AB-1234", "user id 98765".
ID_CUE_RES = [
    re.compile(r"(?i)\b(?:client|employee|emp|user|customer|member|staff)[\s_-]?(?:id|ID|no|number)\b\s*(?:is|:|=)?\s*"),
]
ID_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{3,29}")

# API keys / tokens: known prefixes, or high-entropy long tokens after a cue.
KEY_PREFIX_RES = [
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),                       # sk- / sk-live- / sk-proj-
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),                  # AWS
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{8,}\b"),                # Slack
    re.compile(r"\bgh[op]_[A-Za-z0-9]{8,}\b"),                    # GitHub
    re.compile(r"\bglpat-[A-Za-z0-9_-]{8,}\b"),                    # GitLab
    re.compile(r"\bgsk_[A-Za-z0-9]{8,}\b"),                       # Groq
    re.compile(r"\bAIza[A-Za-z0-9_-]{10,}\b"),                    # Google
]
KEY_CUE_RES = [
    re.compile(r"(?i)\bapi[\s_-]?key\b\s*[:=is]*\s*"),
]
KEY_TOKEN_RE = re.compile(r"[A-Za-z0-9_.-]{16,128}")

# card numbers reuse CARD_RE from rules.py (Luhn-validated there).

# words that make a value look like prose rather than a secret
_SECRET_STOPWORDS = frozenset({
    "password", "secret", "token", "account", "please", "thanks", "hello",
})


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def _entropy_per_char(s: str) -> float:
    """Shannon entropy per character; random tokens sit well above words."""
    import math

    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _plausible_secret(value: str) -> bool:
    """Reject plain words and trivial values; keep secret-shaped tokens."""
    v = value.strip().strip("\"'“”‘’`")
    if len(v) < 6:
        return False
    if v.lower() in _SECRET_STOPWORDS:
        return False
    if re.fullmatch(r"[a-z]+", v):          # single lowercase word
        return False
    if re.fullmatch(r"\d+", v) and len(v) < 8:  # short pure number
        return False
    # secret-shaped: mixed classes, or high entropy, or symbols+digits
    classes = sum(bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    return classes >= 2 or _entropy_per_char(v) >= 3.5 or len(v) >= 16


def _clean(value: str) -> str:
    return value.strip().strip("\"'“”‘’`,.;")


def _phone_ok(raw: str) -> bool:
    digits = _digits(raw)
    if not 7 <= len(digits) <= 15:
        return False
    if re.fullmatch(r"0+", digits):          # 000-0000
        return False
    if len(set(digits)) == 1:                # 9999999
        return False
    return True


def _overlaps(span: tuple[int, int], spans: list[tuple[int, int]]) -> bool:
    return any(a < span[1] and span[0] < b for a, b in spans)


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------

def scan_pii(text: str) -> list[AdHoc]:
    """Find ad-hoc sensitive values. Longest match wins on overlap.

    Order matters: email before ID cues (an intranet email after "id is"
    should stay an email), keys/cards before passwords (a key after
    "password is" should stay a key), IDs before passwords.
    """
    hits: list[AdHoc] = []
    claimed: list[tuple[int, int]] = []

    def claim(etype: str, value: str, s: int, e: int, attrs: dict, rule: str) -> None:
        value = _clean(value)
        if not value or _overlaps((s, e), claimed):
            return
        # re-anchor span to the cleaned value
        hit = AdHoc(etype=etype, value=value, start=s, end=e,
                    attributes=attrs, rule=rule)
        hits.append(hit)
        claimed.append((s, e))

    # 1. dotted emails (no cue needed)
    for m in EMAIL_RE.finditer(text):
        local, host = m.group(0).rsplit("@", 1)
        claim("email", m.group(0), m.start(), m.end(),
              {"domain": host.lower(), "user": local}, "email:dotted")

    # 2. cards (Luhn-validated; rule out years/quantities via checksum)
    for m in CARD_RE.finditer(text):
        if luhn_ok(re.sub(r"\D", "", m.group(0))):
            digits = re.sub(r"\D", "", m.group(0))
            claim("card", m.group(0), m.start(), m.end(),
                  {"last4": digits[-4:], "scheme": "card"}, "card:luhn")

    # 3. known-prefix API keys (no cue needed)
    for rx in KEY_PREFIX_RES:
        for m in rx.finditer(text):
            claim("api_key", m.group(0), m.start(), m.end(),
                  {"scheme": "api_key"}, f"key:prefix:{rx.pattern[:12]}")

    # 4. cue-anchored captures: id / key / password, in that precedence
    for cue in ID_CUE_RES:
        for cm in cue.finditer(text):
            tm = ID_TOKEN_RE.match(text, cm.end())
            if not tm:
                continue
            tok = _clean(tm.group(0))
            if "@" in tok and "." in tok.split("@")[-1]:
                continue  # dotted email claimed above; bare handled below
            if "@" in tok:
                local, host = tok.rsplit("@", 1)
                claim("email", tok, tm.start(), tm.end(),
                      {"domain": host.lower(), "user": local}, "email:bare-after-cue")
            elif len(_digits(tok)) >= 4 or re.search(r"[_-]", tok):
                claim("employee_id", tok, tm.start(), tm.end(),
                      {"value_kind": _value_kind(tok)}, "id:cue")
    for cue in KEY_CUE_RES:
        for cm in cue.finditer(text):
            tm = KEY_TOKEN_RE.match(text, cm.end())
            if tm and _plausible_secret(tm.group(0)):
                claim("api_key", tm.group(0), tm.start(), tm.end(),
                      {"scheme": "api_key"}, "key:cue")
    for cue in PASS_CUE_RES:
        for cm in cue.finditer(text):
            # value runs to whitespace or line end
            vm = re.compile(r"\S+").match(text, cm.end())
            if vm and _plausible_secret(vm.group(0)):
                claim("password", vm.group(0), vm.start(), vm.end(),
                      {"value_kind": _value_kind(vm.group(0))}, "password:cue")

    # 5. bare intranet emails (no dot): only after an id cue nearby would
    # have been claimed above; anything remaining with a cue in ±40 chars
    for m in EMAIL_BARE_RE.finditer(text):
        tok = m.group(0)
        if "." in tok.split("@")[-1]:
            continue  # dotted, handled
        window = text[max(0, m.start() - 40):m.end() + 40]
        if re.search(r"(?i)\b(?:id|pass|email|mail|login|user)\b", window):
            local, host = tok.rsplit("@", 1)
            claim("email", tok, m.start(), m.end(),
                  {"domain": host.lower(), "user": local}, "email:bare-context")

    # 6. phones (cue-free, but validated)
    for m in PHONE_RE.finditer(text):
        if _phone_ok(m.group(0)):
            digits = _digits(m.group(0))
            claim("phone", m.group(0), m.start(), m.end(),
                  {"last4": digits[-4:]}, "phone:shape")

    hits.sort(key=lambda h: (h.start, -(h.end - h.start)))
    return hits


def _value_kind(value: str) -> str:
    v = value.strip()
    if re.fullmatch(r"\d+", v):
        return "numeric"
    if re.fullmatch(r"[A-Za-z0-9]+", v):
        return "alphanumeric"
    return "complex"
