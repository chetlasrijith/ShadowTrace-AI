"""Unicode normalization and evasion checks.

Run before detection. Normalization collapses the classic evasions (mixed
fullwidth, zero-width joins, bidi controls). The confusable check maps common
lookalikes back to their canonical characters. None of this is production
grade, but it closes enough of the gap to measure the ablation in plan 9:
a detector that fails without normalization is a finding, not an oversight.
"""

from __future__ import annotations

import re
import unicodedata

# zero-width and bidirectional control characters
_INVISIBLE = re.compile(
    "[\u200b\u200c\u200d\u2060\ufeff\u180e\u200e\u200f\u202a-\u202e\u2066-\u2069\u3164]"
)

# common confusables, checked before matching
_CONFUSABLES = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",
    "\u043a": "k",
    "\u043c": "m",
    "\u043d": "h",
    "\u0430": "a",
    "\u03bf": "o",
    "\uff41": "a",  # fullwidth, though NFKC already handles these
    "\uff4f": "o",
}


def normalize(text: str) -> str:
    """NFKC fold, strip invisible controls, map confusables."""
    out = unicodedata.normalize("NFKC", text)
    out = _INVISIBLE.sub("", out)
    out = "".join(_CONFUSABLES.get(ch, ch) for ch in out)
    out = re.sub(r"[ \t]+", " ", out)
    return out


def normalization_flags(text: str) -> dict:
    """Report what normalization did to this text."""
    nfkc = unicodedata.normalize("NFKC", text) != text
    invisible = _INVISIBLE.search(text) is not None
    confusable = any(ch in _CONFUSABLES for ch in text)
    return {"nfkc": nfkc, "invisible": invisible, "confusable": confusable}