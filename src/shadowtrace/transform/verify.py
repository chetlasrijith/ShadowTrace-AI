"""Post-transform verification. Plan 6.4, the no-silent-forward rule."""


def verify_no_surviving_spans(text: str, sensitive_surfaces: set[str]) -> bool:
    """True when no sensitive surface string survives in the rewrite."""
    lowered = text.lower()
    return not any(s.lower() in lowered for s in sensitive_surfaces if s)


def count_survivors(text: str, sensitive_surfaces: set[str]) -> int:
    """How many sensitive surfaces survive. Zero is the pass."""
    lowered = text.lower()
    return sum(1 for s in sensitive_surfaces if s and s.lower() in lowered)
