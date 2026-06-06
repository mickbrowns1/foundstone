"""
classifier.py — Determine the class of a detection rule and the number of
synthetic event copies needed to trigger it.

Rule classes
------------
simple
    A single-event filter rule — one copy is enough.
volume
    Aggregates events (``group count()``), or name implies bulk behaviour.
    We need at least threshold + 2 events.
correlation
    Multi-stage rule or lives under a ``/correlation/`` path.
    One event per query stage, sharing a common join entity.
first_seen
    First-time-seen rule — the novel field must look unique every run.
scheduled
    Runs on a schedule; we treat it like a simple rule for verification purposes.
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_VOLUME_NAME_KEYWORDS = re.compile(
    r"\b(multiple|bulk|excessive|repeated|many|high.?volume)\b",
    re.IGNORECASE,
)

_VOLUME_QUERY_PATTERN = re.compile(
    r"\|\s*group\b.*\bcount\s*\(",
    re.IGNORECASE | re.DOTALL,
)

# Regex to extract a numeric threshold from a volume query, e.g. ``count() > 5``
_THRESHOLD_PATTERN = re.compile(
    r"count\s*\(\s*\)\s*[><=!]+\s*(\d+)",
    re.IGNORECASE,
)

_DEFAULT_VOLUME_COPIES = 7  # threshold unknown → safe default


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class RuleClass:
    SIMPLE = "simple"
    VOLUME = "volume"
    CORRELATION = "correlation"
    FIRST_SEEN = "first_seen"
    SCHEDULED = "scheduled"


def classify(rule: dict[str, Any]) -> tuple[str, int]:
    """
    Classify a rule and return ``(class_name, copies_needed)``.

    Parameters
    ----------
    rule:
        A single rule dict from ``extracted.json`` (keys: ``file``, ``name``,
        ``queries``, etc.).

    Returns
    -------
    (class_name, copies)
        *class_name*: one of the :class:`RuleClass` constants.
        *copies*: number of synthetic events to generate (≥ 1).
    """
    file_path: str = rule.get("file", "").lower()
    name: str = rule.get("name", "")
    queries: list[dict[str, Any]] = rule.get("queries", [])
    query_strings = [q.get("query", "") for q in queries]
    combined_query = " ".join(query_strings)

    # --- Correlation ---
    if "/correlation/" in file_path or len(queries) > 1:
        return RuleClass.CORRELATION, len(queries) or 1

    # --- First seen ---
    if "/first_seen/" in file_path or _is_first_seen(name):
        return RuleClass.FIRST_SEEN, 1

    # --- Scheduled ---
    if "/scheduled/" in file_path:
        return RuleClass.SCHEDULED, 1

    # --- Volume ---
    if _VOLUME_QUERY_PATTERN.search(combined_query) or _VOLUME_NAME_KEYWORDS.search(name):
        threshold = _extract_threshold(combined_query)
        copies = (threshold + 2) if threshold is not None else _DEFAULT_VOLUME_COPIES
        return RuleClass.VOLUME, copies

    # --- Simple (default) ---
    return RuleClass.SIMPLE, 1


def _is_first_seen(name: str) -> bool:
    """Return True if the rule name implies a first-seen detection."""
    patterns = [
        r"\bfirst[\s_-]seen\b",
        r"\bfirst[\s_-]time\b",
        r"\bnew\s+\w+",   # e.g. "new device", "new user"
    ]
    for pat in patterns:
        if re.search(pat, name, re.IGNORECASE):
            return True
    return False


def _extract_threshold(query: str) -> int | None:
    """
    Try to parse the numeric threshold from a volume query.

    Returns ``None`` when no threshold can be determined.
    """
    match = _THRESHOLD_PATTERN.search(query)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            pass
    return None
