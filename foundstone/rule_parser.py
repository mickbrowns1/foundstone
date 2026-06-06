"""
rule_parser.py — Translate a rule's ``pair_list`` into the minimal field overlay
needed to fire the detection.

Each pair has the shape ``{"key": str, "op": str, "value": Any}``.
Supported ops: ``=``, ``==``, ``!=``, ``in``, ``contains``, ``not contains``,
``matches``, ``not matches``, ``>``, ``>=``, ``<``, ``<=``.

The output is two dicts:
- ``required``: fields that MUST be present with the given value
- ``excluded``: fields that must NOT equal the given value
  (we set these to a safe ``not_<value>`` string so the event is still realistic)
"""

from __future__ import annotations

import logging
import re
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex → example string generation
# ---------------------------------------------------------------------------

def _regex_to_example(pattern: str) -> str:
    """
    Return a minimal string that satisfies *pattern*.

    Tries ``exrex`` first; falls back to extracting the longest literal run
    from the regex if that library is unavailable or raises.
    """
    try:
        import exrex  # type: ignore
        example = exrex.getone(pattern, limit=10)
        if example:
            return example
    except Exception:
        pass

    # Fallback: strip all regex metacharacters and return what's left
    literal = re.sub(r"[\\^$.*+?{}[\]|()]", "", pattern)
    return literal or "foundstone_match"


# ---------------------------------------------------------------------------
# Numeric coercion helpers
# ---------------------------------------------------------------------------

def _to_number(value: Any) -> float | int:
    """Coerce *value* to a number, raising ValueError on failure."""
    try:
        as_float = float(str(value))
        # Return int when there's no fractional part
        return int(as_float) if as_float == int(as_float) else as_float
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Cannot coerce {value!r} to a number") from exc


# ---------------------------------------------------------------------------
# Core parser
# ---------------------------------------------------------------------------

class ParsedRule:
    """
    Holds the computed field overlays for a single rule query.

    Attributes
    ----------
    required:
        ``{field: value}`` — every key must be present with this exact value.
    excluded:
        ``{field: value}`` — every key must be present but NOT equal to this value.
        We satisfy this by writing ``"not_<value>"``.
    data_source:
        The value of the ``dataSource.name`` field if found in *required*, else ``None``.
    """

    def __init__(self) -> None:
        self.required: dict[str, Any] = {}
        self.excluded: dict[str, Any] = {}

    @property
    def data_source(self) -> str | None:
        return self.required.get("dataSource.name")

    def overlay(self) -> dict[str, Any]:
        """
        Return the final flat field dict to overlay onto a template event.

        For excluded fields, we emit ``"not_<original_value>"`` so the field
        is present (realistic) but will not match the negated clause.
        """
        result: dict[str, Any] = dict(self.required)
        for field, value in self.excluded.items():
            # Only add the exclusion stand-in when there is no positive constraint
            if field not in result:
                result[field] = f"not_{value}"
        return result


def parse_pair_list(pair_list: list[dict[str, Any]]) -> ParsedRule:
    """
    Convert a rule's ``pair_list`` into a :class:`ParsedRule`.

    Parameters
    ----------
    pair_list:
        List of ``{"key": str, "op": str, "value": Any}`` dicts extracted from
        the rule definition.

    Returns
    -------
    ParsedRule
        A parsed rule with ``required`` and ``excluded`` dicts populated.
    """
    parsed = ParsedRule()

    for pair in pair_list:
        key: str = pair["key"]
        op: str = str(pair.get("op", "=")).strip().lower()
        value: Any = pair.get("value")

        try:
            _apply_pair(parsed, key, op, value)
        except Exception as exc:  # noqa: BLE001
            log.warning("Skipping unparseable pair %s %s %r: %s", key, op, value, exc)

    return parsed


def _apply_pair(parsed: ParsedRule, key: str, op: str, value: Any) -> None:
    """Apply a single pair to the :class:`ParsedRule`, mutating it in-place."""

    # ------------------------------------------------------------------
    # Equality / assignment
    # ------------------------------------------------------------------
    if op in ("=", "=="):
        parsed.required[key] = value
        return

    # ------------------------------------------------------------------
    # Inequality — field must be present but differ
    # ------------------------------------------------------------------
    if op in ("!=", "not =", "not=="):
        parsed.excluded[key] = value
        return

    # ------------------------------------------------------------------
    # Membership — use first element of the list
    # ------------------------------------------------------------------
    if op == "in":
        if isinstance(value, list) and value:
            parsed.required[key] = value[0]
        elif isinstance(value, str):
            # Sometimes stored as a comma-joined string
            first = value.split(",")[0].strip().strip("'\"")
            parsed.required[key] = first
        else:
            parsed.required[key] = value
        return

    if op == "not in":
        first: Any
        if isinstance(value, list) and value:
            first = value[0]
        elif isinstance(value, str):
            first = value.split(",")[0].strip().strip("'\"")
        else:
            first = value
        parsed.excluded[key] = first
        return

    # ------------------------------------------------------------------
    # Substring containment
    # ------------------------------------------------------------------
    if op == "contains":
        # The substring itself satisfies the contains check
        parsed.required[key] = value
        return

    if op in ("not contains", "not_contains"):
        parsed.excluded[key] = value
        return

    # ------------------------------------------------------------------
    # Regex matching
    # ------------------------------------------------------------------
    if op == "matches":
        example = _regex_to_example(str(value))
        parsed.required[key] = example
        return

    if op in ("not matches", "not_matches"):
        # We don't need to match — omit the field or use a safe literal
        parsed.excluded[key] = _regex_to_example(str(value))
        return

    # ------------------------------------------------------------------
    # Numeric comparisons
    # ------------------------------------------------------------------
    if op == ">":
        n = _to_number(value)
        parsed.required[key] = n + 1
        return

    if op == ">=":
        parsed.required[key] = _to_number(value)
        return

    if op == "<":
        n = _to_number(value)
        parsed.required[key] = n - 1
        return

    if op == "<=":
        parsed.required[key] = _to_number(value)
        return

    # ------------------------------------------------------------------
    # Unknown op — log and treat as equality as a best-effort fallback
    # ------------------------------------------------------------------
    log.warning("Unknown op %r for key %r — treating as equality", op, key)
    parsed.required[key] = value
