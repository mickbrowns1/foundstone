"""
event_builder.py — Merge a rule's field overlay onto a real SDL event template.

The template provides realistic context (user names, IPs, resource IDs, etc.)
so the synthetic event looks plausible.  The overlay adds or replaces exactly
the fields needed to satisfy the detection rule's conditions.

All synthetic events are tagged with ``_foundstone_test: true`` and
``_rule_id: <id>`` for easy identification and cleanup.
"""

from __future__ import annotations

import copy
import uuid
from typing import Any


def build_event(
    template: dict[str, Any],
    overlay: dict[str, Any],
    rule_id: str,
    *,
    novel_field: str | None = None,
    novel_suffix: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Overlay rule-required fields onto a copy of *template*.

    Parameters
    ----------
    template:
        Flat ``{dotted.key: value}`` dict from a real SDL event.
    overlay:
        Flat ``{dotted.key: value}`` dict of fields required to fire the rule
        (produced by :func:`~foundstone.rule_parser.ParsedRule.overlay`).
    rule_id:
        The rule's UUID, stored in ``_rule_id`` for cleanup queries.
    novel_field:
        When set (for ``first_seen`` rules), this field's value will have
        *novel_suffix* appended so it looks like a first-ever occurrence.
    novel_suffix:
        A UUID or other unique string appended to *novel_field*'s value.
        Defaults to a fresh UUID4 hex string.

    Returns
    -------
    (event, modified_fields)
        *event*: the final flat dict ready for ingestion.
        *modified_fields*: ``{field: new_value}`` — only the fields that differ
        from the original template (useful for reporting).
    """
    event: dict[str, Any] = copy.deepcopy(template)
    modified_fields: dict[str, Any] = {}

    # Apply overlay — overlay values always win over the template
    for field, value in overlay.items():
        if event.get(field) != value:
            modified_fields[field] = value
        event[field] = value

    # Handle first_seen novelty: make the designated field unique
    if novel_field is not None:
        suffix = novel_suffix or uuid.uuid4().hex
        original_value = str(event.get(novel_field, "unknown"))
        new_value = f"{original_value}_{suffix}"
        event[novel_field] = new_value
        modified_fields[novel_field] = new_value

    # FoundStone housekeeping tags
    event["_foundstone_test"] = True
    event["_rule_id"] = rule_id

    return event, modified_fields


def build_events_for_rule(
    template: dict[str, Any],
    overlay: dict[str, Any],
    rule_id: str,
    copies: int = 1,
    *,
    novel_field: str | None = None,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """
    Build *copies* synthetic events for a single rule.

    For volume rules, *copies* should be set to the threshold + 2.
    For first_seen rules, each copy gets a unique *novel_field* suffix so each
    event looks like a brand-new entity the rule has never seen.

    Returns a list of ``(event, modified_fields)`` tuples.
    """
    results: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for i in range(copies):
        suffix = uuid.uuid4().hex if novel_field else None
        event, modified = build_event(
            template,
            overlay,
            rule_id,
            novel_field=novel_field,
            novel_suffix=suffix,
        )
        # Give each copy a slightly different timestamp placeholder
        # (actual ts is set by the ingester from wall-clock time)
        event["_copy_index"] = i
        results.append((event, modified))
    return results
