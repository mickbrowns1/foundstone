"""
runner.py — Orchestrate the full FoundStone pipeline for one or many rules.

For each rule the pipeline is:
  1. Classify the rule (simple / volume / correlation / first_seen / scheduled)
  2. Parse the pair_list → minimal field overlay
  3. Determine the dataSource.name
  4. Fetch real event templates from SDL (cached per source)
  5. Build synthetic event(s) by overlaying rule fields onto the template
  6. Ingest events into SDL
  7. Wait and verify that the alert fired
  8. Return a structured result dict
"""

from __future__ import annotations

import itertools
import logging
from typing import Any, Iterator

from .classifier import RuleClass, classify
from .config import Config
from .event_builder import build_events_for_rule
from .ingester import ingest_events
from .rule_parser import parse_pair_list
from .template_fetcher import fetch_templates
from .verifier import wait_and_verify

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

# Status values for a single rule run
STATUS_INGESTED = "ingested"
STATUS_NO_TEMPLATE = "no_template"
STATUS_DRY_RUN = "dry_run"
STATUS_ERROR = "error"


def run_rule(rule: dict[str, Any], cfg: Config) -> dict[str, Any]:
    """
    Execute the full FoundStone pipeline for a single *rule*.

    Parameters
    ----------
    rule:
        A rule dict from ``extracted.json``.
    cfg:
        Runtime configuration.

    Returns
    -------
    dict
        A result dict matching the FoundStone output schema.
    """
    rule_id: str = rule.get("id", "unknown")
    rule_name: str = rule.get("name", "unknown")

    result: dict[str, Any] = {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "class": RuleClass.SIMPLE,
        "copies": 1,
        "modified_fields": {},
        "template_source": None,
        "status": STATUS_ERROR,
        "alert_fired": None,
        "alert_count": 0,
    }

    try:
        # --- Step 1: classify ---
        rule_class, copies = classify(rule)
        result["class"] = rule_class

        # --- Step 2: parse the first query's pair_list ---
        queries = rule.get("queries", [])
        if not queries:
            log.warning("Rule '%s' has no queries — skipping.", rule_name)
            result["status"] = STATUS_ERROR
            return result

        # For correlation rules we'll process each query in sequence;
        # for all others we only need the first.
        parsed = parse_pair_list(queries[0].get("pair_list", []))
        overlay = parsed.overlay()

        # --- Step 3: determine data source ---
        source = parsed.data_source
        if not source:
            log.warning("Rule '%s': no dataSource.name found in pair_list.", rule_name)
            result["status"] = STATUS_ERROR
            return result

        result["template_source"] = source

        # --- Step 4: fetch templates ---
        templates = fetch_templates(source, cfg)
        if not templates:
            log.info("Rule '%s': no templates found for source '%s'.", rule_name, source)
            result["status"] = STATUS_NO_TEMPLATE
            result["copies"] = copies
            return result

        # Rotate templates across rules for variety
        template = _pick_template(templates, rule_id)

        # --- Step 5: build synthetic events ---
        novel_field: str | None = None
        if rule_class == RuleClass.FIRST_SEEN:
            # Identify the most-likely "novel" field (first non-dataSource required field)
            novel_field = _pick_novel_field(overlay)

        events_and_diffs = build_events_for_rule(
            template,
            overlay,
            rule_id,
            copies=copies,
            novel_field=novel_field,
        )

        flat_events = [e for e, _ in events_and_diffs]
        # Report the modified fields from the first copy
        result["modified_fields"] = events_and_diffs[0][1] if events_and_diffs else {}
        result["copies"] = len(flat_events)

        # --- Step 6: ingest ---
        if cfg.dry_run:
            log.info("[DRY RUN] Rule '%s' — would ingest %d event(s).", rule_name, len(flat_events))
            result["status"] = STATUS_DRY_RUN
            return result

        success = ingest_events(flat_events, cfg, session_tag=rule_id[:8])
        if not success:
            result["status"] = STATUS_ERROR
            return result

        result["status"] = STATUS_INGESTED

        # --- Step 7: verify ---
        fired, count = wait_and_verify(rule_name, cfg)
        result["alert_fired"] = fired
        result["alert_count"] = count

    except Exception as exc:  # noqa: BLE001
        log.exception("Unexpected error processing rule '%s': %s", rule_name, exc)
        result["status"] = STATUS_ERROR

    return result


def run_rules(
    rules: list[dict[str, Any]],
    cfg: Config,
    *,
    progress_callback: Any = None,
) -> Iterator[dict[str, Any]]:
    """
    Yield a result dict for each rule in *rules*.

    Parameters
    ----------
    rules:
        List of rule dicts.
    cfg:
        Runtime configuration.
    progress_callback:
        Optional callable invoked as ``progress_callback(index, total, result)``
        after each rule completes.
    """
    total = len(rules)
    for i, rule in enumerate(rules, start=1):
        result = run_rule(rule, cfg)
        if progress_callback:
            progress_callback(i, total, result)
        yield result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_TEMPLATE_ROTATION: dict[str, itertools.cycle] = {}


def _pick_template(templates: list[dict], rule_id: str) -> dict:
    """
    Pick a template for this rule by cycling through the available templates.

    Using a cycle ensures successive rules for the same source get different
    templates, reducing duplicate-event noise.
    """
    source_key = templates[0].get("dataSource.name", id(templates))
    if source_key not in _TEMPLATE_ROTATION:
        _TEMPLATE_ROTATION[source_key] = itertools.cycle(templates)
    return next(_TEMPLATE_ROTATION[source_key])


def _pick_novel_field(overlay: dict[str, Any]) -> str | None:
    """
    Return the best candidate field to make unique for a first_seen rule.

    We prefer fields like ``user.name``, ``src_ip``, ``device.name`` over
    infrastructure fields like ``dataSource.name``.
    """
    PREFERRED = [
        "user.name", "user.email", "src_ip", "dst_ip",
        "device.name", "host.name", "subject.name",
    ]
    for candidate in PREFERRED:
        if candidate in overlay:
            return candidate
    # Fall back to first non-dataSource field
    for key in overlay:
        if key != "dataSource.name":
            return key
    return None
