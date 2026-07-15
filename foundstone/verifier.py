"""
verifier.py — Query the SDL ``alert`` dataset to confirm whether a rule fired.

After synthetic events are ingested we wait for ``VERIFY_DELAY`` seconds and
then query SDL for alerts whose title matches the rule name.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import requests

from .config import Config

log = logging.getLogger(__name__)

# Look-back window for alert queries (seconds)
_ALERT_LOOKBACK_SECONDS = 300  # 5 minutes — generous to account for lag

# SDL PowerQuery that counts alerts by title over the recent window
_ALERT_QUERY_TEMPLATE = (
    "dataSource.name='alert' "
    "| filter finding_info.title != '' "
    "| group n=count() by finding_info.title"
)


def wait_and_verify(
    rule_name: str,
    cfg: Config,
    *,
    lookback_seconds: int = _ALERT_LOOKBACK_SECONDS,
) -> tuple[bool, int]:
    """
    Wait for the configured delay, then check whether an alert matching
    *rule_name* appeared in SDL.

    Parameters
    ----------
    rule_name:
        The ``name`` field from the rule definition.
    cfg:
        Runtime configuration.
    lookback_seconds:
        How far back (in seconds) to search for alerts.

    Returns
    -------
    (fired, count)
        *fired*: ``True`` if at least one matching alert was found.
        *count*: exact number of matching alert events found.
    """
    if cfg.dry_run:
        log.info("[DRY RUN] Skipping alert verification for '%s'.", rule_name)
        return False, 0

    log.info("Waiting %ds before verifying alerts for '%s' …", cfg.verify_delay, rule_name)
    time.sleep(cfg.verify_delay)

    return query_alerts(rule_name, cfg, lookback_seconds=lookback_seconds)


def query_alerts(
    rule_name: str,
    cfg: Config,
    *,
    lookback_seconds: int = _ALERT_LOOKBACK_SECONDS,
) -> tuple[bool, int]:
    """
    Query SDL for alert counts grouped by title and match against *rule_name*.

    Matching is case-insensitive and strips the common `` - OOTB`` suffix that
    SentinelOne appends to out-of-the-box rule names.

    Parameters
    ----------
    rule_name:
        The detection rule name to look for.
    cfg:
        Runtime configuration.
    lookback_seconds:
        How far back to search.

    Returns
    -------
    (fired, count)
    """
    now_ms = int(time.time() * 1000)
    start_ms = now_ms - lookback_seconds * 1000

    url = f"{cfg.sdl_base_url}/api/powerQuery"
    payload: dict[str, Any] = {
        "token": cfg.sdl_read_token,
        "queryType": "complex",
        "query": _ALERT_QUERY_TEMPLATE,
        "startTime": start_ms,
        "endTime": now_ms,
        "maxCount": 1000,
    }

    try:
        resp = requests.post(url, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        log.error("Alert query failed: %s", exc)
        return False, 0

    rows = _rows_from_powerquery(data)

    canonical_name = _normalise_rule_name(rule_name)
    total_count = 0

    for row in rows:
        title = str(row.get("finding_info.title") or row.get("title") or "")
        if _normalise_rule_name(title) == canonical_name:
            try:
                total_count += int(row.get("n") or row.get("count") or 0)
            except (ValueError, TypeError):
                total_count += 1  # At least one match

    fired = total_count > 0
    log.info(
        "Alert verification for '%s': fired=%s, count=%d",
        rule_name,
        fired,
        total_count,
    )
    return fired, total_count


def get_alert_counts(
    cfg: Config,
    *,
    lookback_seconds: int = _ALERT_LOOKBACK_SECONDS,
) -> dict[str, int]:
    """
    Return a ``{normalised_title: count}`` dict for all recent alerts.

    Useful for the ``verify`` CLI command which checks counts without a
    specific rule in mind.
    """
    now_ms = int(time.time() * 1000)
    start_ms = now_ms - lookback_seconds * 1000

    url = f"{cfg.sdl_base_url}/api/powerQuery"
    payload: dict[str, Any] = {
        "token": cfg.sdl_read_token,
        "queryType": "complex",
        "query": _ALERT_QUERY_TEMPLATE,
        "startTime": start_ms,
        "endTime": now_ms,
        "maxCount": 1000,
    }

    try:
        resp = requests.post(url, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        log.error("Alert count query failed: %s", exc)
        return {}

    rows = _rows_from_powerquery(data)
    result: dict[str, int] = {}
    for row in rows:
        title = str(row.get("finding_info.title") or row.get("title") or "")
        normalised = _normalise_rule_name(title)
        try:
            count = int(row.get("n") or row.get("count") or 0)
        except (ValueError, TypeError):
            count = 1
        result[normalised] = result.get(normalised, 0) + count
    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalise_rule_name(name: str) -> str:
    """Lower-case and strip the `` - OOTB`` suffix that S1 appends."""
    return name.lower().removesuffix(" - ootb").strip()


def _rows_from_powerquery(data: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Convert a ``/api/powerQuery`` response (``{"columns": [...], "values": [...]}``)
    into a list of ``{column_name: value}`` row dicts.
    """
    columns = [c.get("name") for c in data.get("columns", [])]
    return [dict(zip(columns, row)) for row in data.get("values", [])]
