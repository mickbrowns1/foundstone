"""
template_fetcher.py — Fetch real event templates from SDL for a given dataSource.name.

Templates are cached in memory so each unique source is only queried once per
FoundStone run.  If no events are found for a source the result is an empty list
and the calling rule is marked ``no_template``.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import requests

from .config import Config

log = logging.getLogger(__name__)

# In-memory cache: source name → list of raw event dicts
_TEMPLATE_CACHE: dict[str, list[dict[str, Any]]] = {}

# How many days back to look for template events
_LOOKBACK_DAYS = 7
_MS_PER_DAY = 86_400_000


def _epoch_ms_now() -> int:
    return int(time.time() * 1000)


def _epoch_ms_ago(days: int) -> int:
    return _epoch_ms_now() - days * _MS_PER_DAY


def fetch_templates(source: str, cfg: Config, max_count: int = 20) -> list[dict[str, Any]]:
    """
    Return up to *max_count* real event dicts for the given *source*.

    Results are cached — subsequent calls for the same source return the
    cached list immediately without hitting SDL again.

    Parameters
    ----------
    source:
        The ``dataSource.name`` value to query, e.g. ``"CloudTrail"``.
    cfg:
        Runtime configuration (SDL URL, read token, etc.).
    max_count:
        Maximum number of template events to retrieve.

    Returns
    -------
    list[dict[str, Any]]
        Each element is a flat ``{field: value}`` dict representing one SDL event.
        Returns an empty list if the source has no recent events.
    """
    if source in _TEMPLATE_CACHE:
        log.debug("Template cache hit for source '%s' (%d events)", source, len(_TEMPLATE_CACHE[source]))
        return _TEMPLATE_CACHE[source]

    log.info("Fetching templates for source '%s' from SDL …", source)
    url = f"{cfg.sdl_base_url}/api/query"

    payload: dict[str, Any] = {
        "token": cfg.sdl_read_token,
        "queryType": "log",
        "filter": f"dataSource.name == '{source}'",
        "startTime": _epoch_ms_ago(_LOOKBACK_DAYS),
        "endTime": _epoch_ms_now(),
        "maxCount": max_count,
    }

    try:
        resp = requests.post(url, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        log.error("SDL query failed for source '%s': %s", source, exc)
        _TEMPLATE_CACHE[source] = []
        return []

    # SDL V1 returns {"matches": [...]} or {"events": [...]} depending on version
    events: list[dict[str, Any]] = data.get("matches") or data.get("events") or []

    # Normalise: flatten each event's attributes if they are nested
    templates = [_normalise_event(e) for e in events]

    log.info("Fetched %d template(s) for source '%s'", len(templates), source)
    _TEMPLATE_CACHE[source] = templates
    return templates


def clear_cache() -> None:
    """Clear the in-memory template cache (useful between test runs)."""
    _TEMPLATE_CACHE.clear()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalise_event(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Return a flat ``{dotted.key: value}`` dict from a raw SDL event.

    SDL events sometimes arrive as ``{"attributes": {"key": "value", ...}}``
    and sometimes as a flat top-level dict.  We normalise to a flat dict.
    """
    # Prefer the "attributes" sub-dict when present
    attrs = raw.get("attributes") or raw.get("attrs")
    if isinstance(attrs, dict):
        return dict(attrs)
    # Already flat — drop internal SDL bookkeeping keys
    return {k: v for k, v in raw.items() if not k.startswith("__")}
