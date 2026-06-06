"""
ingester.py — Ingest synthetic events into SDL via the ``addEvents`` endpoint.

Each ingestion call uses a session name prefixed with ``foundstone-`` so events
can be identified and cleaned up later.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import requests

from .config import Config

log = logging.getLogger(__name__)


def ingest_events(
    events: list[dict[str, Any]],
    cfg: Config,
    *,
    session_tag: str = "",
) -> bool:
    """
    Send *events* to SDL via ``POST /api/addEvents``.

    Parameters
    ----------
    events:
        List of flat ``{field: value}`` dicts.  Each will be wrapped in the
        ``{"ts": ..., "attrs": {...}}`` envelope SDL expects.
    cfg:
        Runtime configuration (SDL URL, write token, etc.).
    session_tag:
        Optional extra label appended to the session name for traceability.

    Returns
    -------
    bool
        ``True`` on success, ``False`` on any HTTP or network error.
    """
    if cfg.dry_run:
        log.info("[DRY RUN] Would ingest %d event(s) — skipping.", len(events))
        return True

    if not events:
        log.warning("ingest_events called with an empty event list — nothing to do.")
        return True

    now_ms = int(time.time() * 1000)
    session_name = f"foundstone-{now_ms}"
    if session_tag:
        session_name = f"{session_name}-{session_tag}"

    # Build the SDL addEvents payload
    sdl_events = [
        {
            "ts": str(now_ms + i),  # slight offset so events are ordered
            "attrs": _clean_attrs(event),
        }
        for i, event in enumerate(events)
    ]

    payload: dict[str, Any] = {
        "token": cfg.sdl_write_token,
        "session": session_name,
        "events": sdl_events,
    }

    url = f"{cfg.sdl_base_url}/api/addEvents"
    log.info("Ingesting %d event(s) via session '%s' …", len(events), session_name)

    try:
        resp = requests.post(url, json=payload, timeout=30)
        resp.raise_for_status()
    except requests.RequestException as exc:
        log.error("addEvents failed: %s", exc)
        return False

    log.info("Ingestion successful (HTTP %s).", resp.status_code)
    return True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _clean_attrs(event: dict[str, Any]) -> dict[str, Any]:
    """
    Return a copy of *event* with all values coerced to SDL-safe types.

    SDL accepts strings, numbers, and booleans.  Anything else is cast to str.
    Internal bookkeeping keys (``_copy_index``) are dropped.
    """
    SKIP_KEYS = {"_copy_index"}
    result: dict[str, Any] = {}
    for k, v in event.items():
        if k in SKIP_KEYS:
            continue
        if isinstance(v, (str, int, float, bool)):
            result[k] = v
        else:
            result[k] = str(v)
    return result
