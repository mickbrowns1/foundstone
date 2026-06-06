"""
api.py — FoundStone FastAPI backend.
"""
from __future__ import annotations

import io
import json
import os
import threading
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from foundstone.db import (
    init_db, list_environments, get_environment, get_active_environment,
    create_environment, update_environment, delete_environment, set_active_environment,
    save_deployed_names, load_deployed_names, clear_deployed_names,
)

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

_ROOT = Path(__file__).resolve().parent
load_dotenv(_ROOT / ".env")  # fallback for local dev without DB

# Init DB + tables, then restore persisted deployed names into memory
init_db()
_DEPLOYED_NAMES: set[str] | None = load_deployed_names()

_DATA_PATH = _ROOT / "data" / "extracted.json"

with _DATA_PATH.open() as _f:
    _raw = json.load(_f)
    _ALL_RULES: list[dict[str, Any]] = _raw["results"]

# Index by id for O(1) lookup
_RULES_BY_ID: dict[str, dict[str, Any]] = {r["id"]: r for r in _ALL_RULES}

# ---------------------------------------------------------------------------
# Deployed-rules filter
#
# Populated by POST /api/library/sync — hits /web/api/v2.1/detection-library/rules
# on the configured console and stores the set of rule names that are actually
# deployed on that tenant.  Until synced, _DEPLOYED_NAMES is None and we show
# all rules (so the UI works before credentials are configured).
# ---------------------------------------------------------------------------

_DEPLOYED_LOCK = threading.Lock()


def _active_rules() -> list[dict[str, Any]]:
    """Return rules filtered to only those deployed on the tenant, if synced."""
    with _DEPLOYED_LOCK:
        names = _DEPLOYED_NAMES
    if names is None:
        return _ALL_RULES
    return [r for r in _ALL_RULES if r.get("name") in names]


# ---------------------------------------------------------------------------
# Uploaded template store
#
# POST /api/templates/upload accepts a .jsonl or .json file of real log events.
# Events are indexed by dataSource.name so the runner can use them as templates
# instead of (or in addition to) pulling from SDL.
# ---------------------------------------------------------------------------

# { "Okta": [event, event, ...], "CloudTrail": [...], ... }
_UPLOADED_TEMPLATES: dict[str, list[dict[str, Any]]] = {}
_TEMPLATES_LOCK = threading.Lock()


def _get_uploaded_templates(source: str) -> list[dict[str, Any]]:
    with _TEMPLATES_LOCK:
        return list(_UPLOADED_TEMPLATES.get(source, []))


def _all_template_sources() -> dict[str, int]:
    with _TEMPLATES_LOCK:
        return {src: len(evts) for src, evts in _UPLOADED_TEMPLATES.items()}


# ---------------------------------------------------------------------------
# Job store
# ---------------------------------------------------------------------------

_JOBS: dict[str, dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()
_EXECUTOR = ThreadPoolExecutor(max_workers=4)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="FoundStone")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _classify_rule(rule: dict[str, Any]) -> tuple[str, int]:
    try:
        from foundstone.classifier import classify
        return classify(rule)
    except Exception:
        return "simple", 1


def _parse_rule_queries(rule: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        from foundstone.rule_parser import parse_pair_list
        enriched = []
        for q in rule.get("queries", []):
            pair_list = q.get("pair_list", [])
            try:
                parsed = parse_pair_list(pair_list)
                overlay = parsed.overlay()
                data_source = parsed.data_source
            except Exception:
                overlay = {}
                data_source = None
            enriched.append({
                "query": q.get("query", ""),
                "pair_list": pair_list,
                "overlay": overlay,
                "data_source": data_source,
            })
        return enriched
    except Exception:
        return rule.get("queries", [])


def _get_rule_source(rule: dict[str, Any]) -> str | None:
    for q in rule.get("queries", []):
        for p in q.get("pair_list", []):
            if p.get("key") == "dataSource.name":
                return str(p.get("value", ""))
    return None


def _filter_rules(
    rules: list[dict[str, Any]],
    source: str | None,
    app_filter: str | None,
    class_filter: str | None,
    q: str | None,
) -> list[dict[str, Any]]:
    if q:
        ql = q.lower()
        rules = [r for r in rules if ql in r.get("name", "").lower() or ql in r.get("description", "").lower()]
    if app_filter:
        rules = [r for r in rules if r.get("app", "").lower() == app_filter.lower()]
    if source:
        sl = source.lower()
        rules = [
            r for r in rules
            if any(
                any(p.get("key") == "dataSource.name" and sl in str(p.get("value", "")).lower()
                    for p in q2.get("pair_list", []))
                for q2 in r.get("queries", [])
            )
        ]
    if class_filter:
        rules = [r for r in rules if _classify_rule(r)[0] == class_filter]
    return rules


def _rule_summary(r: dict[str, Any]) -> dict[str, Any]:
    rule_class, copies = _classify_rule(r)
    return {
        "id": r.get("id"),
        "name": r.get("name"),
        "app": r.get("app"),
        "file": r.get("file"),
        "source": _get_rule_source(r),
        "rule_class": rule_class,
        "copies": copies,
        "deployed": _DEPLOYED_NAMES is None or r.get("name") in (_DEPLOYED_NAMES or set()),
    }


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class RunRequest(BaseModel):
    rule_ids: list[str]
    dry_run: bool = False
    confirm_poc: bool = False


class EnvironmentRequest(BaseModel):
    name: str
    sdl_base_url: str = ""
    sdl_read_token: str = ""
    sdl_write_token: str = ""
    sdl_account_id: str = ""
    s1_api_token: str = ""
    verify_delay: int = 30
    dry_run: bool = True
    make_active: bool = False


class EnvironmentUpdateRequest(BaseModel):
    name: str | None = None
    sdl_base_url: str | None = None
    sdl_read_token: str | None = None
    sdl_write_token: str | None = None
    sdl_account_id: str | None = None
    s1_api_token: str | None = None
    verify_delay: int | None = None
    dry_run: bool | None = None


# ---------------------------------------------------------------------------
# Background job
# ---------------------------------------------------------------------------

def _run_job(job_id: str, rules: list[dict[str, Any]], dry_run: bool, confirm_poc: bool) -> None:
    with _JOBS_LOCK:
        _JOBS[job_id]["status"] = "running"

    try:
        from foundstone.config import load_config
        from foundstone.runner import run_rules

        original_dry_run = os.environ.get("DRY_RUN")
        if dry_run:
            os.environ["DRY_RUN"] = "true"

        try:
            cfg = load_config(confirm_poc=confirm_poc)
        except Exception as exc:
            with _JOBS_LOCK:
                _JOBS[job_id]["status"] = "error"
                _JOBS[job_id]["error"] = str(exc)
            return
        finally:
            if original_dry_run is None:
                os.environ.pop("DRY_RUN", None)
            else:
                os.environ["DRY_RUN"] = original_dry_run

        completed = 0
        results: list[dict[str, Any]] = []

        def _cb(i: int, total: int, result: dict[str, Any]) -> None:
            nonlocal completed
            completed = i
            results.append(result)
            with _JOBS_LOCK:
                _JOBS[job_id]["progress"] = i
                _JOBS[job_id]["results"] = list(results)

        for result in run_rules(rules, cfg, progress_callback=_cb):
            pass  # progress_callback handles state

        with _JOBS_LOCK:
            _JOBS[job_id]["status"] = "done"
            _JOBS[job_id]["progress"] = len(rules)
            _JOBS[job_id]["results"] = results

    except Exception as exc:
        with _JOBS_LOCK:
            _JOBS[job_id]["status"] = "error"
            _JOBS[job_id]["error"] = str(exc)


# ---------------------------------------------------------------------------
# Endpoints — library sync
# ---------------------------------------------------------------------------

@app.post("/api/library/sync")
def sync_library() -> dict[str, Any]:
    """
    Pull deployed rule names from /web/api/v2.1/detection-library/rules on the
    configured S1 console and store them as the active filter.  Rules in
    extracted.json that are NOT in this set will be hidden from the UI.
    """
    global _DEPLOYED_NAMES

    env = get_active_environment()
    if not env:
        raise HTTPException(status_code=400, detail="No active environment. Set one in the Environments tab.")

    base_url = env.get("sdl_base_url", "").rstrip("/")
    api_token = env.get("s1_api_token", "")  # raw value from DB (not masked)

    if not base_url:
        raise HTTPException(status_code=400, detail="Active environment has no SDL Base URL set.")
    if not api_token:
        raise HTTPException(status_code=400, detail="Active environment has no S1 API Token set.")

    import httpx

    headers = {"Authorization": f"ApiToken {api_token}"}
    all_names: set[str] = set()

    def _fetch_page(client: httpx.Client, scope_level: str, scope_id: str, cursor: str = "") -> dict:
        return client.get(
            f"{base_url}/web/api/v2.1/detection-library/platform-rules",
            headers=headers,
            params={"scopeLevel": scope_level, "scopeId": scope_id, "limit": 1000, "cursor": cursor},
        ).raise_for_status().json() if False else None  # placeholder replaced below

    try:
        with httpx.Client(timeout=60) as client:
            # Resolve scope: prefer account, fall back to first site
            scope_level, scope_id = "", ""
            a = client.get(f"{base_url}/web/api/v2.1/accounts", headers=headers, params={"limit": 1})
            if a.status_code == 200:
                accounts = a.json().get("data", [])
                if accounts:
                    scope_level, scope_id = "account", str(accounts[0]["id"])
            if not scope_level:
                s = client.get(f"{base_url}/web/api/v2.1/sites", headers=headers, params={"limit": 1})
                if s.status_code == 200:
                    data = s.json().get("data", {})
                    sites = data.get("sites") if isinstance(data, dict) else data
                    if sites:
                        scope_level, scope_id = "site", str(sites[0]["id"])
            if not scope_level:
                raise HTTPException(status_code=502, detail="Could not resolve account or site scope for this token.")

            # Paginate through platform-rules
            cursor = ""
            while True:
                resp = client.get(
                    f"{base_url}/web/api/v2.1/detection-library/platform-rules",
                    headers=headers,
                    params={"scopeLevel": scope_level, "scopeId": scope_id, "limit": 1000, "cursor": cursor},
                )
                if not resp.is_success:
                    raise HTTPException(status_code=502, detail=f"S1 API returned {resp.status_code}: {resp.text[:500]}")
                body = resp.json()
                for rule in body.get("data", []):
                    name = rule.get("name", "")
                    if name:
                        all_names.add(name)
                cursor = body.get("pagination", {}).get("nextCursor") or ""
                if not cursor:
                    break
    except HTTPException:
        raise
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"S1 API error: {exc}")

    with _DEPLOYED_LOCK:
        _DEPLOYED_NAMES = all_names
    save_deployed_names(all_names)

    # How many of our extracted rules are covered?
    matched = sum(1 for r in _ALL_RULES if r.get("name") in all_names)

    return {
        "deployed_count": len(all_names),
        "matched_in_extracted": matched,
        "total_in_extracted": len(_ALL_RULES),
    }


@app.delete("/api/library/sync")
def clear_library_sync() -> dict[str, Any]:
    """Remove the deployed-rules filter — show all rules again."""
    global _DEPLOYED_NAMES
    with _DEPLOYED_LOCK:
        _DEPLOYED_NAMES = None
    clear_deployed_names()
    return {"cleared": True}


@app.get("/api/library/status")
def library_status() -> dict[str, Any]:
    with _DEPLOYED_LOCK:
        names = _DEPLOYED_NAMES
    if names is None:
        return {"synced": False, "deployed_count": 0, "matched_in_extracted": 0}
    matched = sum(1 for r in _ALL_RULES if r.get("name") in names)
    return {"synced": True, "deployed_count": len(names), "matched_in_extracted": matched}


# ---------------------------------------------------------------------------
# Endpoints — template upload
# ---------------------------------------------------------------------------

@app.post("/api/templates/upload")
async def upload_templates(file: UploadFile = File(...)) -> dict[str, Any]:
    """
    Accept a .jsonl or .json file of real log events and index them by
    dataSource.name for use as rule-firing templates.

    Supports:
      - JSONL  (one JSON object per line)
      - JSON array  ([{...}, {...}])
      - JSON object with a top-level "events" or "results" array
    """
    content = await file.read()
    text = content.decode("utf-8", errors="replace")

    events: list[dict[str, Any]] = []

    # Try JSONL first
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                events.append(obj)
        except json.JSONDecodeError:
            pass

    # If JSONL produced nothing, try JSON
    if not events:
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                events = [e for e in parsed if isinstance(e, dict)]
            elif isinstance(parsed, dict):
                for key in ("events", "results", "data", "logs"):
                    if isinstance(parsed.get(key), list):
                        events = [e for e in parsed[key] if isinstance(e, dict)]
                        break
                if not events:
                    events = [parsed]
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail=f"Could not parse file as JSON or JSONL: {exc}")

    if not events:
        raise HTTPException(status_code=400, detail="No valid JSON objects found in uploaded file.")

    # Index by dataSource.name
    by_source: dict[str, list[dict[str, Any]]] = {}
    unknown = 0
    for ev in events:
        # Support nested {"dataSource": {"name": "..."}} and flat "dataSource.name"
        src = (
            (ev.get("dataSource") or {}).get("name")
            or ev.get("dataSource.name")
        )
        if src:
            by_source.setdefault(str(src), []).append(ev)
        else:
            unknown += 1

    with _TEMPLATES_LOCK:
        for src, evts in by_source.items():
            _UPLOADED_TEMPLATES.setdefault(src, []).extend(evts)

    return {
        "filename": file.filename,
        "total_events": len(events),
        "indexed_by_source": {src: len(evts) for src, evts in by_source.items()},
        "skipped_no_source": unknown,
    }


@app.get("/api/templates")
def list_templates() -> dict[str, Any]:
    """Return which sources have uploaded templates and how many events each."""
    sources = _all_template_sources()
    return {"sources": sources, "total_sources": len(sources)}


@app.delete("/api/templates")
def clear_templates() -> dict[str, Any]:
    """Wipe all uploaded templates."""
    with _TEMPLATES_LOCK:
        _UPLOADED_TEMPLATES.clear()
    return {"cleared": True}


@app.delete("/api/templates/{source}")
def clear_templates_for_source(source: str) -> dict[str, Any]:
    """Remove uploaded templates for a specific source."""
    with _TEMPLATES_LOCK:
        removed = len(_UPLOADED_TEMPLATES.pop(source, []))
    return {"source": source, "removed": removed}


# ---------------------------------------------------------------------------
# Endpoints — rules
# ---------------------------------------------------------------------------

@app.get("/api/rules")
def list_rules(
    source: str | None = None,
    app: str | None = None,
    cls: str | None = None,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
    deployed_only: bool = True,
) -> dict[str, Any]:
    base = _active_rules() if deployed_only else _ALL_RULES
    filtered = _filter_rules(base, source, app, cls, q)
    total = len(filtered)
    items = [_rule_summary(r) for r in filtered[offset: offset + limit]]
    return {"total": total, "offset": offset, "limit": limit, "items": items}


@app.get("/api/rules/{rule_id}")
def get_rule(rule_id: str) -> dict[str, Any]:
    rule = _RULES_BY_ID.get(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule_class, copies = _classify_rule(rule)
    return {
        **_rule_summary(rule),
        "description": rule.get("description", ""),
        "queries": _parse_rule_queries(rule),
        "copies": copies,
        # Flag whether uploaded templates exist for this rule's source
        "has_uploaded_templates": _get_rule_source(rule) in _all_template_sources(),
    }


@app.get("/api/sources")
def list_sources(deployed_only: bool = True) -> list[dict[str, Any]]:
    base = _active_rules() if deployed_only else _ALL_RULES
    counter: Counter[str] = Counter()
    for r in base:
        src = _get_rule_source(r)
        if src:
            counter[src] += 1
    # Annotate with whether uploaded templates exist
    result = []
    uploaded = _all_template_sources()
    for src, count in counter.most_common():
        result.append({
            "source": src,
            "count": count,
            "has_templates": src in uploaded,
            "template_count": uploaded.get(src, 0),
        })
    return result


@app.get("/api/stats")
def get_stats(deployed_only: bool = True) -> dict[str, Any]:
    base = _active_rules() if deployed_only else _ALL_RULES
    by_class: Counter[str] = Counter()
    by_app: Counter[str] = Counter()
    by_source: Counter[str] = Counter()

    for r in base:
        rule_class, _ = _classify_rule(r)
        by_class[rule_class] += 1
        by_app[r.get("app", "Unknown")] += 1
        src = _get_rule_source(r)
        if src:
            by_source[src] += 1

    with _DEPLOYED_LOCK:
        synced = _DEPLOYED_NAMES is not None

    return {
        "total_rules": len(base),
        "total_in_library": len(_ALL_RULES),
        "synced": synced,
        "by_class": dict(by_class),
        "by_app": dict(by_app),
        "by_source_top10": [{"source": s, "count": c} for s, c in by_source.most_common(10)],
        "template_sources": _all_template_sources(),
    }


# ---------------------------------------------------------------------------
# Endpoints — run / jobs
# ---------------------------------------------------------------------------

@app.post("/api/run")
def start_run(req: RunRequest) -> dict[str, Any]:
    rules = [_RULES_BY_ID[rid] for rid in req.rule_ids if rid in _RULES_BY_ID]
    if not rules:
        raise HTTPException(status_code=400, detail="No valid rule IDs provided")

    job_id = str(uuid.uuid4())
    with _JOBS_LOCK:
        _JOBS[job_id] = {"status": "pending", "progress": 0, "total": len(rules), "results": []}

    _EXECUTOR.submit(_run_job, job_id, rules, req.dry_run, req.confirm_poc)
    return {"job_id": job_id}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str) -> dict[str, Any]:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


# ---------------------------------------------------------------------------
# Endpoints — environments
# ---------------------------------------------------------------------------

def _mask(env: dict[str, Any]) -> dict[str, Any]:
    """Return env dict with token values masked — only expose whether they're set."""
    masked = dict(env)
    for field in ("sdl_read_token", "sdl_write_token", "s1_api_token"):
        masked[field] = bool(env.get(field))
    return masked


@app.get("/api/environments")
def list_envs() -> list[dict[str, Any]]:
    return [_mask(e) for e in list_environments()]


@app.get("/api/environments/active")
def get_active_env() -> dict[str, Any]:
    env = get_active_environment()
    if not env:
        return {"active": False}
    return {"active": True, **_mask(env)}


@app.post("/api/environments")
def create_env(req: EnvironmentRequest) -> dict[str, Any]:
    try:
        env = create_environment(
            name=req.name,
            sdl_base_url=req.sdl_base_url.rstrip("/"),
            sdl_read_token=req.sdl_read_token,
            sdl_write_token=req.sdl_write_token,
            sdl_account_id=req.sdl_account_id,
            s1_api_token=req.s1_api_token,
            verify_delay=req.verify_delay,
            dry_run=req.dry_run,
            make_active=req.make_active,
        )
        return _mask(env)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.put("/api/environments/{env_id}")
def update_env(env_id: int, req: EnvironmentUpdateRequest) -> dict[str, Any]:
    updates = req.model_dump(exclude_none=True)
    if "sdl_base_url" in updates and updates["sdl_base_url"]:
        updates["sdl_base_url"] = updates["sdl_base_url"].rstrip("/")
    env = update_environment(env_id, **updates)
    if not env:
        raise HTTPException(status_code=404, detail="Environment not found")
    return _mask(env)


@app.delete("/api/environments/{env_id}")
def delete_env(env_id: int) -> dict[str, Any]:
    if not delete_environment(env_id):
        raise HTTPException(status_code=404, detail="Environment not found")
    return {"deleted": True}


@app.post("/api/environments/{env_id}/activate")
def activate_env(env_id: int) -> dict[str, Any]:
    env = set_active_environment(env_id)
    if not env:
        raise HTTPException(status_code=404, detail="Environment not found")
    return _mask(env)


# Legacy /api/config shim — returns active environment in old shape so existing
# code that reads config still works during transition
@app.get("/api/config")
def get_config() -> dict[str, Any]:
    env = get_active_environment()
    if not env:
        return {
            "configured": False, "base_url": "", "account_id": "",
            "verify_delay": 30, "dry_run": True,
            "read_token_set": False, "write_token_set": False, "s1_api_token_set": False,
        }
    return {
        "configured": bool(env.get("sdl_base_url") and env.get("sdl_read_token")),
        "base_url": env.get("sdl_base_url", ""),
        "account_id": env.get("sdl_account_id", ""),
        "verify_delay": env.get("verify_delay", 30),
        "dry_run": env.get("dry_run", True),
        "read_token_set": bool(env.get("sdl_read_token")),
        "write_token_set": bool(env.get("sdl_write_token")),
        "s1_api_token_set": bool(env.get("s1_api_token")),
    }


# ---------------------------------------------------------------------------
# Serve built UI (must be last)
# ---------------------------------------------------------------------------

_UI_DIST = _ROOT / "ui" / "dist"
if _UI_DIST.exists():
    app.mount("/", StaticFiles(directory=str(_UI_DIST), html=True), name="ui")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
