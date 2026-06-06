"""
db.py — SQLite-backed environment store for FoundStone.

Stores named tenant configurations (SDL URLs, tokens, etc.) so multiple
environments can be managed without touching .env files.
"""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any

_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "foundstone.db"
_LOCAL = threading.local()


def _conn() -> sqlite3.Connection:
    """Return a thread-local SQLite connection."""
    if not hasattr(_LOCAL, "conn"):
        _LOCAL.conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
        _LOCAL.conn.row_factory = sqlite3.Row
        _LOCAL.conn.execute("PRAGMA journal_mode=WAL")
        _LOCAL.conn.execute("PRAGMA foreign_keys=ON")
    return _LOCAL.conn


def init_db() -> None:
    """Create tables if they don't exist."""
    _conn().executescript("""
        CREATE TABLE IF NOT EXISTS deployed_rules (
            name TEXT PRIMARY KEY
        );

        CREATE TABLE IF NOT EXISTS environments (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL UNIQUE,
            sdl_base_url    TEXT NOT NULL DEFAULT '',
            sdl_read_token  TEXT NOT NULL DEFAULT '',
            sdl_write_token TEXT NOT NULL DEFAULT '',
            sdl_account_id  TEXT NOT NULL DEFAULT '',
            s1_api_token    TEXT NOT NULL DEFAULT '',
            verify_delay    INTEGER NOT NULL DEFAULT 30,
            dry_run         INTEGER NOT NULL DEFAULT 1,
            is_active       INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );
    """)
    _conn().commit()


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    d["dry_run"] = bool(d["dry_run"])
    d["is_active"] = bool(d["is_active"])
    return d


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def list_environments() -> list[dict[str, Any]]:
    rows = _conn().execute(
        "SELECT * FROM environments ORDER BY is_active DESC, name ASC"
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_environment(env_id: int) -> dict[str, Any] | None:
    row = _conn().execute("SELECT * FROM environments WHERE id = ?", (env_id,)).fetchone()
    return _row_to_dict(row) if row else None


def get_active_environment() -> dict[str, Any] | None:
    row = _conn().execute("SELECT * FROM environments WHERE is_active = 1 LIMIT 1").fetchone()
    return _row_to_dict(row) if row else None


def create_environment(
    name: str,
    sdl_base_url: str = "",
    sdl_read_token: str = "",
    sdl_write_token: str = "",
    sdl_account_id: str = "",
    s1_api_token: str = "",
    verify_delay: int = 30,
    dry_run: bool = True,
    make_active: bool = False,
) -> dict[str, Any]:
    db = _conn()
    if make_active:
        db.execute("UPDATE environments SET is_active = 0")
    cur = db.execute(
        """INSERT INTO environments
           (name, sdl_base_url, sdl_read_token, sdl_write_token,
            sdl_account_id, s1_api_token, verify_delay, dry_run, is_active)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (name, sdl_base_url, sdl_read_token, sdl_write_token,
         sdl_account_id, s1_api_token, verify_delay, int(dry_run), int(make_active)),
    )
    db.commit()
    return get_environment(cur.lastrowid)  # type: ignore[arg-type]


def update_environment(env_id: int, **fields: Any) -> dict[str, Any] | None:
    allowed = {
        "name", "sdl_base_url", "sdl_read_token", "sdl_write_token",
        "sdl_account_id", "s1_api_token", "verify_delay", "dry_run",
    }
    updates = {k: v for k, v in fields.items() if k in allowed and v is not None}
    if "dry_run" in updates:
        updates["dry_run"] = int(updates["dry_run"])
    if not updates:
        return get_environment(env_id)
    updates["updated_at"] = "datetime('now')"
    set_clause = ", ".join(
        f"{k} = datetime('now')" if v == "datetime('now')" else f"{k} = ?"
        for k, v in updates.items()
    )
    values = [v for v in updates.values() if v != "datetime('now')"]
    _conn().execute(
        f"UPDATE environments SET {set_clause} WHERE id = ?",
        (*values, env_id),
    )
    _conn().commit()
    return get_environment(env_id)


def delete_environment(env_id: int) -> bool:
    cur = _conn().execute("DELETE FROM environments WHERE id = ?", (env_id,))
    _conn().commit()
    return cur.rowcount > 0


def set_active_environment(env_id: int) -> dict[str, Any] | None:
    db = _conn()
    db.execute("UPDATE environments SET is_active = 0")
    db.execute(
        "UPDATE environments SET is_active = 1, updated_at = datetime('now') WHERE id = ?",
        (env_id,),
    )
    db.commit()
    return get_environment(env_id)


# ---------------------------------------------------------------------------
# Deployed rule names (persisted across restarts)
# ---------------------------------------------------------------------------

def save_deployed_names(names: set[str]) -> None:
    db = _conn()
    db.execute("DELETE FROM deployed_rules")
    db.executemany("INSERT INTO deployed_rules (name) VALUES (?)", [(n,) for n in names])
    db.commit()


def load_deployed_names() -> set[str] | None:
    """Return the persisted set, or None if never synced."""
    rows = _conn().execute("SELECT name FROM deployed_rules").fetchall()
    if not rows:
        return None
    return {r["name"] for r in rows}


def clear_deployed_names() -> None:
    _conn().execute("DELETE FROM deployed_rules")
    _conn().commit()
