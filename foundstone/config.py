"""
config.py — Load and validate FoundStone runtime configuration from environment variables.

All settings are read from the environment (or a .env file via python-dotenv).
A safety check prevents accidental ingestion against production tenants.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# Load .env from the project root (two levels up from this file)
_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(_ENV_PATH)

# Substrings that must NOT appear in SDL_BASE_URL for safety
_BLOCKED_URL_SUBSTRINGS: list[str] = ["prod", "production"]


@dataclass(frozen=True)
class Config:
    """Immutable runtime configuration for FoundStone."""

    sdl_base_url: str
    sdl_read_token: str
    sdl_write_token: str
    sdl_account_id: str
    verify_delay: int = 30
    dry_run: bool = False

    # Extra headers forwarded to every SDL request (not user-configurable yet)
    extra_headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate that we are not targeting a production tenant."""
        url_lower = self.sdl_base_url.lower()
        for blocked in _BLOCKED_URL_SUBSTRINGS:
            if blocked in url_lower:
                raise ValueError(
                    f"SDL_BASE_URL '{self.sdl_base_url}' appears to target a "
                    f"production tenant (contains '{blocked}'). "
                    "Use a POC / lab environment, or rename the host if this is "
                    "intentional and pass --confirm-poc on the CLI."
                )


def load_config(*, confirm_poc: bool = False) -> Config:
    """
    Build a :class:`Config` from environment variables.

    Parameters
    ----------
    confirm_poc:
        When *True*, the production-URL safety check is bypassed.  This should
        only be set when the user explicitly passes ``--confirm-poc`` on the CLI.

    Raises
    ------
    EnvironmentError
        If any required environment variable is missing.
    ValueError
        If SDL_BASE_URL looks like a production tenant (unless *confirm_poc* is True).
    """
    missing: list[str] = []

    def _require(key: str) -> str:
        val = os.getenv(key, "").strip()
        if not val:
            missing.append(key)
        return val

    sdl_base_url = _require("SDL_BASE_URL").rstrip("/")
    sdl_read_token = _require("SDL_READ_TOKEN")
    sdl_write_token = _require("SDL_WRITE_TOKEN")
    sdl_account_id = _require("SDL_ACCOUNT_ID")

    if missing:
        raise EnvironmentError(
            f"Required environment variables not set: {', '.join(missing)}. "
            f"Copy .env.example → .env and fill in the values."
        )

    verify_delay = int(os.getenv("VERIFY_DELAY", "30"))
    dry_run = os.getenv("DRY_RUN", "false").lower() in ("1", "true", "yes")

    cfg = object.__new__(Config)
    # Bypass frozen=True to allow conditional construction
    object.__setattr__(cfg, "sdl_base_url", sdl_base_url)
    object.__setattr__(cfg, "sdl_read_token", sdl_read_token)
    object.__setattr__(cfg, "sdl_write_token", sdl_write_token)
    object.__setattr__(cfg, "sdl_account_id", sdl_account_id)
    object.__setattr__(cfg, "verify_delay", verify_delay)
    object.__setattr__(cfg, "dry_run", dry_run)
    object.__setattr__(cfg, "extra_headers", {})

    if not confirm_poc:
        # Trigger the safety check inside __post_init__ manually
        url_lower = sdl_base_url.lower()
        for blocked in _BLOCKED_URL_SUBSTRINGS:
            if blocked in url_lower:
                raise ValueError(
                    f"SDL_BASE_URL '{sdl_base_url}' appears to target a "
                    f"production tenant (contains '{blocked}'). "
                    "Use a POC / lab environment, or pass --confirm-poc on the CLI "
                    "to override this check."
                )

    return cfg
