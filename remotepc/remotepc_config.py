#!/usr/bin/env python3
"""
RemotePC — configuration loader.

Everything a user might want to personalise lives in a single JSON file so that
no personal data or secrets are ever baked into the source code.

Config file resolution order (first match wins):
  1. The path in the ``REMOTEPC_CONFIG`` environment variable
  2. ``<repo_root>/remotepc.config.json``   (created by the setup wizard)
  3. ``~/.remotepc/config.json``

Every key is optional. Missing keys fall back to safe, generic defaults so the
application still runs on any machine with no config file present. Run the
setup wizard (``python remotepc/setup_wizard.py``) to generate one.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

# ``remotepc/`` -> repo root is one level up.
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = REPO_ROOT / "remotepc.config.json"
USER_CONFIG_PATH = Path.home() / ".remotepc" / "config.json"

# ── Defaults ────────────────────────────────────────────────────────────────
# Generic, non-personal values. Cloud model IDs are public Google model names;
# local models are intentionally empty until the wizard scans LM Studio.
DEFAULTS: Dict[str, Any] = {
    # Branding
    "assistant_name": "RemotePC",
    "owner_name": "Boss",
    "owner_nickname": "Boss",
    "timezone": "",                      # empty -> auto-detect local timezone

    # Cloud AI (optional — local models work without a key)
    "gemini_api_key": "",
    "gemini_models": [
        "gemini-3.5-flash",
        "gemini-3.5-flash-lite",
        "gemini-3.6-flash",
        "gemini-3.8-flash",
    ],
    "antigravity_model": "gemini-3.5-flash-lite",

    # Local AI (LM Studio)
    "lmstudio_api_url": "http://127.0.0.1:1234/v1/chat/completions",
    "lmstudio_exe": "",                  # e.g. C:\Users\me\.lmstudio\bin\lms.exe
    "local_models": [],                  # [{"key": "local:xxx", "name": "xxx", "label": "xxx"}]

    # Security (Tailscale / SSH)
    "allowed_ips": [],                   # extra IPs to allow; loopback always allowed
    "require_pin": False,
    "pin_hash": "",                      # sha256 hex of the PIN

    # Paths (empty -> sensible cross-platform default)
    "screenshot_dir": "",
    "music_dir": "",
    "log_dir": "",
    "notes_dir": "",
    "search_roots": [],                  # extra roots for the file search tool
}


def config_path() -> Path:
    """Return the config path that will be read (and written) by the app."""
    env = os.environ.get("REMOTEPC_CONFIG", "").strip()
    if env:
        return Path(env).expanduser()
    if DEFAULT_CONFIG_PATH.exists():
        return DEFAULT_CONFIG_PATH
    if USER_CONFIG_PATH.exists():
        return USER_CONFIG_PATH
    # Nothing exists yet — the wizard writes here by default.
    return DEFAULT_CONFIG_PATH


def config_exists() -> bool:
    return config_path().exists()


def load_config() -> Dict[str, Any]:
    """Return the merged config (defaults + user file). Never raises."""
    cfg = dict(DEFAULTS)
    # Start from a fresh copy of list defaults so callers can't mutate DEFAULTS.
    cfg["gemini_models"] = list(DEFAULTS["gemini_models"])
    cfg["local_models"] = [dict(m) for m in DEFAULTS["local_models"]]
    cfg["allowed_ips"] = list(DEFAULTS["allowed_ips"])
    cfg["search_roots"] = list(DEFAULTS["search_roots"])

    path = config_path()
    if path.exists():
        try:
            # utf-8-sig transparently strips a BOM (Notepad/PowerShell write one).
            with open(path, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
            if isinstance(data, dict):
                for key, value in data.items():
                    if value is not None:
                        cfg[key] = value
        except Exception:
            # A corrupt config must never prevent the app from starting.
            pass
    return cfg


def save_config(cfg: Dict[str, Any], path: Path | None = None) -> Path:
    """Write ``cfg`` as pretty JSON. Returns the path written."""
    target = path or config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return target


def resolve_path(value: str, default: Path) -> Path:
    """Expand ~ / env vars in ``value``; fall back to ``default`` when empty."""
    if value:
        try:
            return Path(os.path.expandvars(value)).expanduser()
        except Exception:
            return default
    return default


# Convenience: a loaded config for importers that just want the values.
CONFIG: Dict[str, Any] = load_config()
