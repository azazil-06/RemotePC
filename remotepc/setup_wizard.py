#!/usr/bin/env python3
"""
RemotePC — interactive setup wizard.

Run once after cloning:

    python remotepc/setup_wizard.py

It asks a handful of questions (assistant name, optional Gemini key, LM Studio
models, allowed Tailscale/SSH IPs, optional PIN, folders) and writes a single
config file. Nothing personal ever lives in the source tree.

Re-run any time to change your settings. Flags:

    --yes        accept all defaults without prompting (non-interactive)
    --output P   write the config to path P instead of the default location
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import urllib.request
from pathlib import Path

# Make ``import remotepc_config`` work no matter the current directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import remotepc_config as rc
except Exception:  # pragma: no cover - extremely unlikely
    rc = None  # type: ignore

# ── Optional rich UI (falls back to plain input) ────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.rule import Rule
    from rich import box

    _console = Console(force_terminal=True, highlight=False)
    _ACCENT = "bold bright_cyan"
    _DIM = "grey50"
    _OK = "bold bright_green"
    _WARN = "bold yellow"
    _ERR = "bold bright_red"
    _RICH = True
except Exception:  # pragma: no cover
    _console = None  # type: ignore
    _RICH = False

BANNER = r"""
 ____                      _        ____   ____
|  _ \ ___ _ __ ___   ___ | |_ ___ |  _ \ / ___|
| |_) / _ \ '_ ` _ \ / _ \| __/ _ \| |_) | |
|  _ <  __/ | | | | | (_) | ||  __/|  __/| |___
|_| \_\___|_| |_| |_|\___/ \__\___||_|    \____|
"""


# ── Small UI helpers (work with or without rich) ────────────────────────────
def _print(msg: str = "") -> None:
    if _RICH:
        _console.print(msg)
    else:
        print(_strip_markup(msg))


def _strip_markup(text: str) -> str:
    import re

    return re.sub(r"\[/?[^\]]*\]", "", text)


def _ask(question: str, default: str = "") -> str:
    if _RICH:
        return Prompt.ask(f"[{_ACCENT}]{question}[/{_ACCENT}]", default=default or "").strip()
    raw = input(f"{question} [{default}]: ").strip()
    return raw or default


def _ask_yes(question: str, default: bool = True) -> bool:
    if _RICH:
        return Confirm.ask(f"[{_ACCENT}]{question}[/{_ACCENT}]", default=default)
    raw = input(f"{question} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes")


def _heading(text: str) -> None:
    _print()
    if _RICH:
        _console.print(Rule(f"[{_ACCENT}]{text}[/{_ACCENT}]", style=_DIM))
    else:
        print(f"\n=== {text} ===")


# ── Detection helpers ───────────────────────────────────────────────────────
def _tailscale_exe() -> str | None:
    """Return a usable tailscale executable (PATH first, then default install)."""
    exe = shutil.which("tailscale")
    if exe:
        return exe
    for base in (
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
    ):
        cand = Path(base) / "Tailscale" / "tailscale.exe"
        if cand.exists():
            return str(cand)
    return None


def detect_tailscale_ips() -> list:
    """Return the machine's own Tailscale IPv4/IPv6 addresses, if any."""
    exe = _tailscale_exe()
    if not exe:
        return []
    found = []
    for flag in ("-4", "-6"):
        try:
            out = subprocess.run(
                [exe, "ip", flag],
                capture_output=True, text=True, timeout=5,
                encoding="utf-8", errors="replace",
            )
            if out.returncode == 0:
                for line in out.stdout.splitlines():
                    ip = line.strip()
                    if ip:
                        found.append(ip)
        except Exception:
            pass
    return found


def detect_lan_ip() -> str:
    """Best-effort detection of the machine's primary LAN IPv4 address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return ""


def scan_lmstudio(api_url: str) -> list:
    """Return the list of model IDs exposed by a running LM Studio server."""
    models_url = api_url.replace("/chat/completions", "/models")
    try:
        with urllib.request.urlopen(models_url, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return []
    out = []
    for item in data.get("data", []) if isinstance(data, dict) else []:
        mid = item.get("id") if isinstance(item, dict) else None
        if mid:
            out.append(str(mid))
    return out


def _slugify(name: str) -> str:
    import re

    tail = name.split("/")[-1]
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", tail).strip("-").lower()
    return slug or "model"


def _pretty_label(name: str) -> str:
    tail = name.split("/")[-1]
    return tail.replace("_", " ").replace("-", " ").strip().title() or name


def _make_local_model(name: str) -> dict:
    return {"key": f"local:{_slugify(name)}", "name": name, "label": _pretty_label(name)}


# ── Wizard ──────────────────────────────────────────────────────────────────
def run_wizard(non_interactive: bool = False, output: Path | None = None) -> Path:
    if rc is None:
        print("ERROR: could not import remotepc_config.py (is it next to this script?)")
        sys.exit(1)

    target = output or rc.DEFAULT_CONFIG_PATH
    cfg = dict(rc.DEFAULTS)

    _print(f"[{_ACCENT}]{BANNER}[/{_ACCENT}]")
    _print("[bold white]RemotePC — Setup Wizard[/bold white]")
    _print(f"[{_DIM}]This writes your personal settings to a single config file.[/{_DIM}]")
    _print(f"[{_DIM}]Config location: {target}[/{_DIM}]")

    # ── 1. Branding ─────────────────────────────────────────────────────────
    _heading("1. Assistant")
    if non_interactive:
        cfg["assistant_name"] = rc.DEFAULTS["assistant_name"]
        cfg["owner_name"] = rc.DEFAULTS["owner_name"]
        cfg["owner_nickname"] = rc.DEFAULTS["owner_nickname"]
    else:
        cfg["assistant_name"] = _ask("Assistant name", rc.DEFAULTS["assistant_name"]) or "RemotePC"
        cfg["owner_name"] = _ask("What should it call you? (your name)", rc.DEFAULTS["owner_name"]) or "Boss"
        cfg["owner_nickname"] = _ask("Nickname", cfg["owner_name"]) or cfg["owner_name"]

    # ── 2. Cloud AI key ─────────────────────────────────────────────────────
    _heading("2. Cloud AI (optional)")
    _print(f"[{_DIM}]A Google Gemini API key enables cloud models. You can skip this and[/{_DIM}]")
    _print(f"[{_DIM}]use local LM Studio models only.[/{_DIM}]")
    if non_interactive:
        cfg["gemini_api_key"] = ""
    else:
        try:
            key = _ask("Gemini API key (blank to skip)", "").strip()
        except Exception:
            key = ""
        cfg["gemini_api_key"] = key
        _print(f"[{_OK}]✓ Saved.[/{_OK}]" if key else f"[{_WARN}]Skipped — local models only.[/{_WARN}]")

    # ── 3. Local models (LM Studio) ─────────────────────────────────────────
    _heading("3. Local models (LM Studio)")
    api_url = rc.DEFAULTS["lmstudio_api_url"]
    if not non_interactive:
        custom = _ask("LM Studio API URL", api_url)
        if custom:
            api_url = custom
    cfg["lmstudio_api_url"] = api_url

    found = [] if non_interactive else scan_lmstudio(api_url)
    local_models = []
    if found:
        _print(f"[{_OK}]Found {len(found)} model(s) in LM Studio:[/{_OK}]")
        for i, mid in enumerate(found, 1):
            _print(f"   [{_ACCENT}]{i}[/{_ACCENT}]. {mid}")
        if _ask_yes("Register all of them?", default=True):
            local_models = [_make_local_model(m) for m in found]
        else:
            sel = _ask("Enter numbers to keep (comma-separated)", default="")
            for part in sel.split(","):
                part = part.strip()
                if part.isdigit() and 1 <= int(part) <= len(found):
                    local_models.append(_make_local_model(found[int(part) - 1]))
    else:
        _print(f"[{_WARN}]No LM Studio server detected at {api_url}.[/{_WARN}]")
        _print(f"[{_DIM}]Start LM Studio, load a model, enable the server, then re-run this wizard.[/{_DIM}]")
        if not non_interactive and _ask_yes("Add a local model manually?", default=False):
            while True:
                name = _ask("Model ID (blank to finish)", "")
                if not name:
                    break
                local_models.append(_make_local_model(name))
    cfg["local_models"] = local_models
    if local_models:
        _print(f"[{_OK}]✓ Registered {len(local_models)} local model(s).[/{_OK}]")

    # Auto-detect the LM Studio CLI (lms.exe) on Windows if present.
    if not cfg.get("lmstudio_exe"):
        for candidate in (
            Path.home() / ".lmstudio" / "bin" / "lms.exe",
            Path.home() / ".cache" / "lm-studio" / "bin" / "lms.exe",
        ):
            if candidate.exists():
                cfg["lmstudio_exe"] = str(candidate)
                break
    if cfg.get("lmstudio_exe"):
        _print(f"[{_DIM}]LM Studio CLI: {cfg['lmstudio_exe']}[/{_DIM}]")

    # ── 4. Security / Tailscale ─────────────────────────────────────────────
    _heading("4. Remote access security")
    allowed = ["127.0.0.1", "::1"]
    ts_ips = [] if non_interactive else detect_tailscale_ips()
    lan_ip = "" if non_interactive else detect_lan_ip()
    for ip in ts_ips:
        if ip not in allowed:
            allowed.append(ip)
    if lan_ip and lan_ip not in allowed:
        allowed.append(lan_ip)

    if ts_ips:
        _print(f"[{_OK}]Detected this PC's Tailscale IP(s): {', '.join(ts_ips)}[/{_OK}]")
    elif not non_interactive:
        _print(f"[{_DIM}]Tailscale not detected (install from https://tailscale.com/download).[/{_DIM}]")
    if lan_ip:
        _print(f"[{_DIM}]Local LAN IP: {lan_ip}[/{_DIM}]")

    _print(f"[{_DIM}]Note: loopback (127.0.0.1) is always allowed, and any Tailscale[/{_DIM}]")
    _print(f"[{_DIM}]100.x / fd7a: address is accepted automatically.[/{_DIM}]")
    if not non_interactive and _ask_yes("Add extra allowed IPs (your phone, etc.)?", default=False):
        extra = _ask("Extra IPs (comma-separated)", "")
        for ip in extra.split(","):
            ip = ip.strip()
            if ip and ip not in allowed:
                allowed.append(ip)
    cfg["allowed_ips"] = allowed

    # Optional PIN
    cfg["require_pin"] = False
    cfg["pin_hash"] = ""
    if not non_interactive and _ask_yes("Require a PIN on connect?", default=False):
        try:
            pin = getpass.getpass("Choose a PIN: ").strip()
        except Exception:
            pin = _ask("Choose a PIN", "")
        if pin:
            cfg["pin_hash"] = hashlib.sha256(pin.encode()).hexdigest()
            cfg["require_pin"] = True
            _print(f"[{_OK}]✓ PIN enabled (stored as SHA-256).[/{_OK}]")

    # ── 5. Folders ──────────────────────────────────────────────────────────
    _heading("5. Folders")
    cfg["log_dir"] = str(rc.REPO_ROOT)
    cfg["screenshot_dir"] = str(Path.home() / "Pictures" / "Screenshots")
    cfg["music_dir"] = str(Path.home() / "Music")
    cfg["notes_dir"] = str(rc.REPO_ROOT)
    if not non_interactive:
        cfg["log_dir"] = _ask("Logs folder", cfg["log_dir"]) or cfg["log_dir"]
        cfg["screenshot_dir"] = _ask("Screenshots folder", cfg["screenshot_dir"]) or cfg["screenshot_dir"]
        cfg["music_dir"] = _ask("Music folder", cfg["music_dir"]) or cfg["music_dir"]
        cfg["notes_dir"] = _ask("Notes folder", cfg["notes_dir"]) or cfg["notes_dir"]

    # ── Write ───────────────────────────────────────────────────────────────
    written = rc.save_config(cfg, target)
    _heading("Done")
    _print(f"[{_OK}]✓ Config written to:[/{_OK}] [bold]{written}[/bold]")
    _print()
    _print(f"[{_DIM}]Next:[/{_DIM}]  [bold]python remotepc/remotepc.py[/bold]")
    _print(f"[{_DIM}]Re-run this wizard any time to change your settings.[/{_DIM}]")
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description="RemotePC setup wizard")
    parser.add_argument("--yes", action="store_true", help="accept defaults, no prompts")
    parser.add_argument("--output", type=str, default="", help="config file path to write")
    args = parser.parse_args()
    out = Path(args.output).expanduser() if args.output else None

    non_interactive = args.yes
    # No real terminal (piped/redirected stdin, CI, double-click with no console):
    # fall back to defaults instead of crashing on the first prompt.
    if not non_interactive and not sys.stdin.isatty():
        print("No interactive terminal detected - writing a config with default settings.")
        print("Re-run in a terminal (or pass --yes) to customise.")
        non_interactive = True

    try:
        run_wizard(non_interactive=non_interactive, output=out)
    except (KeyboardInterrupt, EOFError):
        print("\nSetup cancelled. No changes were written.")
        sys.exit(1)


if __name__ == "__main__":
    main()
