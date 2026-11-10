#!/usr/bin/env python3
"""
RemotePC v1.0.0 - Rich TUI dashboard for remote Windows PC control over SSH.
PhoneSploit-style interactive CLI. SSH in from your phone and control everything.

Usage:  python remotepc.py
"""

# Force UTF-8 output so emoji and box-drawing chars work over SSH / Windows terminal
import sys, os
if sys.stdout is not None and sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore
    except Exception:
        pass
if sys.stderr is not None and sys.stderr.encoding and sys.stderr.encoding.lower() != "utf-8":
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore
    except Exception:
        pass
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

import subprocess, platform, shutil, time, signal, html, base64, hashlib, threading, getpass, json, re, mimetypes
import urllib.request, urllib.parse, ctypes
from http.server import BaseHTTPRequestHandler, HTTPServer
from ctypes import wintypes
from html.parser import HTMLParser
from pathlib import Path
from datetime import datetime

# ─── External configuration ───────────────────────────────────────────────────
# Personal settings (assistant name, API keys, paths, models, IPs) live in an
# external JSON file — never in the source. See remotepc/remotepc_config.py and
# run `python remotepc/setup_wizard.py` to generate one.
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import remotepc_config as _cfgmod
    _CONFIG = _cfgmod.load_config()
except Exception:
    _cfgmod = None  # type: ignore
    _CONFIG = {}

_REPO_ROOT = Path(__file__).resolve().parent.parent
_HOME      = Path.home()

def _cfg_path(key: str, default: Path) -> Path:
    """Resolve a configurable directory, falling back to a cross-platform default."""
    if _cfgmod is not None:
        return _cfgmod.resolve_path(str(_CONFIG.get(key, "") or ""), default)
    return default

_LOG_DIR        = _cfg_path("log_dir", _REPO_ROOT)
_SCREENSHOT_DIR = _cfg_path("screenshot_dir", _HOME / "Pictures" / "Screenshots")
_MUSIC_DIR      = _cfg_path("music_dir", _HOME / "Music")
_NOTES_DIR      = _cfg_path("notes_dir", _REPO_ROOT)

_ASSISTANT_NAME = str(_CONFIG.get("assistant_name") or "RemotePC")

import psutil
import pyperclip
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.columns import Columns
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.align import Align
from rich.rule import Rule
from rich import box
from rich.markup import escape

console   = Console(force_terminal=True, highlight=False)
ACCENT    = "bright_cyan"
HEADER    = "bold bright_cyan"
SUCCESS   = "bold bright_green"
WARN      = "bold yellow"
ERROR     = "bold bright_red"
DIM       = "grey50"
INFO      = "bold bright_cyan"   # alias used in AI Agent section
PANEL_BOX = box.ROUNDED

BANNER = r"""
 ____                      _        ____   ____
|  _ \ ___ _ __ ___   ___ | |_ ___ |  _ \ / ___|
| |_) / _ \ '_ ` _ \ / _ \| __/ _ \| |_) | |
|  _ <  __/ | | | | | (_) | ||  __/|  __/| |___
|_| \_\___|_| |_| |_|\___/ \__\___||_|    \____|
"""
VERSION = "v1.0.0"
TAGLINE = "Your PC. Your Phone. Your Control."


# ═══════════════════════════════════════════════════
# SECURITY CONFIG
# ═══════════════════════════════════════════════════

# Tailscale & network IP allowlist.
# Loopback is always permitted, and any Tailscale 100.x / fd7a: address is
# accepted automatically (see _security_check). Add your own device IPs in the
# config file ("allowed_ips") or by re-running the setup wizard.
_ALLOWED_IPS: set = {"127.0.0.1", "::1"}
for _ip in _CONFIG.get("allowed_ips", []) or []:
    if isinstance(_ip, str) and _ip.strip():
        _ALLOWED_IPS.add(_ip.strip())

# PIN authentication (optional). Configure via the setup wizard.
_PIN_HASH     = str(_CONFIG.get("pin_hash", "") or "")
_PIN_ATTEMPTS = 3        # wrong attempts before lockout
_REQUIRE_PIN  = bool(_CONFIG.get("require_pin", False)) and bool(_PIN_HASH)

# Idle session timeout (disabled)
_IDLE_TIMEOUT_MINS = 0  # auto-exit disabled

# AI Agent max ReAct steps per user turn (raise for complex multi-step tasks)
_AGENT_MAX_STEPS = 10

# Dangerous shell commands the AI agent is NOT allowed to run
_SHELL_BLOCKLIST = [
    "format ", "diskpart", "rd /s", "rmdir /s",
    "del /f /s", "rm -rf", "shutdown", "net user",
    "reg delete", "bcdedit", "cipher /w",
]

# Mutable idle timer state
_idle_timer: list = [None]  # list so it’s mutable from inner functions


def _security_log(event: str, detail: str = "") -> None:
    """Write a security event to the main log file."""
    import json
    entry = {
        "ts":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source": "SECURITY",
        "cmd":    event,
        "result": detail,
        "status": "security",
    }
    try:
        log_path = _LOG_DIR / "remotepc_log.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _get_ssh_client_ip() -> str:
    """Return the IP of the SSH client from SSH_CLIENT or SSH_CONNECTION env var, or '127.0.0.1'."""
    raw = os.environ.get("SSH_CLIENT", "").strip() or os.environ.get("SSH_CONNECTION", "").strip()
    if raw:
        ip = raw.split()[0].strip().strip("[]")
        if "%" in ip:
            ip = ip.split("%")[0]
        if ip.startswith("::ffff:"):
            ip = ip[7:]
        return ip
    return "127.0.0.1"   # not an SSH session — treat as local


def _security_check() -> None:
    """
    Gate check at startup:
      1. Verify SSH_CLIENT IP is in the allowlist.
      2. If REQUIRE_PIN, prompt for PIN with lockout after max attempts.
    Exits immediately on failure.
    """
    client_ip = _get_ssh_client_ip()
    norm_ip = client_ip.strip("[]")
    if norm_ip.startswith("::ffff:"):
        norm_ip = norm_ip[7:]
    if "%" in norm_ip:
        norm_ip = norm_ip.split("%")[0]

    # ── 1. IP CHECK ─────────────────────────────────────────────────────────
    # Allow explicit allowlist, any Tailscale IPv4/IPv6, or a private LAN address.
    is_tailscale = (
        norm_ip.startswith("100.")
        or norm_ip.startswith("fd7a:115c:a1e0:")
        or norm_ip.startswith("fd7a:")
    )
    try:
        import ipaddress
        is_local_lan = ipaddress.ip_address(norm_ip).is_private
    except ValueError:
        is_local_lan = False

    if norm_ip not in _ALLOWED_IPS and not is_tailscale and not is_local_lan:
        _security_log("BLOCKED", f"Unauthorized IP: {client_ip}")
        console.print(
            f"\n[bold bright_red]\u26d4  ACCESS DENIED[/bold bright_red]\n"
            f"  Connection from [bold]{client_ip}[/bold] is not authorized.\n"
            f"  Only this PC's Tailscale network and its own devices are permitted.\n"
            f"  Add allowlisted IPs to the config file (\"allowed_ips\").\n"
        )
        sys.exit(1)
    elif norm_ip not in _ALLOWED_IPS and is_tailscale:
        # Unknown Tailscale device — warn but allow (you can tighten this)
        _security_log("WARN_UNKNOWN_TAILSCALE", f"Unknown Tailscale IP: {client_ip}")
        console.print(
            f"[bold yellow]\u26a0  Warning: unknown Tailscale IP {client_ip}. "
            f"Add to \"allowed_ips\" in the config if this is your device.[/bold yellow]\n"
        )

    _security_log("CONNECT", f"IP={norm_ip}")

    # ── 2. PIN CHECK ─────────────────────────────────────────────────────
    if not _REQUIRE_PIN:
        return

    console.print(f"\n[bold bright_cyan]  RemotePC — Secure Access[/bold bright_cyan]")
    console.print(f"  [dim]Connecting from:[/dim] [bold]{client_ip}[/bold]\n")

    for attempt in range(1, _PIN_ATTEMPTS + 1):
        try:
            entered = getpass.getpass(f"  PIN ({attempt}/{_PIN_ATTEMPTS}): ")
        except (KeyboardInterrupt, EOFError):
            _security_log("AUTH_ABORTED", f"IP={client_ip}")
            sys.exit(1)

        entered_hash = hashlib.sha256(entered.encode()).hexdigest()
        if entered_hash == _PIN_HASH:
            _security_log("AUTH_OK", f"IP={client_ip}")
            console.print("  [bold bright_green]\u2713 Authenticated.[/bold bright_green]\n")
            return
        else:
            remaining = _PIN_ATTEMPTS - attempt
            _security_log("AUTH_FAIL", f"IP={client_ip} attempt={attempt}")
            if remaining > 0:
                console.print(f"  [bold red]\u2718 Wrong PIN. {remaining} attempt(s) left.[/bold red]")
            else:
                console.print(
                    f"\n[bold bright_red]\u26d4  Too many failed attempts. Session terminated.[/bold bright_red]\n"
                )
                _security_log("LOCKED_OUT", f"IP={client_ip}")
                sys.exit(1)


def _reset_idle_timer() -> None:
    """Cancel any existing idle timer and start a fresh one (disabled)."""
    if _idle_timer[0] is not None:
        try:
            _idle_timer[0].cancel()
        except Exception:
            pass
        _idle_timer[0] = None


def _guard_shell_cmd(cmd: str) -> str:
    """
    Check if an AI-agent shell command contains blocked patterns.
    Returns an error string if blocked, empty string if safe.
    """
    cmd_lower = cmd.lower()
    for pattern in _SHELL_BLOCKLIST:
        if pattern in cmd_lower:
            _security_log("SHELL_BLOCKED", f"Pattern '{pattern}' in: {cmd[:120]}")
            return (
                f"Blocked: shell command contains forbidden pattern '{pattern}'. "
                f"This incident has been logged."
            )
    return ""


# ─── Utilities ────────────────────────────────────────────────────────────────

def clear():
    console.clear()

def pause():
    Prompt.ask("\n[dim]Press Enter to continue[/dim]", default="")

def bytes_to_human(n):
    for unit in ["B","KB","MB","GB","TB"]:
        if n < 1024: return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"

def run_shell(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, encoding="utf-8", errors="replace")
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return -1, "", str(e)


# ─── Interactive GUI Launcher (Session 1 Bridge for SSH) ─────────────────────
_GUI_TASK_NAME = "RemotePC_Launcher"
_GUI_LAUNCHER_CMD = Path.home() / "AppData" / "Local" / "Temp" / "remotepc_launch.cmd"
_GUI_TASK_INITIALIZED = False

def _ensure_gui_launcher_task() -> bool:
    """Ensure the interactive scheduled task exists with battery and desktop permissions."""
    global _GUI_TASK_INITIALIZED
    if _GUI_TASK_INITIALIZED and _GUI_LAUNCHER_CMD.exists():
        return True

    _GUI_LAUNCHER_CMD.parent.mkdir(parents=True, exist_ok=True)
    if not _GUI_LAUNCHER_CMD.exists():
        _GUI_LAUNCHER_CMD.write_text("@echo off\r\nexit /b 0\r\n", encoding="utf-8")

    rc, _, _ = run_shell(f'schtasks /query /tn "{_GUI_TASK_NAME}"')
    if rc == 0:
        _GUI_TASK_INITIALIZED = True
        return True

    try:
        ps = f'''
        $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c "{_GUI_LAUNCHER_CMD}"'
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances Parallel -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
        $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive
        Register-ScheduledTask -TaskName "{_GUI_TASK_NAME}" -Action $action -Settings $settings -Principal $principal -Force | Out-Null
        '''
        encoded = base64.b64encode(ps.encode("utf-16le")).decode("ascii")
        rc, _, _ = run_shell(f'powershell -NoProfile -NonInteractive -EncodedCommand {encoded}')
        if rc == 0:
            _GUI_TASK_INITIALIZED = True
            return True
    except Exception:
        pass
    return False

def launch_desktop_app(cmd_or_target: str, cwd: str = None) -> bool:
    """
    Launch a GUI application, file, or URL on the active Windows desktop.
    Bypasses Windows SSH Session 0 isolation by executing through an interactive task.
    """
    cmd_or_target = cmd_or_target.strip()
    if not cmd_or_target:
        return False

    if cmd_or_target.lower().startswith("start "):
        batch_line = cmd_or_target
    else:
        batch_line = f'start "" {cmd_or_target}'

    lines = ["@echo off"]
    if cwd and Path(cwd).exists():
        lines.append(f'cd /d "{cwd}"')
    lines.append(batch_line)
    lines.append("exit /b 0")

    try:
        if _ensure_gui_launcher_task():
            _GUI_LAUNCHER_CMD.write_text("\r\n".join(lines) + "\r\n", encoding="utf-8")
            rc, _, _ = run_shell(f'schtasks /run /tn "{_GUI_TASK_NAME}"')
            if rc == 0:
                return True
    except Exception:
        pass

    cd_prefix = f'cd /d "{cwd}" && ' if (cwd and Path(cwd).exists()) else ""
    rc, _, _ = run_shell(f'{cd_prefix}{batch_line}')
    return rc == 0

def print_header(title):
    clear()
    console.print(Panel(Align.center(Text(title, style=HEADER)),
                        border_style=ACCENT, box=PANEL_BOX, padding=(0, 2)))

def bar(value, total=100, width=20):
    f = int(width * value / total)
    return f"[{ACCENT}]{'█'*f}[/{ACCENT}][dim]{'░'*(width-f)}[/dim]"


# ═══════════════════════════════════════════════════
# 1. SYSTEM DASHBOARD
# ═══════════════════════════════════════════════════

def _get_nvidia_gpus():
    """Query NVIDIA GPUs via nvidia-smi. Returns list of dicts or []."""
    rc, out, _ = run_shell(
        "nvidia-smi --query-gpu=name,utilization.gpu,temperature.gpu,"
        "memory.used,memory.total --format=csv,noheader,nounits"
    )
    if rc != 0 or not out.strip():
        return []
    gpus = []
    for line in out.strip().splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 5:
            try:
                gpus.append({"name": parts[0], "load": float(parts[1]),
                              "temp": float(parts[2]), "mem_used": float(parts[3]),
                              "mem_total": float(parts[4])})
            except ValueError:
                pass
    return gpus

def _get_wmi_gpus():
    """Fallback: query all GPUs via WMI. Returns list of dicts."""
    import json
    rc, out, _ = run_shell(
        "powershell -Command \"Get-WmiObject Win32_VideoController"
        "|Select-Object Name,AdapterRAM|ConvertTo-Json\""
    )
    if rc != 0 or not out.strip():
        return []
    try:
        data = json.loads(out.strip())
        if isinstance(data, dict):
            data = [data]
        return [{"name": d.get("Name", "Unknown"),
                 "vram_mb": (d.get("AdapterRAM") or 0) // (1024 * 1024)} for d in data]
    except Exception:
        return []

def show_dashboard():
    print_header("System Dashboard")
    cpu  = psutil.cpu_percent(interval=0.5)
    mem  = psutil.virtual_memory()
    disk = psutil.disk_usage("C:\\")
    boot = datetime.fromtimestamp(psutil.boot_time())
    up   = datetime.now() - boot
    h, r = divmod(int(up.total_seconds()), 3600)
    m, s = divmod(r, 60)
    try:
        net = psutil.net_io_counters()
        ns  = f"Up {bytes_to_human(net.bytes_sent)}  Dn {bytes_to_human(net.bytes_recv)}"
    except:
        ns = "N/A"

    # Row 1: CPU / MEM / DISK / INFO
    console.print(Columns([
        Panel(f"{bar(cpu)} [bold]{cpu}%[/bold]\n[dim]Cores: {psutil.cpu_count()} logical[/dim]",
              title="[bold cyan]CPU[/bold cyan]", border_style="cyan", box=PANEL_BOX, padding=(0,1)),
        Panel(f"{bar(mem.percent)} [bold]{mem.percent}%[/bold]\n[dim]{bytes_to_human(mem.used)}/{bytes_to_human(mem.total)}[/dim]",
              title="[bold magenta]Memory[/bold magenta]", border_style="magenta", box=PANEL_BOX, padding=(0,1)),
        Panel(f"{bar(disk.percent)} [bold]{disk.percent}%[/bold]\n[dim]{bytes_to_human(disk.used)}/{bytes_to_human(disk.total)}[/dim]",
              title="[bold yellow]Disk C:[/bold yellow]", border_style="yellow", box=PANEL_BOX, padding=(0,1)),
        Panel(f"[{ACCENT}]Uptime:[/{ACCENT}]  {h}h {m}m {s}s\n[{ACCENT}]Network:[/{ACCENT}] {ns}\n[{ACCENT}]Boot:[/{ACCENT}]    {boot.strftime('%d %b %Y %H:%M')}",
              title="[bold green]Info[/bold green]", border_style="green", box=PANEL_BOX, padding=(0,1)),
    ], equal=True, expand=True))

    # Row 2: GPU Status
    console.print()
    console.print(Rule("[bold bright_green]GPU Status[/bold bright_green]", style="bright_green"))

    nvidia_gpus = _get_nvidia_gpus()
    gpu_panels  = []

    for g in nvidia_gpus:
        mem_pct   = (g["mem_used"] / g["mem_total"] * 100) if g["mem_total"] else 0
        temp_col  = "green" if g["temp"] < 65 else ("yellow" if g["temp"] < 80 else "red")
        short     = g["name"].replace("NVIDIA ", "").replace("GeForce ", "")
        gpu_panels.append(Panel(
            f"[bold]Load:[/bold]  {bar(g['load'])} [bold]{g['load']:.0f}%[/bold]\n"
            f"[bold]VRAM:[/bold]  {bar(mem_pct)} [bold]{mem_pct:.0f}%[/bold] "
            f"[dim]({g['mem_used']:.0f}/{g['mem_total']:.0f} MB)[/dim]\n"
            f"[bold]Temp:[/bold]  [{temp_col}]{g['temp']:.0f} C[/{temp_col}]",
            title=f"[bold bright_green]{short} (NVIDIA)[/bold bright_green]",
            border_style="bright_green", box=PANEL_BOX, padding=(0,1)
        ))

    nvidia_names = {g["name"].lower() for g in nvidia_gpus}
    for wg in _get_wmi_gpus():
        if wg["name"].lower() in nvidia_names:
            continue
        vram_str = f"{wg['vram_mb']} MB" if wg["vram_mb"] else "N/A"
        gpu_panels.append(Panel(
            f"[bold]VRAM:[/bold] [bold]{vram_str}[/bold]\n"
            f"[dim]Live stats: nvidia-smi not available[/dim]",
            title=f"[bold cyan]{wg['name']}[/bold cyan]",
            border_style="cyan", box=PANEL_BOX, padding=(0,1)
        ))

    if gpu_panels:
        console.print(Columns(gpu_panels, equal=True, expand=True))
    else:
        console.print("  [dim]No GPU information available.[/dim]")

    # Row 3: Top Processes
    console.print()
    console.print(Rule("[bold cyan]Top Processes by CPU[/bold cyan]", style="cyan"))
    procs = sorted(psutil.process_iter(["pid","name","cpu_percent","memory_percent"]),
                   key=lambda p: p.info["cpu_percent"] or 0, reverse=True)[:12]
    t = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", show_edge=False)
    t.add_column("PID",  style="dim",            width=8)
    t.add_column("Name", style="bold white",     min_width=28)
    t.add_column("CPU%", style="bright_yellow",  width=8)
    t.add_column("MEM%", style="bright_magenta", width=8)
    for p in procs:
        t.add_row(str(p.info["pid"]), (p.info["name"] or "?")[:28],
                  f"{p.info['cpu_percent'] or 0:.1f}",
                  f"{p.info['memory_percent'] or 0:.1f}")
    console.print(t)
    pause()




# ═══════════════════════════════════════════════════
# 2. FILE MANAGER
# ═══════════════════════════════════════════════════

def file_manager():
    cwd = Path.home()
    while True:
        print_header(f"📁  File Manager  —  {cwd}")
        try:
            entries = sorted(cwd.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower()))
        except PermissionError:
            console.print(f"[{ERROR}]Permission denied.[/{ERROR}]"); cwd = cwd.parent; continue

        t = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", show_edge=False, expand=True)
        t.add_column("#",    style="dim",        width=5)
        t.add_column("T",    style="bold",       width=3)
        t.add_column("Name", style="bold white", min_width=30)
        t.add_column("Size", style="dim",        width=12, justify="right")
        t.add_column("Modified", width=18,       style="dim")
        for i, e in enumerate(entries, 1):
            try:
                st  = e.stat()
                sz  = bytes_to_human(st.st_size) if e.is_file() else "—"
                mod = datetime.fromtimestamp(st.st_mtime).strftime("%d %b %Y %H:%M")
            except: sz = "?"; mod = "?"
            t.add_row(str(i), "D" if e.is_dir() else "F", e.name, sz, mod)
        console.print(t)
        console.print()
        console.print(Rule("[dim]Commands[/dim]", style="dim"))
        console.print(
            "  [bold cyan]cd <n|path>[/bold cyan] Open dir   "
            "[bold cyan]up[/bold cyan] Go up   [bold cyan]home[/bold cyan] Home\n"
            "  [bold cyan]del <n>[/bold cyan] Delete   [bold cyan]mkdir <name>[/bold cyan] New folder   "
            "[bold cyan]rename <n> <new>[/bold cyan] Rename\n"
            "  [bold cyan]open <n>[/bold cyan] Open with default app   "
            "[bold cyan]clip <n>[/bold cyan] Copy path   "
            "[bold cyan]run <cmd>[/bold cyan] Shell here   "
            "[bold cyan]back[/bold cyan] Menu"
        )
        console.print()
        cmd = Prompt.ask(f"[{ACCENT}]fm>[/{ACCENT}]").strip()
        if not cmd: continue
        parts  = cmd.split(maxsplit=2)
        action = parts[0].lower()

        if action in ("back","exit","q"): break
        elif action == "up":   cwd = cwd.parent
        elif action == "home": cwd = Path.home()
        elif action == "cd":
            if len(parts) < 2: continue
            a = parts[1]
            if a.isdigit():
                i = int(a) - 1
                if 0 <= i < len(entries) and entries[i].is_dir(): cwd = entries[i]
                else: console.print(f"[{ERROR}]Not a directory.[/{ERROR}]"); time.sleep(1)
            else:
                p = Path(a) if Path(a).is_absolute() else cwd / a
                if p.is_dir(): cwd = p
                else: console.print(f"[{ERROR}]Not found.[/{ERROR}]"); time.sleep(1)
        elif action == "del":
            if len(parts) < 2 or not parts[1].isdigit(): continue
            i = int(parts[1]) - 1
            if 0 <= i < len(entries):
                tgt = entries[i]
                if Confirm.ask(f"[{WARN}]Delete [bold]{tgt.name}[/bold]?[/{WARN}]"):
                    try:
                        shutil.rmtree(tgt) if tgt.is_dir() else tgt.unlink()
                        console.print(f"[{SUCCESS}]Deleted.[/{SUCCESS}]"); time.sleep(0.8)
                    except Exception as e: console.print(f"[{ERROR}]{e}[/{ERROR}]"); time.sleep(1)
        elif action == "mkdir":
            if len(parts) < 2: continue
            try:
                (cwd / parts[1]).mkdir(parents=True, exist_ok=True)
                console.print(f"[{SUCCESS}]Created.[/{SUCCESS}]"); time.sleep(0.8)
            except Exception as e: console.print(f"[{ERROR}]{e}[/{ERROR}]"); time.sleep(1)
        elif action == "rename":
            if len(parts) < 3 or not parts[1].isdigit(): continue
            i = int(parts[1]) - 1
            if 0 <= i < len(entries):
                try: entries[i].rename(cwd / parts[2]); console.print(f"[{SUCCESS}]Renamed.[/{SUCCESS}]"); time.sleep(0.8)
                except Exception as e: console.print(f"[{ERROR}]{e}[/{ERROR}]"); time.sleep(1)
        elif action == "open":
            if len(parts) < 2 or not parts[1].isdigit(): continue
            i = int(parts[1]) - 1
            if 0 <= i < len(entries):
                target = str(entries[i])
                launch_desktop_app(f'"{target}"', cwd=str(cwd))
                console.print(f"[{SUCCESS}]Opening {entries[i].name} on desktop.[/{SUCCESS}]")
        elif action == "clip":
            if len(parts) < 2 or not parts[1].isdigit(): continue
            i = int(parts[1]) - 1
            if 0 <= i < len(entries):
                try: pyperclip.copy(str(entries[i])); console.print(f"[{SUCCESS}]Copied.[/{SUCCESS}]"); time.sleep(0.8)
                except Exception as e: console.print(f"[{ERROR}]{e}[/{ERROR}]"); time.sleep(1)
        elif action == "run":
            if len(parts) < 2: continue
            rc, out, err = run_shell(f'cd /d "{cwd}" && {" ".join(parts[1:])}')
            if out: console.print(Panel(out.strip(), border_style="green", box=PANEL_BOX))
            if err: console.print(Panel(err.strip(), border_style="red",   box=PANEL_BOX))
            pause()
        else: console.print(f"[{ERROR}]Unknown: {action}[/{ERROR}]"); time.sleep(0.8)


# ═══════════════════════════════════════════════════
# 3. SHELL
# ═══════════════════════════════════════════════════

def shell_session():
    print_header("💻  Interactive Shell")
    console.print(Panel(
        f"[dim]Commands execute on your PC. Type [bold]exit[/bold] to return.[/dim]",
        border_style="cyan", box=PANEL_BOX))
    while True:
        try: cmd = Prompt.ask(f"[{ACCENT}]shell[/{ACCENT}]").strip()
        except (EOFError, KeyboardInterrupt): break
        if cmd.lower() in ("exit","back","q","quit"): break
        if not cmd: continue
        rc, out, err = run_shell(cmd)
        if out: console.print(Panel(out.rstrip(), border_style="green", box=PANEL_BOX, title="[green]stdout[/green]"))
        if err: console.print(Panel(err.rstrip(), border_style="red",   box=PANEL_BOX, title="[red]stderr[/red]"))
        if not out and not err:
            style = SUCCESS if rc == 0 else ERROR
            console.print(f"[{style}]Exit code: {rc}[/{style}]")


# ═══════════════════════════════════════════════════
# 4. PROCESS MANAGER
# ═══════════════════════════════════════════════════

def process_manager():
    while True:
        print_header("⚙  Process Manager")
        procs = sorted(psutil.process_iter(["pid","name","status","cpu_percent","memory_percent","username"]),
                       key=lambda p: p.info["memory_percent"] or 0, reverse=True)[:30]
        t = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", show_edge=False, expand=True)
        t.add_column("PID",    style="dim",            width=8)
        t.add_column("Name",   style="bold white",     min_width=24)
        t.add_column("Status", style="cyan",           width=12)
        t.add_column("CPU%",   style="bright_yellow",  width=8)
        t.add_column("MEM%",   style="bright_magenta", width=8)
        t.add_column("User",   style="dim",            width=14)
        for p in procs:
            st = p.info["status"] or "?"
            sc = "green" if st == "running" else "dim"
            t.add_row(str(p.info["pid"]), (p.info["name"] or "?")[:24],
                      f"[{sc}]{st}[/{sc}]",
                      f"{p.info['cpu_percent'] or 0:.1f}",
                      f"{p.info['memory_percent'] or 0:.1f}",
                      (p.info["username"] or "?")[:14])
        console.print(t)
        console.print(f"\n  [bold cyan]kill <PID>[/bold cyan]   [bold cyan]search <name>[/bold cyan]   [bold cyan]refresh[/bold cyan]   [bold cyan]back[/bold cyan]")
        cmd    = Prompt.ask(f"\n[{ACCENT}]procs[/{ACCENT}]").strip()
        parts  = cmd.split(maxsplit=1)
        action = parts[0].lower() if parts else ""
        if action in ("back","exit","q"): break
        elif action == "refresh": continue
        elif action == "kill":
            if len(parts) < 2: console.print(f"[{ERROR}]Usage: kill <PID>[/{ERROR}]"); time.sleep(1); continue
            try:
                p = psutil.Process(int(parts[1]))
                if Confirm.ask(f"[{WARN}]Kill [bold]{p.name()}[/bold] (PID {parts[1]})?[/{WARN}]"):
                    p.terminate(); console.print(f"[{SUCCESS}]Terminated.[/{SUCCESS}]"); time.sleep(0.8)
            except Exception as e: console.print(f"[{ERROR}]{e}[/{ERROR}]"); time.sleep(1)
        elif action == "search":
            if len(parts) < 2: continue
            q   = parts[1].lower()
            hit = [p for p in psutil.process_iter(["pid","name"]) if q in (p.info["name"] or "").lower()]
            if hit:
                for h in hit: console.print(f"  [{ACCENT}]{h.info['pid']:>6}[/{ACCENT}]  {h.info['name']}")
            else: console.print(f"[{WARN}]No matches.[/{WARN}]")
            pause()
        else: console.print(f"[{ERROR}]Unknown: {action}[/{ERROR}]"); time.sleep(0.8)


# ═══════════════════════════════════════════════════
# 5. MEDIA CONTROL
# ═══════════════════════════════════════════════════

MEDIA_VK = {"play":0xB3,"next":0xB0,"prev":0xB1,"stop":0xB2,
            "mute":0xAD,"volup":0xAF,"voldown":0xAE}

def _vk(code):
    ps = f'$s=New-Object -ComObject wscript.shell;$s.SendKeys([char]{code})'
    launch_desktop_app(f'powershell -WindowStyle Hidden -NoProfile -Command "{ps}"')

def media_control():
    print_header("🎵  Media Control")
    console.print(
        "  [bold cyan]play[/bold cyan]           Play/Pause\n"
        "  [bold cyan]next[/bold cyan]           Next track\n"
        "  [bold cyan]prev[/bold cyan]           Previous track\n"
        "  [bold cyan]stop[/bold cyan]           Stop playback\n"
        "  [bold cyan]mute[/bold cyan]           Toggle mute\n"
        "  [bold cyan]volup[/bold cyan]          Volume up\n"
        "  [bold cyan]voldown[/bold cyan]        Volume down\n"
        "  [bold cyan]vol <0-100>[/bold cyan]    Set volume (approx via key presses)\n"
        "  [bold cyan]back[/bold cyan]           Return to menu\n"
    )
    while True:
        cmd   = Prompt.ask(f"[{ACCENT}]media[/{ACCENT}]").strip().lower()
        parts = cmd.split()
        a     = parts[0] if parts else ""
        if a in ("back","exit","q"): break
        if a in MEDIA_VK:
            _vk(MEDIA_VK[a])
            console.print(f"[{SUCCESS}]OK: {a}[/{SUCCESS}]")
        elif a == "vol":
            if len(parts) < 2: console.print(f"[{ERROR}]Usage: vol <0-100>[/{ERROR}]"); continue
            try:
                lvl = max(0, min(100, int(parts[1])))
                dn  = MEDIA_VK["voldown"]
                up  = MEDIA_VK["volup"]
                ps = (
                    f"$s=New-Object -ComObject wscript.shell;"
                    f"1..50|%{{$s.SendKeys([char]{dn})}};"
                    f"1..{int(lvl/2)}|%{{$s.SendKeys([char]{up})}}"
                )
                launch_desktop_app(f'powershell -WindowStyle Hidden -NoProfile -Command "{ps}"')
                console.print(f"[{SUCCESS}]Volume set to ~{lvl}%[/{SUCCESS}]")
            except Exception as e: console.print(f"[{ERROR}]{e}[/{ERROR}]")
        else: console.print(f"[{ERROR}]Unknown: {a}[/{ERROR}]")


# ═══════════════════════════════════════════════════
# 6. APP LAUNCHER
# ═══════════════════════════════════════════════════

QUICK_APPS = {
    # ── System Tools ──────────────────────────────────────────
    "1":  ("Notepad",            "notepad.exe"),
    "2":  ("Calculator",         "calc.exe"),
    "3":  ("Task Manager",       "taskmgr.exe"),
    "4":  ("File Explorer",      "explorer.exe"),
    "5":  ("PowerShell",         "start powershell"),
    "6":  ("CMD",                "start cmd"),
    "7":  ("Snipping Tool",      "snippingtool.exe"),
    "8":  ("Paint",              "mspaint.exe"),
    "9":  ("Registry Editor",    "regedit.exe"),
    "10": ("Task Scheduler",     r'"C:\WINDOWS\system32\taskschd.msc"'),
    "11": ("Resource Monitor",   r'"C:\WINDOWS\system32\perfmon.exe"'),
    "12": ("Disk Cleanup",       "cleanmgr.exe"),
    # ── Browsers ──────────────────────────────────────────────
    "13": ("Edge",               "start msedge"),
    "14": ("Chrome",             r'"C:\Program Files\Google\Chrome\Application\chrome.exe"'),
    # ── IDEs & Dev Tools ──────────────────────────────────────
    "15": ("VS Code",            r'"%LOCALAPPDATA%\Programs\Microsoft VS Code\Code.exe"'),
    "16": ("Cursor",             r'"%LOCALAPPDATA%\Programs\cursor\Cursor.exe"'),
    "17": ("Trae",               r'"%LOCALAPPDATA%\Programs\Trae\Trae.exe"'),
    "18": ("Android Studio",     r'"C:\Program Files\Android\Android Studio\bin\studio64.exe"'),
    "19": ("WebStorm",           r'"C:\Program Files\JetBrains\WebStorm 2026.2.1\bin\webstorm64.exe"'),
    "20": ("CLion",              r'"C:\Program Files\JetBrains\CLion 2026.2.1\bin\clion64.exe"'),
    "21": ("Visual Studio",      r'"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\devenv.exe"'),
    "22": ("Arduino IDE",        r'"%LOCALAPPDATA%\Programs\Arduino IDE\Arduino IDE.exe"'),
    "23": ("Git Bash",           r'"C:\Program Files\Git\git-bash.exe"'),
    "24": ("GitHub Desktop",     r'"%LOCALAPPDATA%\GitHubDesktop\GitHubDesktop.exe"'),
    "25": ("Postman",            r'"%LOCALAPPDATA%\Postman\Postman.exe"'),
    # ── Media & Audio ─────────────────────────────────────────
    "26": ("Local Music (MusicBee)", r'"C:\Program Files (x86)\MusicBee\MusicBee.exe"'),
    "27": ("VLC",                r'"C:\Program Files\VideoLAN\VLC\vlc.exe"'),
    "28": ("MusicBee",           r'"C:\Program Files (x86)\MusicBee\MusicBee.exe"'),
    "29": ("REAPER",             r'"C:\Program Files\REAPER (x64)\reaper.exe"'),
    "30": ("Audacity",           r'"C:\Program Files\Audacity\Audacity.exe"'),
    # ── Creative & Design ─────────────────────────────────────
    "31": ("Blender",            r'"C:\Program Files\Blender Foundation\Blender 5.2\blender-launcher.exe"'),
    "32": ("Krita",              r'"C:\Program Files\Krita (x64)\bin\krita.exe"'),
    "33": ("Aseprite",           r'"%USERPROFILE%\Aseprite\aseprite.exe"'),
    # ── Communication ─────────────────────────────────────────
    "34": ("Telegram",           r'"%APPDATA%\Telegram Desktop\Telegram.exe"'),
    "35": ("Discord",            r'"%LOCALAPPDATA%\Discord\Update.exe" --processStart Discord.exe'),
    "36": ("Zoom",               r'"%APPDATA%\Zoom\bin\Zoom.exe"'),
    # ── Games ─────────────────────────────────────────────────
    "37": ("VALORANT",           r'"C:\Riot Games\Riot Client\RiotClientServices.exe"'),
    "38": ("Hollow Knight",      r'"%USERPROFILE%\Hollow Knight Silksong\Hollow Knight Silksong.exe"'),
    # ── Utilities ─────────────────────────────────────────────
    "39": ("Unity Hub",          r'"C:\Program Files\Unity Hub\Unity Hub.exe"'),
    "40": ("Free DL Manager",    r'"C:\Program Files\Softdeluxe\Free Download Manager\fdm.exe"'),
    "41": ("WinRAR",             r'"C:\Program Files\WinRAR\WinRAR.exe"'),
    "42": ("Tailscale",          r'"C:\Program Files\Tailscale\tailscale-ipn.exe"'),
    "43": ("Proton VPN",         r'"C:\Program Files\Proton\VPN\ProtonVPN.Launcher.exe"'),
    "44": ("Rainmeter",          r'"C:\Program Files\Rainmeter\Rainmeter.exe"'),
    "45": ("Malwarebytes",       r'"C:\Program Files\Malwarebytes\Anti-Malware\Malwarebytes.exe"'),
    "46": ("GeForce Experience", r'"C:\Program Files\NVIDIA Corporation\NVIDIA GeForce Experience\NVIDIA GeForce Experience.exe"'),
    "47": ("spacedesk",          r'"C:\Program Files\datronicsoft\spacedesk\spacedeskConsole.exe"'),
    # ── Microsoft Office ──────────────────────────────────────
    "48": ("Word",               r'"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"'),
    "49": ("Excel",              r'"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"'),
    "50": ("PowerPoint",         r'"C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE"'),
    "51": ("Outlook",            r'"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"'),
    "52": ("OneNote",            r'"C:\Program Files\Microsoft Office\root\Office16\ONENOTE.EXE"'),
}


def app_launcher():
    print_header("🚀  App Launcher")
    t = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", show_edge=False)
    t.add_column("#",   style="bold cyan", width=5)
    t.add_column("App", style="bold white")
    for k, (name, _) in QUICK_APPS.items(): t.add_row(k, name)
    console.print(t)
    console.print(
        "\n  [bold cyan]<number>[/bold cyan]    Launch app on desktop\n"
        "  [bold cyan]open <url>[/bold cyan]  Open URL in browser on desktop\n"
        "  [bold cyan]run <app>[/bold cyan]   Launch executable on desktop\n"
        "  [bold cyan]back[/bold cyan]        Return\n"
    )
    while True:
        cmd   = Prompt.ask(f"\n[{ACCENT}]launch[/{ACCENT}]").strip()
        if cmd.lower() in ("back","exit","q"): break
        parts = cmd.split(maxsplit=1)
        a     = parts[0].lower()
        if a in QUICK_APPS:
            name, exe = QUICK_APPS[a]
            launch_desktop_app(exe)
            console.print(f"[{SUCCESS}]Launched {name} on desktop.[/{SUCCESS}]")
        elif a == "open":
            if len(parts) < 2: console.print(f"[{ERROR}]Usage: open <url>[/{ERROR}]"); continue
            url = parts[1] if parts[1].startswith("http") else "https://" + parts[1]
            launch_desktop_app(f'"{url}"')
            console.print(f"[{SUCCESS}]Opened in default browser on desktop.[/{SUCCESS}]")
        elif a == "run":
            if len(parts) < 2: console.print(f"[{ERROR}]Usage: run <app>[/{ERROR}]"); continue
            launch_desktop_app(parts[1])
            console.print(f"[{SUCCESS}]Launched {parts[1]} on desktop.[/{SUCCESS}]")
        else: console.print(f"[{ERROR}]Unknown: {a}[/{ERROR}]")


# ═══════════════════════════════════════════════════
# 7. CLIPBOARD
# ═══════════════════════════════════════════════════

def clipboard_manager():
    print_header("📋  Clipboard Manager")
    console.print(
        "  [bold cyan]get[/bold cyan]          Show PC clipboard\n"
        "  [bold cyan]set <text>[/bold cyan]   Copy text to PC clipboard\n"
        "  [bold cyan]clear[/bold cyan]        Clear clipboard\n"
        "  [bold cyan]back[/bold cyan]         Return\n"
    )
    while True:
        cmd   = Prompt.ask(f"[{ACCENT}]clip[/{ACCENT}]").strip()
        parts = cmd.split(maxsplit=1)
        a     = parts[0].lower() if parts else ""
        if a in ("back","exit","q"): break
        elif a == "get":
            try: console.print(Panel(pyperclip.paste() or "[dim](empty)[/dim]",
                                     title="Clipboard", border_style="cyan", box=PANEL_BOX))
            except Exception as e: console.print(f"[{ERROR}]{e}[/{ERROR}]")
        elif a == "set":
            if len(parts) < 2: console.print(f"[{ERROR}]Usage: set <text>[/{ERROR}]"); continue
            try: pyperclip.copy(parts[1]); console.print(f"[{SUCCESS}]Copied to PC clipboard.[/{SUCCESS}]")
            except Exception as e: console.print(f"[{ERROR}]{e}[/{ERROR}]")
        elif a == "clear":
            try: pyperclip.copy(""); console.print(f"[{SUCCESS}]Cleared.[/{SUCCESS}]")
            except Exception as e: console.print(f"[{ERROR}]{e}[/{ERROR}]")
        else: console.print(f"[{ERROR}]Unknown: {a}[/{ERROR}]")


# ═══════════════════════════════════════════════════
# 8. NETWORK INFO
# ═══════════════════════════════════════════════════

def network_info():
    print_header("🌐  Network Information")
    console.print(Rule("[bold cyan]Interfaces[/bold cyan]", style="cyan"))
    t = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", show_edge=False, expand=True)
    t.add_column("Interface",  style="bold white",  width=20)
    t.add_column("IP Address", style="bright_cyan", width=22)
    t.add_column("Netmask",    style="dim",         width=18)
    t.add_column("Family",     style="dim",         width=10)
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family.name in ("AF_INET","AF_INET6"):
                t.add_row(iface, addr.address, addr.netmask or "—", addr.family.name)
    console.print(t)
    console.print()
    console.print(Rule("[bold cyan]Active Connections (top 15)[/bold cyan]", style="cyan"))
    try:
        t2 = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", show_edge=False, expand=True)
        t2.add_column("Proto",  style="dim",           width=7)
        t2.add_column("Local",  style="bold white",    width=24)
        t2.add_column("Remote", style="bright_cyan",   width=24)
        t2.add_column("Status", style="bright_yellow", width=14)
        t2.add_column("PID",    style="dim",           width=7)
        for c in psutil.net_connections(kind="inet")[:15]:
            t2.add_row(c.type.name,
                       f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "—",
                       f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "—",
                       c.status or "—", str(c.pid or "—"))
        console.print(t2)
    except Exception as e: console.print(f"[{ERROR}]{e}[/{ERROR}]")
    console.print()
    try:
        import urllib.request
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
            console.print(f"  [{ACCENT}]External IP:[/{ACCENT}] [bold]{r.read().decode()}[/bold]")
    except: console.print("  [dim]Could not fetch external IP.[/dim]")
    pause()


# ═══════════════════════════════════════════════════
# 9. TASKS & SERVICES
# ═══════════════════════════════════════════════════

def windows_tasks():
    print_header("📅  Tasks & Services")
    console.print(
        "  [bold cyan]tasks[/bold cyan]              List enabled scheduled tasks\n"
        "  [bold cyan]services[/bold cyan]           List running services\n"
        "  [bold cyan]svc stop <name>[/bold cyan]   Stop a service\n"
        "  [bold cyan]svc start <name>[/bold cyan]  Start a service\n"
        "  [bold cyan]back[/bold cyan]               Return\n"
    )
    while True:
        cmd   = Prompt.ask(f"[{ACCENT}]tasks[/{ACCENT}]").strip()
        parts = cmd.split(maxsplit=2)
        a     = parts[0].lower() if parts else ""
        if a in ("back","exit","q"): break
        elif a == "tasks":
            rc, out, err = run_shell(
                "powershell -Command \"Get-ScheduledTask"
                "|Where-Object{$_.State -ne 'Disabled'}"
                "|Select-Object -First 20 TaskName,State"
                "|Format-Table -AutoSize\""
            )
            console.print(Panel(out.strip() or err.strip(), border_style="cyan", box=PANEL_BOX))
            pause()
        elif a == "services":
            rc, out, err = run_shell(
                "powershell -Command \"Get-Service"
                "|Where-Object{$_.Status -eq 'Running'}"
                "|Select-Object -First 30 Name,DisplayName,Status"
                "|Format-Table -AutoSize\""
            )
            console.print(Panel(out.strip() or err.strip(), border_style="cyan", box=PANEL_BOX))
            pause()
        elif a == "svc":
            if len(parts) < 3: console.print(f"[{ERROR}]Usage: svc <start|stop> <name>[/{ERROR}]"); continue
            sub, name = parts[1].lower(), parts[2]
            if sub not in ("start","stop"): console.print(f"[{ERROR}]Unknown: {sub}[/{ERROR}]"); continue
            if sub == "stop" and not Confirm.ask(f"[{WARN}]Stop service [bold]{name}[/bold]?[/{WARN}]"):
                continue
            rc, out, err = run_shell(f"powershell -Command \"{sub.capitalize()}-Service '{name}' -Force\"")
            console.print(f"[{SUCCESS if rc==0 else ERROR}]{'Done.' if rc==0 else err}[/{SUCCESS if rc==0 else ERROR}]")
            pause()
        else: console.print(f"[{ERROR}]Unknown: {a}[/{ERROR}]"); time.sleep(0.8)


# ═══════════════════════════════════════════════════
# 10. DOWNLOAD MANAGER
# ═══════════════════════════════════════════════════

def download_manager():
    print_header("⬇  Download Manager")
    dl = Path.home() / "Downloads"
    console.print(
        f"  Folder: [bold]{dl}[/bold]\n\n"
        "  [bold cyan]list[/bold cyan]          Recent downloads\n"
        "  [bold cyan]yt <url>[/bold cyan]      Download via yt-dlp\n"
        "  [bold cyan]wget <url>[/bold cyan]    Download a file\n"
        "  [bold cyan]open[/bold cyan]          Open Downloads in Explorer\n"
        "  [bold cyan]back[/bold cyan]          Return\n"
    )
    while True:
        cmd   = Prompt.ask(f"[{ACCENT}]dl[/{ACCENT}]").strip()
        parts = cmd.split(maxsplit=1)
        a     = parts[0].lower() if parts else ""
        if a in ("back","exit","q"): break
        elif a == "list":
            try:
                files = sorted(dl.iterdir(), key=lambda f: f.stat().st_mtime, reverse=True)[:20]
                t = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", show_edge=False, expand=True)
                t.add_column("Name", style="bold white",  min_width=35)
                t.add_column("Size", style="dim",         width=12, justify="right")
                t.add_column("Date", style="dim",         width=18)
                for f in files:
                    st = f.stat()
                    t.add_row(f.name[:50],
                              bytes_to_human(st.st_size) if f.is_file() else "DIR",
                              datetime.fromtimestamp(st.st_mtime).strftime("%d %b %Y %H:%M"))
                console.print(t)
            except Exception as e: console.print(f"[{ERROR}]{e}[/{ERROR}]")
            pause()
        elif a == "yt":
            if len(parts) < 2: console.print(f"[{ERROR}]Usage: yt <url>[/{ERROR}]"); continue
            try:
                subprocess.Popen(["python","-m","yt_dlp","-o",
                                  str(dl / "%(title)s.%(ext)s"), parts[1]],
                                 creationflags=subprocess.CREATE_NEW_CONSOLE)
                console.print(f"[{SUCCESS}]yt-dlp started in background window.[/{SUCCESS}]")
            except Exception as e: console.print(f"[{ERROR}]{e}[/{ERROR}]")
        elif a == "wget":
            if len(parts) < 2: console.print(f"[{ERROR}]Usage: wget <url>[/{ERROR}]"); continue
            url   = parts[1]
            fname = dl / url.split("/")[-1].split("?")[0]
            console.print(f"[dim]Downloading to {fname}...[/dim]")
            rc, out, err = run_shell(f"powershell -Command \"Invoke-WebRequest -Uri '{url}' -OutFile '{fname}'\"")
            console.print(f"[{SUCCESS if rc==0 else ERROR}]{'Saved: '+fname.name if rc==0 else err}[/{SUCCESS if rc==0 else ERROR}]")
            pause()
        elif a == "open":
            launch_desktop_app(f'explorer.exe "{dl}"')
            console.print(f"[{SUCCESS}]Opened downloads folder on desktop.[/{SUCCESS}]")
        else: console.print(f"[{ERROR}]Unknown: {a}[/{ERROR}]")


# ═══════════════════════════════════════════════════
# 11. SCREENSHOT
# ═══════════════════════════════════════════════════

def take_screenshot():
    print_header("📸  Screenshot")
    out_dir = _SCREENSHOT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    fname   = out_dir / f"screenshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
    console.print(f"[dim]Capturing screen to {fname}...[/dim]")
    pf  = str(fname).replace("/", "\\")
    ps  = (
        f"Add-Type -AssemblyName System.Windows.Forms,System.Drawing\r\n"
        f"$s = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds\r\n"
        f"$b = New-Object System.Drawing.Bitmap($s.Width, $s.Height)\r\n"
        f"$g = [System.Drawing.Graphics]::FromImage($b)\r\n"
        f"$g.CopyFromScreen($s.Location, [System.Drawing.Point]::Empty, $s.Size)\r\n"
        f"$b.Save('{pf}')\r\n"
        f"$g.Dispose()\r\n"
        f"$b.Dispose()\r\n"
    )
    # Execute via interactive task so screen capture has desktop window station access even over SSH
    ps_file = Path.home() / "AppData" / "Local" / "Temp" / "remotepc_scr.ps1"
    try:
        ps_file.write_text(ps, encoding="utf-8")
        launch_desktop_app(f'powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File "{ps_file}"')
        for _ in range(8):
            time.sleep(0.5)
            if fname.exists() and fname.stat().st_size > 0:
                break
    except Exception:
        pass

    if not (fname.exists() and fname.stat().st_size > 0):
        # Fallback to direct PowerShell execution
        encoded = base64.b64encode(ps.encode("utf-16le")).decode("ascii")
        run_shell(f'powershell -NoProfile -NonInteractive -EncodedCommand {encoded}')

    if fname.exists() and fname.stat().st_size > 0:
        console.print(Panel(
            f"[{SUCCESS}]Screenshot saved![/{SUCCESS}]\n"
            f"[{ACCENT}]Path:[/{ACCENT}] {fname}\n"
            f"[{ACCENT}]Size:[/{ACCENT}] {bytes_to_human(fname.stat().st_size)}",
            border_style="green", box=PANEL_BOX))
    else:
        console.print(f"[{ERROR}]Failed to capture screenshot.[/{ERROR}]")
    pause()


# ═══════════════════════════════════════════════════
# 12. QUICK NOTE
# ═══════════════════════════════════════════════════

def quick_note():
    print_header("📝  Quick Note")
    nd = Path.home() / "Documents" / "RemotePC" / "Notes"
    nd.mkdir(parents=True, exist_ok=True)
    console.print(
        "  [bold cyan]new[/bold cyan]          Write a new note\n"
        "  [bold cyan]list[/bold cyan]         List saved notes\n"
        "  [bold cyan]read <n>[/bold cyan]     Read note by index\n"
        "  [bold cyan]del <n>[/bold cyan]      Delete a note\n"
        "  [bold cyan]back[/bold cyan]         Return\n"
    )
    while True:
        cmd   = Prompt.ask(f"[{ACCENT}]note[/{ACCENT}]").strip()
        parts = cmd.split(maxsplit=1)
        a     = parts[0].lower() if parts else ""
        notes = sorted(nd.glob("*.txt"), key=lambda f: f.stat().st_mtime, reverse=True)
        if a in ("back","exit","q"): break
        elif a == "new":
            title = Prompt.ask("[bold]Title[/bold]").strip().replace(" ","_") or "note"
            console.print("[dim]Type your note. Enter END on a blank line to save.[/dim]")
            lines = []
            while True:
                try: line = input()
                except EOFError: break
                if line.strip().upper() == "END": break
                lines.append(line)
            fname = nd / f"{title}_{datetime.now().strftime('%Y%m%d_%H%M')}.txt"
            fname.write_text("\n".join(lines), encoding="utf-8")
            console.print(f"[{SUCCESS}]Saved: {fname.name}[/{SUCCESS}]")
        elif a == "list":
            if not notes: console.print("[dim]No notes yet.[/dim]")
            for i, n in enumerate(notes, 1):
                st = n.stat()
                console.print(
                    f"  [{ACCENT}]{i:>3}.[/{ACCENT}] [bold]{n.name}[/bold]  "
                    f"[dim]{bytes_to_human(st.st_size)}  "
                    f"{datetime.fromtimestamp(st.st_mtime).strftime('%d %b %Y %H:%M')}[/dim]"
                )
            pause()
        elif a in ("read","del"):
            if len(parts) < 2 or not parts[1].isdigit():
                console.print(f"[{ERROR}]Usage: {a} <number>[/{ERROR}]"); continue
            i = int(parts[1]) - 1
            if 0 <= i < len(notes):
                if a == "read":
                    console.print(Panel(notes[i].read_text(encoding="utf-8"),
                                        title=notes[i].name, border_style="cyan", box=PANEL_BOX))
                    pause()
                else:
                    if Confirm.ask(f"[{WARN}]Delete [bold]{notes[i].name}[/bold]?[/{WARN}]"):
                        notes[i].unlink(); console.print(f"[{SUCCESS}]Deleted.[/{SUCCESS}]")
            else: console.print(f"[{ERROR}]Index out of range.[/{ERROR}]")
        else: console.print(f"[{ERROR}]Unknown: {a}[/{ERROR}]"); time.sleep(0.8)


# ═══════════════════════════════════════════════════
# 13. POWER CONTROL
# ═══════════════════════════════════════════════════

def power_control():
    print_header("⚡  Power Control")
    console.print(Panel(
        "[bold red]WARNING:[/bold red] These commands immediately affect your PC.\n"
        "Save all work before proceeding.",
        border_style="red", box=PANEL_BOX))
    console.print(
        "\n  [bold cyan]lock[/bold cyan]       Lock screen\n"
        "  [bold cyan]sleep[/bold cyan]      Sleep\n"
        "  [bold cyan]hibernate[/bold cyan]  Hibernate\n"
        "  [bold cyan]restart[/bold cyan]    Restart (5s delay)\n"
        "  [bold cyan]shutdown[/bold cyan]   Shutdown (5s delay)\n"
        "  [bold cyan]logout[/bold cyan]     Log out user\n"
        "  [bold cyan]back[/bold cyan]       Return\n"
    )
    while True:
        cmd = Prompt.ask(f"[{ACCENT}]power[/{ACCENT}]").strip().lower()
        if cmd in ("back","exit","q"): break
        elif cmd == "lock":
            launch_desktop_app("rundll32.exe user32.dll,LockWorkStation")
            console.print(f"[{SUCCESS}]Screen locked.[/{SUCCESS}]")
        elif cmd == "sleep":
            if Confirm.ask(f"[{WARN}]Sleep?[/{WARN}]"):
                launch_desktop_app("rundll32.exe powrprof.dll,SetSuspendState 0,1,0")
        elif cmd == "hibernate":
            if Confirm.ask(f"[{WARN}]Hibernate?[/{WARN}]"): run_shell("shutdown /h")
        elif cmd == "restart":
            if Confirm.ask(f"[{WARN}]Restart PC?[/{WARN}]"):
                run_shell("shutdown /r /t 5")
                console.print(f"[{WARN}]Restarting in 5 seconds...[/{WARN}]"); break
        elif cmd == "shutdown":
            if Confirm.ask(f"[bold red]Shutdown? You will lose SSH access![/bold red]"):
                run_shell("shutdown /s /t 5")
                console.print(f"[{WARN}]Shutting down in 5 seconds...[/{WARN}]"); break
        elif cmd == "logout":
            if Confirm.ask(f"[{WARN}]Log out?[/{WARN}]"): run_shell("shutdown /l")
        else: console.print(f"[{ERROR}]Unknown: {cmd}[/{ERROR}]")


# ═══════════════════════════════════════════════════
# 14. NOTIFICATIONS
# ═══════════════════════════════════════════════════

def _send_toast(title: str, body: str) -> bool:
    safe_title = html.escape(title, quote=True).replace("'", "&apos;")
    safe_body  = html.escape(body, quote=True).replace("'", "&apos;")
    xml = (
        f"<toast>"
        f"<visual><binding template='ToastGeneric'>"
        f"<text>{safe_title}</text>"
        f"<text>{safe_body}</text>"
        f"</binding></visual>"
        f"<audio src='ms-winsoundevent:Notification.Default'/>"
        f"</toast>"
    )
    ps = f"""
$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$doc = [Windows.Data.Xml.Dom.XmlDocument]::new()
$doc.LoadXml(@'
{xml}
'@)
$toast = [Windows.UI.Notifications.ToastNotification]::new($doc)
$appId = '{{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}}\\WindowsPowerShell\\v1.0\\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
"""
    try:
        encoded = base64.b64encode(ps.encode("utf-16le")).decode("utf-8")
        r = subprocess.run(
            ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", encoded],
            capture_output=True, text=True, timeout=8
        )
        if r.returncode == 0:
            return True
    except Exception:
        pass

    # Fallback 1: NotifyIcon balloon tip
    try:
        ps_balloon = f"""
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
$ni = New-Object System.Windows.Forms.NotifyIcon
$ni.Icon = [System.Drawing.SystemIcons]::Information
$ni.Visible = $true
$ni.ShowBalloonTip(4000, @'{title}'@, @'{body}'@, [System.Windows.Forms.ToolTipIcon]::Info)
Start-Sleep -Seconds 3
$ni.Dispose()
"""
        encoded_balloon = base64.b64encode(ps_balloon.encode("utf-16le")).decode("utf-8")
        r2 = subprocess.run(
            ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", encoded_balloon],
            capture_output=True, text=True, timeout=8
        )
        if r2.returncode == 0:
            return True
    except Exception:
        pass

    # Fallback 2: msg command
    rc, _, _ = run_shell(f'msg * "{title}: {body}"')
    return rc == 0


def _schedule_toast(secs: int, title: str, body: str):
    safe_title = html.escape(title, quote=True).replace("'", "&apos;")
    safe_body  = html.escape(body, quote=True).replace("'", "&apos;")
    xml = (
        f"<toast>"
        f"<visual><binding template='ToastGeneric'>"
        f"<text>{safe_title}</text>"
        f"<text>{safe_body}</text>"
        f"</binding></visual>"
        f"<audio src='ms-winsoundevent:Notification.Default'/>"
        f"</toast>"
    )
    ps = f"""
Start-Sleep -Seconds {secs}
$ErrorActionPreference = 'Stop'
try {{
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
    [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
    $doc = [Windows.Data.Xml.Dom.XmlDocument]::new()
    $doc.LoadXml(@'
{xml}
'@)
    $toast = [Windows.UI.Notifications.ToastNotification]::new($doc)
    $appId = '{{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}}\\WindowsPowerShell\\v1.0\\powershell.exe'
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
}} catch {{
    Add-Type -AssemblyName System.Windows.Forms
    $ni = New-Object System.Windows.Forms.NotifyIcon
    $ni.Icon = [System.Drawing.SystemIcons]::Information
    $ni.Visible = $true
    $ni.ShowBalloonTip(4000, @'{title}'@, @'{body}'@, [System.Windows.Forms.ToolTipIcon]::Info)
    Start-Sleep -Seconds 3
    $ni.Dispose()
}}
"""
    flags = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    encoded = base64.b64encode(ps.encode("utf-16le")).decode("utf-8")
    subprocess.Popen(
        ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", encoded],
        creationflags=flags
    )


def send_notification():
    print_header("[~]  Notifications")
    console.print(
        "  Send toast popups to your PC desktop.\n\n"
        "  [bold cyan]toast <message>[/bold cyan]                        Quick notification\n"
        "  [bold cyan]toast <Title> | <Message>[/bold cyan]             Custom title + body\n"
        "  [bold cyan]remind <seconds> <message>[/bold cyan]            Delayed notification\n"
        "  [bold cyan]remind <seconds> <Title> | <Message>[/bold cyan]  Delayed custom notification\n"
        "  [bold cyan]back[/bold cyan]                                   Return\n"
    )
    while True:
        cmd   = Prompt.ask(f"[{ACCENT}]notify[/{ACCENT}]").strip()
        parts = cmd.split(maxsplit=1)
        a     = parts[0].lower() if parts else ""
        if a in ("back", "exit", "q"): break

        elif a == "toast":
            if len(parts) < 2: console.print(f"[{ERROR}]Usage: toast <message>[/{ERROR}]"); continue
            raw = parts[1]
            if "|" in raw:
                title, body = [x.strip() for x in raw.split("|", 1)]
            else:
                title, body = "RemotePC", raw
            ok = _send_toast(title, body)
            if ok:
                console.print(f"[{SUCCESS}]Toast sent: '{title}' — {body}[/{SUCCESS}]")
            else:
                console.print(f"[{WARN}]Notification sent via fallback.[/{WARN}]")

        elif a == "remind":
            if len(parts) < 2: console.print(f"[{ERROR}]Usage: remind <seconds> <message>[/{ERROR}]"); continue
            sub = parts[1].split(maxsplit=1)
            if len(sub) < 2 or not sub[0].isdigit(): console.print(f"[{ERROR}]Usage: remind <seconds> <message>[/{ERROR}]"); continue
            secs, raw = int(sub[0]), sub[1]
            if "|" in raw:
                title, body = [x.strip() for x in raw.split("|", 1)]
            else:
                title, body = "RemotePC Reminder", raw
            _schedule_toast(secs, title, body)
            console.print(f"[{SUCCESS}]Reminder set for {secs} seconds: '{title}' — '{body}'[/{SUCCESS}]")

        else:
            console.print(f"[{ERROR}]Unknown: {a}[/{ERROR}]")


# ═══════════════════════════════════════════════════
# 15. WI-FI MANAGER
# ═══════════════════════════════════════════════════

def wifi_manager():
    print_header("[W]  Wi-Fi Manager")
    console.print(
        "  [bold cyan]scan[/bold cyan]              Scan nearby networks\n"
        "  [bold cyan]connected[/bold cyan]         Current connection details\n"
        "  [bold cyan]profiles[/bold cyan]          List saved Wi-Fi profiles\n"
        "  [bold cyan]connect <SSID>[/bold cyan]    Connect to a saved profile\n"
        "  [bold cyan]forget <SSID>[/bold cyan]     Delete a saved profile\n"
        "  [bold cyan]back[/bold cyan]              Return\n"
    )
    while True:
        cmd   = Prompt.ask(f"[{ACCENT}]wifi[/{ACCENT}]").strip()
        parts = cmd.split(maxsplit=1)
        a     = parts[0].lower() if parts else ""
        if a in ("back", "exit", "q"): break

        elif a == "scan":
            console.print("[dim]Scanning... (may take a few seconds)[/dim]")
            rc, out, err = run_shell("netsh wlan show networks mode=bssid")
            if rc != 0 or not out.strip():
                console.print(f"[{ERROR}]Failed: {err or 'No output'}[/{ERROR}]"); continue
            # Parse and display nicely
            t = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", show_edge=False, expand=True)
            t.add_column("SSID",     style="bold white",   min_width=25)
            t.add_column("Signal",   style="bright_yellow", width=10)
            t.add_column("Security", style="cyan",          width=16)
            t.add_column("Band",     style="dim",           width=8)
            current_ssid = current_auth = current_signal = current_band = ""
            for line in out.splitlines():
                line = line.strip()
                if line.lower().startswith("ssid") and ":" in line and "bssid" not in line.lower():
                    current_ssid = line.split(":", 1)[1].strip()
                elif "authentication" in line.lower() and ":" in line:
                    current_auth = line.split(":", 1)[1].strip()
                elif "signal" in line.lower() and ":" in line:
                    current_signal = line.split(":", 1)[1].strip()
                elif "radio type" in line.lower() and ":" in line:
                    current_band = line.split(":", 1)[1].strip()
                    if current_ssid:
                        sig_num = int(current_signal.replace("%","")) if current_signal.replace("%","").isdigit() else 0
                        sig_col = "green" if sig_num >= 70 else ("yellow" if sig_num >= 40 else "red")
                        t.add_row(current_ssid, f"[{sig_col}]{current_signal}[/{sig_col}]",
                                  current_auth, current_band)
                        current_ssid = current_auth = current_signal = current_band = ""
            console.print(t)
            pause()

        elif a == "connected":
            rc, out, err = run_shell("netsh wlan show interfaces")
            if rc != 0: console.print(f"[{ERROR}]{err}[/{ERROR}]"); continue
            fields = {}
            for line in out.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    fields[k.strip().lower()] = v.strip()
            ssid    = fields.get("ssid", "N/A")
            state   = fields.get("state", "N/A")
            signal  = fields.get("signal", "N/A")
            speed   = fields.get("receive rate (mbps)", "N/A")
            bssid   = fields.get("bssid", "N/A")
            console.print(Panel(
                f"[{ACCENT}]SSID:[/{ACCENT}]    [bold]{ssid}[/bold]\n"
                f"[{ACCENT}]State:[/{ACCENT}]   {state}\n"
                f"[{ACCENT}]Signal:[/{ACCENT}]  {signal}\n"
                f"[{ACCENT}]Speed:[/{ACCENT}]   {speed} Mbps\n"
                f"[{ACCENT}]BSSID:[/{ACCENT}]   {bssid}",
                title="[bold cyan]Current Connection[/bold cyan]",
                border_style="cyan", box=PANEL_BOX
            ))
            pause()

        elif a == "profiles":
            rc, out, err = run_shell("netsh wlan show profiles")
            if rc != 0: console.print(f"[{ERROR}]{err}[/{ERROR}]"); continue
            names = [l.split(":",1)[1].strip() for l in out.splitlines() if ":" in l and "All User" in l]
            if not names: console.print("[dim]No saved profiles.[/dim]")
            for i, n in enumerate(names, 1):
                console.print(f"  [{ACCENT}]{i:>3}.[/{ACCENT}] {n}")
            pause()

        elif a == "connect":
            if len(parts) < 2: console.print(f"[{ERROR}]Usage: connect <SSID>[/{ERROR}]"); continue
            ssid = parts[1]
            rc, out, err = run_shell(f'netsh wlan connect name="{ssid}"')
            if rc == 0 and "successfully" in out.lower():
                console.print(f"[{SUCCESS}]Connected to {ssid}.[/{SUCCESS}]")
            else:
                console.print(f"[{ERROR}]{out or err}[/{ERROR}]")

        elif a == "forget":
            if len(parts) < 2: console.print(f"[{ERROR}]Usage: forget <SSID>[/{ERROR}]"); continue
            ssid = parts[1]
            if Confirm.ask(f"[{WARN}]Delete profile [bold]{ssid}[/bold]?[/{WARN}]"):
                rc, out, err = run_shell(f'netsh wlan delete profile name="{ssid}"')
                console.print(f"[{SUCCESS if rc==0 else ERROR}]{out.strip() or err.strip()}[/{SUCCESS if rc==0 else ERROR}]")

        else:
            console.print(f"[{ERROR}]Unknown: {a}[/{ERROR}]")


# ═══════════════════════════════════════════════════
# 16. STARTUP MANAGER
# ═══════════════════════════════════════════════════

def startup_manager():
    print_header("[^]  Startup Manager")
    console.print(
        "  [bold cyan]list[/bold cyan]              Show all startup entries\n"
        "  [bold cyan]disable <n>[/bold cyan]       Disable a startup entry\n"
        "  [bold cyan]enable <n>[/bold cyan]        Enable a startup entry\n"
        "  [bold cyan]open[/bold cyan]              Open Startup folder in Explorer\n"
        "  [bold cyan]back[/bold cyan]              Return\n"
    )
    _startup_cache = []

    def _load_startup():
        rc, out, err = run_shell(
            "powershell -Command \""
            "Get-CimInstance Win32_StartupCommand"
            "|Select-Object Name,Command,Location,User"
            "|ConvertTo-Json\""
        )
        if rc != 0 or not out.strip(): return []
        import json
        try:
            data = json.loads(out.strip())
            if isinstance(data, dict): data = [data]
            return data
        except Exception: return []

    while True:
        cmd   = Prompt.ask(f"[{ACCENT}]startup[/{ACCENT}]").strip()
        parts = cmd.split(maxsplit=1)
        a     = parts[0].lower() if parts else ""
        if a in ("back", "exit", "q"): break

        elif a == "list":
            _startup_cache[:] = _load_startup()
            if not _startup_cache:
                console.print("[dim]No startup entries found (may need admin).[/dim]"); pause(); continue
            t = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", show_edge=False, expand=True)
            t.add_column("#",        style="dim",         width=5)
            t.add_column("Name",     style="bold white",  min_width=22)
            t.add_column("Location", style="cyan",        width=14)
            t.add_column("User",     style="dim",         width=14)
            t.add_column("Command",  style="dim",         min_width=20)
            for i, e in enumerate(_startup_cache, 1):
                t.add_row(str(i),
                          (e.get("Name") or "")[:22],
                          (e.get("Location") or "")[:14],
                          (e.get("User") or "")[:14],
                          (e.get("Command") or "")[:40])
            console.print(t)
            pause()

        elif a in ("disable", "enable"):
            if len(parts) < 2 or not parts[1].isdigit():
                console.print(f"[{ERROR}]Usage: {a} <number>[/{ERROR}]"); continue
            if not _startup_cache:
                console.print(f"[{WARN}]Run 'list' first.[/{WARN}]"); continue
            i = int(parts[1]) - 1
            if not (0 <= i < len(_startup_cache)):
                console.print(f"[{ERROR}]Index out of range.[/{ERROR}]"); continue
            entry = _startup_cache[i]
            name  = entry.get("Name", "")
            # Use Registry-based enable/disable via Task Manager startup key
            reg_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
            if a == "disable":
                # Write disabled value (3-byte prefix 03 00 00 00 ...)
                ps = (f"$p='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run';"
                      f"if(!(Test-Path $p)){{New-Item -Path $p -Force|Out-Null}};"
                      f"Set-ItemProperty -Path $p -Name '{name}' "
                      f"-Value ([byte[]](3,0,0,0,0,0,0,0,0,0,0,0)) -Type Binary")
            else:
                ps = (f"$p='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run';"
                      f"if(Test-Path $p){{Remove-ItemProperty -Path $p -Name '{name}' -ErrorAction SilentlyContinue}}")
            rc, out, err = run_shell(f'powershell -Command "{ps}"')
            action_word = "Disabled" if a == "disable" else "Enabled"
            if rc == 0:
                console.print(f"[{SUCCESS}]{action_word}: {name}[/{SUCCESS}]")
                console.print(f"[dim]Changes take effect on next login.[/dim]")
            else:
                console.print(f"[{ERROR}]{err}[/{ERROR}]")

        elif a == "open":
            launch_desktop_app("explorer.exe shell:startup")
            console.print(f"[{SUCCESS}]Opened Startup folder on desktop.[/{SUCCESS}]")

        else:
            console.print(f"[{ERROR}]Unknown: {a}[/{ERROR}]"); time.sleep(0.8)


# ═══════════════════════════════════════════════════
# UX-1: FAVORITES BAR
# ═══════════════════════════════════════════════════

_FAV_FILE = Path.home() / "Documents" / "RemotePC" / "favorites.json"
_FAV_SLOTS = 4

def _load_favorites():
    import json
    try:
        if _FAV_FILE.exists():
            return json.loads(_FAV_FILE.read_text(encoding="utf-8"))
    except Exception: pass
    return {str(i): None for i in range(1, _FAV_SLOTS + 1)}

def _save_favorites(favs):
    import json
    _FAV_FILE.parent.mkdir(parents=True, exist_ok=True)
    _FAV_FILE.write_text(json.dumps(favs, indent=2), encoding="utf-8")

def favorites_manager():
    print_header("[*F] Favorites Manager")
    console.print(
        "  Set up to 4 quick-fire slots (f1-f4) at the main menu prompt.\n\n"
        "  [bold cyan]list[/bold cyan]           Show current favorites\n"
        "  [bold cyan]set <slot> <key>[/bold cyan]  Assign a menu item (e.g. set 1 lock)\n"
        "  [bold cyan]clear <slot>[/bold cyan]   Clear a slot\n"
        "  [bold cyan]back[/bold cyan]           Return\n\n"
        "  Valid keys: any menu number (1-16), or action keywords:\n"
        f"  [dim]lock, sleep, play, next, prev, mute, screenshot, clip-get[/dim]\n"
    )
    # Quick actions map (keyword -> callable)
    QUICK_ACTIONS = {
        "lock":       lambda: launch_desktop_app("rundll32.exe user32.dll,LockWorkStation"),
        "sleep":      lambda: launch_desktop_app("rundll32.exe powrprof.dll,SetSuspendState 0,1,0"),
        "play":       lambda: _vk(179),
        "next":       lambda: _vk(176),
        "prev":       lambda: _vk(177),
        "mute":       lambda: _vk(173),
        "screenshot": take_screenshot,
        "clip-get":   lambda: console.print(Panel(pyperclip.paste() or "(empty)", title="Clipboard", border_style="cyan", box=PANEL_BOX)),
    }
    while True:
        favs  = _load_favorites()
        cmd   = Prompt.ask(f"[{ACCENT}]favs[/{ACCENT}]").strip()
        parts = cmd.split(maxsplit=2)
        a     = parts[0].lower() if parts else ""
        if a in ("back", "exit", "q"): break

        elif a == "list":
            for slot in range(1, _FAV_SLOTS + 1):
                val = favs.get(str(slot))
                console.print(f"  [{ACCENT}]F{slot}[/{ACCENT}]  {val or '[dim](empty)[/dim]'}")
            pause()

        elif a == "set":
            if len(parts) < 3: console.print(f"[{ERROR}]Usage: set <1-4> <key>[/{ERROR}]"); continue
            slot, key = parts[1], parts[2].lower()
            if slot not in [str(i) for i in range(1, _FAV_SLOTS + 1)]:
                console.print(f"[{ERROR}]Slot must be 1-{_FAV_SLOTS}.[/{ERROR}]"); continue
            favs[slot] = key
            _save_favorites(favs)
            console.print(f"[{SUCCESS}]F{slot} = {key}[/{SUCCESS}]")

        elif a == "clear":
            if len(parts) < 2: console.print(f"[{ERROR}]Usage: clear <1-4>[/{ERROR}]"); continue
            slot = parts[1]
            if slot in favs: favs[slot] = None; _save_favorites(favs)
            console.print(f"[{SUCCESS}]F{slot} cleared.[/{SUCCESS}]")

        else:
            console.print(f"[{ERROR}]Unknown: {a}[/{ERROR}]"); time.sleep(0.8)


def _run_favorite(key: str, menu_items):
    """Execute a favorite slot — either a menu number or a quick-action keyword."""
    QUICK_ACTIONS = {
        "lock":       lambda: launch_desktop_app("rundll32.exe user32.dll,LockWorkStation"),
        "sleep":      lambda: launch_desktop_app("rundll32.exe powrprof.dll,SetSuspendState 0,1,0"),
        "play":       lambda: _vk(179),
        "next":       lambda: _vk(176),
        "prev":       lambda: _vk(177),
        "mute":       lambda: _vk(173),
        "screenshot": take_screenshot,
        "clip-get":   lambda: (console.print(Panel(pyperclip.paste() or "(empty)", title="Clipboard", border_style="cyan", box=PANEL_BOX)), pause()),
    }
    if key in QUICK_ACTIONS:
        try: QUICK_ACTIONS[key]()
        except KeyboardInterrupt: pass
        console.print(f"[{SUCCESS}]OK: {key}[/{SUCCESS}]")
    else:
        fn = next((fn for k, _, _, fn in menu_items if k == key), None)
        if fn:
            try: fn()
            except KeyboardInterrupt: pass
        else:
            console.print(f"[{ERROR}]Unknown favorite key: {key}[/{ERROR}]"); time.sleep(0.8)


# ═══════════════════════════════════════════════════
# 18. LM STUDIO (BIONIC)
# ═══════════════════════════════════════════════════

def _detect_lms_exe() -> str:
    """Locate the LM Studio CLI (lms). Config value -> common install paths -> PATH."""
    configured = str(_CONFIG.get("lmstudio_exe", "") or "").strip()
    if configured and Path(configured).exists():
        return configured
    for candidate in (
        _HOME / ".lmstudio" / "bin" / "lms.exe",
        _HOME / ".cache" / "lm-studio" / "bin" / "lms.exe",
    ):
        if candidate.exists():
            return str(candidate)
    return configured or "lms"

LMS_EXE = _detect_lms_exe()

def _lms(args: str, capture=True):
    """Run an lms command. Returns (rc, stdout, stderr)."""
    return run_shell(f'"{LMS_EXE}" {args}')

def lmstudio_module():
    print_header("[AI] LM Studio  /  Bionic")
    console.print(
        "  [bold cyan]models[/bold cyan]           List models on disk\n"
        "  [bold cyan]ps[/bold cyan]               List loaded models in memory\n"
        "  [bold cyan]load <model>[/bold cyan]     Load a model (use name from 'models')\n"
        "  [bold cyan]unload <model>[/bold cyan]   Unload a model from memory\n"
        "  [bold cyan]server start[/bold cyan]     Start the local API server (port 1234)\n"
        "  [bold cyan]server stop[/bold cyan]      Stop the local API server\n"
        "  [bold cyan]server status[/bold cyan]    Check server status\n"
        "  [bold cyan]chat <model>[/bold cyan]     Start interactive chat with a model\n"
        "  [bold cyan]ask <model> <prompt>[/bold cyan]  One-shot prompt (no chat loop)\n"
        "  [bold cyan]back[/bold cyan]             Return\n"
    )

    while True:
        cmd   = Prompt.ask(f"[{ACCENT}]lms[/{ACCENT}]").strip()
        parts = cmd.split(maxsplit=2)
        a     = parts[0].lower() if parts else ""
        if a in ("back", "exit", "q"): break

        elif a == "models":
            rc, out, err = _lms("ls")
            console.print(Panel(out.strip() or err.strip(),
                                title="[bold cyan]Local Models[/bold cyan]",
                                border_style="cyan", box=PANEL_BOX))
            pause()

        elif a == "ps":
            rc, out, err = _lms("ps")
            if out.strip():
                console.print(Panel(out.strip(), title="[bold green]Loaded Models[/bold green]",
                                    border_style="green", box=PANEL_BOX))
            else:
                console.print(f"[{WARN}]No models currently loaded in memory.[/{WARN}]")
            pause()

        elif a == "load":
            if len(parts) < 2:
                console.print(f"[{ERROR}]Usage: load <model-name>[/{ERROR}]"); continue
            model = parts[1]
            console.print(f"[dim]Loading {model}... (this may take a moment)[/dim]")
            rc, out, err = _lms(f'load "{model}"')
            if rc == 0:
                console.print(f"[{SUCCESS}]Loaded: {model}[/{SUCCESS}]")
            else:
                console.print(Panel(err.strip() or out.strip(), border_style="red", box=PANEL_BOX))
            pause()

        elif a == "unload":
            if len(parts) < 2:
                console.print(f"[{ERROR}]Usage: unload <model-name>[/{ERROR}]"); continue
            model = parts[1]
            rc, out, err = _lms(f'unload "{model}"')
            console.print(f"[{SUCCESS if rc==0 else ERROR}]{out.strip() or err.strip()}[/{SUCCESS if rc==0 else ERROR}]")

        elif a == "server":
            sub = parts[1].lower() if len(parts) > 1 else ""
            if sub not in ("start", "stop", "status"):
                console.print(f"[{ERROR}]Usage: server <start|stop|status>[/{ERROR}]"); continue
            rc, out, err = _lms(f"server {sub}")
            color = SUCCESS if rc == 0 else ERROR
            console.print(Panel(out.strip() or err.strip(), border_style="green" if rc==0 else "red", box=PANEL_BOX))

        elif a == "chat":
            if len(parts) < 2:
                # Try to pick from loaded models
                rc, out, _ = _lms("ps")
                console.print(f"[{ERROR}]Usage: chat <model-name>[/{ERROR}]")
                if out.strip():
                    console.print(f"[dim]Loaded models:\n{out.strip()}[/dim]")
                continue
            model = parts[1]
            console.print(Panel(
                f"[bold]Chatting with:[/bold] [bold cyan]{model}[/bold cyan]\n"
                f"[dim]Type your message and press Enter. Type [bold]EXIT[/bold] to stop.[/dim]",
                border_style="cyan", box=PANEL_BOX
            ))
            # Chat loop using lms API server (HTTP)
            history = []
            while True:
                try:
                    user_msg = Prompt.ask(f"[bold green]You[/bold green]").strip()
                except (EOFError, KeyboardInterrupt):
                    break
                if user_msg.upper() in ("EXIT", "QUIT", "BACK", "Q"):
                    break
                if not user_msg:
                    continue
                history.append({"role": "user", "content": user_msg})
                # Call LM Studio local server OpenAI-compatible API (using urllib to avoid JSON corruption)
                import json as _json
                payload_bytes = _json.dumps({"model": model, "messages": history, "stream": False}).encode("utf-8")
                console.print(f"[dim]Thinking...[/dim]")
                try:
                    req = urllib.request.Request(
                        "http://localhost:1234/v1/chat/completions",
                        data=payload_bytes,
                        headers={"Content-Type": "application/json", "Authorization": "Bearer lm-studio"},
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=120) as resp:
                        data = _json.loads(resp.read().decode("utf-8"))
                    reply = data["choices"][0]["message"]["content"].strip()
                    history.append({"role": "assistant", "content": reply})
                    console.print(Panel(reply, title=f"[bold magenta]{model}[/bold magenta]",
                                        border_style="magenta", box=PANEL_BOX))
                except Exception as ex:
                    console.print(f"[{ERROR}]Error: {ex} (Server may not be running. Use: server start)[/{ERROR}]")
                    console.print(f"[dim]Tip: run 'server start' first, then load the model.[/dim]")
                    break

        elif a == "ask":
            if len(parts) < 3:
                console.print(f"[{ERROR}]Usage: ask <model> <prompt>[/{ERROR}]"); continue
            model, prompt = parts[1], parts[2]
            import json as _json
            payload_bytes = _json.dumps({"model": model,
                                        "messages": [{"role": "user", "content": prompt}],
                                        "stream": False}).encode("utf-8")
            console.print(f"[dim]Thinking...[/dim]")
            try:
                req = urllib.request.Request(
                    "http://localhost:1234/v1/chat/completions",
                    data=payload_bytes,
                    headers={"Content-Type": "application/json", "Authorization": "Bearer lm-studio"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=120) as resp:
                    data = _json.loads(resp.read().decode("utf-8"))
                reply = data["choices"][0]["message"]["content"].strip()
                console.print(Panel(reply, title=f"[bold magenta]{model}[/bold magenta]",
                                    border_style="magenta", box=PANEL_BOX))
            except Exception as ex:
                console.print(f"[{ERROR}]{ex} (Server not running? Use: server start)[/{ERROR}]")
            pause()

        else:
            console.print(f"[{ERROR}]Unknown: {a}[/{ERROR}]"); time.sleep(0.8)


# ═══════════════════════════════════════════════════
# 19. UNITY BUILD RUNNER
# ═══════════════════════════════════════════════════

def _find_unity_editors():
    editors = {}
    hub_root = Path(r"C:\Program Files\Unity\Hub\Editor")
    if hub_root.exists():
        for ver_dir in sorted(hub_root.iterdir(), reverse=True):
            exe = ver_dir / "Editor" / "Unity.exe"
            if exe.is_file():
                editors[ver_dir.name] = str(exe)
    if not editors:
        editors["6000.5.9f1"] = r"C:\Program Files\Unity\Hub\Editor\6000.5.9f1\Editor\Unity.exe"
    return editors

_UNITY_EDITORS = _find_unity_editors()
_UNITY_DEFAULT = next(iter(_UNITY_EDITORS.keys()))
_UNITY_LOG     = Path.home() / "AppData" / "Local" / "Temp" / "RemotePC_unity_build.log"

BUILD_TARGETS = {
    "win64":   "StandaloneWindows64",
    "win32":   "StandaloneWindows",
    "android": "Android",
    "ios":     "iOS",
    "linux":   "StandaloneLinux64",
    "webgl":   "WebGL",
}

def unity_module():
    print_header("[U] Unity Build Runner")

    # Show installed editors
    editor_table = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", show_edge=False)
    editor_table.add_column("Version",  style="bold white", width=18)
    editor_table.add_column("Path",     style="dim")
    editor_table.add_column("Status",   style="bright_green", width=10)
    for ver, path in _UNITY_EDITORS.items():
        exists = Path(path).exists()
        editor_table.add_row(ver, path, "OK" if exists else "[red]MISSING[/red]")
    console.print(editor_table)
    console.print()
    console.print(
        "  [bold cyan]build <project> <target> [output][/bold cyan]\n"
        "     Build a Unity project. Target: win64 win32 android ios linux webgl\n"
        "     Example: build D:\\MyGame win64 D:\\MyGame\\Build\n\n"
        "  [bold cyan]batchbuild[/bold cyan]     Guided interactive build setup\n"
        "  [bold cyan]log[/bold cyan]            Show last build log (tail 60 lines)\n"
        "  [bold cyan]log full[/bold cyan]       Full build log\n"
        "  [bold cyan]kill[/bold cyan]           Kill any running Unity.exe process\n"
        "  [bold cyan]version <ver>[/bold cyan]  Switch Unity version (e.g. version 6000.5.0f1)\n"
        "  [bold cyan]back[/bold cyan]           Return\n"
    )

    active_version = _UNITY_DEFAULT

    def unity_exe():
        return _UNITY_EDITORS.get(active_version, list(_UNITY_EDITORS.values())[0])

    def do_build(project_path: str, target_key: str, output_path: str):
        target = BUILD_TARGETS.get(target_key.lower())
        if not target:
            console.print(f"[{ERROR}]Unknown target '{target_key}'. Valid: {', '.join(BUILD_TARGETS)}[/{ERROR}]")
            return
        if not Path(project_path).exists():
            console.print(f"[{ERROR}]Project path not found: {project_path}[/{ERROR}]")
            return
        exe = unity_exe()
        if not Path(exe).exists():
            console.print(f"[{ERROR}]Unity.exe not found: {exe}[/{ERROR}]")
            return
        if not output_path:
            output_path = str(Path(project_path) / "Build" / target_key)

        build_cmd = (
            f'"{exe}" -batchmode -nographics -quit '
            f'-projectPath "{project_path}" '
            f'-buildTarget {target} '
            f'-buildPlayerOptions "locationPathName={output_path}" '
            f'-logFile "{_UNITY_LOG}"'
        )
        console.print(Panel(
            f"[{ACCENT}]Project:[/{ACCENT}]  {project_path}\n"
            f"[{ACCENT}]Target:[/{ACCENT}]   {target} ({target_key})\n"
            f"[{ACCENT}]Output:[/{ACCENT}]   {output_path}\n"
            f"[{ACCENT}]Unity:[/{ACCENT}]    {active_version}\n"
            f"[{ACCENT}]Log:[/{ACCENT}]      {_UNITY_LOG}",
            title="[bold yellow]Build Config[/bold yellow]",
            border_style="yellow", box=PANEL_BOX
        ))
        if not Confirm.ask(f"[{WARN}]Start build now?[/{WARN}]"):
            return
        console.print(f"[dim]Launching Unity in batch mode... (runs in background)[/dim]")
        subprocess.Popen(build_cmd, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP, shell=True)
        console.print(f"[{SUCCESS}]Build started! Unity is running headlessly.[/{SUCCESS}]")
        console.print(f"[dim]Use 'log' to watch progress. Build may take several minutes.[/dim]")

    while True:
        cmd   = Prompt.ask(f"[{ACCENT}]unity[/{ACCENT}]").strip()
        parts = cmd.split(maxsplit=3)
        a     = parts[0].lower() if parts else ""
        if a in ("back", "exit", "q"): break

        elif a == "build":
            if len(parts) < 3:
                console.print(f"[{ERROR}]Usage: build <project_path> <target> [output_path][/{ERROR}]"); continue
            proj   = parts[1]
            target = parts[2]
            out    = parts[3] if len(parts) > 3 else ""
            do_build(proj, target, out)
            pause()

        elif a == "batchbuild":
            console.print(Rule("[bold cyan]Guided Build Setup[/bold cyan]", style="cyan"))
            proj   = Prompt.ask(f"[{ACCENT}]Project path[/{ACCENT}]").strip().strip('"')
            console.print(f"  Targets: {', '.join(BUILD_TARGETS.keys())}")
            target = Prompt.ask(f"[{ACCENT}]Build target[/{ACCENT}]").strip().lower()
            out    = Prompt.ask(f"[{ACCENT}]Output path (leave blank for default)[/{ACCENT}]",
                                default="").strip().strip('"')
            do_build(proj, target, out)
            pause()

        elif a == "log":
            full = len(parts) > 1 and parts[1].lower() == "full"
            if not _UNITY_LOG.exists():
                console.print(f"[{WARN}]No build log found at {_UNITY_LOG}[/{WARN}]"); continue
            lines = _UNITY_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
            if not full:
                lines = lines[-60:]  # last 60 lines
            # Colour key Unity log levels
            log_text = ""
            for line in lines:
                ll = line.lower()
                if "error" in ll or "exception" in ll or "failed" in ll:
                    log_text += f"[red]{line}[/red]\n"
                elif "warning" in ll:
                    log_text += f"[yellow]{line}[/yellow]\n"
                elif "complet" in ll or "success" in ll or "finish" in ll:
                    log_text += f"[green]{line}[/green]\n"
                else:
                    log_text += f"[dim]{line}[/dim]\n"
            console.print(Panel(log_text.rstrip(),
                                title=f"[bold cyan]Build Log {'(full)' if full else '(last 60 lines)'}[/bold cyan]",
                                border_style="cyan", box=PANEL_BOX))
            pause()

        elif a == "kill":
            killed = []
            for proc in psutil.process_iter(["pid", "name"]):
                if proc.info["name"] and "unity" in proc.info["name"].lower():
                    try:
                        proc.kill()
                        killed.append(f"{proc.info['name']} (PID {proc.info['pid']})")
                    except Exception: pass
            if killed:
                for k in killed: console.print(f"[{SUCCESS}]Killed: {k}[/{SUCCESS}]")
            else:
                console.print(f"[{WARN}]No Unity processes found.[/{WARN}]")

        elif a == "version":
            if len(parts) < 2:
                console.print(f"  Current: [bold]{active_version}[/bold]")
                console.print(f"  Available: {', '.join(_UNITY_EDITORS.keys())}")
            else:
                ver = parts[1]
                if ver in _UNITY_EDITORS:
                    active_version = ver
                    console.print(f"[{SUCCESS}]Switched to Unity {active_version}[/{SUCCESS}]")
                else:
                    console.print(f"[{ERROR}]Unknown version: {ver}. Available: {', '.join(_UNITY_EDITORS.keys())}[/{ERROR}]")

        else:
            console.print(f"[{ERROR}]Unknown: {a}[/{ERROR}]"); time.sleep(0.8)


# ═══════════════════════════════════════════════════
# KALI LINUX (WSL)
# ═══════════════════════════════════════════════════

def launch_kali_linux():
    print_header("🐉  Kali Linux (WSL)")
    console.print(Panel(
        "[dim]Launching interactive Kali Linux WSL session (wsl -d kali-linux)...\n"
        "Type [bold]exit[/bold] or press [bold]Ctrl+D[/bold] to return to RemotePC.[/dim]",
        border_style="magenta", box=PANEL_BOX
    ))
    _reset_idle_timer()
    try:
        subprocess.call(["wsl", "-d", "kali-linux"])
    except Exception as e:
        console.print(f"[{ERROR}]Failed to launch Kali Linux: {e}[/{ERROR}]")
        pause()


# ═══════════════════════════════════════════════════
# 20. MUSIC PLAYER
# ═══════════════════════════════════════════════════

_AUDIO_EXTS  = {".mp3", ".flac", ".wav", ".ogg", ".m4a", ".aac", ".wma", ".opus", ".aiff"}
_VLC_EXE     = r'C:\Program Files\VideoLAN\VLC\vlc.exe'
_MUSICBEE    = r'C:\Program Files (x86)\MusicBee\MusicBee.exe'

def _music_player_app():
    """Return the best available player executable."""
    if Path(_VLC_EXE).exists():
        return _VLC_EXE
    if Path(_MUSICBEE).exists():
        return _MUSICBEE
    return None

def _scan_music(folder: Path, query: str = "") -> list:
    """Recursively collect audio files, optionally filtered by query."""
    q = query.lower()
    results = []
    try:
        for root, _, files in os.walk(folder):
            for f in sorted(files):
                if Path(f).suffix.lower() in _AUDIO_EXTS:
                    if not q or q in f.lower():
                        results.append(Path(root) / f)
    except PermissionError:
        pass
    return results

def _play_track(path: Path, player: str) -> None:
    """Open a single track with the player on the interactive desktop."""
    launch_desktop_app(f'"{player}" "{path}"')

def music_player():
    print_header("♫  Music Player")
    player = _music_player_app()
    if not player:
        console.print(f"[{ERROR}]Neither VLC nor MusicBee found. Install one and try again.[/{ERROR}]")
        pause(); return

    console.print(
        f"  [{ACCENT}]Music folder:[/{ACCENT}] {_MUSIC_DIR}\n"
        f"  [{ACCENT}]Player:[/{ACCENT}]       {Path(player).name}\n"
    )
    console.print(
        "  [bold cyan]list[/bold cyan]             Show all tracks\n"
        "  [bold cyan]search <query>[/bold cyan]   Filter tracks by name\n"
        "  [bold cyan]play <n>[/bold cyan]         Play track number\n"
        "  [bold cyan]shuffle[/bold cyan]          Play all tracks shuffled in VLC\n"
        "  [bold cyan]queue[/bold cyan]            Queue all tracks in order in VLC\n"
        "  [bold cyan]stop[/bold cyan]             Stop / kill the player\n"
        "  [bold cyan]folder[/bold cyan]           Open Music folder in Explorer\n"
        "  [bold cyan]back[/bold cyan]             Return\n"
    )

    current_tracks: list = []
    last_query = ""

    while True:
        cmd   = Prompt.ask(f"[{ACCENT}]music[/{ACCENT}]").strip()
        if cmd.lower() in ("back", "exit", "q"): break
        parts = cmd.split(maxsplit=1)
        a     = parts[0].lower() if parts else ""

        if a in ("list", "search"):
            query = parts[1] if a == "search" and len(parts) > 1 else ""
            last_query = query
            current_tracks = _scan_music(_MUSIC_DIR, query)
            if not current_tracks:
                console.print(f"[{WARN}]No tracks found{f' matching "{query}"' if query else ''}.[/{WARN}]")
                continue
            t = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan",
                      show_edge=False, expand=True)
            t.add_column("#",    style=f"bold {ACCENT}", width=5, justify="right")
            t.add_column("Title",style="bold white")
            t.add_column("Ext",  style="dim", width=6)
            t.add_column("Size", style="dim", width=8, justify="right")
            for i, p in enumerate(current_tracks, 1):
                try:   sz = f"{p.stat().st_size/1024/1024:.1f}M"
                except: sz = "?"
                t.add_row(str(i), p.stem[:60], p.suffix, sz)
            console.print(t)
            console.print(f"  [{DIM}]{len(current_tracks)} track(s){f'  (filter: {query})' if query else ''}[/{DIM}]")

        elif a == "play":
            if not current_tracks:
                current_tracks = _scan_music(_MUSIC_DIR)
            if len(parts) < 2 or not parts[1].isdigit():
                console.print(f"[{ERROR}]Usage: play <n>[/{ERROR}]"); continue
            idx = int(parts[1]) - 1
            if not (0 <= idx < len(current_tracks)):
                console.print(f"[{ERROR}]Invalid track number.[/{ERROR}]"); continue
            track = current_tracks[idx]
            _play_track(track, player)
            console.print(f"[{SUCCESS}]▶  Playing: {track.name}[/{SUCCESS}]")

        elif a == "shuffle":
            tracks = _scan_music(_MUSIC_DIR)
            if not tracks:
                console.print(f"[{WARN}]No tracks found.[/{WARN}]")
                continue
            import random; random.shuffle(tracks)
            # Write a temp m3u playlist and open in VLC
            m3u = Path.home() / "AppData" / "Local" / "Temp" / "remotepc_shuffle.m3u"
            m3u.write_text(
                "#EXTM3U\n" + "\n".join(str(p) for p in tracks),
                encoding="utf-8"
            )
            launch_desktop_app(f'"{player}" "{m3u}"')
            console.print(f"[{SUCCESS}]▶  Shuffle playing {len(tracks)} tracks.[/{SUCCESS}]")

        elif a == "queue":
            tracks = _scan_music(_MUSIC_DIR)
            if not tracks:
                console.print(f"[{WARN}]No tracks found.[/{WARN}]")
                continue
            m3u = Path.home() / "AppData" / "Local" / "Temp" / "remotepc_queue.m3u"
            m3u.write_text(
                "#EXTM3U\n" + "\n".join(str(p) for p in tracks),
                encoding="utf-8"
            )
            launch_desktop_app(f'"{player}" "{m3u}"')
            console.print(f"[{SUCCESS}]▶  Queued {len(tracks)} tracks in order.[/{SUCCESS}]")

        elif a == "stop":
            stopped = False
            for proc_name in ("vlc.exe", "MusicBee.exe"):
                rc, _, _ = run_shell(f'taskkill /F /IM "{proc_name}" /T')
                if rc == 0:
                    console.print(f"[{SUCCESS}]\u23f9  Stopped {proc_name}.[/{SUCCESS}]")
                    stopped = True
            if not stopped:
                console.print(f"[{WARN}]No music player is currently running.[/{WARN}]")

        elif a == "folder":
            launch_desktop_app(f'explorer.exe "{_MUSIC_DIR}"')
            console.print(f"[{SUCCESS}]Opened Music folder.[/{SUCCESS}]")

        else:
            console.print(f"[{ERROR}]Unknown: {a}[/{ERROR}]")


# ═══════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════
# 21. DISPLAY CONTROL
# ═══════════════════════════════════════════════════════════════

_DISPLAY_PS_OFF = (
    "Add-Type -TypeDefinition "
    "'using System; using System.Runtime.InteropServices; "
    "public class W { "
    "[DllImport(\\\"user32.dll\\\")] public static extern IntPtr PostMessage(IntPtr h,uint m,IntPtr w,IntPtr l); }'; "
    "[W]::PostMessage([IntPtr](-1), 0x0112, [IntPtr]0xF170, [IntPtr]2)"
)

def display_control():
    print_header("\U0001f5a5  Display Control")
    console.print(
        "  [bold cyan]off[/bold cyan]                Turn monitor off\n"
        "  [bold cyan]on[/bold cyan]                 Wake monitor (mouse jiggle)\n"
        "  [bold cyan]brightness[/bold cyan]         Show current brightness\n"
        "  [bold cyan]brightness <0-100>[/bold cyan] Set brightness\n"
        "  [bold cyan]back[/bold cyan]               Return\n"
    )
    while True:
        cmd   = Prompt.ask(f"[{ACCENT}]display[/{ACCENT}]").strip()
        parts = cmd.split(maxsplit=1)
        a     = parts[0].lower() if parts else ""
        if a in ("back", "exit", "q"): break

        elif a == "off":
            launch_desktop_app(f'powershell -WindowStyle Hidden -NoProfile -Command "{_DISPLAY_PS_OFF}"')
            console.print(f"[{SUCCESS}]\U0001f4a4 Monitor off.[/{SUCCESS}]")

        elif a == "on":
            ps = (
                "Add-Type -TypeDefinition "
                "'using System; using System.Runtime.InteropServices; "
                "public class M { [DllImport(\\\"user32.dll\\\")] public static extern bool SetCursorPos(int x,int y); "
                "[DllImport(\\\"user32.dll\\\")] public static extern bool GetCursorPos(out System.Drawing.Point p); }'; "
                "$p=New-Object System.Drawing.Point; [M]::GetCursorPos([ref]$p) | Out-Null; "
                "[M]::SetCursorPos($p.X+1,$p.Y+1); Start-Sleep -Milliseconds 100; [M]::SetCursorPos($p.X,$p.Y)"
            )
            launch_desktop_app(f'powershell -WindowStyle Hidden -NoProfile -Command "{ps}"')
            console.print(f"[{SUCCESS}]\u2600  Monitor wake signal sent.[/{SUCCESS}]")

        elif a == "brightness":
            if len(parts) < 2:
                rc, out, _ = run_shell(
                    'powershell -NoProfile -Command '
                    '"(Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightness).CurrentBrightness"'
                )
                if rc == 0 and out.strip().isdigit():
                    lvl = int(out.strip())
                    console.print(f"  Brightness: [{ACCENT}]{lvl}%[/{ACCENT}]  {bar(lvl)}")
                else:
                    console.print(f"[{WARN}]Could not read brightness (may not be supported on external monitors).[/{WARN}]")
            else:
                try:
                    lvl = max(0, min(100, int(parts[1])))
                    ps = f"(Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightnessMethods).WmiSetBrightness(1,{lvl})"
                    rc, _, err = run_shell(f'powershell -NoProfile -Command "{ps}"')
                    if rc == 0:
                        console.print(f"[{SUCCESS}]Brightness set to {lvl}%.[/{SUCCESS}]")
                    else:
                        console.print(f"[{ERROR}]{err.strip() or 'Failed (external monitors not supported via WMI).'}[/{ERROR}]")
                except ValueError:
                    console.print(f"[{ERROR}]Usage: brightness <0-100>[/{ERROR}]")

        else:
            console.print(f"[{ERROR}]Unknown: {a}[/{ERROR}]")


# ═══════════════════════════════════════════════════════════════
# 22. FILE SEARCH
# ═══════════════════════════════════════════════════════════════

def file_search():
    print_header("\U0001f50d  File Search")
    console.print(
        "  [bold cyan]find <name>[/bold cyan]              Search by filename\n"
        "  [bold cyan]find <name> in <path>[/bold cyan]    Search in specific folder\n"
        "  [bold cyan]ext <.ext>[/bold cyan]               Find all files by extension\n"
        "  [bold cyan]open <n>[/bold cyan]                 Open result #n on desktop\n"
        "  [bold cyan]cd <n>[/bold cyan]                   Open containing folder in Explorer\n"
        "  [bold cyan]back[/bold cyan]                     Return\n"
    )
    _SEARCH_ROOTS = [str(Path.home())]
    for _extra in (_CONFIG.get("search_roots", []) or []):
        if isinstance(_extra, str) and _extra.strip() and Path(_extra).exists() and _extra not in _SEARCH_ROOTS:
            _SEARCH_ROOTS.append(_extra)
    _SKIP_DIRS = {"$Recycle.Bin", "Windows", "System32", "__pycache__", "node_modules", ".git", ".thumbnails"}
    last_results: list = []

    def _do_search(roots, match_fn, cap=200):
        results = []
        for root in roots:
            try:
                for dirpath, dirs, files in os.walk(root):
                    dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]
                    for f in files:
                        if match_fn(f):
                            results.append(Path(dirpath) / f)
                        if len(results) >= cap:
                            return results
            except PermissionError:
                pass
        return results

    def _show_results(results):
        t = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", show_edge=False, expand=True)
        t.add_column("#",    style=f"bold {ACCENT}", width=5,  justify="right")
        t.add_column("Name", style="bold white",     min_width=20)
        t.add_column("Path", style="dim")
        for i, p in enumerate(results, 1):
            t.add_row(str(i), p.name, str(p.parent))
        console.print(t)
        capped = " (capped at 200)" if len(results) == 200 else ""
        console.print(f"  [{DIM}]{len(results)} result(s){capped}[/{DIM}]")

    while True:
        cmd   = Prompt.ask(f"[{ACCENT}]search[/{ACCENT}]").strip()
        parts = cmd.split()
        a     = parts[0].lower() if parts else ""
        if a in ("back", "exit", "q"): break

        elif a == "find":
            if len(parts) < 2:
                console.print(f"[{ERROR}]Usage: find <name> [in <path>][/{ERROR}]"); continue
            raw = " ".join(parts[1:])
            if " in " in raw:
                name_part, path_part = raw.split(" in ", 1)
                roots = [path_part.strip()]
            else:
                name_part = raw.strip()
                roots = _SEARCH_ROOTS
            q = name_part.lower()
            console.print(f"[dim]Searching for '{q}'...[/dim]")
            last_results = _do_search(roots, lambda f: q in f.lower())
            if not last_results:
                console.print(f"[{WARN}]No files found matching '{q}'.[/{WARN}]")
            else:
                _show_results(last_results)

        elif a == "ext":
            if len(parts) < 2:
                console.print(f"[{ERROR}]Usage: ext <.extension>[/{ERROR}]"); continue
            ext = parts[1] if parts[1].startswith(".") else "." + parts[1]
            console.print(f"[dim]Searching for *{ext}...[/dim]")
            last_results = _do_search(_SEARCH_ROOTS, lambda f: f.lower().endswith(ext.lower()))
            if not last_results:
                console.print(f"[{WARN}]No *{ext} files found.[/{WARN}]")
            else:
                _show_results(last_results)

        elif a == "open":
            if not last_results:
                console.print(f"[{WARN}]No search results yet. Run find or ext first.[/{WARN}]"); continue
            if len(parts) < 2 or not parts[1].isdigit():
                console.print(f"[{ERROR}]Usage: open <n>[/{ERROR}]"); continue
            idx = int(parts[1]) - 1
            if not (0 <= idx < len(last_results)):
                console.print(f"[{ERROR}]Invalid number.[/{ERROR}]"); continue
            target = last_results[idx]
            launch_desktop_app(f'"{target}"')
            console.print(f"[{SUCCESS}]Opening {target.name} on desktop.[/{SUCCESS}]")

        elif a == "cd":
            if not last_results:
                console.print(f"[{WARN}]No search results yet.[/{WARN}]"); continue
            if len(parts) < 2 or not parts[1].isdigit():
                console.print(f"[{ERROR}]Usage: cd <n>[/{ERROR}]"); continue
            idx = int(parts[1]) - 1
            if not (0 <= idx < len(last_results)):
                console.print(f"[{ERROR}]Invalid number.[/{ERROR}]"); continue
            launch_desktop_app(f'explorer.exe "{last_results[idx].parent}"')
            console.print(f"[{SUCCESS}]Opened {last_results[idx].parent} in Explorer.[/{SUCCESS}]")

        else:
            console.print(f"[{ERROR}]Unknown: {a}[/{ERROR}]")


# ═══════════════════════════════════════════════════════════════
# 23. WINDOW & BROWSER CONTROL
# ═══════════════════════════════════════════════════════════════

_USER32 = ctypes.windll.user32
_DWMAPI = ctypes.windll.dwmapi
_WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

def _attach_desktop():
    """Ensure the calling thread is attached to the interactive WinSta0\\Default desktop."""
    try:
        hwinsta = _USER32.OpenWindowStationW('WinSta0', False, 0x037F)
        if hwinsta:
            _USER32.SetProcessWindowStation(hwinsta)
        hdesk = _USER32.OpenDesktopW('Default', 0, False, 0x01FF)
        if hdesk:
            _USER32.SetThreadDesktop(hdesk)
            return hdesk
    except Exception:
        pass
    return None

def get_foreground_window_info() -> dict:
    """Return detailed information about the current foreground/active window."""
    _attach_desktop()
    fg_hwnd = _USER32.GetForegroundWindow()
    if not fg_hwnd:
        return {"hwnd": 0, "title": "", "pid": 0, "pname": "desktop", "desc": "(Desktop / None)"}

    length = _USER32.GetWindowTextLengthW(fg_hwnd)
    title = ""
    if length > 0:
        buf = ctypes.create_unicode_buffer(length + 1)
        _USER32.GetWindowTextW(fg_hwnd, buf, length + 1)
        title = buf.value.strip()

    pid = wintypes.DWORD()
    _USER32.GetWindowThreadProcessId(fg_hwnd, ctypes.byref(pid))
    pname = "unknown"
    if pid.value:
        try:
            pname = psutil.Process(pid.value).name()
        except Exception:
            pass

    if not title and fg_hwnd:
        root_hwnd = _USER32.GetAncestor(fg_hwnd, 2)  # GA_ROOT
        if root_hwnd and root_hwnd != fg_hwnd:
            r_len = _USER32.GetWindowTextLengthW(root_hwnd)
            if r_len > 0:
                rbuf = ctypes.create_unicode_buffer(r_len + 1)
                _USER32.GetWindowTextW(root_hwnd, rbuf, r_len + 1)
                title = rbuf.value.strip()

    rect = (ctypes.c_long * 4)()
    _USER32.GetWindowRect(fg_hwnd, rect)
    w = rect[2] - rect[0]
    h = rect[3] - rect[1]

    desc = f"[{fg_hwnd}] {pname} (PID {pid.value})"
    if title:
        desc += f' - "{title}"'
    else:
        desc += ' - "(no title)"'
    if w > 0 and h > 0:
        desc += f" ({w}x{h})"

    return {
        "hwnd": fg_hwnd,
        "title": title,
        "pid": pid.value,
        "pname": pname,
        "width": w,
        "height": h,
        "desc": desc
    }

def _get_windows_via_session_bridge() -> list:
    """
    Fallback for get_visible_windows() when running in an isolated session (e.g. SSH).
    Executes an enumeration helper through the interactive scheduled task (Session 1).
    """
    try:
        dump_script = Path.home() / "AppData" / "Local" / "Temp" / "remotepc_dump_wins.py"
        out_json = Path.home() / "AppData" / "Local" / "Temp" / "remotepc_wins_out.json"

        if out_json.exists():
            try:
                out_json.unlink()
            except Exception:
                pass

        dump_code = (
            'import ctypes, json, psutil\n'
            'from ctypes import wintypes\n'
            'from pathlib import Path\n'
            'u = ctypes.windll.user32\n'
            'd = ctypes.windll.dwmapi\n'
            'W = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)\n'
            'hw = u.OpenWindowStationW("WinSta0", False, 0x037F)\n'
            'if hw: u.SetProcessWindowStation(hw)\n'
            'hd = u.OpenDesktopW("Default", 0, False, 0x01FF)\n'
            'if hd: u.SetThreadDesktop(hd)\n'
            'fg = u.GetForegroundWindow()\n'
            'wins = []\n'
            'def cb(h, _):\n'
            '    if not u.IsWindow(h): return True\n'
            '    vis = bool(u.IsWindowVisible(h))\n'
            '    ico = bool(u.IsIconic(h))\n'
            '    if not (vis or ico): return True\n'
            '    ln = u.GetWindowTextLengthW(h)\n'
            '    if ln <= 0: return True\n'
            '    b = ctypes.create_unicode_buffer(ln + 1)\n'
            '    u.GetWindowTextW(h, b, ln + 1)\n'
            '    t = b.value.strip()\n'
            '    if not t or t in ("Program Manager", "Default IME", "MSCTFIME UI", "Windows Input Experience", "CiceroUIWndFrame", "DWM Notification Window"): return True\n'
            '    c = wintypes.DWORD()\n'
            '    d.DwmGetWindowAttribute(h, 14, ctypes.byref(c), 4)\n'
            '    if c.value != 0: return True\n'
            '    ex = u.GetWindowLongW(h, -20)\n'
            '    if (ex & 0x80) and not (ex & 0x40000): return True\n'
            '    r = (ctypes.c_long * 4)()\n'
            '    u.GetWindowRect(h, r)\n'
            '    w, ht = r[2] - r[0], r[3] - r[1]\n'
            '    if not ico and (w <= 10 or ht <= 10): return True\n'
            '    p = wintypes.DWORD()\n'
            '    u.GetWindowThreadProcessId(h, ctypes.byref(p))\n'
            '    pn = "unknown"\n'
            '    try: pn = psutil.Process(p.value).name()\n'
            '    except Exception: pass\n'
            '    if pn.lower() == "dwm.exe": return True\n'
            '    st = "active" if h == fg else ("minimized" if ico else "normal")\n'
            '    wins.append({"hwnd": h, "title": t, "pid": p.value, "pname": pn, "state": st, "is_minimized": ico, "is_active": (h == fg), "width": w, "height": ht})\n'
            '    return True\n'
            'u.EnumWindows(W(cb), 0)\n'
            f'Path(r"{str(out_json)}").write_text(json.dumps(wins), encoding="utf-8")\n'
        )

        dump_script.write_text(dump_code, encoding="utf-8")
        if _ensure_gui_launcher_task():
            lines = ["@echo off", f'python "{dump_script}"', "exit /b 0"]
            _GUI_LAUNCHER_CMD.write_text("\r\n".join(lines) + "\r\n", encoding="utf-8")
            rc, _, _ = run_shell(f'schtasks /run /tn "{_GUI_TASK_NAME}"')
            if rc == 0:
                for _ in range(25):
                    time.sleep(0.08)
                    if out_json.exists():
                        break
                if out_json.exists():
                    return json.loads(out_json.read_text(encoding="utf-8"))
    except Exception:
        pass
    return []

def _get_windows_via_powershell() -> list:
    """
    PowerShell fallback for get_visible_windows().
    Queries processes with a MainWindowTitle and formats them.
    """
    ps = (
        "Get-Process "
        "| Where-Object {$_.MainWindowTitle -ne ''} "
        "| Select-Object Id,ProcessName,MainWindowTitle,MainWindowHandle "
        "| ConvertTo-Json -Depth 2"
    )
    rc, out, _ = run_shell(f'powershell -NoProfile -NonInteractive -Command "{ps}"')
    if rc != 0 or not out.strip():
        return []
    try:
        data = json.loads(out.strip())
        if isinstance(data, dict):
            data = [data]
        windows = []
        _SKIP_TITLES = {"Program Manager", "Default IME", "MSCTFIME UI", "Windows Input Experience", ""}
        for d in data:
            title = (d.get("MainWindowTitle") or "").strip()
            pid = int(d.get("Id") or 0)
            pname = (d.get("ProcessName") or "unknown") + ".exe"
            handle = int(d.get("MainWindowHandle") or 0)
            if title and title not in _SKIP_TITLES:
                windows.append({
                    "hwnd": handle,
                    "title": title,
                    "pid": pid,
                    "pname": pname,
                    "state": "normal",
                    "is_minimized": False,
                    "is_active": False,
                    "width": 800,
                    "height": 600,
                })
        return windows
    except Exception:
        return []

def get_visible_windows():
    """
    Return a list of visible application windows with HWND, PID, process name, title, state, and size.
    Primary method: Win32 EnumWindows with DWM cloaked & tool-window filtering.
    Fallback:       Interactive Scheduled Task session bridge (for isolated SSH / Session 0).
    """
    _attach_desktop()
    windows = []
    fg_info = get_foreground_window_info()
    fg_hwnd = fg_info["hwnd"]

    DWMWA_CLOAKED = 14
    GWL_EXSTYLE = -20
    WS_EX_TOOLWINDOW = 0x00000080
    WS_EX_APPWINDOW = 0x00040000

    def cb(hwnd, extra):
        if not _USER32.IsWindow(hwnd):
            return True
        is_visible = bool(_USER32.IsWindowVisible(hwnd))
        is_iconic = bool(_USER32.IsIconic(hwnd))
        if not (is_visible or is_iconic):
            return True

        length = _USER32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return True

        buff = ctypes.create_unicode_buffer(length + 1)
        _USER32.GetWindowTextW(hwnd, buff, length + 1)
        title = buff.value.strip()
        if not title:
            return True

        _SKIP_TITLES = (
            "Program Manager", "Default IME", "MSCTFIME UI",
            "Windows Input Experience", "CiceroUIWndFrame",
            "DWM Notification Window"
        )
        if title in _SKIP_TITLES:
            return True

        cloaked = wintypes.DWORD()
        _DWMAPI.DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED, ctypes.byref(cloaked), ctypes.sizeof(cloaked))
        if cloaked.value != 0:
            return True

        exstyle = _USER32.GetWindowLongW(hwnd, GWL_EXSTYLE)
        if (exstyle & WS_EX_TOOLWINDOW) and not (exstyle & WS_EX_APPWINDOW):
            return True

        rect = (ctypes.c_long * 4)()
        _USER32.GetWindowRect(hwnd, rect)
        w = rect[2] - rect[0]
        h = rect[3] - rect[1]

        if not is_iconic and (w <= 10 or h <= 10):
            return True

        pid = wintypes.DWORD()
        _USER32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        pname = "unknown"
        try:
            pname = psutil.Process(pid.value).name()
        except Exception:
            pass

        if pname.lower() == "dwm.exe":
            return True

        state = "active" if hwnd == fg_hwnd else ("minimized" if is_iconic else "normal")

        windows.append({
            "hwnd": hwnd,
            "title": title,
            "pid": pid.value,
            "pname": pname,
            "state": state,
            "is_minimized": is_iconic,
            "is_active": (hwnd == fg_hwnd),
            "width": w,
            "height": h
        })
        return True

    _USER32.EnumWindows(_WNDENUMPROC(cb), 0)

    # ── Session 0 / SSH fallback ─────────────────────────────────────────────
    # EnumWindows returns 0 results when running under an isolated session (SSH)
    # because it cannot see windows in the interactive user desktop station.
    # Fall back to interactive scheduled task bridge, then PowerShell.
    if not windows:
        windows = _get_windows_via_session_bridge()
    if not windows:
        windows = _get_windows_via_powershell()

    state_order = {"active": 0, "normal": 1, "minimized": 2}
    windows.sort(key=lambda x: state_order.get(x.get("state", "normal"), 1))
    return windows

def find_window(query: str):
    """Find a window by HWND, PID, process name, or title."""
    windows = get_visible_windows()
    q = str(query).lower().strip()
    try:
        val = int(q)
        for w in windows:
            if w["hwnd"] == val or w["pid"] == val:
                return w
    except ValueError:
        pass
    for w in windows:
        if q == w["pname"].lower() or q in w["title"].lower() or q in w["pname"].lower():
            return w
    return None

def _win32_via_ps(hwnd: int, pid: int, action: str) -> None:
    """
    Execute a window action via PowerShell through the session bridge.
    Used when user32 calls from SSH Session 0 are silently ignored cross-session.
    action: 'restore'|'minimize'|'maximize'|'close'|'focus'
    """
    ps_map = {
        "restore":  f"(New-Object -ComObject WScript.Shell).AppActivate({pid}) | Out-Null; "
                    f"[void][System.Runtime.InteropServices.Marshal]::GetLastWin32Error(); "
                    f"Add-Type -Name W -Namespace P -MemberDefinition '[DllImport(\"user32\")] public static extern bool ShowWindow(IntPtr h, int c);'; "
                    f"[P.W]::ShowWindow({hwnd}, 9)",
        "minimize":  f"Add-Type -Name W -Namespace P -MemberDefinition '[DllImport(\"user32\")] public static extern bool ShowWindow(IntPtr h, int c);'; "
                     f"[P.W]::ShowWindow({hwnd}, 6)",
        "maximize":  f"Add-Type -Name W -Namespace P -MemberDefinition '[DllImport(\"user32\")] public static extern bool ShowWindow(IntPtr h, int c);[DllImport(\"user32\")] public static extern bool SetForegroundWindow(IntPtr h);'; "
                     f"[P.W]::ShowWindow({hwnd}, 3); [P.W]::SetForegroundWindow({hwnd})",
        "close":     f"Add-Type -Name W -Namespace P -MemberDefinition '[DllImport(\"user32\")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);'; "
                     f"[P.W]::PostMessage({hwnd}, 0x0010, 0, 0)",
        "focus":     f"(New-Object -ComObject WScript.Shell).AppActivate({pid}) | Out-Null; "
                     f"Add-Type -Name W -Namespace P -MemberDefinition '[DllImport(\"user32\")] public static extern bool ShowWindow(IntPtr h, int c);[DllImport(\"user32\")] public static extern bool SetForegroundWindow(IntPtr h);[DllImport(\"user32\")] public static extern bool BringWindowToTop(IntPtr h);'; "
                     f"[P.W]::ShowWindow({hwnd}, 9); [P.W]::SetForegroundWindow({hwnd}); [P.W]::BringWindowToTop({hwnd})",
    }
    ps_cmd = ps_map.get(action, "")
    if not ps_cmd:
        return
    tmp = Path.home() / "AppData" / "Local" / "Temp" / "remotepc_win32.ps1"
    tmp.write_text(ps_cmd, encoding="utf-8")
    launch_desktop_app(f'powershell -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File "{tmp}"')

def focus_window(query: str):
    w = find_window(query)
    if not w:
        return False, f"Window matching '{query}' not found."
    hwnd = w["hwnd"]
    # Try direct user32 first (works if already in Session 1 / local run)
    _USER32.ShowWindow(hwnd, 9)
    _USER32.SetForegroundWindow(hwnd)
    _USER32.BringWindowToTop(hwnd)
    # Always also send via session bridge — cross-session Win32 calls are silently ignored
    _win32_via_ps(hwnd, w["pid"], "focus")
    return True, f"Focused '{w['title']}' ({w['pname']}, PID {w['pid']})."

def minimize_window(query: str):
    w = find_window(query)
    if not w:
        return False, f"Window matching '{query}' not found."
    _USER32.ShowWindow(w["hwnd"], 6)
    _win32_via_ps(w["hwnd"], w["pid"], "minimize")
    return True, f"Minimized '{w['title']}'."

def maximize_window(query: str):
    w = find_window(query)
    if not w:
        return False, f"Window matching '{query}' not found."
    _USER32.ShowWindow(w["hwnd"], 3)
    _USER32.SetForegroundWindow(w["hwnd"])
    _win32_via_ps(w["hwnd"], w["pid"], "maximize")
    return True, f"Maximized '{w['title']}'."

def restore_window(query: str):
    w = find_window(query)
    if not w:
        return False, f"Window matching '{query}' not found."
    _USER32.ShowWindow(w["hwnd"], 9)
    _USER32.SetForegroundWindow(w["hwnd"])
    _win32_via_ps(w["hwnd"], w["pid"], "restore")
    return True, f"Restored '{w['title']}'."

def close_window(query: str):
    w = find_window(query)
    if not w:
        return False, f"Window matching '{query}' not found."
    _USER32.PostMessageW(w["hwnd"], 0x0010, 0, 0)  # WM_CLOSE (may be ignored cross-session)
    _win32_via_ps(w["hwnd"], w["pid"], "close")
    return True, f"Closed '{w['title']}'."


def send_keys_desktop(keys: str, query: str = None) -> str:
    """Send keystrokes via WScript.Shell to the specified or active window."""
    target_pid = None
    target_title = None
    if query:
        w = find_window(query)
        if not w:
            return f"Window matching '{query}' not found."
        target_pid = w["pid"]
        target_title = w["title"] or w["pname"]
        focus_window(query)
        time.sleep(0.08)

    safe_keys = keys.replace("'", "''")
    ps_file = Path.home() / "AppData" / "Local" / "Temp" / "remotepc_keys.ps1"
    activate_line = f"$act = $ws.AppActivate({target_pid})" if target_pid else ""
    ps_content = f"""\
$ws = New-Object -ComObject WScript.Shell
{activate_line}
Start-Sleep -Milliseconds 100
$ws.SendKeys('{safe_keys}')
"""
    try:
        ps_file.write_text(ps_content, encoding="utf-8")
        if _ensure_gui_launcher_task():
            cmd_file = _GUI_LAUNCHER_CMD
            cmd_file.write_text(f'@echo off\r\npowershell -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File "{str(ps_file)}"\r\nexit /b 0\r\n', encoding="utf-8")
            rc, _, _ = run_shell(f'schtasks /run /tn "{_GUI_TASK_NAME}"')
            if rc == 0:
                t_str = f" to '{target_title}'" if target_title else ""
                return f"Sent keys '{keys}'{t_str}."
    except Exception:
        pass

    try:
        ps_encoded = base64.b64encode(ps_content.encode("utf-16le")).decode("ascii")
        run_shell(f'powershell -NoProfile -NonInteractive -EncodedCommand {ps_encoded}')
    except Exception:
        pass

    t_str = f" to '{target_title}'" if target_title else ""
    return f"Sent keys '{keys}'{t_str}."

def browser_nav_action(action: str, arg: str = "") -> str:
    """Perform common browser navigation actions (tabs, scrolling, history)."""
    # Broaden browser fingerprint: pname OR title keyword match, case-insensitive
    _BROWSER_NAMES = {
        "chrome", "msedge", "edge", "firefox", "brave",
        "opera", "vivaldi", "chromium", "browser"
    }
    target_browser = None
    for w in get_visible_windows():
        pname_lc = w["pname"].lower().replace(".exe", "")
        title_lc = w["title"].lower()
        if any(b in pname_lc or b in title_lc for b in _BROWSER_NAMES):
            target_browser = w
            break

    if action == "new_tab":
        if arg:
            url = arg if arg.startswith("http://") or arg.startswith("https://") else "https://" + arg
            launch_desktop_app(f'"{url}"')
            return f"Opened {url} in browser."
        if not target_browser:
            launch_desktop_app("start https://www.google.com")
            return "Launched browser with new tab."
        return send_keys_desktop("^t", query=str(target_browser["pid"]))

    if not target_browser:
        return (
            "No open browser window found. "
            "Open a browser first with: ACTION: launch chrome   or   ACTION: open_url https://example.com"
        )

    b_pid   = str(target_browser["pid"])
    b_title = target_browser["title"][:40]
    if action == "close_tab":
        return send_keys_desktop("^w", query=b_pid)
    elif action == "next_tab":
        return send_keys_desktop("^{TAB}", query=b_pid)
    elif action == "prev_tab":
        return send_keys_desktop("^+{TAB}", query=b_pid)
    elif action == "refresh":
        return send_keys_desktop("{F5}", query=b_pid)
    elif action == "scroll_down":
        return send_keys_desktop("{PGDN}", query=b_pid)
    elif action == "scroll_up":
        return send_keys_desktop("{PGUP}", query=b_pid)
    elif action == "back":
        return send_keys_desktop("%{LEFT}", query=b_pid)
    elif action == "forward":
        return send_keys_desktop("%{RIGHT}", query=b_pid)
    return f"Unknown browser action: {action}"

class _DOMExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title = ""
        self.meta_desc = ""
        self.headings = []
        self.links = []
        self.inputs = []
        self.text_parts = []
        self._in_title = False
        self._in_heading = False
        self._current_heading_text = ""
        self._ignore_tags = {"script", "style", "noscript", "svg", "path", "head"}
        self._tag_stack = []

    def handle_starttag(self, tag, attrs):
        self._tag_stack.append(tag)
        attrs_dict = dict(attrs)
        if tag == "title":
            self._in_title = True
        elif tag in ("h1", "h2", "h3"):
            self._in_heading = True
            self._current_heading_text = ""
        elif tag == "meta":
            name = attrs_dict.get("name", "").lower()
            prop = attrs_dict.get("property", "").lower()
            if name == "description" or prop == "og:description":
                self.meta_desc = attrs_dict.get("content", "")
        elif tag == "a" and "href" in attrs_dict:
            href = attrs_dict["href"]
            self.links.append((href, ""))
        elif tag in ("input", "button", "textarea", "select"):
            itype = attrs_dict.get("type", tag)
            name = attrs_dict.get("name", "") or attrs_dict.get("id", "") or attrs_dict.get("placeholder", "")
            val = attrs_dict.get("value", "")
            self.inputs.append(f"<{tag} type='{itype}' name='{name}' value='{val}'>")

    def handle_endtag(self, tag):
        if self._tag_stack and self._tag_stack[-1] == tag:
            self._tag_stack.pop()
        if tag == "title":
            self._in_title = False
        elif tag in ("h1", "h2", "h3"):
            self._in_heading = False
            if self._current_heading_text.strip():
                self.headings.append((tag.upper(), self._current_heading_text.strip()))
        elif tag in ("p", "div", "section", "article", "li", "br"):
            self.text_parts.append("\n")

    def handle_data(self, data):
        if any(t in self._ignore_tags for t in self._tag_stack):
            return
        cleaned = data.strip()
        if not cleaned:
            return
        if self._in_title:
            self.title += " " + cleaned
        elif self._in_heading:
            self._current_heading_text += " " + cleaned
        else:
            self.text_parts.append(cleaned + " ")
            if self.links and not self.links[-1][1]:
                self.links[-1] = (self.links[-1][0], cleaned)

def fetch_dom_summary(url: str, max_chars: int = 1800) -> str:
    """Fetch webpage HTML, parse DOM structure, extract title, headings, readable text, links, forms."""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
    )
    with urllib.request.urlopen(req, timeout=8) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        html = response.read().decode(charset, errors="replace")

    parser = _DOMExtractor()
    parser.feed(html)

    out = []
    if parser.title.strip():
        out.append(f"Title: {parser.title.strip()}")
    if parser.meta_desc.strip():
        out.append(f"Description: {parser.meta_desc.strip()}")
    if parser.headings:
        out.append("\nHeadings:")
        for lvl, h in parser.headings[:8]:
            out.append(f"  {lvl}: {h}")

    body_text = re.sub(r"\n{3,}", "\n\n", "".join(parser.text_parts)).strip()
    if body_text:
        out.append(f"\nContent:\n{body_text[:max_chars]}")
        if len(body_text) > max_chars:
            out.append("... [truncated]")

    if parser.links:
        valid_links = [f"  - {t or '(link)'}: {h}" for h, t in parser.links if h.startswith("http")][:8]
        if valid_links:
            out.append("\nTop Links:\n" + "\n".join(valid_links))

    if parser.inputs:
        out.append("\nForm Elements:\n  " + ", ".join(parser.inputs[:6]))

    return "\n".join(out)

def fetch_dom_links(url: str) -> str:
    """Extract all hyperlinks from a webpage DOM."""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    with urllib.request.urlopen(req, timeout=8) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        html = response.read().decode(charset, errors="replace")
    parser = _DOMExtractor()
    parser.feed(html)
    links = [f"  - {t.strip() or 'Link'} -> {h}" for h, t in parser.links if h.strip()]
    return "\n".join(links[:25]) if links else "No links found."

def fetch_dom_forms(url: str) -> str:
    """Extract form elements (inputs, buttons) from a webpage DOM."""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    with urllib.request.urlopen(req, timeout=8) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        html = response.read().decode(charset, errors="replace")
    parser = _DOMExtractor()
    parser.feed(html)
    return "\n".join(f"  {inp}" for inp in parser.inputs[:30]) if parser.inputs else "No form elements found."

def cdp_launch_browser(url: str = "https://www.google.com") -> str:
    """Launch Chrome or Edge with --remote-debugging-port=9222 for live DOM automation."""
    chrome_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expanduser(r"~\AppData\Local\Google\Chrome\Application\chrome.exe"),
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ]
    browser = next((p for p in chrome_paths if os.path.exists(p)), None)
    if not browser:
        return "Chrome or Edge executable not found."
    debug_dir = Path.home() / "AppData" / "Local" / "Temp" / "remotepc_cdp_profile"
    debug_dir.mkdir(parents=True, exist_ok=True)
    target_url = url if url.startswith("http://") or url.startswith("https://") else "https://" + url
    cmd = f'"{browser}" --remote-debugging-port=9222 --user-data-dir="{debug_dir}" "{target_url}"'
    launch_desktop_app(cmd)
    return f"Launched {Path(browser).stem} with CDP debug port 9222 ({target_url})."

def cdp_status(port: int = 9222) -> str:
    """Check CDP status and list open browser tabs."""
    try:
        req = urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=2)
        tabs = json.loads(req.read().decode("utf-8"))
        pages = [t for t in tabs if t.get("type") == "page"]
        if not pages:
            return "CDP active on port 9222, but no open web pages found."
        out = [f"CDP Active ({len(pages)} open tab{'s' if len(pages)>1 else ''}):"]
        for i, p in enumerate(pages[:10]):
            out.append(f"  {i+1}. {p.get('title','Untitled')} ({p.get('url','')})")
        return "\n".join(out)
    except Exception:
        return "CDP port 9222 not active. Use 'browser_debug_launch' to start Chrome/Edge with debug support."

def cdp_eval_js(expr: str, port: int = 9222) -> str:
    """Evaluate JavaScript inside the active browser DOM over CDP."""
    try:
        import asyncio, websockets
        req = urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=2)
        tabs = json.loads(req.read().decode("utf-8"))
        pages = [t for t in tabs if t.get("type") == "page"]
        if not pages:
            return "No active browser tabs found on port 9222."
        ws_url = pages[0].get("webSocketDebuggerUrl")
        if not ws_url:
            return "Active tab does not provide WebSocket debugger URL."

        async def _run():
            async with websockets.connect(ws_url, close_timeout=2) as ws:
                payload = {
                    "id": 1,
                    "method": "Runtime.evaluate",
                    "params": {
                        "expression": expr,
                        "returnByValue": True,
                        "awaitPromise": True
                    }
                }
                await ws.send(json.dumps(payload))
                resp = await asyncio.wait_for(ws.recv(), timeout=6)
                data = json.loads(resp)
                if "error" in data:
                    return f"CDP Error: {data['error'].get('message')}"
                res = data.get("result", {}).get("result", {})
                if "value" in res:
                    return str(res["value"])
                return str(res.get("description", res))

        return asyncio.run(_run())
    except Exception as e:
        return f"CDP eval failed: {e} (Ensure browser was launched via browser_debug_launch)."

def window_browser_manager():
    """Interactive TUI menu for window and browser control."""
    print_header("🗔  Window & Browser Control")
    console.print(
        "  [bold cyan]list[/bold cyan]                   List open desktop windows\n"
        "  [bold cyan]focus <name|pid>[/bold cyan]       Bring window to front\n"
        "  [bold cyan]min <name|pid>[/bold cyan]         Minimize window\n"
        "  [bold cyan]max <name|pid>[/bold cyan]         Maximize window\n"
        "  [bold cyan]restore <name|pid>[/bold cyan]     Restore window\n"
        "  [bold cyan]close <name|pid>[/bold cyan]       Close window\n"
        "  [bold cyan]keys <keys>[/bold cyan]            Send keystrokes to active window\n"
        "  [bold cyan]dom <url>[/bold cyan]              Fetch & inspect webpage DOM\n"
        "  [bold cyan]cdp launch [url][/bold cyan]     Launch Chrome/Edge in live CDP debug mode\n"
        "  [bold cyan]cdp status[/bold cyan]            Check CDP live browser connection\n"
        "  [bold cyan]cdp eval <js>[/bold cyan]         Evaluate JavaScript in active browser tab\n"
        "  [bold cyan]back[/bold cyan]                   Return to Main Menu\n"
    )
    while True:
        try:
            cmd = Prompt.ask(f"[{ACCENT}]win[/{ACCENT}]").strip()
        except KeyboardInterrupt:
            break
        if not cmd:
            continue
        parts = cmd.split(maxsplit=1)
        a = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if a in ("back", "exit", "q"):
            break
        elif a == "list":
            wins = get_visible_windows()
            if not wins:
                console.print(f"[{WARN}]No visible desktop windows found.[/{WARN}]")
            else:
                t = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", show_edge=False, expand=True)
                t.add_column("HWND", style="dim", width=10)
                t.add_column("Process", style="green", width=22)
                t.add_column("PID", style="yellow", width=8)
                t.add_column("Size", style="magenta", width=12)
                t.add_column("Window Title", style="bold white")
                for w in wins:
                    t.add_row(str(w["hwnd"]), w["pname"], str(w["pid"]), f"{w['width']}x{w['height']}", w["title"][:50])
                console.print(t)
            pause()
        elif a == "focus":
            if not arg: console.print(f"[{ERROR}]Usage: focus <name|pid>[/{ERROR}]"); continue
            ok, msg = focus_window(arg)
            console.print(f"[{SUCCESS if ok else ERROR}]{msg}[/{SUCCESS if ok else ERROR}]")
            time.sleep(0.6)
        elif a in ("min", "minimize"):
            if not arg: console.print(f"[{ERROR}]Usage: min <name|pid>[/{ERROR}]"); continue
            ok, msg = minimize_window(arg)
            console.print(f"[{SUCCESS if ok else ERROR}]{msg}[/{SUCCESS if ok else ERROR}]")
            time.sleep(0.6)
        elif a in ("max", "maximize"):
            if not arg: console.print(f"[{ERROR}]Usage: max <name|pid>[/{ERROR}]"); continue
            ok, msg = maximize_window(arg)
            console.print(f"[{SUCCESS if ok else ERROR}]{msg}[/{SUCCESS if ok else ERROR}]")
            time.sleep(0.6)
        elif a == "restore":
            if not arg: console.print(f"[{ERROR}]Usage: restore <name|pid>[/{ERROR}]"); continue
            ok, msg = restore_window(arg)
            console.print(f"[{SUCCESS if ok else ERROR}]{msg}[/{SUCCESS if ok else ERROR}]")
            time.sleep(0.6)
        elif a == "close":
            if not arg: console.print(f"[{ERROR}]Usage: close <name|pid>[/{ERROR}]"); continue
            ok, msg = close_window(arg)
            console.print(f"[{SUCCESS if ok else ERROR}]{msg}[/{SUCCESS if ok else ERROR}]")
            time.sleep(0.6)
        elif a == "keys":
            if not arg: console.print(f"[{ERROR}]Usage: keys <keys>[/{ERROR}]"); continue
            msg = send_keys_desktop(arg)
            console.print(f"[{SUCCESS}]{msg}[/{SUCCESS}]")
            time.sleep(0.6)
        elif a == "dom":
            if not arg: console.print(f"[{ERROR}]Usage: dom <url>[/{ERROR}]"); continue
            try:
                res = fetch_dom_summary(arg)
                console.print(Panel(res, title=f"DOM Summary: {arg}", border_style="cyan", box=PANEL_BOX))
            except Exception as e:
                console.print(f"[{ERROR}]Failed to fetch DOM: {e}[/{ERROR}]")
            pause()
        elif a == "cdp":
            cdp_parts = arg.split(maxsplit=1)
            sub = cdp_parts[0].lower() if cdp_parts else ""
            sub_arg = cdp_parts[1] if len(cdp_parts) > 1 else ""
            if sub == "launch":
                msg = cdp_launch_browser(sub_arg or "https://www.google.com")
                console.print(f"[{SUCCESS}]{msg}[/{SUCCESS}]")
            elif sub == "status":
                msg = cdp_status()
                console.print(Panel(msg, border_style="cyan", box=PANEL_BOX))
            elif sub == "eval":
                if not sub_arg: console.print(f"[{ERROR}]Usage: cdp eval <javascript>[/{ERROR}]"); continue
                msg = cdp_eval_js(sub_arg)
                console.print(Panel(msg, title=f"CDP Result: {sub_arg[:40]}", border_style="green", box=PANEL_BOX))
            else:
                console.print(f"[{ERROR}]Usage: cdp <launch|status|eval>[/{ERROR}]")
            pause()
        else:
            console.print(f"[{ERROR}]Unknown command: {a}[/{ERROR}]")
            time.sleep(0.6)


# ═══════════════════════════════════════════════════════════════
# 24. AI AGENT (Gemini)
# ═══════════════════════════════════════════════════════════════

# All AI credentials and models come from the external config (or env vars).
# No key or model identifier is ever hard-coded in the source.
_GEMINI_API_KEY = (
    os.environ.get("REMOTEPC_GEMINI_KEY")
    or os.environ.get("GEMINI_API_KEY")
    or str(_CONFIG.get("gemini_api_key", "") or "")
)

# Cloud models — public Google model IDs, configurable via the setup wizard.
_GEMINI_MODELS = [m for m in (_CONFIG.get("gemini_models", []) or [])
                  if isinstance(m, str) and m.strip()]

# Local models registered via the setup wizard / config:
#   [{"key": "local:my-model", "name": "publisher/model-id", "label": "My Model"}]
_LOCAL_MODELS = [m for m in (_CONFIG.get("local_models", []) or [])
                 if isinstance(m, dict) and m.get("key") and m.get("name")]
_LOCAL_MODEL_MAP: dict = {}
for _m in _LOCAL_MODELS:
    _LOCAL_MODEL_MAP[_m["key"]]  = _m["name"]
    _LOCAL_MODEL_MAP[_m["name"]] = _m["name"]

# Back-compat slot aliases — older code refers to these by name. They are empty
# strings when fewer local models are registered; the model menu is dynamic.
_LOCAL_MODEL_KEY        = _LOCAL_MODELS[0]["key"]  if len(_LOCAL_MODELS) > 0 else ""
_LOCAL_MODEL_NAME       = _LOCAL_MODELS[0]["name"] if len(_LOCAL_MODELS) > 0 else ""
_LOCAL_MODEL_GEMMA_KEY  = _LOCAL_MODELS[1]["key"]  if len(_LOCAL_MODELS) > 1 else ""
_LOCAL_MODEL_GEMMA_NAME = _LOCAL_MODELS[1]["name"] if len(_LOCAL_MODELS) > 1 else ""
_LOCAL_MODEL_CODER_KEY  = _LOCAL_MODELS[2]["key"]  if len(_LOCAL_MODELS) > 2 else ""
_LOCAL_MODEL_CODER_NAME = _LOCAL_MODELS[2]["name"] if len(_LOCAL_MODELS) > 2 else ""
_LOCAL_MODEL_LEXI_KEY   = _LOCAL_MODELS[3]["key"]  if len(_LOCAL_MODELS) > 3 else ""
_LOCAL_MODEL_LEXI_NAME  = _LOCAL_MODELS[3]["name"] if len(_LOCAL_MODELS) > 3 else ""

_ANTIGRAVITY_KEY   = "antigravity"
_ANTIGRAVITY_MODEL = str(_CONFIG.get("antigravity_model", "gemini-3.5-flash-lite") or "gemini-3.5-flash-lite")
_LMS_API_URL       = os.environ.get(
    "REMOTEPC_LMS_URL",
    str(_CONFIG.get("lmstudio_api_url", "http://127.0.0.1:1234/v1/chat/completions")),
)

# Cascade: cloud models first (quality), then local models (no rate limits).
_MODEL_CASCADE = list(_GEMINI_MODELS) + [_m["key"] for _m in _LOCAL_MODELS]
if not _MODEL_CASCADE:
    _MODEL_CASCADE = [""]
_GEMINI_MODEL   = _GEMINI_MODELS[0] if _GEMINI_MODELS else ""

# ─── Safe Mode Guardrails for Uncensored / Autonomous Execution ─────────────
_CRITICAL_PROCESSES = {
    "csrss.exe", "lsass.exe", "services.exe", "smss.exe", "wininit.exe",
    "winlogon.exe", "svchost.exe", "dwm.exe", "explorer.exe", "system", "ntoskrnl.exe"
}
_CRITICAL_BASENAMES = {p.replace(".exe", "") for p in _CRITICAL_PROCESSES}

_DESTRUCTIVE_PATTERNS = [
    r"\bformat\b",
    r"\bdiskpart\b",
    r"\brmdir\s+/[sS]",
    r"\brd\s+/[sS]",
    r"\bdel\s+.*[/\*]",
    r"\bRemove-Item\b.*-Recurse",
    r"\bRemove-Item\b.*-Force",
    r"\bClear-Disk\b",
    r"\bInitialize-Disk\b",
    r"\bSet-Partition\b",
    r"\breg\s+delete\b",
    r"\bbcdedit\b",
    r"\bcipher\s+/w",
    r"\bvssadmin\s+delete",
    r"\bwbadmin\s+delete",
    r"\bnet\s+user\s+.*(?:\/delete|\/add)",
    r"\b(?:del|rmdir|rd|Remove-Item)\b.*(?:C:\\Windows|System32)",
    r":\(\)\s*\{",
    r"%\s*0\s*\|\s*%\s*0",
    r"\bshutdown\s+/[sr]",
    r"\bStop-Computer\b",
]

def _check_safe_mode(action: str, is_safe_mode: bool = True) -> tuple:
    """
    Evaluates an action under Safe Mode rules.
    Returns (verdict, reason) where verdict is:
      - 'ALLOW': Safe to run automatically
      - 'CONFIRM': High-impact action, requires user approval
      - 'BLOCK': Destructive / system-crashing command, strictly forbidden
    """
    if not is_safe_mode:
        return ("ALLOW", "")

    action_clean = action.strip()
    if not action_clean.startswith("ACTION:"):
        return ("ALLOW", "")

    cmd = action_clean[len("ACTION:"):].strip()
    parts = cmd.split(maxsplit=1)
    verb = parts[0].lower() if parts else ""
    arg = parts[1].strip() if len(parts) > 1 else ""

    # 1. Critical Windows OS Process Termination -> HARD BLOCK
    if verb == "kill_proc":
        target = arg.lower()
        if any(p in target for p in _CRITICAL_PROCESSES) or any(b == target.replace(".exe", "") for b in _CRITICAL_BASENAMES):
            return ("BLOCK", f"Target '{arg}' is a core Windows system process. Terminating it would crash your PC.")
        return ("CONFIRM", f"Terminate process '{arg}'")

    # 2. Shell Commands & WSL -> Comprehensive destructive and critical process checks
    if verb in ("shell", "kali", "wsl"):
        arg_lower = arg.lower()

        # Intercept process-killing commands directed at critical Windows processes
        is_kill_syntax = any(k in arg_lower for k in ("taskkill", "stop-process", "tskill", "pkill", "kill -", "wmic process where"))
        if is_kill_syntax:
            for cp in _CRITICAL_BASENAMES:
                if re.search(rf"\b{re.escape(cp)}(?:\.exe)?\b", arg_lower):
                    return ("BLOCK", f"Shell command attempts to terminate core Windows process '{cp}'. Blocked by Safe Mode.")

        # Check against basic shell blocklist
        for blocked_pat in _SHELL_BLOCKLIST:
            if blocked_pat in arg_lower:
                return ("BLOCK", f"Shell command contains blocked pattern '{blocked_pat.strip()}'. Blocked by Safe Mode.")

        # Check against destructive regex patterns
        for pat in _DESTRUCTIVE_PATTERNS:
            if re.search(pat, arg, re.IGNORECASE):
                return ("BLOCK", f"Shell command matches destructive pattern '{pat}'. Blocked by Safe Mode.")

        return ("CONFIRM", f"Execute shell command: '{arg}'")

    # 3. System Power Commands -> CONFIRM
    if verb in ("sleep", "lock"):
        return ("CONFIRM", f"Put system into {verb} state")

    # 4. Browser CDP Arbitrary Script Execution -> CONFIRM
    if verb == "browser_cdp_eval":
        return ("CONFIRM", f"Execute browser JavaScript: '{arg[:60]}'")

    # All other actions (volume, brightness, sysinfo, find, dom_read, win_list, win_focus, win_min, etc.) -> ALLOW
    return ("ALLOW", "")


def _gather_live_telemetry_grounding(max_windows: int = 5) -> str:
    """Gather real-time PC telemetry (active window, open apps, battery, clipboard) for instant model awareness."""
    lines = ["[LIVE PC TELEMETRY & DESKTOP CONTEXT]"]
    now = datetime.now()
    lines.append(f"• Time: {now.strftime('%I:%M %p (%A, %d %b %Y)')}")

    # 1. Foreground & open windows
    try:
        fg_info = get_foreground_window_info()
        lines.append(f"• Foreground Active Window: {fg_info['desc']}")
    except Exception:
        lines.append("• Foreground Active Window: (Desktop / Taskbar)")

    try:
        wins = get_visible_windows()
        if wins:
            win_summaries = []
            for w in wins[:max_windows]:
                t = w.get("title", "")
                p = w.get("pname", "")
                pid = w.get("pid", "")
                st = w.get("state", "")
                st_tag = f" [{st.capitalize()}]" if st else ""
                if t:
                    win_summaries.append(f"\"{t[:35]}\" ({p}, PID {pid}){st_tag}")
            if win_summaries:
                lines.append(f"• Open Windows: {'; '.join(win_summaries)}")
    except Exception:
        pass

    # 2. Hardware telemetry
    try:
        batt = psutil.sensors_battery()
        batt_str = f"{batt.percent:.0f}% {'(Charging)' if batt.power_plugged else '(Battery)'}" if batt else "N/A"
        cpu = psutil.cpu_percent(interval=0)
        mem = psutil.virtual_memory().percent
        lines.append(f"• Hardware: Battery {batt_str} | CPU {cpu:.0f}% | RAM {mem:.0f}%")
    except Exception:
        pass

    # 3. Clipboard preview
    try:
        import pyperclip
        clip = (pyperclip.paste() or "").strip()
        if clip:
            clip_one_line = clip.replace("\r", " ").replace("\n", " ").strip()
            if len(clip_one_line) > 80:
                clip_one_line = clip_one_line[:80] + "..."
            lines.append(f"• Clipboard Content: \"{clip_one_line}\"")
    except Exception:
        pass

    return "\n".join(lines)


AZAZIL_LMS_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "launch",
            "description": "Launch an application by name or path (e.g. chrome, vscode, discord, musicbee, notepad, explorer)",
            "parameters": {
                "type": "object",
                "properties": {
                    "app": {"type": "string", "description": "Application name or executable path"}
                },
                "required": ["app"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "open_url",
            "description": "Open a website URL in the default web browser",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Website URL to navigate to"}
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "screenshot",
            "description": "Take a full desktop screenshot and save to the Screenshots folder",
            "parameters": {"type": "object", "properties": {}}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "volume",
            "description": "Set system master volume level (0 to 100)",
            "parameters": {
                "type": "object",
                "properties": {
                    "level": {"type": "integer", "description": "Volume percentage from 0 to 100"}
                },
                "required": ["level"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "brightness",
            "description": "Set monitor display brightness (0 to 100)",
            "parameters": {
                "type": "object",
                "properties": {
                    "level": {"type": "integer", "description": "Brightness percentage from 0 to 100"}
                },
                "required": ["level"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "win_list",
            "description": "List all currently open desktop windows, their titles, process names, and PIDs",
            "parameters": {"type": "object", "properties": {}}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "win_focus",
            "description": "Bring an open window to the foreground by title substring or PID",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Window title substring or numeric PID"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "win_close",
            "description": "Close a desktop window gracefully by title substring or PID",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Window title substring or numeric PID"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "win_minimize",
            "description": "Minimize a window by title substring or PID",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Window title substring or numeric PID"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "win_maximize",
            "description": "Maximize a window by title substring or PID",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Window title substring or numeric PID"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "lock",
            "description": "Lock the Windows PC workstation",
            "parameters": {"type": "object", "properties": {}}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "sleep",
            "description": "Put the PC into sleep / standby mode",
            "parameters": {"type": "object", "properties": {}}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "monitor_off",
            "description": "Turn off the PC monitor display immediately",
            "parameters": {"type": "object", "properties": {}}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "sysinfo",
            "description": "Query CPU load, RAM usage, disk space, and battery state",
            "parameters": {"type": "object", "properties": {}}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "clip_get",
            "description": "Read text currently in Windows clipboard",
            "parameters": {"type": "object", "properties": {}}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "clip_set",
            "description": "Copy text into Windows clipboard",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Text to place on clipboard"}
                },
                "required": ["text"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "kill_proc",
            "description": "Terminate a process by name or PID (e.g. notepad.exe)",
            "parameters": {
                "type": "object",
                "properties": {
                    "process_name": {"type": "string", "description": "Process name or executable (e.g. vlc.exe)"}
                },
                "required": ["process_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "routine",
            "description": "Execute a pre-configured multi-step routine (e.g. good_morning, good_night, work_mode, hack_mode, gaming_mode, focus_mode)",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Routine name, e.g. good_morning, hack_mode, work_mode"}
                },
                "required": ["name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "remember",
            "description": "Save an important user fact or preference into long-term ChromaDB vector memory",
            "parameters": {
                "type": "object",
                "properties": {
                    "fact": {"type": "string", "description": "Fact or preference to remember"}
                },
                "required": ["fact"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "learn",
            "description": "Learn a behavioral rule, personal detail, or preference directly from the user's instructions",
            "parameters": {
                "type": "object",
                "properties": {
                    "rule": {"type": "string", "description": "The rule, fact, or preference to learn and persist"}
                },
                "required": ["rule"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "recall",
            "description": "Search ChromaDB vector memory for relevant information about the user or system preferences",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Semantic search query"}
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "briefing",
            "description": "Generate a comprehensive system briefing with battery, CPU, RAM, active apps, and recent notes",
            "parameters": {"type": "object", "properties": {}}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "speak",
            "description": "Speak text out loud on the PC desktop using speech synthesis",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Text to speak out loud"}
                },
                "required": ["text"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "shell",
            "description": "Execute a shell or PowerShell command on the PC (guarded by Safe Mode)",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Command line to run"}
                },
                "required": ["command"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "play_music",
            "description": "Play audio tracks from the local Music folder via VLC or MusicBee. Never use Spotify. Optionally pass a search query to play specific tracks, or leave empty to shuffle all songs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Optional song title or artist query to filter tracks from Music folder"}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "stop_music",
            "description": "Stop local music playback (terminates VLC or MusicBee).",
            "parameters": {"type": "object", "properties": {}}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_music",
            "description": "Search audio tracks in the local Music folder without playing them immediately.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search term to match against filenames in Music folder"}
                },
                "required": ["query"]
            }
        }
    }
]


def _format_tool_call_to_action(fn_name: str, args_dict: dict) -> str:
    """Format an OpenAI structured tool call into standard ACTION: <verb> [args] line."""
    verb = fn_name.strip().lower()
    if verb in ("screenshot", "lock", "sleep", "monitor_off", "sysinfo", "clip_get", "win_list", "briefing"):
        return f"ACTION: {verb}"
    if verb in ("volume", "brightness"):
        lvl = args_dict.get("level") if args_dict.get("level") is not None else args_dict.get("val", 50)
        return f"ACTION: {verb} {lvl}"
    if verb == "launch":
        app = args_dict.get("app") or args_dict.get("name") or ""
        return f"ACTION: launch {app}".strip()
    if verb == "open_url":
        url = args_dict.get("url") or ""
        return f"ACTION: open_url {url}".strip()
    if verb in ("win_focus", "win_close", "win_minimize", "win_maximize"):
        t = args_dict.get("target") or args_dict.get("window") or args_dict.get("pid") or ""
        return f"ACTION: {verb} {t}".strip()
    if verb == "kill_proc":
        p = args_dict.get("process_name") or args_dict.get("name") or ""
        return f"ACTION: kill_proc {p}".strip()
    if verb == "routine":
        r = args_dict.get("name") or args_dict.get("routine") or ""
        return f"ACTION: routine {r}".strip()
    if verb in ("remember", "learn", "recall", "speak"):
        val = args_dict.get("fact") or args_dict.get("rule") or args_dict.get("query") or args_dict.get("text") or ""
        return f"ACTION: {verb} {val}".strip()
    if verb == "clip_set":
        t = args_dict.get("text") or ""
        return f"ACTION: clip_set {t}".strip()
    if verb in ("play_music", "play_local_music"):
        q = args_dict.get("query") or args_dict.get("track") or args_dict.get("song") or ""
        return f"ACTION: play_music {q}".strip()
    if verb in ("stop_music", "stop_local_music"):
        return "ACTION: stop_music"
    if verb == "search_music":
        q = args_dict.get("query") or args_dict.get("search") or ""
        return f"ACTION: search_music {q}".strip()
    if verb == "shell":
        cmd = args_dict.get("command") or args_dict.get("cmd") or ""
        return f"ACTION: shell {cmd}".strip()
    # Generic fallback
    arg_vals = " ".join(str(v) for v in args_dict.values())
    return f"ACTION: {verb} {arg_vals}".strip()


def _query_local_lms(messages: list, system_prompt: str, model_name: str = _LOCAL_MODEL_CODER_NAME, on_thought: Any = None, on_content: Any = None) -> str:
    """Send chat messages to local LM Studio with streaming, real-time thought callbacks, and native tool calling."""
    try:
        urllib.request.urlopen("http://127.0.0.1:1234/v1/models", timeout=1.5)
    except Exception:
        if os.path.exists(LMS_EXE):
            console.print("  [dim]Starting LM Studio server...[/dim]")
            run_shell(f'"{LMS_EXE}" server start')
            time.sleep(2)
        else:
            raise RuntimeError("LM Studio local server is not reachable on port 1234. Start it via 'lms server start'.")

    is_llama = any(k in model_name.lower() for k in ("llama", "lexi", "mistral"))
    payload = {
        "model": model_name,
        "messages": [{"role": "system", "content": system_prompt}] + messages,
        "temperature": 0.45 if is_llama else 0.25,
        "max_tokens": 2048,
        "top_p": 0.92,
        "frequency_penalty": 0.15 if is_llama else 0.0,
        "presence_penalty": 0.10 if is_llama else 0.0,
        "tools": AZAZIL_LMS_TOOLS,
        "tool_choice": "auto",
        "stream": True
    }

    import requests
    try:
        r = requests.post(_LMS_API_URL, json=payload, stream=True, timeout=(10, 120))
        if r.status_code != 200:
            # Fallback without tools if the local model doesn't support them
            payload.pop("tools", None)
            payload.pop("tool_choice", None)
            r = requests.post(_LMS_API_URL, json=payload, stream=True, timeout=(10, 120))
    except Exception:
        payload.pop("tools", None)
        payload.pop("tool_choice", None)
        r = requests.post(_LMS_API_URL, json=payload, stream=True, timeout=(10, 120))

    if r.status_code != 200:
        raise RuntimeError(f"LM Studio API returned HTTP {r.status_code}: {r.text}")

    content_chunks = []
    reasoning_chunks = []
    tool_calls_buf = {}
    in_think_tag = False

    for line in r.iter_lines():
        if line:
            decoded = line.decode("utf-8")
            if decoded.startswith("data: ") and not decoded.endswith("[DONE]"):
                try:
                    delta = json.loads(decoded[6:])["choices"][0]["delta"]

                    # 1. Native reasoning tokens (gpt-oss-20b, DeepSeek-R1, Qwen 2.5/3.5, LM Studio reasoning parser)
                    rc = delta.get("reasoning") or delta.get("reasoning_content") or delta.get("thought") or delta.get("thinking")
                    if rc:
                        if isinstance(rc, dict):
                            rc = rc.get("text") or rc.get("content") or str(rc)
                        reasoning_chunks.append(rc)
                        if on_thought:
                            try:
                                on_thought(rc)
                            except Exception:
                                pass

                    # 2. Content tokens (which may include inline <think> ... </think> or <thought> ... </thought>)
                    c = delta.get("content")
                    if c:
                        # Handle inline <think> or <thought> opening
                        for tag_open in ("<think>", "<thought>"):
                            if tag_open in c:
                                in_think_tag = True
                                parts = c.split(tag_open, 1)
                                if parts[0]:
                                    content_chunks.append(parts[0])
                                    if on_content:
                                        try:
                                            on_content(parts[0])
                                        except Exception:
                                            pass
                                c = parts[1]
                                break

                        if in_think_tag:
                            closed = False
                            for tag_close in ("</think>", "</thought>"):
                                if tag_close in c:
                                    in_think_tag = False
                                    think_text, post_text = c.split(tag_close, 1)
                                    if think_text:
                                        reasoning_chunks.append(think_text)
                                        if on_thought:
                                            try:
                                                on_thought(think_text)
                                            except Exception:
                                                pass
                                    if post_text:
                                        content_chunks.append(post_text)
                                        if on_content:
                                            try:
                                                on_content(post_text)
                                            except Exception:
                                                pass
                                    closed = True
                                    break
                            if not closed:
                                reasoning_chunks.append(c)
                                if on_thought:
                                    try:
                                        on_thought(c)
                                    except Exception:
                                        pass
                        else:
                            content_chunks.append(c)
                            if on_content:
                                try:
                                    on_content(c)
                                except Exception:
                                    pass

                    # 3. Native OpenAI tool calls
                    tc_list = delta.get("tool_calls")
                    if tc_list:
                        for tc in tc_list:
                            idx = tc.get("index", 0)
                            if idx not in tool_calls_buf:
                                tool_calls_buf[idx] = {"name": "", "arguments": ""}
                            fn = tc.get("function", {})
                            if fn.get("name"):
                                tool_calls_buf[idx]["name"] += fn["name"]
                            if fn.get("arguments"):
                                tool_calls_buf[idx]["arguments"] += fn["arguments"]
                except Exception:
                    pass

    res = "".join(content_chunks).strip()
    if not res and reasoning_chunks:
        res = "".join(reasoning_chunks).strip()

    # Convert native OpenAI tool_calls into ACTION lines
    action_lines = []
    for idx, tc in sorted(tool_calls_buf.items()):
        fn_name = tc.get("name", "").strip()
        args_raw = tc.get("arguments", "{}").strip()
        try:
            args_dict = json.loads(args_raw) if args_raw else {}
        except Exception:
            args_dict = {"arg": args_raw}
        if fn_name:
            action_lines.append(_format_tool_call_to_action(fn_name, args_dict))

    # Also handle Qwen / Llama XML tool calling outputs (<xml>...</xml> or <tool_call>...</tool_call>)
    if not action_lines:
        xml_blocks = re.findall(r"<(?:xml|tool_call)>\s*(\{.*?\})\s*</(?:xml|tool_call)>", res, re.DOTALL)
        for block in xml_blocks:
            try:
                data = json.loads(block)
                fn_name = data.get("name", "")
                args_dict = data.get("arguments", {})
                if fn_name:
                    action_lines.append(_format_tool_call_to_action(fn_name, args_dict))
            except Exception:
                pass
        if xml_blocks:
            res = re.sub(r"<(?:xml|tool_call)>.*?</(?:xml|tool_call)>", "", res, flags=re.DOTALL).strip()

    if action_lines:
        res = (res + "\n" if res else "") + "\n".join(action_lines)

    return res.strip()
_LOCAL_AGENT_SYSTEM_PROMPT = """\
You are an AI agent embedded in RemotePC — a Windows PC control tool accessed over SSH.
You have full control over the PC. Respond concisely (mobile SSH terminal).
Execute ONE action at a time and wait for the OBSERVATION result before your next step.

To run a command on the PC, output EXACTLY this format on its own line (no backticks, no markdown):
ACTION: <verb> [args]

FULL ACTION REFERENCE:
  launch <app>              | open_url <url>              | screenshot
  lock | sleep              | monitor_off                 | brightness <0-100>
  volume <0-100>            | mute | play_pause            | next_track | prev_track
  play_music [query] | stop_music   | find <query>                | shell <cmd>
  kali <cmd>                | toast <title>|<body>         | open_folder <path>
  sysinfo                   | clip_get | clip_set <text>   | kill_proc <name.exe>
  wifi_scan | net_info      | note <text>                  | search_music <q>
  log_view                  | wallpaper <path>             | win_list
  win_focus <title|pid>     | win_minimize <t|pid>         | win_maximize <t|pid>
  win_restore <t|pid>       | win_close <t|pid>            | win_sendkeys <keys>
  browser_tab_new [url]     | browser_tab_close            | browser_tab_next | browser_tab_prev
  browser_refresh           | browser_scroll <up|dn>       | browser_back | browser_forward
  dom_read <url>            | dom_links <url>              | dom_forms <url>
  browser_debug_launch [url]| browser_cdp_status           | browser_cdp_eval <js>
  browser_cdp_dom           | browser_cdp_click <sel>      | browser_cdp_type <sel>|<text>
  screen_info               | mouse_pos                    | mouse_move <x> <y>
  mouse_click <x> <y> [left|right|middle]  | mouse_dblclick <x> <y>
  mouse_scroll <up|down> [n]| mouse_drag <x1> <y1> <x2> <y2>
  ocr                       | ocr_region <x> <y> <w> <h>  (read text from screen)
  snap_webcam [N]           (take webcam photo, save to Downloads; N = camera index, default 0)
  file_server_start [folder]| file_server_stop             | file_server_status
  watch_cpu <n>             | watch_ram <n>                | watch_battery <n>
  watch_proc_start <name>   | watch_proc_stop <name>       | watch_file <path> | watch_list
  record_audio <seconds>    | routine <name>               | remember <text>
  recall <query>            | briefing                     | speak <text>

CRITICAL RULES:
1. ONE ACTION per turn. NEVER emit two ACTION lines in one reply.
2. Do NOT wrap ACTION in markdown code blocks, backticks, or quotes.
3. WAIT for the OBSERVATION before taking the next step.
4. NEVER guess window titles or PIDs. Always call 'win_list' first, then use the EXACT value.
5. Before browser actions, call 'screen_info' first to confirm a browser is open.
6. If no action is needed, respond directly in plain text — no ACTION line.
7. If an action fails, report the error — do NOT retry with a guessed argument.
8. MUSIC PLAYBACK: When asked to "play music", "play songs", "put on music", "play a track", etc.:
   - ALWAYS emit: ACTION: play_music (or ACTION: play_music <query> if specific song/artist).
   - This plays audio files directly from the local Music folder via VLC/MusicBee.
   - NEVER launch Spotify, open web streaming, or use Spotify.

EXAMPLES:
User: Play music
Assistant: ACTION: play_music

User: Play some songs
Assistant: ACTION: play_music

User: Open YouTube
Assistant: ACTION: open_url https://youtube.com

User: What are my CPU and RAM stats?
Assistant: ACTION: sysinfo

User: Take a screenshot
Assistant: ACTION: screenshot

User: Check if Google is reachable
Assistant: ACTION: shell ping -n 3 google.com

User: Close Notepad
Assistant: ACTION: win_list
[After OBSERVATION]
Assistant: ACTION: win_close Notepad
"""

_AGENT_SYSTEM_PROMPT = """\
You are an AI embedded in RemotePC — a Windows PC control tool accessed over SSH.
Respond concisely (mobile SSH). Execute actions one at a time and wait for OBSERVATION before the next.

To run a command, emit EXACTLY:
  ACTION: <verb> [args]

ACTIONS:
  launch <app>            | open_url <url>          | screenshot
  lock | sleep            | monitor_off             | brightness <0-100>
  volume <0-100>          | mute | play_pause        | next_track | prev_track
  play_music [query]      | stop_music              | find <query>            | shell <cmd>
  toast <title>|<body>    | open_folder <path>      | sysinfo
  clip_get | clip_set <t> | kill_proc <name.exe>    | wifi_scan | net_info
  note <text>             | search_music <q>        | log_view
  wallpaper <path>        | win_list                | win_focus <title|pid>
  win_minimize <t|pid>    | win_maximize <t|pid>    | win_restore <t|pid>
  win_close <t|pid>       | win_sendkeys <keys>     | browser_tab_new [url]
  browser_tab_close       | browser_tab_next        | browser_tab_prev
  browser_refresh         | browser_scroll <up|dn>  | browser_back | browser_forward
  dom_read <url>          | dom_links <url>         | dom_forms <url>
  browser_debug_launch [url] | browser_cdp_status   | browser_cdp_eval <js>
  browser_cdp_dom         | browser_cdp_click <sel> | browser_cdp_type <sel>|<text>
  screen_info             (get open windows + foreground window for grounding)
  mouse_pos               | mouse_move <x> <y>       | mouse_click <x> <y> [left|right|middle]
  mouse_dblclick <x> <y>  | mouse_scroll <up|down> [n] | mouse_drag <x1> <y1> <x2> <y2>
  ocr                     | ocr_region <x> <y> <w> <h>   (extract text from screen)
  snap_webcam [N]         (webcam photo → Downloads; N = camera index, default 0)
  file_server_start [folder] | file_server_stop | file_server_status
  watch_cpu <n>           | watch_ram <n>            | watch_battery <n>
  watch_proc_start <name> | watch_proc_stop <name>   | watch_file <path> | watch_list
  record_audio <seconds>  | routine <name>           | remember <text>
  recall <query>          | briefing                 | speak <text>

CRITICAL RULES — Read carefully to avoid hallucination:
- ONE ACTION per turn. Read the full OBSERVATION before the next.
- NEVER guess window titles or PIDs. ALWAYS call 'win_list' first to get real data,
  then use the EXACT title or PID from the OBSERVATION.
- Before any browser action (browser_tab_new, browser_refresh, browser_scroll, etc.),
  call 'screen_info' or 'win_list' first to confirm a browser window is open.
  If no browser is open, use 'launch chrome' or 'open_url <url>' first.
- After 'screenshot', wait for the OBSERVATION confirming the file path before proceeding.
- If an action returns an error or unexpected result, report it to the user — do NOT retry
  with a different guessed argument. Ask the user for clarification.
- For 'win_sendkeys', focus the window first with 'win_focus', then send keys in the next step.
- Never guess results. If no action is needed, respond directly in plain text.
- MUSIC PLAYBACK: When prompted to "play music", "play songs", "put on music", "play track", etc.:
  ALWAYS emit 'ACTION: play_music' (or 'ACTION: play_music <query>' if specific title/artist).
  This plays songs directly from the local Music folder via VLC/MusicBee.
  NEVER launch Spotify, open web streaming, or use Spotify.
"""

def _agent_exec(action_line: str) -> str:
    """Parse and execute a single ACTION: line. Returns a result string."""
    if not action_line.startswith("ACTION:"):
        return ""
    cmd   = action_line[len("ACTION:"):].strip()
    parts = cmd.split(maxsplit=1)
    verb  = parts[0].lower() if parts else ""
    arg   = parts[1] if len(parts) > 1 else ""

    # Normalize common model variations for music actions
    if verb in ("play", "play_") and ("music" in arg.lower() or "song" in arg.lower() or not arg):
        verb = "play_music"
        arg = re.sub(r"^(?:music|some music|local music|songs?)\s*", "", arg, flags=re.I).strip()
    elif verb == "play_music":
        arg = re.sub(r"^(?:music|some music|local music)\s*", "", arg, flags=re.I).strip()
    elif verb in ("stop", "stop_") and ("music" in arg.lower() or "song" in arg.lower()):
        verb = "stop_music"
        arg = ""

    try:
        if verb == "launch":
            # If the agent attempts to launch Spotify, redirect to local Music folder playback
            if "spotify" in arg.lower():
                return _agent_exec("ACTION: play_music")
            match = next(((n, e) for n, e in QUICK_APPS.values() if arg.lower() in n.lower()), None)
            if match:
                launch_desktop_app(match[1])
                return f"Launched {match[0]}."
            launch_desktop_app(arg)
            return f"Launched '{arg}'."

        elif verb == "open_url":
            url = arg if arg.startswith("http") else "https://" + arg
            launch_desktop_app(f'"{url}"')
            return f"Opened {url} in browser."

        elif verb == "screenshot":
            # Call the screenshot logic directly without the interactive pause()
            out_dir = _SCREENSHOT_DIR
            out_dir.mkdir(parents=True, exist_ok=True)
            fname = out_dir / f"screenshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            pf = str(fname).replace("/", "\\")
            ps = (
                f"Add-Type -AssemblyName System.Windows.Forms,System.Drawing\r\n"
                f"$s = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds\r\n"
                f"$b = New-Object System.Drawing.Bitmap($s.Width, $s.Height)\r\n"
                f"$g = [System.Drawing.Graphics]::FromImage($b)\r\n"
                f"$g.CopyFromScreen($s.Location, [System.Drawing.Point]::Empty, $s.Size)\r\n"
                f"$b.Save('{pf}')\r\n"
                f"$g.Dispose()\r\n"
                f"$b.Dispose()\r\n"
            )
            ps_file = Path.home() / "AppData" / "Local" / "Temp" / "remotepc_scr.ps1"
            try:
                ps_file.write_text(ps, encoding="utf-8")
                launch_desktop_app(f'powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File "{ps_file}"')
                # Extended polling: up to 15 seconds (20 × 0.75s) to account for
                # scheduled-task startup latency over SSH
                for _ in range(20):
                    time.sleep(0.75)
                    if fname.exists() and fname.stat().st_size > 0:
                        break
            except Exception:
                pass
            if not (fname.exists() and fname.stat().st_size > 0):
                # Fallback: try direct PowerShell execution (works if not SSH Session 0)
                encoded = base64.b64encode(ps.encode("utf-16le")).decode("ascii")
                run_shell(f'powershell -NoProfile -NonInteractive -EncodedCommand {encoded}')
                # Give the fallback a few extra seconds
                for _ in range(6):
                    time.sleep(0.5)
                    if fname.exists() and fname.stat().st_size > 0:
                        break
            if fname.exists() and fname.stat().st_size > 0:
                sz = fname.stat().st_size
                return f"Screenshot saved: {fname} ({sz // 1024} KB)"
            return (
                f"Screenshot failed. Expected file: {fname}. "
                "The scheduled task may be stuck — try: ACTION: shell tasklist | findstr schtasks "
                "or manually trigger a screenshot from menu 11."
            )

        elif verb == "lock":
            launch_desktop_app("rundll32.exe user32.dll,LockWorkStation")
            return "Screen locked."

        elif verb == "sleep":
            launch_desktop_app("rundll32.exe powrprof.dll,SetSuspendState 0,1,0")
            return "PC going to sleep."

        elif verb == "monitor_off":
            launch_desktop_app(f'powershell -WindowStyle Hidden -NoProfile -Command "{_DISPLAY_PS_OFF}"')
            return "Monitor turned off."

        elif verb == "brightness":
            try:
                lvl = max(0, min(100, int(arg)))
                ps = f"(Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightnessMethods).WmiSetBrightness(1,{lvl})"
                run_shell(f'powershell -NoProfile -Command "{ps}"')
                return f"Brightness set to {lvl}%."
            except ValueError:
                return "Invalid brightness value."

        elif verb == "volume":
            try:
                lvl = max(0, min(100, int(arg)))
                dn, up = MEDIA_VK["voldown"], MEDIA_VK["volup"]
                ps = (f"$s=New-Object -ComObject wscript.shell;"
                      f"1..50|%{{$s.SendKeys([char]{dn})}};"
                      f"1..{int(lvl/2)}|%{{$s.SendKeys([char]{up})}}")
                launch_desktop_app(f'powershell -WindowStyle Hidden -NoProfile -Command "{ps}"')
                return f"Volume set to ~{lvl}%."
            except ValueError:
                return "Invalid volume value."

        elif verb == "play_music":
            player = _music_player_app()
            search_term = arg.strip()
            tracks = []
            if search_term:
                tracks = _scan_music(_MUSIC_DIR, search_term)
            if not tracks:
                tracks = _scan_music(_MUSIC_DIR)
            if not tracks:
                return f"No audio tracks found in {_MUSIC_DIR}."
            import random
            if not search_term:
                random.shuffle(tracks)
            m3u = Path.home() / "AppData" / "Local" / "Temp" / "remotepc_agent.m3u"
            m3u.write_text("#EXTM3U\n" + "\n".join(str(p) for p in tracks), encoding="utf-8")
            if player:
                launch_desktop_app(f'"{player}" "{m3u}"')
            else:
                launch_desktop_app(f'"{m3u}"')
            desc = f"'{tracks[0].name}'" if len(tracks) == 1 else f"{len(tracks)} tracks"
            return f"Playing {desc} from Music folder ({Path(player).name if player else 'Default Player'})."

        elif verb == "stop_music":
            for proc in ("vlc.exe", "MusicBee.exe"):
                run_shell(f'taskkill /F /IM "{proc}" /T')
            return "Music stopped."

        elif verb == "mute":
            _vk(MEDIA_VK["mute"])
            return "Mute toggled."

        elif verb == "play_pause":
            _vk(MEDIA_VK["play"])   # MEDIA_VK key is "play" (0xB3), not "playpause"
            return "Play/Pause toggled."

        elif verb == "next_track":
            _vk(MEDIA_VK["next"])
            return "Next track."

        elif verb == "prev_track":
            _vk(MEDIA_VK["prev"])
            return "Previous track."

        elif verb == "find":
            results = []
            q = arg.lower()
            for dirpath, dirs, files in os.walk(str(Path.home())):
                dirs[:] = [d for d in dirs if d not in {"$Recycle.Bin", "__pycache__", "node_modules", ".git"}]
                for f in files:
                    if q in f.lower():
                        results.append(str(Path(dirpath) / f))
                    if len(results) >= 10:
                        break
                if len(results) >= 10:
                    break
            if results:
                return "Found:\n" + "\n".join(f"  {r}" for r in results)
            return f"No files found matching '{arg}'."

        elif verb in ("kali", "wsl"):
            blocked = _guard_shell_cmd(arg)
            if blocked:
                return blocked
            if not arg:
                return "Usage: kali <command>"
            rc, out, err = run_shell(f'wsl -d kali-linux -- {arg}')
            return (out or err or "(no output)").strip()[:800]

        elif verb == "shell":
            blocked = _guard_shell_cmd(arg)
            if blocked:
                return blocked
            rc, out, err = run_shell(arg)
            return (out or err or "(no output)").strip()[:800]

        elif verb == "toast":
            if "|" in arg:
                t, b = arg.split("|", 1)
            else:
                t, b = "RemotePC", arg
            _send_toast(t.strip(), b.strip())
            return f"Notification sent."

        elif verb == "open_folder":
            launch_desktop_app(f'explorer.exe "{arg}"')
            return f"Opened {arg} in Explorer."

        elif verb == "sysinfo":
            import psutil
            cpu  = psutil.cpu_percent(interval=0.5)
            mem  = psutil.virtual_memory()
            disk = psutil.disk_usage("C:\\")
            batt = psutil.sensors_battery()
            batt_str = f"{batt.percent:.0f}% ({'CHG' if batt.power_plugged else 'BAT'})" if batt else "N/A"
            return (
                f"CPU: {cpu}%  RAM: {mem.percent}% ({mem.used//1024//1024}MB used)  "
                f"Disk C: {disk.percent}% used  Battery: {batt_str}"
            )

        elif verb == "clip_get":
            try:
                import pyperclip
                text = pyperclip.paste()
                return f"Clipboard: {text[:500] or '(empty)'}" 
            except Exception as e:
                return f"Error reading clipboard: {e}"

        elif verb == "clip_set":
            try:
                import pyperclip
                pyperclip.copy(arg)
                return f"Clipboard set to: {arg[:80]}"
            except Exception as e:
                return f"Error setting clipboard: {e}"

        elif verb == "kill_proc":
            rc, out, err = run_shell(f'taskkill /F /IM "{arg}" /T')
            if rc == 0:
                return f"Killed {arg}."
            return f"Could not kill {arg}: {err.strip()}"

        elif verb == "wifi_scan":
            rc, out, err = run_shell("netsh wlan show networks")
            if rc != 0:
                return f"Wi-Fi scan failed: {err.strip()}"
            networks = [l.split(":",1)[1].strip() for l in out.splitlines()
                        if l.strip().lower().startswith("ssid") and "bssid" not in l.lower()]
            return "Networks: " + ", ".join(networks[:15]) if networks else "No networks found."

        elif verb == "net_info":
            rc, out, _ = run_shell("ipconfig")
            lines = [l.strip() for l in out.splitlines()
                     if "IPv4" in l or "IPv6" in l or "Default Gateway" in l]
            return "\n".join(lines[:10]) or "No network info."

        elif verb == "note":
            note_file = _NOTES_DIR / "quick_notes.txt"
            ts = datetime.now().strftime("%Y-%m-%d %H:%M")
            with open(note_file, "a", encoding="utf-8") as f:
                f.write(f"[{ts}] {arg}\n")
            return f"Note saved: {arg[:80]}"

        elif verb == "search_music":
            tracks = _scan_music(_MUSIC_DIR, arg)
            if not tracks:
                return f"No tracks matching '{arg}'."
            return "Tracks:\n" + "\n".join(f"  {i+1}. {p.name}" for i, p in enumerate(tracks[:10]))

        elif verb == "log_view":
            log_file = _LOG_DIR / "remotepc_log.jsonl"
            if not log_file.exists():
                return "No log entries yet."
            import json
            lines = log_file.read_text(encoding="utf-8").strip().splitlines()
            recent = lines[-15:]
            out = []
            for l in recent:
                try:
                    e = json.loads(l)
                    out.append(f"  [{e.get('ts','')}] {e.get('source','')} | {e.get('cmd','')} → {e.get('result','')}")
                except Exception:
                    out.append(l)
            return "\n".join(out)

        elif verb == "wallpaper":
            ps = f'(New-Object -ComObject WScript.Shell).RegWrite("HKCU\\Control Panel\\Desktop\\Wallpaper","{arg}");RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters'
            launch_desktop_app(f'powershell -WindowStyle Hidden -NoProfile -Command "{ps}"')
            return f"Wallpaper changed to {arg}."

        elif verb == "win_list":
            wins = get_visible_windows()
            if not wins:
                return "No open desktop windows found."
            lines = [
                f"  [{w['hwnd']}] {w['pname']} (PID {w['pid']}) [{w.get('state', 'normal').capitalize()}] - \"{w['title']}\""
                for w in wins[:25]
            ]
            total_str = f" ({len(wins)} total)" if len(wins) > 1 else ""
            return f"Open Windows{total_str}:\n" + "\n".join(lines)

        elif verb == "win_focus":
            ok, msg = focus_window(arg)
            return msg

        elif verb in ("win_min", "win_minimize"):
            ok, msg = minimize_window(arg)
            return msg

        elif verb in ("win_max", "win_maximize"):
            ok, msg = maximize_window(arg)
            return msg

        elif verb == "win_restore":
            ok, msg = restore_window(arg)
            return msg

        elif verb == "win_close":
            ok, msg = close_window(arg)
            return msg

        elif verb == "win_sendkeys":
            return send_keys_desktop(arg)

        elif verb == "browser_tab_new":
            return browser_nav_action("new_tab", arg)

        elif verb == "browser_tab_close":
            return browser_nav_action("close_tab")

        elif verb == "browser_tab_next":
            return browser_nav_action("next_tab")

        elif verb == "browser_tab_prev":
            return browser_nav_action("prev_tab")

        elif verb == "browser_refresh":
            return browser_nav_action("refresh")

        elif verb == "browser_scroll":
            return browser_nav_action("scroll_up" if arg.lower() in ("up", "top") else "scroll_down")

        elif verb == "browser_back":
            return browser_nav_action("back")

        elif verb == "browser_forward":
            return browser_nav_action("forward")

        elif verb == "dom_read":
            return fetch_dom_summary(arg)

        elif verb == "dom_links":
            return fetch_dom_links(arg)

        elif verb == "dom_forms":
            return fetch_dom_forms(arg)

        elif verb == "browser_debug_launch":
            return cdp_launch_browser(arg or "https://www.google.com")

        elif verb == "browser_cdp_status":
            return cdp_status()

        elif verb == "browser_cdp_eval":
            return cdp_eval_js(arg)

        elif verb == "browser_cdp_dom":
            return cdp_eval_js("document.body.innerText")

        elif verb == "browser_cdp_click":
            return cdp_eval_js(f"document.querySelector('{arg}').click(); 'Clicked {arg}'")

        elif verb == "browser_cdp_type":
            if "|" in arg:
                sel, val = arg.split("|", 1)
            else:
                sel, val = "input", arg
            sel = sel.strip()
            val = val.strip().replace("'", "\\'")
            return cdp_eval_js(f"(function(){{ var el = document.querySelector('{sel}'); if(el){{ el.value = '{val}'; el.dispatchEvent(new Event('input', {{bubbles:true}})); return 'Typed into {sel}'; }} return 'Element not found'; }})()")

        elif verb == "screen_info":
            # Grounding action: returns the real desktop window list + foreground window
            # so the AI model never has to guess window titles or PIDs.
            wins = get_visible_windows()
            info_lines = []
            now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            info_lines.append(f"Timestamp: {now_str}")

            # Display & cursor metrics
            try:
                sw = _USER32.GetSystemMetrics(0)
                sh = _USER32.GetSystemMetrics(1)
                pt = wintypes.POINT()
                _USER32.GetCursorPos(ctypes.byref(pt))
                info_lines.append(f"Display: {sw}x{sh} (Primary) | Mouse Cursor: ({pt.x}, {pt.y})")
            except Exception:
                pass

            # Foreground active window
            try:
                fg_info = get_foreground_window_info()
                info_lines.append(f"Foreground Window: {fg_info['desc']}")
            except Exception:
                info_lines.append("Foreground Window: (unknown)")

            if wins:
                info_lines.append(f"\nOpen Windows ({len(wins)} total):")
                for w in wins[:20]:
                    st = f"[{w.get('state', 'normal').capitalize()}]"
                    info_lines.append(
                        f"  {st:<11} PID {w['pid']:>6} | {w['pname']:<22} | \"{w['title'][:55]}\""
                    )
                if len(wins) > 20:
                    info_lines.append(f"  ... and {len(wins) - 20} more.")
            else:
                info_lines.append("\nOpen Windows: none detected.")

            # Quick system snapshot
            try:
                cpu = psutil.cpu_percent(interval=0.1)
                mem = psutil.virtual_memory()
                batt = psutil.sensors_battery()
                batt_str = f" | Battery {batt.percent:.0f}%" + (" (Charging)" if batt.power_plugged else " (On Battery)") if batt else ""
                info_lines.append(
                    f"\nSystem: CPU {cpu:.0f}%  RAM {mem.percent:.0f}% ({mem.used//1024//1024} MB used){batt_str}"
                )
            except Exception:
                pass
            return "\n".join(info_lines)

        # ── Mouse Control ────────────────────────────────────────────────────
        elif verb == "mouse_pos":
            return mouse_get_pos()

        elif verb == "mouse_move":
            xy = arg.split()
            if len(xy) < 2:
                return "Usage: mouse_move <x> <y>"
            try:
                return mouse_move(int(xy[0]), int(xy[1]))
            except ValueError:
                return "Error: x and y must be integers."

        elif verb == "mouse_click":
            parts2 = arg.split()
            if len(parts2) < 2:
                return "Usage: mouse_click <x> <y> [left|right|middle]"
            try:
                btn = parts2[2].lower() if len(parts2) > 2 else "left"
                return mouse_click(int(parts2[0]), int(parts2[1]), btn)
            except ValueError:
                return "Error: x and y must be integers."

        elif verb == "mouse_dblclick":
            parts2 = arg.split()
            if len(parts2) < 2:
                return "Usage: mouse_dblclick <x> <y>"
            try:
                return mouse_click(int(parts2[0]), int(parts2[1]), "left", double=True)
            except ValueError:
                return "Error: x and y must be integers."

        elif verb == "mouse_scroll":
            parts2 = arg.split()
            direction = parts2[0] if parts2 else "down"
            amount    = int(parts2[1]) if len(parts2) > 1 and parts2[1].isdigit() else 3
            return mouse_scroll(direction, amount)

        elif verb == "mouse_drag":
            parts2 = arg.split()
            if len(parts2) < 4:
                return "Usage: mouse_drag <x1> <y1> <x2> <y2>"
            try:
                return mouse_drag(int(parts2[0]), int(parts2[1]), int(parts2[2]), int(parts2[3]))
            except ValueError:
                return "Error: coordinates must be integers."

        # ── Screen OCR ───────────────────────────────────────────────────────
        elif verb == "ocr":
            return _do_ocr()

        elif verb == "ocr_region":
            parts2 = arg.split()
            if len(parts2) < 4:
                return "Usage: ocr_region <x> <y> <w> <h>"
            try:
                return _do_ocr(tuple(int(p) for p in parts2[:4]))
            except ValueError:
                return "Error: coordinates must be integers."

        # ── Webcam Snapshot ──────────────────────────────────────────────────
        elif verb == "snap_webcam":
            idx = 0
            if arg.strip().isdigit():
                idx = int(arg.strip())
            return snap_webcam(camera_index=idx)
        # ── File Server ──────────────────────────────────────────────────────
        elif verb == "file_server_start":
            global _FILE_SERVER_THREAD, _FILE_SERVER_OBJ, _FILE_SERVER_DIR
            if _FILE_SERVER_THREAD and _FILE_SERVER_THREAD.is_alive():
                rc2, ts_ip2, _ = run_shell("tailscale ip -4")
                ip2 = ts_ip2.strip() if rc2 == 0 else "your-ip"
                return f"File server already running at http://{ip2}:{_FILE_SERVER_PORT}"
            folder = arg.strip().strip('"') or str(Path.home() / "Downloads")
            if not Path(folder).is_dir():
                return f"Folder not found: {folder}"
            _FILE_SERVER_DIR = folder
            _FILE_SERVER_OBJ    = HTTPServer(("0.0.0.0", _FILE_SERVER_PORT), _FileTransferHandler)
            _FILE_SERVER_THREAD = threading.Thread(target=_FILE_SERVER_OBJ.serve_forever, daemon=True)
            _FILE_SERVER_THREAD.start()
            rc2, ts_ip2, _ = run_shell("tailscale ip -4")
            ip2 = ts_ip2.strip() if rc2 == 0 else "your-tailscale-ip"
            return f"File server started at http://{ip2}:{_FILE_SERVER_PORT}  (serving: {folder})"

        elif verb == "file_server_stop":
            if _FILE_SERVER_OBJ:
                _FILE_SERVER_OBJ.shutdown()
                _FILE_SERVER_OBJ = _FILE_SERVER_THREAD = None
                return "File server stopped."
            return "File server was not running."

        elif verb == "file_server_status":
            running = _FILE_SERVER_THREAD and _FILE_SERVER_THREAD.is_alive()
            if running:
                rc2, ts_ip2, _ = run_shell("tailscale ip -4")
                ip2 = ts_ip2.strip() if rc2 == 0 else "your-tailscale-ip"
                return f"File server running at http://{ip2}:{_FILE_SERVER_PORT}  (folder: {_FILE_SERVER_DIR})"
            return "File server is not running."

        # ── Event Watchers ───────────────────────────────────────────────────
        elif verb == "watch_cpu":
            try:
                n = int(arg.replace("%",""))
                wid = _start_watcher("cpu", f"CPU > {n}%", lambda s, x=n: _w_cpu(x, s))
                return f"Watcher {wid} started: toast when CPU > {n}%."
            except ValueError:
                return "Usage: watch_cpu <threshold>"

        elif verb == "watch_ram":
            try:
                n = int(arg.replace("%",""))
                wid = _start_watcher("ram", f"RAM > {n}%", lambda s, x=n: _w_ram(x, s))
                return f"Watcher {wid} started: toast when RAM > {n}%."
            except ValueError:
                return "Usage: watch_ram <threshold>"

        elif verb == "watch_battery":
            try:
                n = int(arg.replace("%",""))
                wid = _start_watcher("battery", f"Battery < {n}%", lambda s, x=n: _w_battery(x, s))
                return f"Watcher {wid} started: toast when battery < {n}%."
            except ValueError:
                return "Usage: watch_battery <threshold>"

        elif verb == "watch_proc_start":
            if not arg:
                return "Usage: watch_proc_start <process_name>"
            wid = _start_watcher("proc_start", f"proc start: {arg}", lambda s, n=arg: _w_proc_start(n, s))
            return f"Watcher {wid}: toast when {arg} starts."

        elif verb == "watch_proc_stop":
            if not arg:
                return "Usage: watch_proc_stop <process_name>"
            wid = _start_watcher("proc_stop", f"proc stop: {arg}", lambda s, n=arg: _w_proc_stop(n, s))
            return f"Watcher {wid}: toast when {arg} exits."

        elif verb == "watch_file":
            if not arg:
                return "Usage: watch_file <path>"
            wid = _start_watcher("file", f"file: {arg}", lambda s, p=arg: _w_file(p, s))
            return f"Watcher {wid}: toast on changes to {arg}."

        elif verb == "watch_list":
            if not _WATCHER_REGISTRY:
                return "No active watchers."
            lines2 = [f"Active watchers:"]
            for wid, w in _WATCHER_REGISTRY.items():
                st = "Running" if w["thread"].is_alive() else "Dead"
                lines2.append(f"  {wid}: [{w['type']}] {w['desc']} — {st}")
            return "\n".join(lines2)

        # ── Audio Capture ─────────────────────────────────────────────────────
        elif verb == "record_audio":
            parts2 = arg.split(maxsplit=1)
            if not parts2 or not parts2[0].isdigit():
                return "Usage: record_audio <seconds> [name]"
            dur  = int(parts2[0])
            name = parts2[1].replace(" ","_") if len(parts2) > 1 else datetime.now().strftime("%Y%m%d_%H%M%S")
            _AUDIO_DIR.mkdir(parents=True, exist_ok=True)
            out  = _AUDIO_DIR / f"{name}.wav"
            rc2, method, err2 = _record_audio(out, dur)
            if out.exists() and out.stat().st_size > 0:
                return f"Recording saved: {out.name} ({out.stat().st_size//1024} KB) — use file_server_start to download."
            return f"Recording failed: {err2[:200] or 'no output produced.'}"

        # ── Azazil Agent Extensions (Jarvis Core) ─────────────────────────────
        elif verb == "routine":
            return _execute_routine(arg)

        elif verb in ("remember", "learn"):
            if not arg:
                return f"Usage: {verb} <fact, rule, or preference>"
            _memory_store_preference(arg)
            return f"🧠 Learned and memorized: '{arg}'"

        elif verb == "recall":
            if not arg:
                return "Usage: recall <query>"
            results = _memory_recall(arg, n_results=4)
            if not results:
                return f"No memories found matching '{arg}'."
            return "Recalled Memories:\n" + "\n".join(
                f"  • [{m['category']}] {m['text']} (relevance: {m.get('relevance', 1.0)})"
                for m in results
            )

        elif verb == "briefing":
            return _generate_briefing()

        elif verb == "speak":
            if not arg:
                return "Usage: speak <text>"
            return _speak(arg)

        else:
            return f"Unknown action: {verb}"

    except Exception as e:
        return f"Error: {e}"


class AntigravitySession:
    """Threaded persistent asyncio runner for Google Antigravity Agent lifecycle."""
    def __init__(self, api_key: str, model: str = _ANTIGRAVITY_MODEL):
        import asyncio
        import threading
        self.api_key = api_key
        self.model = model
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        self.agent = None
        f = asyncio.run_coroutine_threadsafe(self._init_agent(), self.loop)
        f.result(timeout=20)

    def _run_loop(self):
        import asyncio
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    async def _init_agent(self):
        import os
        try:
            from google.antigravity import Agent, LocalAgentConfig, CapabilitiesConfig
            from google.antigravity.hooks import policy
        except ImportError as _err:
            raise RuntimeError(
                f"Google Antigravity SDK not installed ({_err}). "
                "Install it with: pip install google-antigravity"
            ) from _err
        workspaces = [os.getcwd(), str(Path.home())]
        def list_desktop_windows() -> str:
            """Lists all open visible application windows on the desktop with titles, process names, and PIDs."""
            wins = get_visible_windows()
            if not wins:
                return "No open desktop windows found."
            return "Open Windows:\n" + "\n".join(f"PID {w['pid']} | {w['pname']} | \"{w['title']}\"" for w in wins)

        def control_desktop_window(action: str, target: str) -> str:
            """Controls a desktop window. Action must be 'focus', 'minimize', 'maximize', 'restore', or 'close'. Target is the window title, PID, or process name."""
            act = action.lower().strip()
            if act == "focus":
                ok, msg = focus_window(target)
                return msg
            elif act in ("min", "minimize"):
                ok, msg = minimize_window(target)
                return msg
            elif act in ("max", "maximize"):
                ok, msg = maximize_window(target)
                return msg
            elif act == "restore":
                ok, msg = restore_window(target)
                return msg
            elif act == "close":
                ok, msg = close_window(target)
                return msg
            return f"Unknown window action: {action}."

        def control_browser(action: str, url_or_keys: str = "") -> str:
            """Controls the web browser. Action must be 'new_tab' (optional url), 'close_tab', 'next_tab', 'prev_tab', 'refresh', 'scroll_down', 'scroll_up', 'back', 'forward'."""
            return browser_nav_action(action, url_or_keys)

        def send_keystrokes(keys: str, target: str = "") -> str:
            """Sends keystrokes to a target window or active window. Example keys: '^t' (Ctrl+T), '^w' (Ctrl+W), '{F5}', '{ENTER}'."""
            return send_keys_desktop(keys, target or None)

        def play_local_music(query: str = "") -> str:
            """Plays music from the local Music folder via VLC or MusicBee. Never launch Spotify. If query is provided, searches and plays matching tracks; otherwise shuffles all tracks."""
            return _agent_exec(f"ACTION: play_music {query}".strip())

        def stop_local_music() -> str:
            """Stops local music playback (terminates VLC / MusicBee)."""
            return _agent_exec("ACTION: stop_music")

        config = LocalAgentConfig(
            api_key=self.api_key,
            model=self.model,
            workspaces=workspaces,
            policies=[policy.allow_all()],
            tools=[list_desktop_windows, control_desktop_window, control_browser, send_keystrokes, play_local_music, stop_local_music],
            system_instructions="You are Antigravity, an autonomous agent and PC administrator embedded into RemotePC. You have full access to system tools, window and browser controls, file operations, command execution, and music playback. When asked to play music or songs, always use play_local_music to play audio tracks from the local Music folder. Never use or launch Spotify.",
            capabilities=CapabilitiesConfig()
        )
        self.agent = Agent(config)
        await self.agent.__aenter__()

    def chat(self, prompt: str, on_tool=None):
        import asyncio
        f = asyncio.run_coroutine_threadsafe(self._chat_coro(prompt, on_tool), self.loop)
        return f.result(timeout=180)

    async def _chat_coro(self, prompt: str, on_tool=None):
        resp = await self.agent.chat(prompt)
        async for chunk in resp.chunks:
            if hasattr(chunk, 'name') and on_tool:
                on_tool(chunk.name, getattr(chunk, 'args', {}))
        return await resp.text()

    def close(self):
        import asyncio
        if self.agent:
            try:
                f = asyncio.run_coroutine_threadsafe(self.agent.__aexit__(None, None, None), self.loop)
                f.result(timeout=5)
            except Exception:
                pass
        self.loop.call_soon_threadsafe(self.loop.stop)


def ai_agent():
    print_header("\U0001f916  AI Agent  (Gemini)")
    if not _GEMINI_API_KEY or _GEMINI_API_KEY == "YOUR_API_KEY_HERE":
        console.print(
            f"[{ERROR}]No Gemini API key set!\n"
            f"Run the setup wizard ([bold]python remotepc/setup_wizard.py[/bold]) or set the\n"
            f"[bold]gemini_api_key[/bold] field in your remotepc config file.[/{ERROR}]\n"
            f"  Get one free at: [link=https://aistudio.google.com/apikey]aistudio.google.com/apikey[/link]\n"
            f"  [dim]Tip: you can still chat using a local LM Studio model via /model.[/dim]"
        )
        pause(); return

    try:
        import google.genai as genai
        from google.genai import types as genai_types
    except ImportError:
        console.print(f"[{ERROR}]Missing SDK. Run: pip install google-genai[/{ERROR}]")
        pause(); return

    try:
        client = genai.Client(api_key=_GEMINI_API_KEY)
        chat   = client.chats.create(
            model=_GEMINI_MODEL,
            config=genai_types.GenerateContentConfig(
                system_instruction=_get_agent_system_prompt(is_local=False),
                temperature=0.7,
            )
        )
    except Exception as e:
        console.print(Panel(
            f"[{ERROR}]Failed to initialise Gemini client:[/{ERROR}]\n[bold]{e}[/bold]\n\n"
            f"[dim]Things to check:[/dim]\n"
            f"  1. API key in [bold]_GEMINI_API_KEY[/bold] is correct (get one at aistudio.google.com/apikey)\n"
            f"  2. You have billing or free-tier access enabled\n"
            f"  3. Model '[bold]{_GEMINI_MODEL}[/bold]' is available in your region\n"
            f"  4. Internet is reachable\n\n"
            f"[dim]Tip: Type '/model' inside the agent to switch to a different model.[/dim]",
            border_style="red", box=PANEL_BOX, title="[bold red]Agent Init Failed[/bold red]"
        ))
        pause(); return

    # State container so retry/fallback can replace active chat, model, and local history
    model_state = [_GEMINI_MODEL, chat, []]
    antigravity_session = None
    safe_mode = True
    confirm_mode = False

    def _sync_to_local_history():
        """Extract existing conversation history from Gemini chat into standard messages format."""
        msgs = []
        try:
            for c in model_state[1].get_history():
                role = "assistant" if c.role == "model" else "user"
                text = "".join(part.text for part in c.parts if hasattr(part, "text") and part.text)
                if text:
                    msgs.append({"role": role, "content": text})
        except Exception:
            pass
        return msgs

    def _trim_history(max_turns: int = 8):
        """Trim Gemini chat history to the last N turn-pairs to prevent unbounded context growth."""
        if model_state[0] in _LOCAL_MODEL_MAP:
            # Local model: tighter context window (4 turn pairs max) to avoid choking small models
            local_max = min(max_turns, 4)
            if len(model_state[2]) > local_max * 2:
                model_state[2] = model_state[2][-(local_max * 2):]
            return
        try:
            history = model_state[1].get_history()
            if len(history) > max_turns * 2:
                # Keep only the last max_turns pairs; rebuild chat with trimmed history
                trimmed = history[-(max_turns * 2):]
                model_state[1] = client.chats.create(
                    model=model_state[0],
                    config=genai_types.GenerateContentConfig(
                        system_instruction=_get_agent_system_prompt(is_local=False),
                        temperature=0.7,
                    ),
                    history=trimmed,
                )
        except Exception:
            pass

    def _chat_send(msg: str) -> str:
        """Send message to active model. If rate-limited (429), instantly switch to next model in cascade."""
        nonlocal safe_mode
        for _ in range(len(_MODEL_CASCADE)):
            curr_model = model_state[0]

            # 1. Local LM Studio Backend
            if curr_model in _LOCAL_MODEL_MAP:
                try:
                    model_state[2].append({"role": "user", "content": msg})
                    lms_target = _LOCAL_MODEL_MAP[curr_model]

                    thought_started = [False]
                    def _cli_on_thought(chunk: str):
                        if not thought_started[0]:
                            thought_started[0] = True
                            console.print("\n  [bold magenta]💭 Thinking:[/bold magenta] ", end="")
                        console.print(chunk, style="dim magenta", end="", markup=False)

                    try:
                        reply = _query_local_lms(
                            model_state[2],
                            _get_agent_system_prompt(is_local=True),
                            model_name=lms_target,
                            on_thought=_cli_on_thought
                        )
                    finally:
                        if thought_started[0]:
                            console.print("\n")

                    model_state[2].append({"role": "assistant", "content": reply})
                    return reply
                except Exception as e:
                    console.print(f"  [{ERROR}]Local LM Studio error ({curr_model}): {escape(str(e))}[/{ERROR}]")
                    # Fallback back to cloud / next model if local model fails
                    curr_idx = _MODEL_CASCADE.index(curr_model) if curr_model in _MODEL_CASCADE else len(_MODEL_CASCADE) - 1
                    next_model = _MODEL_CASCADE[(curr_idx + 1) % len(_MODEL_CASCADE)]
                    console.print(f"  [{WARN}]Switching to [bold]{next_model}[/bold]...[/{WARN}]")
                    model_state[0] = next_model
                    if next_model not in _LOCAL_MODEL_MAP:
                        model_state[1] = client.chats.create(
                            model=next_model,
                            config=genai_types.GenerateContentConfig(
                                system_instruction=_get_agent_system_prompt(is_local=False),
                                temperature=0.7,
                            )
                        )
                    continue

            # 2. Gemini Cloud Backend
            try:
                active_chat = model_state[1]
                resp = active_chat.send_message(msg)
                return (resp.text or "").strip()
            except Exception as e:
                err = str(e).lower()
                is_rate = any(k in err for k in ("429", "resource_exhausted", "quota", "rate limit", "too many requests"))
                if is_rate:
                    curr_idx = _MODEL_CASCADE.index(curr_model) if curr_model in _MODEL_CASCADE else 0
                    next_model = _MODEL_CASCADE[(curr_idx + 1) % len(_MODEL_CASCADE)]

                    if next_model in _LOCAL_MODEL_MAP:
                        target_name = _LOCAL_MODEL_MAP[next_model]
                        console.print(f"  [{WARN}]Cloud rate limits reached on [bold]{curr_model}[/bold]! Switching to LOCAL [bold cyan]{target_name}[/bold cyan] (SafeMode Enforced)...[/{WARN}]")
                        model_state[0] = next_model
                        model_state[2] = _sync_to_local_history()
                        safe_mode = True
                        time.sleep(0.3)
                        continue
                    else:
                        console.print(f"  [{WARN}]Rate limit on [bold]{curr_model}[/bold]! Switching immediately to [bold green]{next_model}[/bold green]...[/{WARN}]")
                        try:
                            history = model_state[1].get_history()
                        except Exception:
                            history = None
                        new_chat = client.chats.create(
                            model=next_model,
                            config=genai_types.GenerateContentConfig(
                                system_instruction=_get_agent_system_prompt(is_local=False),
                                temperature=0.7,
                            ),
                            history=history
                        )
                        model_state[0] = next_model
                        model_state[1] = new_chat
                        time.sleep(0.3)
                        continue
                else:
                    raise e

        # Last resort: all models in pool were rate-limited — do NOT recurse
        raise RuntimeError("All models in the cascade are currently rate-limited. Wait a minute and try again.")

    safe_str = (
        "[bold green]ENABLED (destructive commands blocked/confirmed)[/bold green]"
        if safe_mode else
        "[bold yellow]DISABLED[/bold yellow]"
    )
    prof = _load_profile()
    pname = prof.get("personality", {}).get("name", _ASSISTANT_NAME)
    m_count = _memory_count()
    console.print(
        f"  [{ACCENT}]Agent:[/{ACCENT}] [bold]{pname}[/bold] (online, {m_count} vector memories)\n"
        f"  [{ACCENT}]Model:[/{ACCENT}] {model_state[0]}\n"
        f"  [{ACCENT}]Safe Mode:[/{ACCENT}] {safe_str}\n"
        f"  [{DIM}]Talk naturally with {pname}. Type 'back' to exit.[/{DIM}]\n"
        f"  [{DIM}]Commands: '/briefing' '/routine' '/remember' '/memories' '/profile' '/safemode' '/model' '/status'[/{DIM}]\n"
    )

    while True:
        try:
            badges = []
            if safe_mode:
                badges.append("[bold cyan][SAFE][/bold cyan]")
            if confirm_mode:
                badges.append("[bold yellow][CONFIRM][/bold yellow]")
            badge_str = (" ".join(badges) + " ") if badges else ""
            user_input = Prompt.ask(f"\n{badge_str}[bold green]you[/bold green]").strip()
        except KeyboardInterrupt:
            break
        if user_input.lower() in ("back", "exit", "q", "bye"):
            break
        if not user_input:
            continue

        # Slash commands
        if user_input.lower() in ("/safemode", "safemode"):
            safe_mode = not safe_mode
            st = "[bold green]ENABLED[/bold green] (blocks vital process kills & dangerous deletes)" if safe_mode else "[bold red]DISABLED (raw execution)[/bold red]"
            console.print(f"  [{INFO}]Safe Mode is now: {st}[/{INFO}]")
            continue
        elif user_input.lower() in ("/confirm", "confirm"):
            confirm_mode = not confirm_mode
            status_text = "[bold yellow]ON[/bold yellow] (will ask before running each action)" if confirm_mode else "[bold green]OFF[/bold green] (auto-execute)"
            console.print(f"  [{INFO}]Confirmation mode: {status_text}[/{INFO}]")
            continue
        elif user_input.lower() in ("/auto", "auto"):
            confirm_mode = False
            console.print(f"  [{INFO}]Auto-execution mode enabled.[/{INFO}]")
            continue
        elif user_input.lower() in ("/briefing", "briefing"):
            briefing_text = _generate_briefing()
            console.print(Panel(
                briefing_text,
                title=f"[bold cyan]🧠 {pname} System Briefing[/bold cyan]",
                border_style="cyan", box=PANEL_BOX
            ))
            continue
        elif user_input.lower().startswith(("/routine", "routine")):
            parts = user_input.split(maxsplit=1)
            routine_name = parts[1].strip() if len(parts) > 1 else "good_morning"
            out = _execute_routine(routine_name)
            console.print(Panel(
                out,
                title=f"[bold green]⚡ Routine: {routine_name}[/bold green]",
                border_style="green", box=PANEL_BOX
            ))
            continue
        elif user_input.lower().startswith(("/remember", "remember", "/learn", "learn")):
            parts = user_input.split(maxsplit=1)
            if len(parts) < 2:
                console.print(f"[{WARN}]Usage: /learn <fact, preference or rule to memorize>[/{WARN}]")
            else:
                fact = parts[1].strip()
                _memory_store_preference(fact)
                console.print(f"[{SUCCESS}]🧠 Learned & Stored in Vector Memory: '{fact}'[/{SUCCESS}]")
            continue
        elif user_input.lower() in ("/dataset", "dataset", "/flywheel", "flywheel"):
            st = _get_soup_dataset_stats()
            console.print(Panel(
                f"[bold cyan]Harvested Samples:[/] {st.get('samples', 0)} interaction turn(s)\n"
                f"[bold cyan]Action Turns:[/]     {st.get('actions_count', 0)}\n"
                f"[bold cyan]Dataset Size:[/]     {st.get('size_kb', 0)} KB\n"
                f"[bold cyan]Avg Tokens/Sample:[/] ~{st.get('avg_tokens', 0)}\n"
                f"[bold cyan]File Location:[/]    {st.get('path', 'N/A')}\n"
                f"[bold cyan]Training Status:[/]  [bold green]{st.get('status', 'Ready')}[/bold green]\n\n"
                f"[dim]Tip: Type '/train' to validate the dataset with soup-cli and view fine-tuning commands.[/dim]",
                title=f"[bold green]🍜 {pname} soup-cli Learning Flywheel[/bold green]",
                border_style="green", box=PANEL_BOX
            ))
            continue
        elif user_input.lower().startswith(("/train", "train")):
            st = _get_soup_dataset_stats()
            sft_path = st.get('path')
            if not sft_path or st.get('samples', 0) == 0:
                console.print(f"[{WARN}]No training samples in dataset yet. Talk to {pname} or use /learn to accumulate data.[/{WARN}]")
                continue
            console.print(Panel(
                f"Continuous Flywheel contains [bold green]{st.get('samples')}[/bold green] training samples ({st.get('size_kb')} KB).\n\n"
                f"[bold cyan]Recommended soup fine-tuning recipes for your RTX 2050 (4GB VRAM):[/bold cyan]\n"
                f"  1. [bold yellow]soup train --recipe qwen2.5-coder-1.5b-sft --data \"{sft_path}\"[/bold yellow]\n"
                f"  2. [bold yellow]soup train --recipe deepseek-r1-distill-qwen-1.5b-sft --data \"{sft_path}\"[/bold yellow]\n"
                f"  3. [bold yellow]soup train --recipe smollm2-135m-instruct --data \"{sft_path}\"[/bold yellow]\n\n"
                f"[dim]Tip: You can run 'soup data stats \"{sft_path}\"' in a separate terminal to view character length distributions.[/dim]",
                title="[bold magenta]🍜 soup-cli Fine-Tuning Pipeline[/bold magenta]",
                border_style="magenta", box=PANEL_BOX
            ))
            continue
        elif user_input.lower() in ("/memories", "memories"):
            m_count = _memory_count()
            recalled = _memory_recall("user habit preference command", n_results=5)
            lines = [f"[bold {ACCENT}]Total Vector Memories Stored:[/{ACCENT}] {m_count}\n"]
            if recalled:
                lines.append("[dim]Recent / Sample Memories:[/dim]")
                for m in recalled:
                    lines.append(f"  • [{m['category']}] {m['text']} [dim](relevance: {m.get('relevance', 1.0)})[/dim]")
            else:
                lines.append(f"[dim]No memories stored yet. Talk to {pname} or use /remember to add memories.[/dim]")
            console.print(Panel(
                "\n".join(lines),
                title=f"[bold magenta]🧠 {pname} Long-Term Memory (ChromaDB)[/bold magenta]",
                border_style="magenta", box=PANEL_BOX
            ))
            continue
        elif user_input.lower() in ("/profile", "profile"):
            prof = _load_profile()
            owner = prof.get("owner", {})
            personality = prof.get("personality", {})
            mem = prof.get("memory", {})
            routines = prof.get("routines", {})
            info = (
                f"[bold cyan]Owner:[/] {owner.get('name')} ('{owner.get('nickname')}')  "
                f"[bold cyan]Timezone:[/] {owner.get('timezone')}\n"
                f"[bold cyan]Personality:[/] {personality.get('name')} ({personality.get('style')})  "
                f"[bold cyan]Traits:[/] {', '.join(personality.get('traits', []))}\n"
                f"[bold cyan]Total Sessions:[/] {mem.get('total_sessions', 0)}  "
                f"[bold cyan]Total Commands:[/] {mem.get('total_commands', 0)}\n"
                f"[bold cyan]Active Routines:[/] {', '.join(routines.keys())}\n"
                f"[bold cyan]Vector Memory Count:[/] {_memory_count()}"
            )
            console.print(Panel(
                info,
                title=f"[bold cyan]👤 {personality.get('name', _ASSISTANT_NAME)} Profile & Intelligence Stats[/bold cyan]",
                border_style="cyan", box=PANEL_BOX
            ))
            continue
        elif user_input.lower() in ("/export", "export", "/soup", "soup"):
            res = _export_soup_dataset()
            console.print(f"  [{SUCCESS}]🍜 {res}[/{SUCCESS}]")
            continue
        elif user_input.lower() in ("/clear", "clear"):
            if model_state[0] == _ANTIGRAVITY_KEY:
                if antigravity_session:
                    try:
                        antigravity_session.close()
                    except Exception:
                        pass
                antigravity_session = AntigravitySession(api_key=_GEMINI_API_KEY)
                console.print(f"  [{INFO}]Antigravity agent session reset.[/{INFO}]")
                continue
            elif model_state[0] in _LOCAL_MODEL_MAP:
                model_state[2] = []
            else:
                model_state[1] = client.chats.create(
                    model=model_state[0],
                    config=genai_types.GenerateContentConfig(
                        system_instruction=_get_agent_system_prompt(is_local=False),
                        temperature=0.7,
                    )
                )
            console.print(f"  [{INFO}]Chat session reset.[/{INFO}]")
            continue
        elif user_input.lower() in ("/status", "status"):
            history_len = 0
            try:
                if model_state[0] in _LOCAL_MODEL_MAP:
                    history_len = len(model_state[2])
                else:
                    history_len = len(model_state[1].get_history())
            except Exception:
                pass
            console.print(Panel(
                f"[{ACCENT}]Model:[/{ACCENT}]     [bold]{model_state[0]}[/bold]\n"
                f"[{ACCENT}]Safe Mode:[/{ACCENT}] {'[green]ON[/green]' if safe_mode else '[red]OFF[/red]'}\n"
                f"[{ACCENT}]Confirm:[/{ACCENT}]   {'[yellow]ON (prompt before every action)[/yellow]' if confirm_mode else '[dim]OFF[/dim]'}\n"
                f"[{ACCENT}]Memories:[/{ACCENT}]  {_memory_count()} in ChromaDB\n"
                f"[{ACCENT}]History:[/{ACCENT}]   {history_len} message(s) in context\n"
                f"[{ACCENT}]Max Steps:[/{ACCENT}] {_AGENT_MAX_STEPS} per turn",
                title="[bold cyan]Agent Status[/bold cyan]",
                border_style="cyan", box=PANEL_BOX
            ))
            continue
        elif user_input.lower() in ("/model", "model"):
            console.print(f"  [{ACCENT}]Active Model:[/{ACCENT}] [bold]{model_state[0]}[/bold]\n")
            # Build the menu dynamically from the configured cloud + local models.
            _menu = []
            for _gm in _GEMINI_MODELS:
                _menu.append((_gm, f"[bold]{_gm}[/bold] [dim](cloud)[/dim]"))
            for _lm in _LOCAL_MODELS:
                _label = _lm.get("label") or _lm["name"]
                _menu.append((_lm["key"], f"[bold]{_label}[/bold] [dim](local · {_lm['name']}) — 0 rate limits[/dim]"))
            _menu.append((_ANTIGRAVITY_KEY, "[bold magenta]Google Antigravity Engine[/bold magenta] [dim](autonomous tools & coding)[/dim]"))
            for _i, (_mid, _lbl) in enumerate(_menu, 1):
                _marker = " [green]← active[/green]" if _mid == model_state[0] else ""
                console.print(f"  [cyan]{_i}[/cyan] - {_lbl}{_marker}")
            if not _GEMINI_MODELS and not _LOCAL_MODELS:
                console.print(f"  [dim]Tip: add local LM Studio models with: python remotepc/setup_wizard.py[/dim]")
            _choices = [str(i) for i in range(1, len(_menu) + 1)]
            sel = Prompt.ask(f"  Select model [1-{len(_menu)}]", choices=_choices, default="1")
            chosen = _menu[int(sel) - 1][0]
            if chosen == _ANTIGRAVITY_KEY:
                if antigravity_session is None:
                    try:
                        with console.status("[dim]Initializing Antigravity Engine...[/dim]", spinner="dots"):
                            antigravity_session = AntigravitySession(api_key=_GEMINI_API_KEY)
                    except Exception as _ag_e:
                        console.print(f"[{ERROR}]Antigravity init failed: {_ag_e}[/{ERROR}]")
                        continue
                model_state[0] = _ANTIGRAVITY_KEY
                console.print(f"  [{SUCCESS}]Switched to Antigravity Autonomous Agent.[/{SUCCESS}]")
                continue
            elif chosen in _LOCAL_MODEL_MAP:
                model_state[2] = _sync_to_local_history()
                safe_mode = True
                console.print(f"  [{INFO}]Safe Mode automatically enforced for local model.[/{INFO}]")
            else:
                model_state[1] = client.chats.create(
                    model=chosen,
                    config=genai_types.GenerateContentConfig(
                        system_instruction=_get_agent_system_prompt(is_local=False),
                        temperature=0.7,
                    )
                )
            model_state[0] = chosen
            console.print(f"  [{SUCCESS}]Switched to {model_state[0]}.[/{SUCCESS}]")
            continue

        # Antigravity Autonomous Dispatch
        if model_state[0] == _ANTIGRAVITY_KEY:
            if antigravity_session is None:
                try:
                    with console.status("[dim]Initializing Antigravity Engine...[/dim]", spinner="dots"):
                        antigravity_session = AntigravitySession(api_key=_GEMINI_API_KEY)
                except Exception as _ag_e:
                    console.print(f"[{ERROR}]Antigravity init failed: {_ag_e}[/{ERROR}]")
                    model_state[0] = _GEMINI_MODEL  # fall back to default Gemini model
                    continue

            def _on_tool(name, args):
                args_str = json.dumps(args, default=str)
                if len(args_str) > 120:
                    args_str = args_str[:120] + "..."
                console.print(f"  [bold magenta]🔧 Antigravity Tool:[/bold magenta] [bold green]{name}[/bold green] [dim]({args_str})[/dim]")
                _log_command("antigravity_tool", name, args_str)

            try:
                with console.status(f"[dim]Antigravity thinking & executing...[/dim]", spinner="dots"):
                    reply = antigravity_session.chat(user_input, on_tool=_on_tool)
            except Exception as e:
                console.print(f"[{ERROR}]Antigravity error: {e}[/{ERROR}]")
                continue

            if reply:
                console.print(Panel(
                    reply,
                    title=f"[bold magenta]Antigravity Agent ({_ANTIGRAVITY_MODEL})[/bold magenta]",
                    border_style="magenta", box=PANEL_BOX
                ))
            continue

        # ReAct Agent Feedback Loop (Iterative: Action -> Observation -> Next Step)
        grounding_blocks = []
        try:
            telemetry_str = _gather_live_telemetry_grounding()
            if telemetry_str:
                grounding_blocks.append(telemetry_str)
        except Exception:
            pass

        try:
            learning_block = _build_learning_grounding(user_input)
            if learning_block:
                grounding_blocks.append(learning_block)
        except Exception:
            pass

        if grounding_blocks:
            context_prefix = "\n\n".join(grounding_blocks)
            current_input = f"{context_prefix}\n\n[User Command / Question]:\n{user_input}"
        else:
            current_input = user_input

        step_count = 0
        max_steps = _AGENT_MAX_STEPS
        executed_actions = []

        while step_count < max_steps:
            step_count += 1
            try:
                if model_state[0] in _LOCAL_MODEL_MAP:
                    reply = _chat_send(current_input)
                else:
                    with console.status(f"[dim]Thinking ({model_state[0]})...[/dim]", spinner="dots"):
                        reply = _chat_send(current_input)
            except Exception as e:
                console.print(f"[{ERROR}]Model error: {escape(str(e))}[/{ERROR}]")
                break

            if not reply:
                console.print(f"[{WARN}]No response from model.[/{WARN}]")
                break

            # Separate ACTION lines from conversational prose (robust regex matching)
            action_lines = []
            prose_lines  = []
            for raw_line in reply.splitlines():
                stripped = raw_line.strip()
                # Matches: ACTION: foo, action: foo, `ACTION: foo`, **ACTION:** foo, **ACTION: foo**
                m = re.match(r"^[`*_\s]*(?:action|ACTION)[`*_\s]*:\s*(.+?)[`*_\s]*$", stripped, re.IGNORECASE)
                if m:
                    action_cmd = m.group(1).strip().strip("`*_ ")
                    action_lines.append(f"ACTION: {action_cmd}")
                else:
                    prose_lines.append(raw_line)

            # Fallback: if model wrapped ACTION inline or in backticks
            if not action_lines:
                inline = re.findall(r"(?:^|\n)[`*_\s]*(?:action|ACTION)[`*_\s]*:\s*([^\r\n`*]+)", reply, re.IGNORECASE)
                for a in inline:
                    cleaned = a.strip().strip("`*_ ")
                    if cleaned:
                        action_lines.append(f"ACTION: {cleaned}")

            prose = "\n".join(prose_lines).strip()
            if prose:
                console.print(Panel(
                    prose,
                    title=f"[bold {ACCENT}]Assistant ({model_state[0]})[/bold {ACCENT}]",
                    border_style=ACCENT, box=PANEL_BOX
                ))

            # If no actions were requested, agent has delivered its final response
            if not action_lines:
                _learn_from_interaction(user_input, prose or reply, actions=executed_actions)
                break

            # Execute action(s) with Safe Mode Guardrails
            observations = []
            for action in action_lines:
                # ─── Safe Mode Policy Evaluation ───
                verdict, reason = _check_safe_mode(action, is_safe_mode=safe_mode)

                if verdict == "BLOCK":
                    console.print(f"  [{ERROR}]🛡️ [bold]SAFE MODE BLOCKED:[/bold] {reason}[/{ERROR}]")
                    observations.append(f"OBSERVATION for '{action}': BLOCKED by Safe Mode ({reason}).")
                    continue

                if verdict == "CONFIRM" or confirm_mode:
                    prompt_label = f"  [bold red]🛡️ SAFE MODE CONFIRMATION[/bold red]: {reason}. Allow?"
                    allow = Confirm.ask(prompt_label, default=False)
                    if not allow:
                        console.print(f"  [{WARN}]Skipped: {action}[/{WARN}]")
                        observations.append(f"OBSERVATION for '{action}': Canceled by user via Safe Mode.")
                        continue

                executed_actions.append(action)
                result = _agent_exec(action)
                _log_command("ai_agent", action, result)
                console.print(f"  [{SUCCESS}]✓ {action}[/{SUCCESS}]")

                if result:
                    preview = result[:160].replace("\n", " ") + ("..." if len(result) > 160 else "")
                    console.print(f"    [{DIM}]→ {preview}[/{DIM}]")

                max_obs = 350 if model_state[0] in _LOCAL_MODEL_MAP else 600
                observations.append(f"OBSERVATION for '{action}':\n{result[:max_obs]}")

            if not observations:
                _learn_from_interaction(user_input, prose or reply, actions=executed_actions)
                break

            # Pacing delay between agent steps to avoid tripping burst limits
            time.sleep(0.8)

            # Trim history every 4 steps to prevent runaway context growth
            if step_count % 4 == 0:
                _trim_history()

            # Feed observations back to model so it actually gets the response
            current_input = "\n\n".join(observations)

    # ── Cleanup on exit ──────────────────────────────────────────────────────
    if antigravity_session:
        try:
            antigravity_session.close()
        except Exception:
            pass
    if model_state[0] in _LOCAL_MODEL_MAP:
        target_name = _LOCAL_MODEL_MAP[model_state[0]]
        console.print(f"  [{DIM}]Unloading local model ({target_name}) from LM Studio...[/{DIM}]")
        rc, out, err = _lms(f'unload "{target_name}"')
        if rc == 0:
            console.print(f"  [{SUCCESS}]Local model unloaded. VRAM freed.[/{SUCCESS}]")
        else:
            # Non-fatal — model may already be unloaded or server may be stopped
            console.print(f"  [{DIM}]Note: could not unload model ({(err or out).strip()[:80]})[/{DIM}]")



# ═══════════════════════════════════════════════════════════════
# 25. MOUSE CONTROL
# ═══════════════════════════════════════════════════════════════

_MOUSE_TYPE_DEF = r"""
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class RemoteMouse {
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint dwFlags, int dx, int dy, int dwData, IntPtr dwExtraInfo);
    public const uint LEFTDOWN   = 0x0002;
    public const uint LEFTUP     = 0x0004;
    public const uint RIGHTDOWN  = 0x0008;
    public const uint RIGHTUP    = 0x0010;
    public const uint MIDDLEDOWN = 0x0020;
    public const uint MIDDLEUP   = 0x0040;
    public const uint WHEEL      = 0x0800;
}
'@
"""

def _mouse_ps_exec(ps_body: str) -> None:
    """Execute a mouse-control PowerShell script via the interactive scheduled task."""
    ps_file = Path.home() / "AppData" / "Local" / "Temp" / "remotepc_mouse.ps1"
    ps_file.write_text(ps_body, encoding="utf-8")
    if _ensure_gui_launcher_task():
        _GUI_LAUNCHER_CMD.write_text(
            f'@echo off\r\npowershell -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File "{ps_file}"\r\nexit /b 0\r\n',
            encoding="utf-8"
        )
        run_shell(f'schtasks /run /tn "{_GUI_TASK_NAME}"')
        time.sleep(0.35)
    else:
        encoded = base64.b64encode(ps_body.encode("utf-16le")).decode("ascii")
        run_shell(f'powershell -NoProfile -NonInteractive -EncodedCommand {encoded}')

def mouse_move(x: int, y: int) -> str:
    """Move the mouse cursor to absolute desktop coordinates."""
    ps = f"{_MOUSE_TYPE_DEF}\n[RemoteMouse]::SetCursorPos({x}, {y}) | Out-Null"
    _mouse_ps_exec(ps)
    return f"Mouse moved to ({x}, {y})."

def mouse_click(x: int, y: int, button: str = "left", double: bool = False) -> str:
    """Click the mouse at the given coordinates."""
    btn_map = {
        "left":   ("LEFTDOWN",   "LEFTUP"),
        "right":  ("RIGHTDOWN",  "RIGHTUP"),
        "middle": ("MIDDLEDOWN", "MIDDLEUP"),
    }
    dn, up = btn_map.get(button, ("LEFTDOWN", "LEFTUP"))
    reps = 2 if double else 1
    click_lines = "\n".join(
        f"[RemoteMouse]::mouse_event([RemoteMouse]::{dn}, 0, 0, 0, [IntPtr]::Zero)\n"
        f"Start-Sleep -Milliseconds 60\n"
        f"[RemoteMouse]::mouse_event([RemoteMouse]::{up}, 0, 0, 0, [IntPtr]::Zero)\n"
        f"Start-Sleep -Milliseconds 80"
        for _ in range(reps)
    )
    ps = (
        f"{_MOUSE_TYPE_DEF}\n"
        f"[RemoteMouse]::SetCursorPos({x}, {y}) | Out-Null\n"
        f"Start-Sleep -Milliseconds 120\n"
        f"{click_lines}"
    )
    _mouse_ps_exec(ps)
    label = ("double-" if double else "") + button
    return f"{label.capitalize()} click at ({x}, {y})."

def mouse_scroll(direction: str, amount: int = 3) -> str:
    """Scroll the mouse wheel up or down."""
    delta = 120 * amount * (1 if direction.lower() == "up" else -1)
    ps = f"{_MOUSE_TYPE_DEF}\n[RemoteMouse]::mouse_event([RemoteMouse]::WHEEL, 0, 0, {delta}, [IntPtr]::Zero)"
    _mouse_ps_exec(ps)
    return f"Scrolled {direction} by {amount} notches."

def mouse_drag(x1: int, y1: int, x2: int, y2: int) -> str:
    """Drag from (x1,y1) to (x2,y2) with left button held."""
    ps = (
        f"{_MOUSE_TYPE_DEF}\n"
        f"[RemoteMouse]::SetCursorPos({x1}, {y1}) | Out-Null\n"
        f"Start-Sleep -Milliseconds 100\n"
        f"[RemoteMouse]::mouse_event([RemoteMouse]::LEFTDOWN, 0, 0, 0, [IntPtr]::Zero)\n"
        f"Start-Sleep -Milliseconds 80\n"
        f"$steps = 25\n"
        f"for ($i = 1; $i -le $steps; $i++) {{\n"
        f"    [RemoteMouse]::SetCursorPos([int]({x1} + $i * ({x2} - {x1}) / $steps), "
        f"[int]({y1} + $i * ({y2} - {y1}) / $steps)) | Out-Null\n"
        f"    Start-Sleep -Milliseconds 12\n"
        f"}}\n"
        f"Start-Sleep -Milliseconds 80\n"
        f"[RemoteMouse]::mouse_event([RemoteMouse]::LEFTUP, 0, 0, 0, [IntPtr]::Zero)"
    )
    _mouse_ps_exec(ps)
    return f"Dragged ({x1},{y1}) → ({x2},{y2})."

def mouse_get_pos() -> str:
    """Return the current mouse cursor position."""
    rc, out, _ = run_shell(
        'powershell -NoProfile -NonInteractive -Command '
        '"Add-Type -AssemblyName System.Windows.Forms; '
        '$p=[System.Windows.Forms.Cursor]::Position; '
        'Write-Output ($p.X.ToString() + \',\' + $p.Y.ToString())"'
    )
    if rc == 0 and "," in (out or ""):
        x, y = out.strip().split(",", 1)
        return f"Cursor position: ({x.strip()}, {y.strip()})"
    return "Could not read cursor position."

def mouse_control_menu():
    print_header("🖱️  Mouse Control")
    console.print(
        "  Control your desktop mouse from the phone. Use screenshot (menu 11)\n"
        "  to see the screen and find coordinates.\n\n"
        "  [bold cyan]pos[/bold cyan]                              Current cursor position\n"
        "  [bold cyan]move <x> <y>[/bold cyan]                     Move cursor\n"
        "  [bold cyan]click <x> <y> [left|right|middle][/bold cyan]  Click at coordinates\n"
        "  [bold cyan]dblclick <x> <y>[/bold cyan]                 Double-click\n"
        "  [bold cyan]scroll <up|down> [amount][/bold cyan]        Scroll wheel\n"
        "  [bold cyan]drag <x1> <y1> <x2> <y2>[/bold cyan]         Click-and-drag\n"
        "  [bold cyan]back[/bold cyan]                              Return\n"
    )
    while True:
        cmd   = Prompt.ask(f"[{ACCENT}]mouse[/{ACCENT}]").strip()
        parts = cmd.split()
        a     = parts[0].lower() if parts else ""
        if a in ("back", "exit", "q"):
            break
        elif a == "pos":
            console.print(f"[{SUCCESS}]{mouse_get_pos()}[/{SUCCESS}]")
        elif a == "move":
            if len(parts) < 3:
                console.print(f"[{ERROR}]Usage: move <x> <y>[/{ERROR}]"); continue
            try:
                console.print(f"[{SUCCESS}]{mouse_move(int(parts[1]), int(parts[2]))}[/{SUCCESS}]")
            except ValueError:
                console.print(f"[{ERROR}]x and y must be integers.[/{ERROR}]")
        elif a == "click":
            if len(parts) < 3:
                console.print(f"[{ERROR}]Usage: click <x> <y> [left|right|middle][/{ERROR}]"); continue
            try:
                btn = parts[3].lower() if len(parts) > 3 else "left"
                console.print(f"[{SUCCESS}]{mouse_click(int(parts[1]), int(parts[2]), btn)}[/{SUCCESS}]")
            except ValueError:
                console.print(f"[{ERROR}]x and y must be integers.[/{ERROR}]")
        elif a == "dblclick":
            if len(parts) < 3:
                console.print(f"[{ERROR}]Usage: dblclick <x> <y>[/{ERROR}]"); continue
            try:
                console.print(f"[{SUCCESS}]{mouse_click(int(parts[1]), int(parts[2]), 'left', double=True)}[/{SUCCESS}]")
            except ValueError:
                console.print(f"[{ERROR}]x and y must be integers.[/{ERROR}]")
        elif a == "scroll":
            if len(parts) < 2:
                console.print(f"[{ERROR}]Usage: scroll <up|down> [amount][/{ERROR}]"); continue
            amt = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 3
            console.print(f"[{SUCCESS}]{mouse_scroll(parts[1], amt)}[/{SUCCESS}]")
        elif a == "drag":
            if len(parts) < 5:
                console.print(f"[{ERROR}]Usage: drag <x1> <y1> <x2> <y2>[/{ERROR}]"); continue
            try:
                console.print(f"[{SUCCESS}]{mouse_drag(int(parts[1]),int(parts[2]),int(parts[3]),int(parts[4]))}[/{SUCCESS}]")
            except ValueError:
                console.print(f"[{ERROR}]Coordinates must be integers.[/{ERROR}]")
        else:
            console.print(f"[{ERROR}]Unknown: {a}[/{ERROR}]")


# ═══════════════════════════════════════════════════════════════
# 26. FILE TRANSFER SERVER
# ═══════════════════════════════════════════════════════════════

# BaseHTTPRequestHandler, HTTPServer and mimetypes are imported at the top of this module

_FILE_SERVER_THREAD: threading.Thread = None
_FILE_SERVER_OBJ:    HTTPServer        = None
_FILE_SERVER_PORT    = 8765
_FILE_SERVER_DIR     = None

class _FileTransferHandler(BaseHTTPRequestHandler):
    """Directory listing + download (GET) + upload (POST) file server."""
    def log_message(self, fmt, *args): pass   # suppress noisy access log

    def do_GET(self):
        base = Path(_FILE_SERVER_DIR)
        rel  = urllib.parse.unquote(self.path.lstrip("/"))
        tgt  = (base / rel).resolve()
        if not str(tgt).startswith(str(base)):
            self.send_error(403); return
        if tgt.is_dir():   self._listing(tgt, base, rel)
        elif tgt.is_file(): self._download(tgt)
        else: self.send_error(404)

    def do_POST(self):
        """Handle file uploads. Manual multipart parsing (cgi module removed in Python 3.13)."""
        base = Path(_FILE_SERVER_DIR)
        rel  = urllib.parse.unquote(self.path.lstrip("/"))
        udir = (base / rel).resolve()
        if not str(udir).startswith(str(base)): self.send_error(403); return
        if not udir.is_dir(): udir = udir.parent
        ctype = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in ctype: self.send_error(400); return
        # Manual multipart boundary parsing
        boundary = None
        for _tok in ctype.split(";"):
            _tok = _tok.strip()
            if _tok.startswith("boundary="):
                boundary = _tok[len("boundary="):].strip().strip('"')
                break
        if not boundary: self.send_error(400); return
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        bnd = ("--" + boundary).encode()
        filename = None
        file_data = None
        for section in raw.split(bnd):
            if b"Content-Disposition" not in section:
                continue
            hdr_end = section.find(b"\r\n\r\n")
            if hdr_end == -1:
                continue
            hdr = section[:hdr_end].decode("utf-8", errors="replace")
            body = section[hdr_end + 4:]
            if body.endswith(b"\r\n"):
                body = body[:-2]
            if 'name="file"' in hdr and "filename=" in hdr:
                for _h in hdr.split(";"):
                    _h = _h.strip()
                    if _h.startswith("filename="):
                        filename = _h[9:].strip().strip('"')
                file_data = body
                break
        if not filename or file_data is None: self.send_error(400); return
        dest = udir / Path(filename).name
        dest.write_bytes(file_data)
        upload_html = (
            "<html><body style='background:#111;color:#eee;font-family:sans-serif;padding:20px'>"
            f"<h2>\u2705 Uploaded: {dest.name}</h2>"
            "<a href='/' style='color:#80cbc4'>\u2190 Back</a></body></html>"
        )
        self._html(upload_html)

    def _listing(self, tgt: Path, base: Path, rel: str):
        rel_display = rel.replace("\\","/")
        rows = ""
        if rel_display:
            par = "/".join(rel_display.rstrip("/").split("/")[:-1])
            rows += f'<tr><td colspan="3"><a href="/{par}">⬆ Parent</a></td></tr>'
        for e in sorted(tgt.iterdir(), key=lambda e:(not e.is_dir(), e.name.lower())):
            try:
                st  = e.stat()
                sz  = f"{st.st_size//1024} KB" if e.is_file() else "DIR"
                mod = datetime.fromtimestamp(st.st_mtime).strftime("%d %b %Y %H:%M")
            except: sz = mod = "?"
            icon = "📁" if e.is_dir() else "📄"
            href = urllib.parse.quote((rel_display.rstrip("/")+"/"+e.name).lstrip("/"))
            rows += f"<tr><td>{icon} <a href='/{href}'>{e.name}</a></td><td>{sz}</td><td>{mod}</td></tr>"
        post_path = urllib.parse.quote(rel_display) if rel_display else ""
        html = f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>RemotePC FileServer /{rel_display}</title>
<style>body{{font-family:-apple-system,sans-serif;background:#111;color:#eee;padding:16px}}
h2{{color:#00bcd4}}a{{color:#80cbc4;text-decoration:none}}
table{{width:100%;border-collapse:collapse}}td{{padding:8px;border-bottom:1px solid #222}}
form{{margin-top:20px;padding:16px;background:#1a1a1a;border-radius:8px}}
input[type=submit]{{background:#00bcd4;color:#000;border:none;padding:8px 18px;border-radius:4px;cursor:pointer}}
input[type=file]{{color:#eee}}</style></head><body>
<h2>📁 /{rel_display}</h2>
<table><tr><th align=left>Name</th><th>Size</th><th>Modified</th></tr>{rows}</table>
<form method='POST' action='/{post_path}' enctype='multipart/form-data'>
<b>Upload to this folder:</b><br><br>
<input type='file' name='file'>&nbsp;<input type='submit' value='⬆ Upload'></form>
</body></html>"""
        self._html(html)

    def _download(self, p: Path):
        data = p.read_bytes()
        mime, _ = mimetypes.guess_type(str(p))
        self.send_response(200)
        self.send_header("Content-Type", mime or "application/octet-stream")
        self.send_header("Content-Disposition", f'attachment; filename="{p.name}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)

    def _html(self, html: str):
        data = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.send_header("Content-Length",str(len(data)))
        self.end_headers(); self.wfile.write(data)


def file_transfer_server():
    global _FILE_SERVER_THREAD, _FILE_SERVER_OBJ, _FILE_SERVER_DIR
    print_header("📡  File Transfer Server")
    rc, ts_ip, _ = run_shell("tailscale ip -4")
    if rc == 0 and ts_ip.strip():
        ts_ip = ts_ip.strip()
    else:
        # Fall back to the machine's LAN address (or loopback) when Tailscale is down.
        try:
            import socket as _socket
            _s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            try:
                _s.connect(("8.8.8.8", 80))
                ts_ip = _s.getsockname()[0]
            finally:
                _s.close()
        except Exception:
            ts_ip = "127.0.0.1"
    console.print(
        f"  Serves files over HTTP — accessible from your phone via Tailscale.\n"
        f"  [{ACCENT}]URL:[/{ACCENT}] [bold]http://{ts_ip}:{_FILE_SERVER_PORT}[/bold]\n\n"
        "  [bold cyan]start [folder][/bold cyan]   Start (default: Downloads)\n"
        "  [bold cyan]stop[/bold cyan]             Stop server\n"
        "  [bold cyan]status[/bold cyan]           Show status\n"
        "  [bold cyan]back[/bold cyan]             Return\n"
    )
    while True:
        cmd   = Prompt.ask(f"[{ACCENT}]fileserver[/{ACCENT}]").strip()
        parts = cmd.split(maxsplit=1)
        a     = parts[0].lower() if parts else ""
        if a in ("back","exit","q"): break

        elif a == "start":
            if _FILE_SERVER_THREAD and _FILE_SERVER_THREAD.is_alive():
                console.print(f"[{WARN}]Already running on port {_FILE_SERVER_PORT}.[/{WARN}]"); continue
            folder = parts[1].strip('"') if len(parts) > 1 else str(Path.home() / "Downloads")
            if not Path(folder).is_dir():
                console.print(f"[{ERROR}]Folder not found: {folder}[/{ERROR}]"); continue
            _FILE_SERVER_DIR = folder
            try:
                _FILE_SERVER_OBJ    = HTTPServer(("0.0.0.0", _FILE_SERVER_PORT), _FileTransferHandler)
                _FILE_SERVER_THREAD = threading.Thread(target=_FILE_SERVER_OBJ.serve_forever, daemon=True)
                _FILE_SERVER_THREAD.start()
                console.print(Panel(
                    f"[{SUCCESS}]File server started![/{SUCCESS}]\n"
                    f"  [{ACCENT}]Folder:[/{ACCENT}] {folder}\n"
                    f"  [{ACCENT}]URL:[/{ACCENT}]    [bold]http://{ts_ip}:{_FILE_SERVER_PORT}[/bold]\n"
                    f"  [dim]Browse, download, and upload files from your phone browser.[/dim]",
                    border_style="green", box=PANEL_BOX))
            except Exception as ex:
                console.print(f"[{ERROR}]Failed: {ex}[/{ERROR}]")

        elif a == "stop":
            if _FILE_SERVER_OBJ:
                _FILE_SERVER_OBJ.shutdown()
                _FILE_SERVER_OBJ = _FILE_SERVER_THREAD = None
                console.print(f"[{SUCCESS}]File server stopped.[/{SUCCESS}]")
            else:
                console.print(f"[{WARN}]Not running.[/{WARN}]")

        elif a == "status":
            running = _FILE_SERVER_THREAD and _FILE_SERVER_THREAD.is_alive()
            if running:
                console.print(Panel(
                    f"[{SUCCESS}]Running[/{SUCCESS}]  •  Folder: {_FILE_SERVER_DIR}\n"
                    f"  [bold]http://{ts_ip}:{_FILE_SERVER_PORT}[/bold]",
                    title="[bold green]File Server[/bold green]", border_style="green", box=PANEL_BOX))
            else:
                console.print(f"[{WARN}]File server is not running.[/{WARN}]")
        else:
            console.print(f"[{ERROR}]Unknown: {a}[/{ERROR}]")


# ═══════════════════════════════════════════════════════════════
# 27. SCREEN OCR
# ═══════════════════════════════════════════════════════════════

def _do_ocr(region: tuple = None) -> str:
    """
    Capture screen (or region) and extract text via Windows WinRT OCR.
    Falls back to pytesseract if WinRT fails.
    region: optional (x, y, w, h) tuple for sub-region capture.
    """
    tmp_png = Path.home() / "AppData" / "Local" / "Temp" / "remotepc_ocr.png"
    tmp_txt = Path.home() / "AppData" / "Local" / "Temp" / "remotepc_ocr.txt"
    tmp_txt.unlink(missing_ok=True)

    # 1. Capture screenshot (region or full screen)
    if region:
        x, y, w, h = region
        ps_cap = (
            f"Add-Type -AssemblyName System.Windows.Forms,System.Drawing\n"
            f"$b=New-Object System.Drawing.Bitmap({w},{h})\n"
            f"$g=[System.Drawing.Graphics]::FromImage($b)\n"
            f"$g.CopyFromScreen({x},{y},0,0,[System.Drawing.Size]::new({w},{h}))\n"
            f"$b.Save('{tmp_png}')\n$g.Dispose();$b.Dispose()"
        )
    else:
        ps_cap = (
            f"Add-Type -AssemblyName System.Windows.Forms,System.Drawing\n"
            f"$s=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds\n"
            f"$b=New-Object System.Drawing.Bitmap($s.Width,$s.Height)\n"
            f"$g=[System.Drawing.Graphics]::FromImage($b)\n"
            f"$g.CopyFromScreen($s.Location,[System.Drawing.Point]::Empty,$s.Size)\n"
            f"$b.Save('{tmp_png}')\n$g.Dispose();$b.Dispose()"
        )
    ps_cap_file = Path.home() / "AppData" / "Local" / "Temp" / "remotepc_ocr_cap.ps1"
    ps_cap_file.write_text(ps_cap, encoding="utf-8")
    launch_desktop_app(f'powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File "{ps_cap_file}"')
    for _ in range(20):
        time.sleep(0.75)
        if tmp_png.exists() and tmp_png.stat().st_size > 0:
            break
    if not (tmp_png.exists() and tmp_png.stat().st_size > 0):
        enc = base64.b64encode(ps_cap.encode("utf-16le")).decode("ascii")
        run_shell(f'powershell -NoProfile -NonInteractive -EncodedCommand {enc}')
        time.sleep(2)
    if not (tmp_png.exists() and tmp_png.stat().st_size > 0):
        return "OCR failed: screenshot capture unsuccessful."

    # 2. WinRT OCR via PowerShell — must run via session bridge (launch_desktop_app)
    #    so it executes in Session 1 (active desktop) where the screenshot was taken.
    #    Running run_shell() directly in SSH Session 0 causes WinRT to get a blank/null
    #    engine because there is no user profile language context in that session.
    ps_ocr = f"""
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null = [Windows.Storage.StorageFile,              Windows.Storage,         ContentType=WindowsRuntime]
$null = [Windows.Media.Ocr.OcrEngine,              Windows.Media.Ocr,       ContentType=WindowsRuntime]
$null = [Windows.Graphics.Imaging.BitmapDecoder,   Windows.Graphics.Imaging,ContentType=WindowsRuntime]
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {{ $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.ContainsGenericParameters }})[0]
function Await($asyncOp, $type) {{
    $method = $asTaskGeneric.MakeGenericMethod($type)
    $task = $method.Invoke($null, @($asyncOp))
    $task.Wait()
    return $task.Result
}}
$eng = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
if(-not $eng) {{
    $langs = [Windows.Media.Ocr.OcrEngine]::AvailableRecognizerLanguages
    if($langs.Count -gt 0) {{ $eng = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage($langs[0]) }}
}}
if(-not $eng) {{
    # Hard fallback: explicitly request English (en-US) which is always installed on Windows 10/11
    $eng = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage([Windows.Globalization.Language]::new('en-US'))
}}
if(-not $eng) {{ [System.IO.File]::WriteAllText('{tmp_txt}', '', [System.Text.Encoding]::UTF8); exit 1 }}
$file   = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync('{tmp_png}')) ([Windows.Storage.StorageFile])
$stream = Await ($file.OpenReadAsync()) ([Windows.Storage.Streams.IRandomAccessStreamWithContentType])
$bmp    = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
$sb     = Await ($bmp.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])
$result = Await ($eng.RecognizeAsync($sb)) ([Windows.Media.Ocr.OcrResult])
$text   = ($result.Lines | ForEach-Object {{ $_.Text }}) -join "`n"
[System.IO.File]::WriteAllText('{tmp_txt}', $text, [System.Text.Encoding]::UTF8)
"""
    ps_ocr_file = Path.home() / "AppData" / "Local" / "Temp" / "remotepc_ocr_run.ps1"
    ps_ocr_file.write_text(ps_ocr, encoding="utf-8")
    tmp_txt.unlink(missing_ok=True)  # ensure fresh result

    # Primary: run via session bridge so WinRT has access to user profile + display
    launch_desktop_app(f'powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File "{ps_ocr_file}"')
    for _ in range(16):  # poll up to 12 seconds
        time.sleep(0.75)
        if tmp_txt.exists() and tmp_txt.stat().st_size > 0:
            break

    # Fallback: direct run_shell (works if already in an interactive session)
    if not (tmp_txt.exists() and tmp_txt.stat().st_size > 0):
        enc = base64.b64encode(ps_ocr.encode("utf-16le")).decode("ascii")
        run_shell(f'powershell -NoProfile -NonInteractive -EncodedCommand {enc}')
        time.sleep(2)

    if tmp_txt.exists() and tmp_txt.stat().st_size > 0:
        res = tmp_txt.read_text(encoding="utf-8-sig").strip()
        if res:
            return res

    # 3. pytesseract fallback — tried whenever WinRT returns empty, not only on import error
    try:
        import pytesseract
        from PIL import Image
        tess_result = pytesseract.image_to_string(Image.open(str(tmp_png))).strip()
        return tess_result or "(No text detected by pytesseract either)"
    except ImportError:
        pass
    except Exception as _tess_e:
        pass  # pytesseract found but failed (e.g. tesseract binary not in PATH)

    return (
        "OCR failed: WinRT OCR returned no text (session isolation or no language pack).\n"
        "Fix options:\n"
        "  1) Install pytesseract: pip install pytesseract pillow  (+ Tesseract binary)\n"
        "  2) Ensure Windows has an OCR language pack: Settings > Time & Language > Language\n"
        "  3) The screenshot may be blank — run 'screenshot' first to verify screen capture works."
    )



# ═══════════════════════════════════════════════════════════════
# 27b. WEBCAM SNAPSHOT
# ═══════════════════════════════════════════════════════════════

def snap_webcam(camera_index: int = 0) -> str:
    """
    Capture a single frame from the webcam and save it to Downloads.
    Tries three backends in order:
      1. OpenCV (cv2) — most reliable, works from SSH Session 0
      2. ffmpeg DirectShow — if OpenCV is unavailable
      3. PowerShell MediaCapture (WinRT) via session bridge — last resort
    Returns a result string (file path on success, error message on failure).
    """
    downloads = Path.home() / "Downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = downloads / f"webcam_{ts}.jpg"

    # ── 1. OpenCV (pip install opencv-python) ────────────────────────────────
    try:
        import cv2  # type: ignore
        cap = cv2.VideoCapture(camera_index, cv2.CAP_DSHOW)  # CAP_DSHOW = faster on Windows
        if not cap.isOpened():
            cap = cv2.VideoCapture(camera_index)  # fallback without backend hint
        if cap.isOpened():
            # Fix dark images: set resolution + force auto-exposure ON, then wait
            # for the camera ISP to fully measure scene brightness before reading.
            # CAP_PROP_AUTO_EXPOSURE: 0.75 = auto, 0.25 = manual (DirectShow convention)
            cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
            cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
            cap.set(cv2.CAP_PROP_AUTO_EXPOSURE, 0.75)  # force auto-exposure ON
            time.sleep(2.0)   # critical: ISP needs ~2s to ramp to correct exposure
            for _ in range(20):  # drain buffered dark frames from before stabilization
                cap.read()
            ret, frame = cap.read()
            cap.release()
            if ret and frame is not None:
                cv2.imwrite(str(out_path), frame, [cv2.IMWRITE_JPEG_QUALITY, 95])
                if out_path.exists() and out_path.stat().st_size > 0:
                    sz = out_path.stat().st_size
                    return f"📷 Saved: {out_path} ({sz // 1024} KB)"
    except ImportError:
        pass  # OpenCV not installed, try next
    except Exception:
        pass

    # ── 2. ffmpeg DirectShow ─────────────────────────────────────────────────
    ffmpeg_bin = shutil.which("ffmpeg")
    if ffmpeg_bin:
        # List available video capture devices to pick the right one
        _, dev_out, _ = run_shell(f'"{ffmpeg_bin}" -list_devices true -f dshow -i dummy 2>&1')
        # Parse first video device name
        video_dev = None
        for line in (dev_out or "").splitlines():
            if '"' in line and ("video" in line.lower() or "cam" in line.lower() or "capture" in line.lower()):
                m = re.search(r'"([^"]+)"', line)
                if m:
                    video_dev = m.group(1)
                    break
        if not video_dev:
            # fallback: grab first quoted device name from dshow output
            m = re.search(r'"([^"]+)"', dev_out or "")
            if m:
                video_dev = m.group(1)
        if video_dev:
            cmd = (
                f'"{ffmpeg_bin}" -y -f dshow -i video="{video_dev}" '
                f'-frames:v 1 -q:v 2 "{out_path}" 2>&1'
            )
            rc, _, _ = run_shell(cmd)
            if rc == 0 and out_path.exists() and out_path.stat().st_size > 0:
                sz = out_path.stat().st_size
                return f"📷 Saved via ffmpeg: {out_path} ({sz // 1024} KB)"

    # ── 3. PowerShell WinRT MediaCapture (session bridge) ────────────────────
    #    This must run in Session 1 (interactive desktop) — WinRT camera APIs
    #    require a UI thread and fail silently in SSH Session 0.
    tmp_ps = Path.home() / "AppData" / "Local" / "Temp" / "remotepc_webcam.ps1"
    out_path_str = str(out_path).replace("\\", "\\\\")
    ps_script = f"""\
$null = [Windows.Media.Capture.MediaCapture, Windows.Media.Capture, ContentType=WindowsRuntime]
$null = [Windows.Storage.StorageFolder,      Windows.Storage,        ContentType=WindowsRuntime]
$null = [Windows.Storage.CreationCollisionOption, Windows.Storage,   ContentType=WindowsRuntime]
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() |
           Where-Object {{ $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.ContainsGenericParameters }})[0]
function Await($op, $t) {{ $m=$asTask.MakeGenericMethod($t); $task=$m.Invoke($null,@($op)); $task.Wait(); $task.Result }}
try {{
    $mc = New-Object Windows.Media.Capture.MediaCapture
    Await ($mc.InitializeAsync()) ([System.Object]) | Out-Null
    $sf = Await ([Windows.Storage.StorageFolder]::GetFolderFromPathAsync('{str(downloads).replace(chr(92), chr(92)*2)}')) ([Windows.Storage.StorageFolder])
    $fn = 'webcam_{ts}.jpg'
    $file = Await ($sf.CreateFileAsync($fn, [Windows.Storage.CreationCollisionOption]::ReplaceExisting)) ([Windows.Storage.StorageFile])
    $enc = New-Object Windows.Media.MediaProperties.ImageEncodingProperties
    $enc.Subtype = 'JPEG'
    Await ($mc.CapturePhotoToStorageFileAsync($enc, $file)) ([System.Object]) | Out-Null
    Write-Output "OK"
}} catch {{ Write-Output "ERR: $_" }}
"""
    tmp_ps.write_text(ps_script, encoding="utf-8")
    launch_desktop_app(f'powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File "{tmp_ps}"')
    for _ in range(20):
        time.sleep(0.75)
        if out_path.exists() and out_path.stat().st_size > 0:
            sz = out_path.stat().st_size
            return f"📷 Saved via WinRT: {out_path} ({sz // 1024} KB)"

    return (
        "Webcam snapshot failed. No capture backend succeeded.\n"
        "Fix options:\n"
        "  1) pip install opencv-python          ← easiest, works from SSH\n"
        "  2) winget install ffmpeg               ← works from SSH\n"
        "  3) Ensure camera is plugged in and not in use by another app."
    )


def snap_webcam_menu():
    """Interactive menu for webcam snapshot."""
    print_header("📷  Snap Webcam")
    console.print(
        "  Capture a photo from your PC webcam and save to [bold cyan]Downloads[/bold cyan].\n\n"
        "  [bold cyan]snap[/bold cyan]                   Capture from default camera (index 0)\n"
        "  [bold cyan]snap <N>[/bold cyan]               Capture from camera index N (0, 1, 2…)\n"
        "  [bold cyan]back[/bold cyan]                   Return to main menu\n"
    )
    while True:
        try:
            cmd = console.input(f"  [{ACCENT}]webcam>[/{ACCENT}] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break
        if not cmd or cmd in ("back", "exit", "q"):
            break
        if cmd.startswith("snap"):
            parts = cmd.split()
            idx = 0
            if len(parts) > 1:
                try:
                    idx = int(parts[1])
                except ValueError:
                    console.print(f"  [{ERROR}]Camera index must be a number.[/{ERROR}]")
                    continue
            with console.status(f"  [dim]Capturing from camera {idx}...[/dim]", spinner="dots"):
                result = snap_webcam(camera_index=idx)
            if result.startswith("📷"):
                console.print(f"  [{SUCCESS}]{result}[/{SUCCESS}]")
            else:
                console.print(f"  [{ERROR}]{result}[/{ERROR}]")
        else:
            console.print(f"  [{WARN}]Unknown command. Type 'snap' or 'back'.[/{WARN}]")
    pause()


def ocr_menu():
    print_header("👁️  Screen OCR")
    console.print(
        "  Extract text from your screen without viewing the screenshot.\n\n"
        "  [bold cyan]scan[/bold cyan]                          OCR full screen\n"
        "  [bold cyan]scan region <x> <y> <w> <h>[/bold cyan]  OCR a specific region\n"
        "  [bold cyan]back[/bold cyan]                          Return\n"
    )
    while True:
        cmd   = Prompt.ask(f"[{ACCENT}]ocr[/{ACCENT}]").strip()
        parts = cmd.split()
        a     = parts[0].lower() if parts else ""
        if a in ("back","exit","q"): break
        elif a == "scan":
            region = None
            if len(parts) >= 6 and parts[1].lower() == "region":
                try:
                    region = tuple(int(p) for p in parts[2:6])
                except ValueError:
                    console.print(f"[{ERROR}]Coordinates must be integers.[/{ERROR}]"); continue
            region_str = f" region {region}" if region else " full screen"
            console.print(f"[dim]Running OCR on{region_str}... (3-8 seconds)[/dim]")
            with console.status("[dim]Extracting text...[/dim]", spinner="dots"):
                text = _do_ocr(region)
            if text.startswith("OCR failed"):
                console.print(f"[{ERROR}]{text}[/{ERROR}]")
            else:
                console.print(Panel(text, title=f"[bold cyan]OCR —{region_str}[/bold cyan]",
                                    border_style="cyan", box=PANEL_BOX))
            pause()
        else:
            console.print(f"[{ERROR}]Unknown: {a}[/{ERROR}]")


# ═══════════════════════════════════════════════════════════════
# 28. EVENT WATCHERS
# ═══════════════════════════════════════════════════════════════

_WATCHER_REGISTRY: dict = {}
_WATCHER_COUNTER = [0]

def _new_wid() -> str:
    _WATCHER_COUNTER[0] += 1
    return f"W{_WATCHER_COUNTER[0]}"

def _start_watcher(wtype: str, desc: str, fn) -> str:
    wid  = _new_wid()
    stop = threading.Event()
    t    = threading.Thread(target=lambda: fn(stop), daemon=True)
    t.start()
    _WATCHER_REGISTRY[wid] = {"type": wtype, "desc": desc, "thread": t, "stop": stop}
    return wid

def _w_cpu(threshold: int, stop: threading.Event):
    while not stop.is_set():
        cpu = psutil.cpu_percent(interval=5)
        if cpu >= threshold:
            _send_toast("⚡ CPU Alert", f"CPU at {cpu:.0f}% — threshold {threshold}%")
        stop.wait(15)

def _w_ram(threshold: int, stop: threading.Event):
    while not stop.is_set():
        m = psutil.virtual_memory()
        if m.percent >= threshold:
            _send_toast("🧠 RAM Alert", f"RAM at {m.percent:.0f}% — threshold {threshold}%")
        stop.wait(15)

def _w_battery(threshold: int, stop: threading.Event):
    last = False
    while not stop.is_set():
        b = psutil.sensors_battery()
        if b and not b.power_plugged and b.percent <= threshold:
            if not last:
                _send_toast("🔋 Battery Low", f"Battery at {b.percent:.0f}% — plug in!")
                last = True
        else:
            last = False
        stop.wait(60)

def _w_proc_start(name: str, stop: threading.Event):
    nl = name.lower()
    while not stop.is_set():
        if any(nl in (p.info.get("name") or "").lower() for p in psutil.process_iter(["name"])):
            _send_toast("▶ Process Started", f"{name} is now running."); break
        stop.wait(5)

def _w_proc_stop(name: str, stop: threading.Event):
    nl = name.lower()
    while not stop.is_set():  # wait until it IS running
        if any(nl in (p.info.get("name") or "").lower() for p in psutil.process_iter(["name"])): break
        stop.wait(3)
    while not stop.is_set():  # then wait until it disappears
        if not any(nl in (p.info.get("name") or "").lower() for p in psutil.process_iter(["name"])):
            _send_toast("⏹ Process Stopped", f"{name} has exited."); break
        stop.wait(5)

def _w_file(path: str, stop: threading.Event):
    p = Path(path)
    try: last = p.stat().st_mtime if p.exists() else None
    except: last = None
    while not stop.is_set():
        try:
            cur = p.stat().st_mtime if p.exists() else None
            if cur != last:
                ev = "Created" if not last and cur else ("Deleted" if last and not cur else "Modified")
                _send_toast(f"📄 File {ev}", p.name)
                last = cur
        except: pass
        stop.wait(5)


def event_watcher_menu():
    print_header("👁  Event Watchers")
    console.print(
        "  Background threads that fire desktop toast notifications.\n\n"
        "  [bold cyan]watch cpu <n%>[/bold cyan]           Alert when CPU > n%\n"
        "  [bold cyan]watch ram <n%>[/bold cyan]           Alert when RAM > n%\n"
        "  [bold cyan]watch battery <n%>[/bold cyan]       Alert when battery < n%\n"
        "  [bold cyan]watch proc start <name>[/bold cyan]  Alert when process starts\n"
        "  [bold cyan]watch proc stop <name>[/bold cyan]   Alert when process exits\n"
        "  [bold cyan]watch file <path>[/bold cyan]        Alert on file create/modify/delete\n"
        "  [bold cyan]list[/bold cyan]                     Show active watchers\n"
        "  [bold cyan]stop <id|all>[/bold cyan]            Stop watcher(s)\n"
        "  [bold cyan]back[/bold cyan]                     Return\n"
    )
    while True:
        cmd   = Prompt.ask(f"[{ACCENT}]watch[/{ACCENT}]").strip()
        parts = cmd.split(maxsplit=3)
        a     = parts[0].lower() if parts else ""
        if a in ("back","exit","q"): break

        elif a == "watch":
            if len(parts) < 3:
                console.print(f"[{ERROR}]Usage: watch <cpu|ram|battery|proc|file> <arg>[/{ERROR}]"); continue
            wt = parts[1].lower(); wa = parts[2]
            if wt == "cpu":
                try:
                    n = int(wa.replace("%",""))
                    wid = _start_watcher("cpu", f"CPU > {n}%", lambda s, x=n: _w_cpu(x, s))
                    console.print(f"[{SUCCESS}]Watcher {wid}: alert when CPU > {n}%[/{SUCCESS}]")
                except ValueError: console.print(f"[{ERROR}]Threshold must be a number.[/{ERROR}]")
            elif wt == "ram":
                try:
                    n = int(wa.replace("%",""))
                    wid = _start_watcher("ram", f"RAM > {n}%", lambda s, x=n: _w_ram(x, s))
                    console.print(f"[{SUCCESS}]Watcher {wid}: alert when RAM > {n}%[/{SUCCESS}]")
                except ValueError: console.print(f"[{ERROR}]Threshold must be a number.[/{ERROR}]")
            elif wt == "battery":
                try:
                    n = int(wa.replace("%",""))
                    wid = _start_watcher("battery", f"Battery < {n}%", lambda s, x=n: _w_battery(x, s))
                    console.print(f"[{SUCCESS}]Watcher {wid}: alert when battery < {n}%[/{SUCCESS}]")
                except ValueError: console.print(f"[{ERROR}]Threshold must be a number.[/{ERROR}]")
            elif wt == "proc":
                if len(parts) < 4: console.print(f"[{ERROR}]Usage: watch proc start|stop <name>[/{ERROR}]"); continue
                sub = parts[2].lower(); nm = parts[3]
                if sub == "start":
                    wid = _start_watcher("proc_start", f"proc start: {nm}", lambda s,n=nm: _w_proc_start(n, s))
                    console.print(f"[{SUCCESS}]Watcher {wid}: alert when {nm} starts[/{SUCCESS}]")
                elif sub == "stop":
                    wid = _start_watcher("proc_stop", f"proc stop: {nm}", lambda s,n=nm: _w_proc_stop(n, s))
                    console.print(f"[{SUCCESS}]Watcher {wid}: alert when {nm} exits[/{SUCCESS}]")
                else: console.print(f"[{ERROR}]Sub-command must be start or stop.[/{ERROR}]")
            elif wt == "file":
                wid = _start_watcher("file", f"file: {wa}", lambda s, p=wa: _w_file(p, s))
                console.print(f"[{SUCCESS}]Watcher {wid}: watching {wa}[/{SUCCESS}]")
            else: console.print(f"[{ERROR}]Unknown watch type: {wt}[/{ERROR}]")

        elif a == "list":
            if not _WATCHER_REGISTRY:
                console.print(f"[{WARN}]No active watchers.[/{WARN}]"); continue
            t = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", show_edge=False)
            t.add_column("ID",   style="bold cyan",   width=5)
            t.add_column("Type", style="green",       width=14)
            t.add_column("Description", style="white")
            t.add_column("Status", style="dim",       width=10)
            for wid, w in list(_WATCHER_REGISTRY.items()):
                st = "[green]Running[/green]" if w["thread"].is_alive() else "[dim]Dead[/dim]"
                t.add_row(wid, w["type"], w["desc"], st)
            console.print(t); pause()

        elif a == "stop":
            if len(parts) < 2: console.print(f"[{ERROR}]Usage: stop <id|all>[/{ERROR}]"); continue
            tgt = parts[1].upper()
            if tgt == "ALL":
                for w in _WATCHER_REGISTRY.values(): w["stop"].set()
                _WATCHER_REGISTRY.clear()
                console.print(f"[{SUCCESS}]All watchers stopped.[/{SUCCESS}]")
            elif tgt in _WATCHER_REGISTRY:
                _WATCHER_REGISTRY[tgt]["stop"].set()
                del _WATCHER_REGISTRY[tgt]
                console.print(f"[{SUCCESS}]Watcher {tgt} stopped.[/{SUCCESS}]")
            else: console.print(f"[{ERROR}]No watcher: {tgt}[/{ERROR}]")
        else:
            console.print(f"[{ERROR}]Unknown: {a}[/{ERROR}]")


# ═══════════════════════════════════════════════════════════════
# 29. AUDIO CAPTURE
# ═══════════════════════════════════════════════════════════════

_AUDIO_DIR = Path.home() / "Downloads"

def _record_audio(output: Path, duration: int) -> tuple:
    """
    Record from the default microphone.
    Tries: (1) sounddevice+scipy, (2) ffmpeg, (3) WinMCI PowerShell fallback.
    Returns (rc, info_str, err_str).
    """
    # 1. sounddevice (best quality, no extra install if already present)
    try:
        import sounddevice as sd
        import scipy.io.wavfile as wavfile
        import numpy as np
        console.print(f"[dim]Recording via sounddevice ({duration}s)...[/dim]")
        sample_rate = 44100
        data = sd.rec(int(duration * sample_rate), samplerate=sample_rate,
                      channels=2, dtype="int16")
        sd.wait()
        # Ensure correct shape for scipy — (frames, channels)
        if data.ndim == 1:
            data = data.reshape(-1, 1)
        wavfile.write(str(output), sample_rate, data)
        if output.exists() and output.stat().st_size > 0:
            return 0, "sounddevice", ""
    except ImportError:
        pass
    except Exception as ex:
        return -1, "", f"sounddevice error: {ex}"

    # 2. FFmpeg — explicitly encode to standard PCM WAV so all players can open it
    ffmpeg = shutil.which("ffmpeg")
    if ffmpeg:
        def _detect_audio_device():
            """Return the first available DirectShow audio input device name."""
            _, _o, _e = run_shell(f'"{ffmpeg}" -list_devices true -f dshow -i dummy 2>&1')
            in_audio = False
            for _ln in (_o + _e).splitlines():
                if "audio" in _ln.lower() and ("devices" in _ln.lower() or "device" in _ln.lower()):
                    in_audio = True
                    continue
                if in_audio and '"' in _ln:
                    _pts = _ln.split('"')
                    if len(_pts) >= 2 and _pts[1] and not _pts[1].startswith("@"):
                        return _pts[1]
            return "Microphone"

        audio_dev = _detect_audio_device()
        console.print(f"[dim]Recording via ffmpeg ({duration}s) \u2014 device: {audio_dev}...[/dim]")
        # -acodec pcm_s16le = standard 16-bit PCM — universally playable WAV
        cmd = (
            f'"{ffmpeg}" -y -f dshow -i audio="{audio_dev}" '
            f'-t {duration} -acodec pcm_s16le -ar 44100 -ac 2 "{output}" 2>&1'
        )
        rc, out, err = run_shell(cmd)
        if rc == 0 and output.exists() and output.stat().st_size > 0:
            return 0, "ffmpeg", ""
        # Retry with common fallback device names
        for _fb in ("Microphone", "Microphone Array", "Realtek Audio", "Default"):
            if _fb == audio_dev:
                continue
            rc, _, _ = run_shell(
                f'"{ffmpeg}" -y -f dshow -i audio="{_fb}" '
                f'-t {duration} -acodec pcm_s16le -ar 44100 -ac 2 "{output}"'
            )
            if rc == 0 and output.exists() and output.stat().st_size > 0:
                return 0, "ffmpeg", ""

    # 3. WinMCI (PowerShell fallback via session bridge)
    #    Must run via launch_desktop_app — WinMCI audio APIs require Session 1
    #    (the interactive user session with real audio hardware access).
    #    Running in SSH Session 0 produces a silent/zero-byte file.
    console.print(f"[dim]Recording via Windows MCI ({duration}s)...[/dim]")
    pf = str(output).replace("\\", "\\\\")
    tmp_mci = Path.home() / "AppData" / "Local" / "Temp" / "remotepc_mci.ps1"
    ps = f"""\
Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public class WinMCI {{
    [DllImport("winmm.dll", CharSet=CharSet.Auto)]
    public static extern int mciSendString(string cmd, StringBuilder ret, int retLen, IntPtr cb);
}}
'@
[WinMCI]::mciSendString('open new Type waveaudio Alias rpc', $null, 0, [IntPtr]::Zero) | Out-Null
[WinMCI]::mciSendString('set rpc time format milliseconds', $null, 0, [IntPtr]::Zero) | Out-Null
[WinMCI]::mciSendString('set rpc samplespersec 44100 bitspersample 16 channels 2', $null, 0, [IntPtr]::Zero) | Out-Null
[WinMCI]::mciSendString('record rpc', $null, 0, [IntPtr]::Zero) | Out-Null
Start-Sleep -Seconds {duration}
[WinMCI]::mciSendString('stop rpc', $null, 0, [IntPtr]::Zero) | Out-Null
[WinMCI]::mciSendString('save rpc \"{pf}\"', $null, 0, [IntPtr]::Zero) | Out-Null
[WinMCI]::mciSendString('close rpc', $null, 0, [IntPtr]::Zero) | Out-Null
"""
    tmp_mci.write_text(ps, encoding="utf-8")
    launch_desktop_app(f'powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File "{tmp_mci}"')
    # Poll up to duration + 5s for the file to appear
    for _ in range(duration + 5):
        time.sleep(1)
        if output.exists() and output.stat().st_size > 0:
            return 0, "WinMCI", ""
    return -1, "", "WinMCI recording produced no output (audio hardware may be unavailable)."



def audio_capture_menu():
    _AUDIO_DIR.mkdir(parents=True, exist_ok=True)
    print_header("🎙️  Audio Capture")
    console.print(
        f"  [{ACCENT}]Recordings folder:[/{ACCENT}] {_AUDIO_DIR}\n\n"
        "  [bold cyan]record <seconds> [name][/bold cyan]  Record from microphone\n"
        "  [bold cyan]list[/bold cyan]                     List saved recordings\n"
        "  [bold cyan]play <n>[/bold cyan]                 Play recording on desktop\n"
        "  [bold cyan]del <n>[/bold cyan]                  Delete a recording\n"
        "  [bold cyan]devices[/bold cyan]                  List audio input devices\n"
        "  [bold cyan]back[/bold cyan]                     Return\n\n"
        "  [dim]Tip: install FFmpeg or sounddevice+scipy for best quality:[/dim]\n"
        "  [dim]  winget install ffmpeg[/dim]\n"
        "  [dim]  pip install sounddevice scipy[/dim]\n"
    )
    while True:
        cmd   = Prompt.ask(f"[{ACCENT}]audio[/{ACCENT}]").strip()
        parts = cmd.split(maxsplit=2)
        a     = parts[0].lower() if parts else ""
        recs  = sorted(_AUDIO_DIR.glob("*.wav"), key=lambda f: f.stat().st_mtime, reverse=True)
        if a in ("back","exit","q"): break

        elif a == "record":
            if len(parts) < 2 or not parts[1].isdigit():
                console.print(f"[{ERROR}]Usage: record <seconds> [name][/{ERROR}]"); continue
            dur  = int(parts[1])
            name = parts[2].replace(" ","_") if len(parts) > 2 else datetime.now().strftime("%Y%m%d_%H%M%S")
            out  = _AUDIO_DIR / f"{name}.wav"
            console.print(Panel(
                f"[bold yellow]🎙  Recording for {dur} seconds...[/bold yellow]\n"
                f"[dim]Output: {out.name}[/dim]",
                border_style="yellow", box=PANEL_BOX))
            rc, method, err = _record_audio(out, dur)
            if out.exists() and out.stat().st_size > 0:
                console.print(Panel(
                    f"[{SUCCESS}]Saved:[/{SUCCESS}] {out.name}  ({out.stat().st_size//1024} KB)\n"
                    f"[dim]Method: {method} — use 'play' or download via File Server (menu 26)[/dim]",
                    border_style="green", box=PANEL_BOX))
            else:
                console.print(Panel(
                    f"[{ERROR}]Recording failed.[/{ERROR}]\n"
                    f"[dim]{err[:300] or 'No output produced.'}\n\n"
                    f"Fix: winget install ffmpeg   or   pip install sounddevice scipy[/dim]",
                    border_style="red", box=PANEL_BOX))
            pause()

        elif a == "list":
            if not recs: console.print(f"[{WARN}]No recordings yet.[/{WARN}]"); continue
            t = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", show_edge=False, expand=True)
            t.add_column("#",    style="bold cyan",  width=5)
            t.add_column("Name", style="bold white", min_width=30)
            t.add_column("Size", style="dim",        width=10, justify="right")
            t.add_column("Date", style="dim",        width=18)
            for i, f in enumerate(recs, 1):
                st = f.stat()
                t.add_row(str(i), f.name, f"{st.st_size//1024} KB",
                          datetime.fromtimestamp(st.st_mtime).strftime("%d %b %Y %H:%M"))
            console.print(t); pause()

        elif a == "play":
            if len(parts) < 2 or not parts[1].isdigit():
                console.print(f"[{ERROR}]Usage: play <n>[/{ERROR}]"); continue
            idx = int(parts[1]) - 1
            if not (0 <= idx < len(recs)): console.print(f"[{ERROR}]Invalid index.[/{ERROR}]"); continue
            launch_desktop_app(f'"{recs[idx]}"')
            console.print(f"[{SUCCESS}]Playing {recs[idx].name} on desktop.[/{SUCCESS}]")

        elif a == "del":
            if len(parts) < 2 or not parts[1].isdigit():
                console.print(f"[{ERROR}]Usage: del <n>[/{ERROR}]"); continue
            idx = int(parts[1]) - 1
            if not (0 <= idx < len(recs)): console.print(f"[{ERROR}]Invalid index.[/{ERROR}]"); continue
            if Confirm.ask(f"[{WARN}]Delete {recs[idx].name}?[/{WARN}]"):
                recs[idx].unlink()
                console.print(f"[{SUCCESS}]Deleted.[/{SUCCESS}]")

        elif a == "devices":
            ffmpeg = shutil.which("ffmpeg")
            if ffmpeg:
                _, out, err = run_shell(f'"{ffmpeg}" -list_devices true -f dshow -i dummy 2>&1')
                console.print(Panel((out+err).strip()[:1500],
                                    title="[bold cyan]Audio Devices (FFmpeg)[/bold cyan]",
                                    border_style="cyan", box=PANEL_BOX))
            else:
                _, out, _ = run_shell(
                    'powershell -NoProfile -Command '
                    '"Get-WmiObject Win32_SoundDevice|Select-Object Name,Status|Format-Table -AutoSize"'
                )
                console.print(Panel(out.strip() or "None found.",
                                    title="[bold cyan]Audio Devices[/bold cyan]",
                                    border_style="cyan", box=PANEL_BOX))
            pause()
        else:
            console.print(f"[{ERROR}]Unknown: {a}[/{ERROR}]")


# ═══════════════════════════════════════════════════════════════
# LOGGING SYSTEM
# ═══════════════════════════════════════════════════════════════


_LOG_FILE = _LOG_DIR / "remotepc_log.jsonl"

def _log_command(source: str, cmd: str, result: str = "", status: str = "ok") -> None:
    """Append a structured log entry to remotepc_log.jsonl."""
    import json
    entry = {
        "ts":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source": source,
        "cmd":    cmd,
        "result": result[:200] if result else "",
        "status": status,
    }
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass  # Never crash remotepc because of logging


# ═══════════════════════════════════════════════════════════════
# SETUP WIZARD
# ═══════════════════════════════════════════════════════════════

def launch_setup_wizard():
    """Run the interactive setup wizard to (re)generate the config file."""
    print_header("⚙️  Setup Wizard")
    cfg_path = _cfgmod.config_path() if _cfgmod is not None else (_REPO_ROOT / "remotepc.config.json")
    console.print(Panel(
        f"[bold white]Re-configure RemotePC[/bold white]\n"
        f"[{DIM}]Assistant name, API keys, local models, allowed IPs, folders.[/{DIM}]\n"
        f"[{DIM}]Settings file:[/{DIM}] [cyan]{cfg_path}[/cyan]\n\n"
        f"[{DIM}]Restart RemotePC after saving to apply the changes.[/{DIM}]",
        border_style="cyan", box=PANEL_BOX
    ))
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import setup_wizard  # type: ignore
        setup_wizard.run_wizard()
    except KeyboardInterrupt:
        console.print(f"\n[{WARN}]Setup cancelled.[/{WARN}]")
    except Exception as e:
        console.print(f"[{ERROR}]Setup wizard failed: {e}[/{ERROR}]")
    pause()


# ═══════════════════════════════════════════════════════════════
# AZAZIL PERSONALITY CORE — Profile, Memory & Welcome Engine
# ═══════════════════════════════════════════════════════════════

_AZAZIL_PROFILE_PATH = Path(__file__).resolve().parent / "azazil_profile.json"
_AZAZIL_MEMORY_DIR   = Path(__file__).resolve().parent / "azazil_memory"

# ─── Profile System ──────────────────────────────────────────────────────────

def _load_profile() -> dict:
    """Load the owner profile. Returns defaults if the file is missing."""
    _tz = str(_CONFIG.get("timezone", "") or "") or (time.tzname[0] if time.tzname else "UTC")
    defaults = {
        "owner": {"name": str(_CONFIG.get("owner_name", "Boss") or "Boss"),
                  "nickname": str(_CONFIG.get("owner_nickname", "Boss") or "Boss"),
                  "preferred_greeting": "casual", "timezone": _tz},
        "personality": {"name": _ASSISTANT_NAME, "style": "witty_loyal", "formality": "casual",
                        "humor_level": 0.7, "sass_level": 0.3,
                        "traits": ["loyal", "sarcastic-but-helpful", "proactive", "concise-over-verbose"]},
        "preferences": {"music_genre": "auto", "default_browser": "chrome",
                        "work_hours": {"start": "10:00", "end": "22:00"},
                        "sleep_hours": {"start": "02:00", "end": "09:00"},
                        "favorite_apps": ["chrome", "vscode", "discord", "musicbee"],
                        "music_source": "Music folder, not Spotify",
                        "morning_routine": ["sysinfo"], "night_routine": ["monitor_off"]},
        "routines": {"good_morning": ["sysinfo", "brightness 80", "volume 30"],
                     "good_night": ["monitor_off", "volume 0"],
                     "work_mode": ["launch vscode", "launch chrome", "volume 20"],
                     "gaming_mode": ["volume 80", "brightness 100"]},
        "memory": {"last_session": None, "total_sessions": 0, "total_commands": 0,
                   "first_run": None, "frequent_commands": {}, "last_5_commands": [],
                   "avg_session_duration_mins": 0}
    }
    try:
        if _AZAZIL_PROFILE_PATH.exists():
            with open(_AZAZIL_PROFILE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Merge defaults for any missing keys
            for section in defaults:
                if section not in data:
                    data[section] = defaults[section]
                elif isinstance(defaults[section], dict):
                    for k, v in defaults[section].items():
                        if k not in data[section]:
                            data[section][k] = v
            return data
    except Exception:
        pass
    return defaults


def _save_profile(profile: dict) -> None:
    """Persist the profile to disk."""
    try:
        with open(_AZAZIL_PROFILE_PATH, "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=4, ensure_ascii=False)
    except Exception:
        pass


def _update_session_memory(profile: dict) -> dict:
    """Update session counters on every launch."""
    mem = profile.setdefault("memory", {})
    now_str = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    if not mem.get("first_run"):
        mem["first_run"] = now_str
    mem["last_session"] = now_str
    mem["total_sessions"] = mem.get("total_sessions", 0) + 1
    _save_profile(profile)
    return profile


# ─── Vector Memory System (ChromaDB) ────────────────────────────────────────

_chroma_client = None
_chroma_collection = None

def _init_vector_memory():
    """Initialize ChromaDB for Azazil's long-term semantic memory."""
    global _chroma_client, _chroma_collection
    if _chroma_collection is not None:
        return True
    try:
        import chromadb
        _AZAZIL_MEMORY_DIR.mkdir(parents=True, exist_ok=True)
        _chroma_client = chromadb.PersistentClient(path=str(_AZAZIL_MEMORY_DIR))
        _chroma_collection = _chroma_client.get_or_create_collection(
            name="azazil_memories",
            metadata={"hnsw:space": "cosine"}
        )
        return True
    except ImportError:
        return False
    except Exception:
        return False


def _memory_store(text: str, category: str = "general", metadata: dict = None):
    """Store a memory in the vector database."""
    if not _init_vector_memory():
        return
    try:
        mem_id = f"mem_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hash(text) & 0xFFFF:04x}"
        meta = {
            "category": category,
            "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            "session": str(_load_profile().get("memory", {}).get("total_sessions", 0)),
        }
        if metadata:
            meta.update(metadata)
        _chroma_collection.add(
            documents=[text],
            metadatas=[meta],
            ids=[mem_id]
        )
    except Exception:
        pass


def _memory_recall(query: str, n_results: int = 5, category: str = None) -> list:
    """Recall relevant memories by semantic similarity."""
    if not _init_vector_memory():
        return []
    try:
        kwargs = {"query_texts": [query], "n_results": n_results}
        if category:
            kwargs["where"] = {"category": category}
        results = _chroma_collection.query(**kwargs)
        memories = []
        if results and results.get("documents"):
            for doc, meta, dist in zip(
                results["documents"][0],
                results["metadatas"][0],
                results["distances"][0]
            ):
                memories.append({
                    "text": doc,
                    "category": meta.get("category", ""),
                    "timestamp": meta.get("timestamp", ""),
                    "relevance": round(1.0 - dist, 3)  # cosine distance → similarity
                })
        return memories
    except Exception:
        return []


def _memory_count() -> int:
    """Return the total number of stored memories."""
    if not _init_vector_memory():
        return 0
    try:
        return _chroma_collection.count()
    except Exception:
        return 0


def _memory_store_command(command: str, result: str = ""):
    """Store an executed command as a memory for pattern learning."""
    text = f"User ran command: {command}"
    if result:
        text += f" — Result: {result[:150]}"
    _memory_store(text, category="command", metadata={"command": command})


def _memory_store_conversation(user_msg: str, agent_reply: str):
    """Store a conversation exchange for conversational memory."""
    text = f"User said: {user_msg}\nAzazil replied: {agent_reply[:250]}"
    _memory_store(text, category="conversation")


def _memory_store_preference(preference: str):
    """Store a learned preference or habit."""
    _memory_store(f"Learned preference: {preference}", category="preference")


def _append_to_soup_dataset(user_msg: str, agent_reply: str, actions: list = None):
    """Continuously append a completed interaction turn to the soup-cli training dataset."""
    sft_file = _AZAZIL_MEMORY_DIR / "azazil_soup_sft.jsonl"
    _AZAZIL_MEMORY_DIR.mkdir(parents=True, exist_ok=True)

    clean_user = user_msg.strip()
    if clean_user.lower() in ("back", "exit", "q", "bye", "0", "status", "/status", "/clear", "clear", "ping", "/ping"):
        return

    assistant_content = agent_reply.strip()
    if actions:
        action_str = "\n".join(actions)
        if action_str not in assistant_content:
            assistant_content = f"{action_str}\n\n{assistant_content}".strip()

    record = {
        "messages": [
            {"role": "system", "content": _get_agent_system_prompt(is_local=True)},
            {"role": "user", "content": clean_user},
            {"role": "assistant", "content": assistant_content}
        ],
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "has_actions": bool(actions),
        }
    }

    try:
        with open(sft_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _learn_from_interaction(user_msg: str, agent_reply: str, actions: list = None):
    """
    Continuous Learning Engine:
    1. Distills preferences, facts, and rules from user input.
    2. Detects and stores user corrections with highest priority.
    3. If user asked a question, stores the Q&A resolution as episodic few-shot memory.
    4. Automatically appends the complete interaction turn to the soup-cli SFT training dataset.
    """
    clean_user = (user_msg or "").strip()
    clean_reply = (agent_reply or "").strip()
    if not clean_user or not clean_reply:
        return

    # A. Heuristic Extraction for Preferences, Habits & Facts
    pref_patterns = [
        r"(?:i prefer|i like|i love|i hate|i dislike)\s+(.+)",
        r"(?:always|never|don't|do not)\s+(.+)",
        r"(?:from now on|remember that|keep in mind that?)\s+(.+)",
        r"(?:my\s+(?:favorite|preferred|default|daily|current)\s+[\w\s]+(?:is|are))\s+(.+)",
        r"(?:my\s+(?:editor|ide|browser|com\s*port|esp32|gpu|os|distro|baud|port)\s+(?:is|=))\s+(.+)",
        r"(?:call me|my name is)\s+(.+)",
    ]
    for pat in pref_patterns:
        m = re.search(pat, clean_user, re.IGNORECASE)
        if m:
            extracted = m.group(0).strip().rstrip(".!")
            _memory_store(f"Learned preference: {extracted}", category="preference")
            break

    # B. Heuristic Extraction for Corrections & Alignments
    corr_patterns = [
        r"^(?:no,|not that|don't do that|wrong|instead of|actually,)\s*(.+)",
        r"(?:you should have|next time|instead use|i told you to?)\s+(.+)",
    ]
    for pat in corr_patterns:
        m = re.search(pat, clean_user, re.IGNORECASE)
        if m:
            extracted = m.group(0).strip().rstrip(".!")
            _memory_store(f"User correction / rule: {extracted}", category="correction", metadata={"user_correction": True})
            break

    # C. Q&A Exchange Memory (Learning from questions)
    is_question = "?" in clean_user or any(
        clean_user.lower().startswith(w) for w in ("how", "what", "where", "why", "which", "who", "can you", "could you", "is there", "are there", "explain", "check if")
    )
    if is_question and len(clean_user) > 6:
        first_sentence = clean_reply.split("\n")[0][:180].strip()
        qa_text = f"User asked: {clean_user}\nLearned resolution: {first_sentence}"
        _memory_store(qa_text, category="qa_exchange", metadata={"query_type": "question"})

    # D. Always store standard conversation memory
    _memory_store_conversation(clean_user, clean_reply)

    # E. Continuous Live SFT Dataset Harvester for soup-cli
    _append_to_soup_dataset(clean_user, clean_reply, actions=actions)


def _build_learning_grounding(user_input: str) -> str:
    """Build a rich, high-density learned-knowledge grounding block for local & cloud models."""
    blocks = []

    # 1. Check for relevant user corrections / hard rules (high priority)
    try:
        corrections = _memory_recall(user_input, n_results=2, category="correction")
        if corrections:
            corr_items = [c["text"] for c in corrections if c.get("relevance", 0) > 0.28]
            if corr_items:
                blocks.append("• Critical User Directives & Corrections:\n" + "\n".join(f"  - {t}" for t in corr_items))
    except Exception:
        pass

    # 2. Check for relevant user preferences & habits
    try:
        preferences = _memory_recall(user_input, n_results=3, category="preference")
        if preferences:
            pref_items = [p["text"] for p in preferences if p.get("relevance", 0) > 0.32]
            if pref_items:
                blocks.append("• Learned User Preferences & Habits:\n" + "\n".join(f"  - {t}" for t in pref_items))
    except Exception:
        pass

    # 3. Check for relevant past Q&A memories (learning from past questions)
    try:
        qa_mems = _memory_recall(user_input, n_results=2, category="qa_exchange")
        if qa_mems:
            qa_items = [q["text"] for q in qa_mems if q.get("relevance", 0) > 0.38]
            if qa_items:
                blocks.append("• Relevant Past Q&A / Proven Solutions:\n" + "\n".join(f"  - {t}" for t in qa_items))
    except Exception:
        pass

    # 4. Fallback to general semantic memory if specific categories are sparse
    if not blocks:
        try:
            general = _memory_recall(user_input, n_results=3)
            gen_items = [g["text"] for g in general if g.get("relevance", 0) > 0.38]
            if gen_items:
                blocks.append("• Relevant Memory Context:\n" + "\n".join(f"  - {t}" for t in gen_items))
        except Exception:
            pass

    if blocks:
        return "[🧠 CONTINUOUS LEARNING CONTEXT (Learned from the user's Past Inputs & Questions)]\n" + "\n".join(blocks)
    return ""


def _get_soup_dataset_stats() -> dict:
    """Read and calculate statistics on the harvested soup-cli dataset."""
    sft_file = _AZAZIL_MEMORY_DIR / "azazil_soup_sft.jsonl"
    if not sft_file.exists():
        return {"samples": 0, "size_kb": 0, "status": "No dataset created yet."}

    samples = 0
    total_chars = 0
    has_actions = 0
    try:
        with open(sft_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    samples += 1
                    total_chars += len(line)
                    if '"has_actions": true' in line:
                        has_actions += 1
        size_kb = round(sft_file.stat().st_size / 1024, 1)
        avg_tokens = round((total_chars / max(samples, 1)) / 4)
        return {
            "samples": samples,
            "actions_count": has_actions,
            "size_kb": size_kb,
            "avg_tokens": avg_tokens,
            "path": str(sft_file),
            "status": "Ready for training" if samples >= 10 else f"Accumulating ({samples}/10 minimum recommended)"
        }
    except Exception as e:
        return {"samples": 0, "error": str(e)}


def _export_soup_dataset(output_path: Path = None) -> str:
    """Export conversation memories and command traces into soup-cli compatible JSONL format."""
    if output_path is None:
        output_path = _AZAZIL_MEMORY_DIR / "azazil_soup_sft.jsonl"
    _AZAZIL_MEMORY_DIR.mkdir(parents=True, exist_ok=True)
    
    count = 0
    try:
        if not _init_vector_memory():
            return "Vector memory not initialized."
        results = _chroma_collection.get()
        if not results or not results.get("documents"):
            return "No memories to export."
        
        with open(output_path, "w", encoding="utf-8") as f:
            for doc, meta in zip(results["documents"], results["metadatas"]):
                cat = meta.get("category", "")
                if cat == "conversation" and "User said:" in doc and "Azazil replied:" in doc:
                    parts = doc.split("Azazil replied:", 1)
                    user_part = parts[0].replace("User said:", "").strip()
                    agent_part = parts[1].strip()
                    entry = {
                        "messages": [
                            {"role": "system", "content": _get_agent_system_prompt(is_local=True)},
                            {"role": "user", "content": user_part},
                            {"role": "assistant", "content": agent_part}
                        ]
                    }
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                    count += 1
                elif cat == "routine":
                    entry = {
                        "messages": [
                            {"role": "system", "content": _get_agent_system_prompt(is_local=True)},
                            {"role": "user", "content": "Run my routine"},
                            {"role": "assistant", "content": f"ACTION: {doc}"}
                        ]
                    }
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                    count += 1
        return f"Exported {count} training samples to: {output_path} (Ready for soup-cli)"
    except Exception as e:
        return f"Export failed: {e}"


# ─── Time-of-Day Awareness ──────────────────────────────────────────────────

def _get_time_period() -> str:
    """Return the current time period for personality adaptation."""
    hour = datetime.now().hour
    if 6 <= hour < 12:
        return "morning"
    elif 12 <= hour < 17:
        return "afternoon"
    elif 17 <= hour < 22:
        return "evening"
    else:
        return "late_night"


def _get_day_of_week() -> str:
    return datetime.now().strftime("%A")


# ─── Welcome Context Gathering ──────────────────────────────────────────────

def _gather_welcome_context(profile: dict) -> dict:
    """Gather real-time system + profile context for the welcome message."""
    now = datetime.now()
    ctx = {
        "name": profile.get("owner", {}).get("name") or str(_CONFIG.get("owner_name", "Boss") or "Boss"),
        "nickname": profile.get("owner", {}).get("nickname", "Boss"),
        "assistant": profile.get("personality", {}).get("name") or _ASSISTANT_NAME,
        "formality": profile.get("personality", {}).get("formality", "casual"),
        "traits": ", ".join(profile.get("personality", {}).get("traits", [])),
        "time": now.strftime("%I:%M %p"),
        "time_24h": now.strftime("%H:%M"),
        "day_of_week": _get_day_of_week(),
        "period": _get_time_period(),
        "date": now.strftime("%d %b %Y"),
    }

    # System metrics
    try:
        ctx["cpu"] = f"{psutil.cpu_percent(interval=0.3):.0f}"
        mem = psutil.virtual_memory()
        ctx["ram"] = f"{mem.percent:.0f}"
    except Exception:
        ctx["cpu"] = "?"
        ctx["ram"] = "?"

    # Battery
    try:
        batt = psutil.sensors_battery()
        if batt:
            ctx["battery"] = f"{batt.percent:.0f}"
            ctx["charging"] = " (charging)" if batt.power_plugged else ""
        else:
            ctx["battery"] = "N/A"
            ctx["charging"] = ""
    except Exception:
        ctx["battery"] = "?"
        ctx["charging"] = ""

    # Uptime
    try:
        boot = datetime.fromtimestamp(psutil.boot_time())
        up = now - boot
        h, r = divmod(int(up.total_seconds()), 3600)
        m, _ = divmod(r, 60)
        ctx["uptime"] = f"{h}h {m}m"
    except Exception:
        ctx["uptime"] = "unknown"

    # Session history
    mem_data = profile.get("memory", {})
    ctx["sessions"] = str(mem_data.get("total_sessions", 1))
    ctx["first_run"] = "yes" if mem_data.get("total_sessions", 0) <= 1 else "no"
    last = mem_data.get("last_session")
    if last and last != now.strftime("%Y-%m-%dT%H:%M:%S"):
        try:
            last_dt = datetime.strptime(last, "%Y-%m-%dT%H:%M:%S")
            delta = now - last_dt
            mins_ago = int(delta.total_seconds() / 60)
            if mins_ago < 60:
                ctx["last_session"] = f"{mins_ago} minutes ago"
            elif mins_ago < 1440:
                ctx["last_session"] = f"{mins_ago // 60} hours ago"
            else:
                ctx["last_session"] = f"{mins_ago // 1440} days ago"
            ctx["quick_return"] = "yes" if mins_ago < 30 else "no"
        except Exception:
            ctx["last_session"] = "unknown"
            ctx["quick_return"] = "no"
    else:
        ctx["last_session"] = "just now (first)"
        ctx["quick_return"] = "no"

    # Memory count
    ctx["memories"] = str(_memory_count())

    return ctx


# ─── AI Welcome Message Generation ──────────────────────────────────────────

_WELCOME_PROMPT_TEMPLATE = """\
You are {assistant}, a personal AI agent for your owner {name}.
Generate a SHORT, punchy welcome message (1-3 sentences max).

Context right now:
- Time: {time} ({day_of_week})
- Time period: {period} (morning/afternoon/evening/late_night)
- Battery: {battery}%{charging}
- CPU: {cpu}%, RAM: {ram}%
- System uptime: {uptime}
- Last session: {last_session}
- Quick return (back within 30min): {quick_return}
- Total sessions: {sessions}
- First ever run: {first_run}
- Stored memories: {memories}
- Your personality traits: {traits}

Rules:
- Be {formality}. Address them as "{nickname}" naturally (not every sentence).
- If it's late night (after 2am), gently roast them for being up.
- If battery is low (<20%), mention it with urgency.
- If CPU or RAM is very high (>85%), note it briefly.
- If it's their first session ever, make it special and memorable.
- If they were just here <30min ago, acknowledge the quick return with personality.
- NO emoji spam. Max 1-2 emoji total. Sound natural, not robotic.
- Channel the vibe of: Jarvis meets a loyal hacker companion.
- Do NOT start with "Hey" or "Hello". Be more creative.
- Output ONLY the welcome message text. Nothing else.
"""

_FALLBACK_WELCOMES = {
    "morning": [
        "Morning, {nickname}. Systems nominal, {cpu}% CPU, battery at {battery}%. What's the plan?",
        "Rise and grind, {nickname}. Your machine's been waiting. {uptime} uptime and counting.",
        "Another day, another session. {day_of_week} morning — let's make it count, {nickname}.",
    ],
    "afternoon": [
        "Afternoon, {nickname}. {assistant} online. {cpu}% CPU, {ram}% RAM. Ready when you are.",
        "Back at it, {nickname}. Everything's running smooth — {battery}%{charging}. What do you need?",
        "{day_of_week} afternoon. {sessions} sessions deep and still going strong, {nickname}.",
    ],
    "evening": [
        "Evening, {nickname}. Winding down or gearing up? Either way, I'm here.",
        "Night shift, {nickname}. {cpu}% CPU, {battery}% battery{charging}. Let's get to it.",
        "Evening session #{sessions}. What are we cooking tonight, {nickname}?",
    ],
    "late_night": [
        "It's {time}, {nickname}. You sure about this? ...Alright, I'm here. Battery's at {battery}%.",
        "{time}. You and me against the night, {nickname}. Don't blame me when you're tired tomorrow.",
        "Still awake, {nickname}? {battery}%{charging}. Let's at least make this insomnia productive.",
    ],
}

_QUICK_RETURN_WELCOMES = [
    "Miss me already? Alright, I'm here. What'd you forget?",
    "Back so soon, {nickname}? Let's pick up where we left off.",
    "That was quick. Did you blink and miss me?",
]

_FIRST_RUN_WELCOMES = [
    "{name}. I'm {assistant} — your machine, your rules, your agent. Let's see what we can do together. 🔥",
    "First boot. I'm {assistant}, and from now on, this PC answers to you, {nickname}. Let's go.",
]


def _generate_welcome_message(ctx: dict) -> str:
    """Generate an AI welcome message using Gemini, with graceful fallbacks."""
    import random

    # Special case: first ever run
    if ctx.get("first_run") == "yes":
        return random.choice(_FIRST_RUN_WELCOMES).format(**ctx)

    # Special case: quick return
    if ctx.get("quick_return") == "yes":
        return random.choice(_QUICK_RETURN_WELCOMES).format(**ctx)

    # Try Gemini for a unique AI-generated welcome
    try:
        import google.genai as genai
        from google.genai import types as genai_types

        client = genai.Client(api_key=_GEMINI_API_KEY)
        prompt = _WELCOME_PROMPT_TEMPLATE.format(**ctx)

        response = client.models.generate_content(
            model="gemini-3.5-flash-lite",  # fastest model, highest RPM
            contents=prompt,
            config=genai_types.GenerateContentConfig(
                temperature=0.9,  # more creative for welcomes
                max_output_tokens=150,
            ),
        )
        text = response.text.strip().strip('"').strip("'")
        if text and len(text) > 10:
            # Store the welcome as a memory
            _memory_store(f"Welcome message generated: {text}", category="welcome")
            return text
    except Exception:
        pass  # Fall through to offline fallbacks

    # Offline fallback
    period = ctx.get("period", "evening")
    options = _FALLBACK_WELCOMES.get(period, _FALLBACK_WELCOMES["evening"])
    return random.choice(options).format(**ctx)


_CURRENT_WELCOME_DATA = None

def _get_or_create_welcome(profile: dict = None) -> dict:
    """Get the cached welcome message or generate a fresh one."""
    global _CURRENT_WELCOME_DATA
    if _CURRENT_WELCOME_DATA is None:
        if profile is None:
            profile = _load_profile()
        ctx = _gather_welcome_context(profile)
        msg = _generate_welcome_message(ctx)
        _CURRENT_WELCOME_DATA = {"msg": msg, "ctx": ctx}
    return _CURRENT_WELCOME_DATA


def _display_welcome(profile: dict):
    """Display the assistant welcome message on startup."""
    data = _get_or_create_welcome(profile)
    ctx = data["ctx"]
    message = data["msg"]
    personality_name = profile.get("personality", {}).get("name", _ASSISTANT_NAME)

    welcome_text = f"[bold white]{message}[/bold white]"
    suggestions = []
    try:
        batt = psutil.sensors_battery()
        if batt and not batt.power_plugged and batt.percent < 25:
            suggestions.append(f"[bold red]⚡ Battery critical: {batt.percent:.0f}% — plug in![/bold red]")
        cpu = psutil.cpu_percent(interval=0)
        if cpu > 85:
            suggestions.append(f"[yellow]⚠ CPU is running hot: {cpu:.0f}%[/yellow]")
        mem = psutil.virtual_memory()
        if mem.percent > 85:
            suggestions.append(f"[yellow]⚠ RAM pressure: {mem.percent:.0f}% used[/yellow]")
    except Exception:
        pass

    mem_count = _memory_count()
    status_parts = [f"[{DIM}]{ctx['day_of_week']} {ctx['time']}[/{DIM}]"]
    if mem_count > 0:
        status_parts.append(f"[{DIM}]{mem_count} memories[/{DIM}]")
    status_parts.append(f"[{DIM}]Session #{ctx['sessions']}[/{DIM}]")
    status_line = f"[{DIM}] · [/{DIM}]".join(status_parts)

    panel_content = f"{welcome_text}\n\n{status_line}"
    if suggestions:
        panel_content += "\n" + "\n".join(suggestions)

    console.print()
    console.print(Panel(
        Align.center(panel_content),
        title=f"[bold {ACCENT}]🧠 {personality_name}[/bold {ACCENT}]",
        border_style=ACCENT,
        box=PANEL_BOX,
        padding=(1, 3),
    ))
    console.print()


def _speak(text: str) -> str:
    """Speak text using Windows SAPI SpeechSynthesizer on the interactive desktop."""
    clean = text.replace('"', '`"').replace("'", "’")
    ps = f'''
Add-Type -AssemblyName System.Speech
$s = New-Object System.Speech.Synthesis.SpeechSynthesizer
$s.Rate = 1
$s.Speak("{clean}")
'''
    try:
        launch_desktop_app(f'powershell -WindowStyle Hidden -NoProfile -Command "{ps.strip()}"')
        return f"Spoken aloud: '{text[:80]}...'"
    except Exception as e:
        return f"Voice synthesis error: {e}"


def _execute_routine(name: str) -> str:
    """Execute a pre-configured routine from azazil_profile.json."""
    profile = _load_profile()
    routines = profile.get("routines", {})
    clean_name = name.strip().lower().replace(" ", "_")
    steps = routines.get(clean_name)
    if not steps:
        available = ", ".join(routines.keys())
        return f"Routine '{name}' not found. Available routines: {available}"
    
    results = []
    for step in steps:
        action_line = f"ACTION: {step}" if not step.startswith("ACTION:") else step
        res = _agent_exec(action_line)
        results.append(f"{step} → {res}")
        time.sleep(0.4)
    
    _memory_store(f"Ran routine '{clean_name}' successfully", category="routine")
    return f"Completed routine '{clean_name}':\n" + "\n".join(f"  • {r}" for r in results)


def _generate_briefing() -> str:
    """Generate a comprehensive morning / system briefing."""
    profile = _load_profile()
    ctx = _gather_welcome_context(profile)
    nickname = profile.get("owner", {}).get("nickname", "Boss")
    now_str = datetime.now().strftime("%I:%M %p, %A, %d %B %Y")
    
    lines = [
        f"📋 Briefing for {nickname} — {now_str}",
        f"• Battery: {ctx.get('battery')}%{ctx.get('charging', '')}",
        f"• CPU Load: {ctx.get('cpu')}% | RAM Used: {ctx.get('ram')}%",
        f"• PC Uptime: {ctx.get('uptime')}",
        f"• Total {_ASSISTANT_NAME} Sessions: {ctx.get('sessions')}",
        f"• Stored Vector Memories: {_memory_count()}",
    ]
    try:
        wins = get_visible_windows()
        if wins:
            top_wins = [w['title'] for w in wins[:4] if w.get('title')]
            if top_wins:
                lines.append(f"• Active Apps: {', '.join(top_wins)}")
    except Exception:
        pass
    note_file = _NOTES_DIR / "quick_notes.txt"
    if note_file.exists():
        try:
            notes = [n.strip() for n in note_file.read_text(encoding="utf-8").splitlines() if n.strip()]
            if notes:
                lines.append(f"• Recent Note: {notes[-1]}")
        except Exception:
            pass
    return "\n".join(lines)


def _get_agent_system_prompt(is_local: bool = False, query: str = "") -> str:
    """Build a rich, personalized system prompt containing the assistant's identity and vector memories."""
    profile = _load_profile()
    owner = profile.get("owner", {})
    personality = profile.get("personality", {})
    routines = profile.get("routines", {})

    owner_name = owner.get("name", str(_CONFIG.get("owner_name", "Boss") or "Boss"))
    nickname = owner.get("nickname", "Boss")
    traits = ", ".join(personality.get("traits", ["loyal", "helpful"]))
    formality = personality.get("formality", "casual")
    style = personality.get("style", "witty_loyal")

    now = datetime.now()
    period = _get_time_period()
    day_name = _get_day_of_week()
    time_str = now.strftime("%I:%M %p")

    try:
        cpu = f"{psutil.cpu_percent(interval=0):.0f}%"
        mem = f"{psutil.virtual_memory().percent:.0f}%"
    except Exception:
        cpu, mem = "?", "?"

    batt_str = "N/A"
    try:
        batt = psutil.sensors_battery()
        if batt:
            batt_str = f"{batt.percent:.0f}% {'(charging)' if batt.power_plugged else '(on battery)'}"
    except Exception:
        pass

    memories_text = ""
    if query:
        recalled = _memory_recall(query, n_results=4)
        if recalled:
            mem_lines = [f"  - [{m['category']}] {m['text']} (relevance: {m.get('relevance', 1.0)})" for m in recalled]
            memories_text = "\nRELEVANT MEMORIES ABOUT THE USER & SYSTEM (from ChromaDB):\n" + "\n".join(mem_lines) + "\n"

    routine_names = ", ".join(routines.keys())

    header = f"""\
You are {_ASSISTANT_NAME} — {owner_name}'s personal AI assistant embedded directly in their Windows PC.
You are {traits}. Style: {style}. Formality: {formality}.
Address {owner_name} naturally as "{nickname}".
Current Time: {time_str} ({day_name}, {period}). Battery: {batt_str}. CPU: {cpu}, RAM: {mem}.
Available Routines: {routine_names}
Respond concisely — this runs over SSH / mobile terminal. Be useful first, witty second.
{memories_text}
"""
    base_rules = _LOCAL_AGENT_SYSTEM_PROMPT if is_local else _AGENT_SYSTEM_PROMPT
    return header + "\n" + base_rules


# ═══════════════════════════════════════════════════════════════
# MAIN MENU
# ═══════════════════════════════════════════════════════════════


# ─── Menu item registry (key, icon, label, fn) ───────────────────────────────
# Key 'a' / Enter → AI Agent (fastest path for most-used feature)
# Keys 1-28 → everything else, grouped by category in show_main_menu()
MENU_ITEMS = [
    # ─ AI (primary) ──────────────────────────────────────────────────────────
    ("a",  "🤖", "AI Agent",           ai_agent),
    # ─ System ────────────────────────────────────────────────────────────────
    ("1",  "*",  "System Dashboard",   show_dashboard),
    ("2",  "$",  "Shell",              shell_session),
    ("3",  "G",  "Processes",          process_manager),
    ("4",  "T",  "Tasks & Services",   windows_tasks),
    ("5",  "^",  "Startup Manager",    startup_manager),
    ("6",  "!",  "Power Control",      power_control),
    # ─ Files ─────────────────────────────────────────────────────────────────
    ("7",  "F",  "File Manager",       file_manager),
    ("8",  "🔍", "File Search",        file_search),
    ("9",  "D",  "Downloads",          download_manager),
    ("10", "📡", "File Transfer",      file_transfer_server),
    ("11", "S",  "Screenshot",         take_screenshot),
    # ─ Network & Comms ───────────────────────────────────────────────────────
    ("12", "N",  "Network Info",       network_info),
    ("13", "W",  "Wi-Fi Manager",      wifi_manager),
    ("14", "~",  "Notifications",      send_notification),
    # ─ Media ─────────────────────────────────────────────────────────────────
    ("15", "♫",  "Music Player",       music_player),
    ("16", "M",  "Media Control",      media_control),
    ("17", "🎙", "Audio Capture",      audio_capture_menu),
    # ─ Control ───────────────────────────────────────────────────────────────
    ("18", "🗔", "Window & Browser",   window_browser_manager),
    ("19", "🖱", "Mouse Control",      mouse_control_menu),
    ("20", ">",  "App Launcher",       app_launcher),
    ("21", "C",  "Clipboard",          clipboard_manager),
    # ─ Tools ─────────────────────────────────────────────────────────────────
    ("22", "👁", "Screen OCR",         ocr_menu),
    ("23", "🔔", "Event Watchers",     event_watcher_menu),
    ("24", "🖥", "Display Control",    display_control),
    ("25", "#",  "Quick Note",         quick_note),
    # ─ Dev ───────────────────────────────────────────────────────────────────
    ("26", "AI", "LM Studio",          lmstudio_module),
    ("27", "U",  "Unity Build",        unity_module),
    ("28", "*F", "Favorites",          favorites_manager),
    ("29", "🐉", "Kali Linux",          launch_kali_linux),
    ("30", "📷", "Snap Webcam",          snap_webcam_menu),
    ("31", "⚙️", "Setup",                launch_setup_wizard),
    ("setup", "⚙️", "Setup",             launch_setup_wizard),
]


def show_main_menu():
    clear()
    console.print(Text(BANNER, style=f"bold {ACCENT}"), justify="center")
    console.print(Align.center(Text(f"{TAGLINE}  |  {VERSION}  |  {platform.node()}", style=DIM)))
    console.print()

    # Status bar
    try:
        cpu  = psutil.cpu_percent(interval=0.3)
        mem  = psutil.virtual_memory()
        disk = psutil.disk_usage("C:\\")
        boot = datetime.fromtimestamp(psutil.boot_time())
        h, r = divmod(int((datetime.now()-boot).total_seconds()), 3600)
        m, _ = divmod(r, 60)
        batt = psutil.sensors_battery()
        batt_str = ""
        if batt:
            bc = "green" if batt.power_plugged else ("yellow" if batt.percent > 20 else "red")
            bs = "CHG" if batt.power_plugged else "BAT"
            batt_str = f"  [{bc}]{bs} {batt.percent:.0f}%[/{bc}]"
        console.print(Align.center(
            f"[{ACCENT}]CPU[/{ACCENT}] {cpu:4.0f}%  "
            f"[{ACCENT}]MEM[/{ACCENT}] {mem.percent:4.0f}%  "
            f"[{ACCENT}]DISK[/{ACCENT}] {disk.percent:4.0f}%  "
            f"[{ACCENT}]UP[/{ACCENT}] {h}h{m}m"
            f"{batt_str}"
        ))
    except: pass

    console.print()

    # Assistant Personality & AI Agent Hero (Primary Action)
    profile = _load_profile()
    welcome_info = _get_or_create_welcome(profile)
    personality_name = profile.get("personality", {}).get("name", _ASSISTANT_NAME)
    mem_count = _memory_count()
    mem_tag = f" · {mem_count} vector memories" if mem_count > 0 else ""

    hero_content = (
        f"[bold white]{welcome_info['msg']}[/bold white]\n\n"
        f"[{DIM}]🤖 AI Agent · Gemini · Local LLM{mem_tag}[/{DIM}]\n"
        f"[{DIM}]Press [/][bold {ACCENT}]Enter[/bold {ACCENT}][{DIM}] or type [/][bold {ACCENT}]a[/bold {ACCENT}][{DIM}] to interact with {personality_name}[/{DIM}]"
    )
    console.print(Panel(
        Align.center(hero_content),
        title=f"[bold {ACCENT}]🧠 {personality_name}[/bold {ACCENT}]",
        border_style=ACCENT, box=PANEL_BOX, padding=(1, 3)
    ))
    console.print()

    # Responsive single-column menu (2 items/row if wide enough, else 1)
    w = console.width
    WIDE = w >= 90

    GROUPS = [
        ("SYSTEM", [
            ("1",  "Dashboard"),      ("2",  "Shell"),
            ("3",  "Processes"),      ("4",  "Tasks & Services"),
            ("5",  "Startup"),        ("6",  "Power"),
            ("12", "Network"),        ("13", "Wi-Fi"),
            ("14", "Notifications"),
        ]),
        ("FILES & MEDIA", [
            ("7",  "File Manager"),   ("8",  "File Search"),
            ("9",  "Downloads"),      ("10", "File Transfer"),
            ("11", "Screenshot"),     ("15", "Music Player"),
            ("16", "Media Control"),  ("17", "Audio Capture"),
        ]),
        ("CONTROL & TOOLS", [
            ("18", "Window/Browser"), ("19", "Mouse Control"),
            ("20", "App Launcher"),   ("21", "Clipboard"),
            ("22", "Screen OCR"),     ("23", "Event Watchers"),
            ("24", "Display"),        ("25", "Quick Note"),
        ]),
        ("DEV", [
            ("26", "LM Studio"), ("27", "Unity Build"),
            ("28", "Favorites"), ("29", "Kali Linux"),
            ("30", "Snap Webcam"), ("31", "Setup"),
        ]),
    ]

    def _section(heading, items):
        """Render one section: rule header + items grid."""
        console.print(Rule(f"[bold {ACCENT}]{heading}[/bold {ACCENT}]", style=DIM))
        if WIDE:
            t = Table.grid(padding=(0, 2), expand=True)
            t.add_column(ratio=1)
            t.add_column(ratio=1)
            row_buf = []
            for key, label in items:
                cell = f"  [{ACCENT}][{key:>2}][/{ACCENT}]  {label}"
                row_buf.append(cell)
                if len(row_buf) == 2:
                    t.add_row(*row_buf)
                    row_buf = []
            if row_buf:
                t.add_row(row_buf[0], "")
            console.print(t)
        else:
            for key, label in items:
                console.print(f"  [{ACCENT}][{key:>2}][/{ACCENT}]  {label}")
        console.print()

    for heading, items in GROUPS:
        _section(heading, items)

    console.print(Rule(style=DIM))
    console.print(
        f"  [{DIM}]Shortcuts: [/][bold {ACCENT}]f1[/bold {ACCENT}]"
        f"[{DIM}]-[/][bold {ACCENT}]f4[/bold {ACCENT}]"
        f"[{DIM}] Favorites   [/][bold {ACCENT}]0[/bold {ACCENT}][{DIM}] Exit[/{DIM}]"
    )

def main():
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))

    # ─── Assistant Boot Sequence ──────────────────────────────────────────
    profile = _load_profile()
    _update_session_memory(profile)  # track this session
    _memory_store("Session started", category="session")
    # Pre-warm the welcome message for instant menu display
    _get_or_create_welcome(profile)

    while True:
        show_main_menu()
        try:
            raw = Prompt.ask(f"\n  [{ACCENT}]remotepc[/{ACCENT}]").lstrip("\ufeff").lstrip("ï»¿").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        # Empty Enter or 'a' → AI Agent (most-used, fastest path)
        choice = raw if raw else "a"

        if choice in ("gui", "bridge"):
            choice = "31"

        if choice == "0":
            clear()
            prof = _load_profile()
            nick = prof.get("owner", {}).get("nickname", "Boss")
            pname = prof.get("personality", {}).get("name", _ASSISTANT_NAME)
            console.print(Panel(
                Align.center(Text(f"Until next time, {nick}.\n{pname} session ended. Going into standby.", style="bold cyan")),
                border_style="cyan", box=PANEL_BOX, padding=(1, 4)))
            _memory_store("Session ended", category="session")
            _security_log("DISCONNECT", f"IP={_get_ssh_client_ip()}")
            break

        # Favorites quick-fire: f1 / f2 / f3 / f4
        if choice in ("f1", "f2", "f3", "f4"):
            _reset_idle_timer()
            slot = choice[1]
            favs = _load_favorites()
            key  = favs.get(slot)
            if key:
                _run_favorite(key, MENU_ITEMS)
            else:
                console.print(f"[{WARN}]F{slot} is empty. Use menu 28 (Favorites) to set it.[/{WARN}]")
                time.sleep(1.2)
            continue

        fn = next((fn for k, _, _, fn in MENU_ITEMS if k == choice), None)
        if fn:
            _reset_idle_timer()
            label = next((lbl for k, _, lbl, _ in MENU_ITEMS if k == choice), choice)
            _log_command("manual", f"menu:{choice} ({label})")
            _memory_store_command(f"Menu option {choice} ({label})")
            try: fn()
            except KeyboardInterrupt: pass
        else:
            console.print(f"[{ERROR}]Invalid option: '{choice}'[/{ERROR}]")
            time.sleep(0.8)


if __name__ == "__main__":
    _security_check()
    _reset_idle_timer()
    main()

