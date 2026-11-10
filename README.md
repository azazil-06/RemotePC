# RemotePC

<p align="center">
  <b>Your PC. Your Phone. Your Control.</b><br>
  A terminal control center and autonomous AI agent for managing Windows desktops over SSH.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?logo=python" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/OS-Windows%2010%20%2F%2011-0078D6?logo=windows" alt="Windows 10/11">
  <img src="https://img.shields.io/badge/Network-Tailscale-4B70E2?logo=tailscale" alt="Tailscale">
  <img src="https://img.shields.io/badge/AI-Gemini%20%2B%20Local%20LLM-8E75C2?logo=google" alt="AI">
  <img src="https://img.shields.io/badge/Security-Safe%20Mode-green" alt="Safe Mode">
</p>

---

## Overview

**RemotePC** turns a Windows PC into a remote-accessible terminal workstation. It is designed for
mobile SSH clients (Termux, JuiceSSH, Prompt, the built-in OpenSSH client, …) and gives you full
control over the machine — processes, files, windows, browsers, media, power — without a heavy
remote-desktop tool.

Key highlights:

- **Interactive TUI** built with [`rich`](https://github.com/Textualize/rich) — clean, mobile-friendly screens.
- **Desktop Session Bridge** — works around Windows OpenSSH's Session 0 / Session 1 isolation so remote
  commands can interact with your real monitor and desktop.
- **Autonomous AI Agent** — talk to your PC in natural language to launch apps, manage windows, query
  websites over CDP, control volume, or run diagnostics.
- **Hybrid cloud + local AI** — runs Google Gemini models with automatic failover to local LM Studio
  models when rate limits are hit.
- **Safe Mode** — a three-tier guardrail (ALLOW / CONFIRM / BLOCK) that prevents accidental damage.
- **Everything personal lives in a config file** — no API keys, models, paths or IPs are hard-coded in
  the source.

---

## Demo

<p align="center">
  <a href="Demo/Screenshot%202026-11-11%20002655.png"><img src="Demo/Screenshot%202026-11-11%20002655.png" width="30%" alt="RemotePC demo screenshot 1"></a>
  <a href="Demo/Screenshot%202026-11-11%20002757.png"><img src="Demo/Screenshot%202026-11-11%20002757.png" width="30%" alt="RemotePC demo screenshot 2"></a>
  <a href="Demo/Screenshot%202026-11-11%20002812.png"><img src="Demo/Screenshot%202026-11-11%20002812.png" width="30%" alt="RemotePC demo screenshot 3"></a>
</p>

---

## Prerequisites

### Control PC (Windows)

| Requirement | Notes |
|-------------|-------|
| **Windows 10 / 11** | The app drives Windows-only APIs (WMI, PowerShell, `schtasks`). |
| **Python 3.10 – 3.14** | 64-bit. Tick **"Add python.exe to PATH"** in the installer. |
| **pip** | Ships with Python. |
| *(optional)* **LM Studio** | Only needed if you want local models — cloud models need nothing installed. |
| *(optional)* **Tailscale** | Needed to reach the PC from outside your home LAN. |
| *(optional)* **Git** | To clone the repository. |

Quick check:

```bat
python --version
pip --version
```

### Client device (Android — Termux + Tailscale)

Your phone runs **none** of RemotePC — it is only an SSH client. Two free apps are all you need:

| App | Get it from | Purpose |
|-----|-------------|---------|
| **Tailscale** | [Google Play](https://play.google.com/store/apps/details?id=com.tailscale.ipn) | Puts the phone on the same private network as the PC. |
| **Termux** | [F-Droid](https://f-droid.org/packages/com.termux/) or [GitHub releases](https://github.com/termux/termux-app/releases) | The terminal + SSH client. **Do not use the Play Store build — it is deprecated and broken.** |

#### 1. Put both devices on Tailscale

Install Tailscale on the **PC** and the **phone** and sign in with the **same account** on both. On the PC,
run:

```bat
tailscale ip -4
```

That prints the PC's `100.x.y.z` address — the one you will SSH to. (Tailscale's *Machines* page shows the
same address for every signed-in device.)

#### 2. Install and prepare Termux

Install Termux from **F-Droid**, open it, then:

```bash
pkg update && pkg upgrade -y
pkg install -y openssh
```

#### 3. (Recommended) Set up a key so you skip the password

Generate a key pair inside Termux:

```bash
ssh-keygen -t ed25519
cat ~/.ssh/id_ed25519.pub      # copy this output
```

Append that public key on the PC to the correct `authorized_keys` file:

| PC account type | File to append it to |
|-----------------|----------------------|
| Normal user | `C:\Users\<you>\.ssh\authorized_keys` |
| Member of the **Administrators** group | `C:\ProgramData\ssh\administrators_authorized_keys` |

> **Windows quirk:** for Administrator accounts the key must go in
> `C:\ProgramData\ssh\administrators_authorized_keys`, **not** in your user profile. In an **Administrator**
> PowerShell create it with
> `notepad $env:ProgramData\ssh\administrators_authorized_keys` — Windows requires that file to be owned by
> `Administrators`/`SYSTEM`.

#### 4. Connect

```bash
ssh <your-windows-username>@<pc-tailscale-ip>
```

Type `yes` to trust the host key on first connect, then enter your Windows password (or rely on the key
above). Once you're in, launch RemotePC:

```bash
remotepc.bat
# or: python remotepc/remotepc.py
```

You need **sshd enabled on the PC** first — see [Remote Access](#remote-access--tailscale--ssh) below.

---

## Quick Start

> Assumes a Windows PC with Python 3.10+ — see [Prerequisites](#prerequisites).

```bat
:: 1. Clone
git clone https://github.com/azazil-06/RemotePC.git
cd RemotePC

:: 2. Install dependencies
pip install -r requirements.txt

:: 3. Launch — the first run starts the setup wizard automatically
remotepc.bat
```

Prefer to configure before launching?

```bat
python remotepc\setup_wizard.py
remotepc.bat
```

`remotepc.bat` detects your Python interpreter, and if no configuration exists yet it launches the
setup wizard automatically before starting the app. Any shortcut works:

| Command | Purpose |
|---------|---------|
| `remotepc.bat` | Launch from the repo root |
| `remotepc\remotepc.bat` (or `.cmd`) | Launch from inside `remotepc\` |
| `python remotepc\remotepc.py` | Launch directly |
| `python remotepc\setup_wizard.py` | Re-run the setup wizard any time |

---

## Setup Wizard

A short, guided first-run setup (like `npm create vite`) that writes a single config file. Run it with
`python remotepc\setup_wizard.py`, or open menu **[31] Setup** inside the app.

It walks through:

1. **Assistant** — the assistant's name and what it should call you.
2. **Cloud AI (optional)** — a Google Gemini API key. Skip it to run on local models only.
3. **Local models (LM Studio)** — it **scans your running LM Studio server**, lists the models it finds,
   and registers the ones you pick. The app's model menu is built from these dynamically.
4. **Remote access security** — auto-detects this PC's Tailscale and LAN IPs, and optionally sets a PIN
   (stored as a SHA-256 hash).
5. **Folders** — logs, screenshots, music, notes.

Non-interactive mode (accept all defaults):

```bat
python remotepc\setup_wizard.py --yes
```

---

## Configuration

The wizard writes **`remotepc.config.json`** in the repo root. The app looks for it in this order:

1. the path in the `REMOTEPC_CONFIG` environment variable,
2. `<repo root>/remotepc.config.json`,
3. `~/.remotepc/config.json`.

Every key is optional — missing values fall back to safe, generic defaults, so the app starts on any
machine even with no config file at all.

```jsonc
{
  "assistant_name": "RemotePC",
  "owner_name": "Boss",
  "owner_nickname": "Boss",
  "timezone": "",                          // "" = auto-detect

  "gemini_api_key": "",                    // optional — local models work without it
  "gemini_models": ["gemini-3.5-flash", "gemini-3.5-flash-lite"],
  "antigravity_model": "gemini-3.5-flash-lite",

  "lmstudio_api_url": "http://127.0.0.1:1234/v1/chat/completions",
  "lmstudio_exe": "",                      // auto-detected, e.g. C:\Users\me\.lmstudio\bin\lms.exe
  "local_models": [                        // filled in by the wizard's LM Studio scan
    { "key": "local:my-model", "name": "publisher/model-id", "label": "My Model" }
  ],

  "allowed_ips": ["127.0.0.1", "::1"],     // extra IPs to allow; loopback always allowed
  "require_pin": false,
  "pin_hash": "",

  "screenshot_dir": "",
  "music_dir": "",
  "log_dir": "",
  "notes_dir": "",
  "search_roots": []
}
```

You may also set the Gemini key / LM Studio URL through environment variables, which take precedence:
`REMOTEPC_GEMINI_KEY` (or `GEMINI_API_KEY`) and `REMOTEPC_LMS_URL`.

> `remotepc.config.json` is **git-ignored** — it holds your personal settings and should never be committed.

---

## Remote Access — Tailscale + SSH

RemotePC is meant to be reached over a private [Tailscale](https://tailscale.com/) network, so you never
expose SSH to the public internet.

### 1. Install Tailscale

Install Tailscale on **both** the PC you want to control and the device you'll connect from
(phone/laptop), then sign in to the same account on both:

- PC: <https://tailscale.com/download/windows>
- Android: [Google Play](https://play.google.com/store/apps/details?id=com.tailscale.ipn) · **iOS**: App Store

Run `tailscale ip -4` on the PC to get its `100.x.y.z` address — that's the address you'll SSH to. The
full phone walkthrough (Termux install, SSH keys, the Windows `authorized_keys` quirk) is in
[Prerequisites → Client device](#client-device-android--termux--tailscale).

### 2. Enable the OpenSSH Server on the PC

The easy way is the included helper — **right-click [`remotepc\fix_sshd.bat`](remotepc/fix_sshd.bat) →
Run as administrator**. It will:

1. install the OpenSSH Server Windows capability if it's missing,
2. start `sshd` and set it to auto-start, with automatic restart on crash / sleep wake,
3. make `sshd` start *after* Tailscale (only if Tailscale is installed),
4. add an inbound firewall rule for SSH (port 22),
5. verify everything and print your Tailscale IP.

Manual equivalent (PowerShell, as Administrator):

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' `
  -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

### 3. Connect

From the phone (Termux), or any other SSH client:

```bash
ssh <your-windows-username>@<pc-tailscale-ip>
```

Then start RemotePC on the PC:

```bash
remotepc.bat
# or: python remotepc/remotepc.py
```

### 4. Lock it down (recommended)

- In the app, run the setup wizard and add your phone's Tailscale IP to `allowed_ips`.
- Turn on the optional **PIN** for an extra authentication step on connect.
- RemotePC already refuses non-private, non-Tailscale addresses, but a PIN is the strongest gate.

---

## Security

RemotePC ships with layered protections:

1. **IP gate** — loopback (`127.0.0.1`) is always allowed. Any Tailscale `100.x` / `fd7a:` address and any
   private LAN address is accepted; everything else is rejected and logged. Add specific IPs to
   `allowed_ips` to tighten this.
2. **Optional PIN** — when `require_pin` is set, a SHA-256–hashed PIN gate with a 3-attempt lockout runs on
   connect.
3. **Safe Mode** — the AI agent runs every action through a verdict:

   | Verdict | Behaviour |
   |---------|-----------|
   | **⛔ BLOCK** | Instantly rejected (killing core processes like `lsass.exe`, `format`, `diskpart`, recursive deletes, registry/boot tampering, fork bombs). An observation is returned to the agent so it can self-correct. |
   | **⚠️ CONFIRM** | Halts and asks `Allow? [y/N]` over SSH (killing user apps, arbitrary shell commands, power state changes, raw browser JS eval). |
   | **✅ ALLOW** | Read-only / everyday actions run immediately (volume, brightness, media keys, window management, DOM reads, diagnostics). |

4. **Shell blocklist** — a global regex list prevents dangerous shell syntax from being run by the agent.

---

## The AI Agent

The agent (menu **[a]**, or **[23]**) implements a **ReAct** loop: it emits one `ACTION:`,
RemotePC executes it safely, and the real output is fed back as an `OBSERVATION` for the next step.

### Model cascade

Cloud models are tried first, then local models (no rate limits):

```text
gemini-3.5-flash → gemini-3.5-flash-lite → gemini-3.6-flash → gemini-3.8-flash
        └── all cloud quotas exhausted? ──►  local LM Studio model(s)  (Safe Mode enforced)
```

Conversation history is converted automatically between Google and OpenAI-compatible formats when
switching between cloud and local models. Type `/model` inside the agent to switch manually — the list is
built from the models in your config.

### In-chat commands

| Command | Effect |
|---------|--------|
| `/model` | Pick a model (cloud, local, or the Antigravity engine) |
| `/safemode` | Toggle Safe Mode |
| `/confirm` | Prompt before *every* action |
| `/auto` | Back to standard Safe Mode |
| `/clear` | Reset the conversation |
| `back` / `exit` | Return to the main menu |

---

## Features

Everything listed here is implemented and wired to real code — not a roadmap.

### Menu map

```text
 [a] AI Agent        [1] Dashboard      [2] Shell            [3] Processes
 [4] Tasks/Services  [5] Startup        [6] Power            [7] File Manager
 [8] File Search     [9] Downloads      [10] File Transfer   [11] Screenshot
 [12] Network        [13] Wi-Fi         [14] Notifications    [15] Music
 [16] Media          [17] Audio Capture [18] Window/Browser   [19] Mouse
 [20] App Launcher   [21] Clipboard     [22] Screen OCR       [23] Event Watchers
 [24] Display        [25] Quick Note    [26] LM Studio        [27] Unity Build
 [28] Favorites      [29] Kali (WSL)    [30] Snap Webcam      [31] Setup
```

### What each area does

| Area | Implemented |
|------|-------------|
| **System monitoring** | Live dashboard — CPU, RAM, GPU, disk, battery, uptime; process manager (list / sort / kill); Windows tasks & services; startup manager. |
| **Shell & files** | Interactive PowerShell / CMD with UTF-8 handling; file manager (browse, view, edit, copy, move, delete, new folder); file search by name or extension across multiple roots; downloads manager; built-in HTTP file-transfer server. |
| **Windows & browser** | List / focus / resize / close windows; open tabs; read page DOM; drive a live Chrome/Edge over the DevTools Protocol (port 9222); mouse control; app launcher; clipboard read & write. |
| **Capture & media** | Screenshot; webcam snapshot; screen OCR (Tesseract); audio capture; music player with playlists; hardware media keys; volume, brightness and monitor control. |
| **Network** | Adapter and route info; Tailscale peer list; Wi-Fi profile scan & connect; desktop notifications. |
| **Power** | Lock, sleep, restart, shutdown. |
| **AI agent** | ReAct agent with Safe Mode; Google Gemini cloud models; local LM Studio models; automatic failover cascade from cloud to local; `/model` switching; optional long-term vector memory (chromadb). |
| **Remote access** | Tailscale + OpenSSH workflow; **Desktop Session Bridge** that works around Windows Session 0 / Session 1 isolation; IP allow-list gate; optional SHA-256 PIN with lockout. |
| **Dev extras** | LM Studio controller, Unity build runner, Kali Linux (WSL) launcher, favourites, quick notes, event watchers. |
| **Safety & ops** | Three-tier ALLOW / CONFIRM / BLOCK guardrail; shell blocklist; JSONL audit log of every manual command, AI action and security event. |
| **Config & setup** | Guided setup wizard ([31] Setup); external JSON config; all personal data kept out of the source tree; multi-launcher support (`.bat` / `.cmd` / bash). |

---

## Audit Logging

Every manual command, AI action, and security event is appended to `remotepc_log.jsonl` (in the configured
`log_dir`, default: repo root):

```json
{ "ts": "2026-09-05 22:45:10", "source": "ai_agent", "cmd": "ACTION: volume 40", "result": "Volume set to ~40%.", "status": "success" }
```

---

## Troubleshooting

**`sshd` won't connect over Tailscale.**
Re-run `remotepc\fix_sshd.bat` as Administrator. Confirm `tailscale status` shows the peer and that the
firewall rule for port 22 exists.

**"No Gemini API key set".**
Either add a key in the setup wizard, or use a local LM Studio model instead (start LM Studio, load a
model, enable the local server, re-run the wizard to register it).

**The AI agent reports `429 Resource Exhausted`.**
The cascade automatically falls back to the next model, ultimately to a local LM Studio model if one is
registered. Type `/model` to switch immediately.

**Live browser automation does nothing.**
Launch the browser in debug mode from menu **[18]** (or `browser_debug_launch <url>`); it opens with
`--remote-debugging-port=9222`.

**Safe Mode blocked something I meant to run.**
That's the guardrail working. Toggle it with `/safemode` inside the agent if you understand the risk.

**Optional features are missing (vector memory, audio capture, OCR).**
Install the matching optional dependency (see the comments in [`requirements.txt`](requirements.txt)).

---

## Project Layout

```text
RemotePC/
├─ remotepc.bat            # launcher (runs the wizard on first run)
├─ requirements.txt
├─ .gitignore
├─ Demo/                   # demo screenshots
└─ remotepc/
   ├─ remotepc.py          # the entire application
   ├─ remotepc_config.py   # config loader (defaults + JSON file)
   ├─ setup_wizard.py      # interactive first-run setup
   ├─ fix_sshd.bat         # OpenSSH + Tailscale service hardening
   └─ remotepc / .bat / .cmd / start.bat   # alternate launchers
```

---

<p align="center"><b>RemotePC</b> — remote control for Windows, from your phone.</p>
