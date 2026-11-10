@echo off
:: ───────────────────────────────────────────────────────────────────────────
::  RemotePC — OpenSSH + Tailscale service hardening (Windows)
::  Run this ONCE as Administrator on the PC you want to control remotely.
:: ───────────────────────────────────────────────────────────────────────────
setlocal enabledelayedexpansion

:: Ensure administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Please right-click this file and select 'Run as administrator'.
    echo.
    pause
    exit /b 1
)

echo ========================================================
echo    RemotePC - OpenSSH and Tailscale Service Healing
echo ========================================================
echo.

:: ── Locate the Tailscale CLI (it may not be on PATH) ───────────────────────
set "TAILSCALE=tailscale"
where tailscale >nul 2>&1
if not errorlevel 1 goto ts_found
if exist "%ProgramFiles%\Tailscale\tailscale.exe" set "TAILSCALE=%ProgramFiles%\Tailscale\tailscale.exe"
:ts_found

:: ── 0/5 Verify OpenSSH Server is installed ─────────────────────────────────
echo [0/5] Checking OpenSSH Server installation...
sc query sshd >nul 2>&1
if !errorlevel! neq 0 (
    echo   OpenSSH Server not found. Installing...
    powershell -NoProfile -Command "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"
) else (
    echo   OpenSSH Server is installed.
)

:: ── 1/5 Start sshd ─────────────────────────────────────────────────────────
echo.
echo [1/5] Starting OpenSSH Server (sshd)...
net start sshd
if !errorlevel! neq 0 (
    echo   sshd did not start (it may already be running). Continuing...
) else (
    echo   OpenSSH Server started successfully.
)

:: ── 2/5 Auto-start + auto-restart on crash / sleep wake ────────────────────
echo.
echo [2/5] Setting sshd to start automatically and auto-recover...
sc config sshd start= auto >nul 2>&1
sc failure sshd reset= 86400 actions= restart/5000/restart/10000/restart/60000
if !errorlevel! neq 0 (
    echo   [WARN] Could not set recovery actions.
) else (
    echo   Recovery actions configured.
)

:: ── 3/5 Start sshd AFTER Tailscale (only if Tailscale is installed) ─────────
echo.
echo [3/5] Checking Tailscale...
sc query Tailscale >nul 2>&1
if !errorlevel! equ 0 (
    echo   Tailscale service found. Linking sshd startup to it...
    sc config Tailscale start= auto >nul 2>&1
    sc config sshd depend= Tailscale
) else (
    echo   [WARN] Tailscale service not found.
    echo          Install Tailscale from https://tailscale.com/download, sign in
    echo          on BOTH this PC and your phone, then re-run this file.
)

:: ── 4/5 Firewall: allow SSH (port 22) ──────────────────────────────────────
echo.
echo [4/5] Adding inbound firewall rule for SSH (port 22)...
powershell -NoProfile -Command "if (-not (Get-NetFirewallRule -DisplayName 'RemotePC SSH' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName 'RemotePC SSH' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 -ErrorAction SilentlyContinue | Out-Null }"

:: ── 5/5 Verify ─────────────────────────────────────────────────────────────
echo.
echo ========================================================
echo    Verification
echo ========================================================
sc query sshd | findstr /C:"STATE"
echo.

where ssh >nul 2>&1
if !errorlevel! equ 0 (
    ssh -V
) else (
    echo [WARN] ssh client not found on PATH.
)

echo.
sc query Tailscale >nul 2>&1
if !errorlevel! equ 0 (
    echo Tailscale status:
    "!TAILSCALE!" ip -4 2>nul
    "!TAILSCALE!" status
) else (
    echo Tailscale is not installed or not running.
)

echo.
echo ========================================================
echo    Done. Using this PC's Tailscale IP shown above, connect with:
echo      ssh ^<your-windows-username^>@^<tailscale-ip^>
echo ========================================================
echo.
pause
