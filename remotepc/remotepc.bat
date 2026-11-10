@echo off
setlocal
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"

rem Locate a Python 3 interpreter
set "PY_EXE="
where py >nul 2>&1
if not errorlevel 1 set "PY_EXE=py -3"
if defined PY_EXE goto have_python

where python >nul 2>&1
if not errorlevel 1 set "PY_EXE=python"
if defined PY_EXE goto have_python

echo.
echo   [ERROR] Python 3 was not found on PATH.
echo   Install Python 3.10+ from https://www.python.org/downloads/
echo   and make sure "Add python.exe to PATH" is checked.
echo.
pause
exit /b 1

:have_python
if exist "%~dp0..\remotepc.config.json" goto launch

echo.
echo   No configuration found - starting the setup wizard...
echo.
%PY_EXE% "%~dp0setup_wizard.py"

:launch
%PY_EXE% "%~dp0remotepc.py" %*
