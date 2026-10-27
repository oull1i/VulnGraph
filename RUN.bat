@echo off
setlocal
cd /d "%~dp0"
title VulnGraph - Local Vulnerability Dashboard
echo.
echo ================================================
echo  VulnGraph - Vulnerability Intelligence Platform
echo ================================================
echo.
where py >nul 2>&1
if not errorlevel 1 (
  set "PYTHON_CMD=py -3"
) else (
  where python >nul 2>&1
  if errorlevel 1 (
    echo ERROR: Python 3.11 or newer is required.
    echo Install Python from python.org and reopen this launcher.
    goto :failed
  )
  set "PYTHON_CMD=python"
)
%PYTHON_CMD% -c "import sys; assert sys.version_info >= (3,11), 'Python 3.11+ required'"
if errorlevel 1 goto :failed
if not exist ".venv\Scripts\python.exe" (
  echo [1/3] Creating an isolated Python environment...
  %PYTHON_CMD% -m venv .venv
  if errorlevel 1 goto :failed
) else (
  echo [1/3] Python environment already found.
)
echo [2/3] Installing or checking dependencies (internet needed first time)...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 goto :failed
echo [3/3] Starting VulnGraph on http://127.0.0.1:8000
echo.
echo Keep this window open. Press Ctrl+C to stop VulnGraph.
echo.
".venv\Scripts\python.exe" -m vulngraph.cli serve
if errorlevel 1 goto :failed
exit /b 0
:failed
echo.
echo VulnGraph did not start. Please check the error shown above.
pause
exit /b 1

