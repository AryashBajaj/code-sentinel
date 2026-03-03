@echo off
REM CodeSentinel Runner
REM Usage: run.bat "path/to/project" [options]

set SCRIPT_DIR=%~dp0
set VENV_PATH=%SCRIPT_DIR%venv\Scripts

REM Check if venv exists
if not exist "%VENV_PATH%\python.exe" (
    echo Creating virtual environment...
    python -m venv venv
    call venv\Scripts\pip install -r requirements.txt
)

REM Run the analyzer
"%VENV_PATH%\python.exe" -m src.cli %*
