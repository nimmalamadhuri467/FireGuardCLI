@echo off
REM FireGuardCLI Launch Script

REM Change to script directory
cd /d "%~dp0"

REM Activate virtual environment if it exists
if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
)

REM Run FireGuardCLI with arguments
python main.py %*
