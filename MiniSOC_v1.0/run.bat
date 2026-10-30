@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Creating Python virtual environment...
  py -m venv .venv
)
call ".venv\Scripts\activate.bat"
python -m pip install -r requirements.txt
if errorlevel 1 (
  echo Dependency installation failed. Check your Python installation and internet connection.
  pause
  exit /b 1
)
python tests\run_rule_tests.py >nul 2>&1 || echo WARNING: some detection rule tests fail - see Detection page.
start "" http://127.0.0.1:5055
python app.py
pause
