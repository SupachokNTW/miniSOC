@echo off
cd /d %~dp0
if not exist .venv\Scripts\python.exe call install_windows.bat
call .venv\Scripts\activate
net session >nul 2>&1
if errorlevel 1 echo NOTE: not running as Administrator - the Security and Sysmon channels may be unreadable.
python app.py
pause
