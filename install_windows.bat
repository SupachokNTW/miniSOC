@echo off
cd /d %~dp0
py -3 -m venv .venv
call .venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
if errorlevel 1 (echo Install failed. Check Python installation & pause & exit /b 1)
echo Dependencies installed.
pause
