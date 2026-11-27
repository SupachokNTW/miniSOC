@echo off
REM ======================================================================
REM  MiniSOC 2.3 - install or update Microsoft Sysinternals Sysmon with the
REM  bundled configuration (sysmonconfig-minisoc.xml). Run as Administrator.
REM  Sysmon is downloaded from Microsoft: https://download.sysinternals.com
REM  Uninstall any time with:  Sysmon64.exe -u
REM ======================================================================
cd /d %~dp0
net session >nul 2>&1
if errorlevel 1 (
  echo This script must be run as Administrator.
  echo Right-click install_sysmon.bat and choose "Run as administrator".
  pause
  exit /b 1
)
set "SYSMON_DIR=%ProgramData%\MiniSOC\sysmon"
set "SYSMON_EXE=%SYSMON_DIR%\Sysmon64.exe"
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "SYSMON_EXE=%SYSMON_DIR%\Sysmon64a.exe"
if not exist "%SYSMON_DIR%" mkdir "%SYSMON_DIR%"

if not exist "%SYSMON_EXE%" (
  echo Downloading Sysmon from Microsoft Sysinternals...
  powershell -NoProfile -Command "Invoke-WebRequest -UseBasicParsing 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile '%SYSMON_DIR%\Sysmon.zip'; Expand-Archive -Force '%SYSMON_DIR%\Sysmon.zip' '%SYSMON_DIR%'"
)
if not exist "%SYSMON_EXE%" (
  echo Download failed. Get Sysmon manually from https://learn.microsoft.com/sysinternals/downloads/sysmon
  echo and put Sysmon64.exe in %SYSMON_DIR%
  pause
  exit /b 1
)

sc query Sysmon64 >nul 2>&1
if errorlevel 1 sc query Sysmon64a >nul 2>&1
if errorlevel 1 (
  echo Installing Sysmon service...
  "%SYSMON_EXE%" -accepteula -i "%~dp0sysmonconfig-minisoc.xml"
) else (
  echo Sysmon already installed - updating configuration...
  "%SYSMON_EXE%" -c "%~dp0sysmonconfig-minisoc.xml"
)
if errorlevel 1 (
  echo Sysmon reported an error. If it complains about the schema version, update Sysmon to 15 or newer.
  pause
  exit /b 1
)
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:209715200
echo.
echo Sysmon is running. MiniSOC will pick up the Sysmon channel on its next poll.
pause
