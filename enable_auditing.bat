@echo off
REM ======================================================================
REM  MiniSOC 2.3 - turn on the Windows logging MiniSOC needs.
REM  Run ONCE as Administrator. Safe to run again. Changes are standard
REM  Windows audit settings; nothing is installed.
REM ======================================================================
net session >nul 2>&1
if errorlevel 1 (
  echo This script must be run as Administrator.
  echo Right-click enable_auditing.bat and choose "Run as administrator".
  pause
  exit /b 1
)

echo [1/4] Audit policy (sub-category GUIDs work on every Windows language)
REM Logon (4624/4625) and Logoff (4634/4647)
auditpol /set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
auditpol /set /subcategory:{0CCE9216-69AE-11D9-BED3-505054503030} /success:enable
REM Special Logon (4672)
auditpol /set /subcategory:{0CCE921B-69AE-11D9-BED3-505054503030} /success:enable
REM Process Creation (4688)
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable
REM Security System Extension (4697 service installed)
auditpol /set /subcategory:{0CCE9211-69AE-11D9-BED3-505054503030} /success:enable
REM Other Object Access Events (4698/4699/4702 scheduled tasks)
auditpol /set /subcategory:{0CCE9227-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
REM Audit Policy Change (4719)
auditpol /set /subcategory:{0CCE922F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
REM User Account Management (4720-4740) and Security Group Management (4728/4732/4756)
auditpol /set /subcategory:{0CCE9235-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
auditpol /set /subcategory:{0CCE9237-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
REM Credential Validation (4776)
auditpol /set /subcategory:{0CCE923F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
REM Make sure sub-category settings win over legacy category settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f >nul

echo [2/4] Include the command line in process creation events (4688)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

echo [3/4] PowerShell Script Block Logging (4104)
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

echo [4/4] Bigger logs so events are not overwritten before MiniSOC reads them
wevtutil sl Security /ms:209715200
wevtutil sl System /ms:67108864
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:104857600
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:209715200 >nul 2>&1

echo.
echo Done. Next: run install_sysmon.bat (recommended), then start MiniSOC as Administrator
echo and press "Run health check" on the Coverage page.
pause
