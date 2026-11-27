# MiniSOC 2.4 — Local Desktop Edition

**Scope:** one Windows 10/11 endpoint; reads 8 event-log channels; local SQLite; no cloud upload.
**Since 2.4 MiniSOC can change this computer** (kill processes, firewall rules, accounts) when you approve an action,
or automatically for a few Critical alerts. Run it as Administrator.

## What's new in 2.4 — response actions
| Action | Typical use | Undo |
|---|---|---|
| Kill process (and children) | malware, malicious PowerShell, lsass reader, ransomware | – |
| Block IP (Windows Firewall, in + out) | brute force, password spray, C2 | yes, and blocks expire (1 h / 24 h / 7 d / never) |
| Disable local account | account created by an attacker / compromised | yes |
| Quarantine file | dropped executable (moved to `%ProgramData%\MiniSOC\quarantine`, SHA-256 kept) | yes |
| Remove Run / RunOnce value | registry persistence (value exported first) | yes |
| Stop + disable service | malicious service (old start type kept) | yes |
| Disable scheduled task | malicious task | yes |
| Isolate computer | ransomware in progress: firewall blocks all traffic except loopback | yes (**Release isolation** banner) |

- **Respond…** on an incident or alert lists the actions that fit the evidence, with the exact command. Ticked actions wait on the
  **Response** page until you press **Approve & run**.
- **Auto-response** (Tuning page: On / Dry-run / Off, **default Dry-run** - it only logs what it would do until you switch it On)
  acts immediately, without approval, only on **Critical** alerts of:
  `SHADOW_COPY_DELETION` → kill the parent process + isolate · `MASS_FILE_ACTIVITY` / `RANSOM_NOTE` → kill + isolate ·
  `LSASS_ACCESS` / `CREDENTIAL_DUMP_COMMAND` → kill. A tray notification tells you what was done.
  An alert that grows worse (e.g. 100 → 300 encrypted files) is escalated and then answered.
- **Safety checks.** Everything comes from event logs, which an attacker can write to, so every value is validated and commands
  are run as argument lists, never through a shell. MiniSOC refuses to: kill system processes (lsass, csrss, svchost, explorer, Defender,
  Sysmon…) or itself; kill a PID that now belongs to a different program (PID reuse); block loopback, this computer, its gateway or DNS;
  disable built-in accounts, domain accounts or the account you are using; quarantine anything under `C:\Windows`;
  touch protected services or `\Microsoft\` tasks; remove registry values other than Run / RunOnce.
- DEMO events are never acted on (status **Simulated**). Dry-run logs the command without running it.
- Collector polls every 2.5 s while auto-response is on.

> Tune before trusting auto-response: run a week in **Dry-run**, check the Response page, and allowlist anything legitimate
> (e.g. a backup tool that runs `vssadmin resize shadowstorage`). Isolation cuts the network until you release it.

## 2.3
- **New collector (EvtQuery + XML)** instead of the legacy `ReadEventLog` API. It can read the "Applications and Services" channels,
  every field arrives **by name** (no more positional insert strings), and times come as true UTC from `SystemTime`.
- **8 channels:** Security, System, **Sysmon**, **PowerShell** (4104 script blocks), **Defender**, Task Scheduler, RDP session + RDP auth.
  A missing channel (e.g. Sysmon not installed) is reported, never fatal.
- **No more skipped events:** forward reading from a per-channel cursor. If a poll has too much to read, the cursor stops at what was read.
- **Backfill** on first start (none / 24 h / 7 days).
- **Deep fields stored:** logon ID, process, parent, command line, process GUIDs, hashes, destination IP/port, registry key,
  file path, 4625 failure reason (wrong password vs. user does not exist), plus every raw field as JSON.
- **49 detection rules with MITRE ATT&CK IDs** in three layers (single-event, stateful, baseline/anomaly) — see below.
- **Alert de-duplication** (repeats raise the *Hits* count instead of a new alert).
- **Incident correlation:** alerts sharing a logon session, user or source IP within 30 minutes become one incident,
  with a timeline. Several techniques by one actor escalate the severity.
- **Sensor watch:** alert if a channel stops being readable or Sysmon goes silent.
- **Coverage → Health check:** audit policy, command-line logging, Script Block Logging, Sysmon, log size, admin rights.
- **Tuning page:** baseline learning period, retention, backfill, allowlist.
- Old 2.x databases are migrated automatically (alerts keep pointing at the right events).

## Setup (once, as Administrator)
1. `install_windows.bat` — Python dependencies (PySide6, pywin32).
2. `enable_auditing.bat` — turns on the audit policy, command line in 4688, PowerShell Script Block Logging, bigger logs.
3. `install_sysmon.bat` — downloads Microsoft Sysinternals Sysmon and installs it with `sysmonconfig-minisoc.xml`
   (recommended: most of the deep detections need Sysmon).
4. Right-click `run_windows.bat` → **Run as administrator** → **Start Collector**.
5. Coverage → **Run health check** and fix anything red.

## Detection
| Layer | Examples |
|---|---|
| Single event | encoded / hidden PowerShell, download cradles, Office spawning a shell, LOLBins (certutil, mshta, regsvr32, rundll32…), shadow-copy deletion, log clearing, Defender tampering, credential-dump commands, `net user /add`, fake system processes, **lsass memory access**, remote-thread injection, Run-key / Startup / WMI persistence, unsigned drivers, malicious PowerShell script blocks (AMSI bypass, Mimikatz, shellcode loaders, reverse shells), Defender detections, new services / scheduled tasks |
| Stateful | failed-logon burst, success after failures, **password spraying**, **discovery-command burst**, **mass file changes in user folders (ransomware)**, ransom notes, **C2 beaconing** |
| Baseline | never-seen parent→child process chain, first RDP logon from a source, first internet connection by a process (after a learning period, default 7 days) |

Try **Add Demo Attack** on the Overview page: a synthetic RDP brute-force → discovery → PowerShell → lsass → service → shadow-copy chain,
correlated into one Critical incident. Demo rows are flagged `DEMO`.

### Tuning false positives
Alerts → select → **Allowlist…** (e.g. rule `LOLBIN_ABUSE`, field `command_line` contains `intranet.local`).
Sysmon noise is tuned in `sysmonconfig-minisoc.xml`, then re-run `install_sysmon.bat`.

## Testing
`python -m unittest test_detection test_features test_response` (94 tests; runs on any OS — Windows APIs and commands are faked).

## Data
`%LOCALAPPDATA%\MiniSOC2\minisoc.db` (SQLite, WAL mode). Retention default 30 days; events linked to an alert are kept.

## Limitations
- Prototype, not a certified EDR/SIEM. Detection works from logs, so even auto-response reacts a few seconds after the fact;
  it cannot prevent the first files of a ransomware run from being encrypted. Isolation does not cut connections that are
  already established in every case.
- An attacker with admin rights can stop Sysmon or clear logs. MiniSOC alerts on that (Sysmon 4/16, 1102/104, 1100,
  channel lost / silent), but cannot prevent it.
- Kernel-level and purely in-memory techniques may leave no event-log trace.
- Expect false positives during the first days; use the allowlist. Anomaly alerts start only after the learning period.
- Not yet tested on every Windows build / language. Audit policy is set and read by GUID so it is language-independent.
