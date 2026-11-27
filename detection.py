"""MiniSOC detection engine.

Three layers:
  1. Single-event rules   - one event is enough (encoded PowerShell, lsass access, log cleared...)
  2. Stateful rules       - a pattern over a time window (failed-logon burst, password spray,
                            recon burst, mass file activity, beaconing)
  3. Baseline / anomaly   - learn what is normal for this machine for N days, then flag
                            things never seen before (new parent->child pair, new RDP source,
                            new process talking to the internet)

Every rule carries a MITRE ATT&CK technique. Results pass through the user allowlist.
Correlation of alerts into incidents and de-duplication happen in database.py.

evaluate(conn, e) works on the normalised event dict produced by event_catalog.
"""
import ipaddress
import re
import sqlite3
import statistics
from datetime import datetime, timedelta, timezone

SEV_ORDER = ['Info', 'Low', 'Medium', 'High', 'Critical']
PROC = {('Sysmon', 1), ('Security', 4688)}           # events that describe a new process

RULES = {}          # rule_id -> metadata + function
SEVERITY = {}       # rule_id -> default severity (kept for v2.2 compatibility)
RULE_EVENTS = {}    # rule_id -> [(channel, event_id)]   (Coverage page)


def rule(rid, severity, mitre, title, events, window=60):
    """Register a rule. fn(conn, e) returns None or dict(summary, [severity], [key])."""
    def deco(fn):
        RULES[rid] = dict(id=rid, severity=severity, mitre=mitre, title=title, events=set(events), window=window, fn=fn)
        SEVERITY[rid] = severity
        RULE_EVENTS[rid] = sorted(events)
        return fn
    return deco


# ----------------------------------------------------------------------------- helpers
def dt(s):
    try:
        x = datetime.fromisoformat(str(s).replace('Z', '+00:00'))
        return x if x.tzinfo else x.replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def base(path):
    return re.split(r'[\\/]', path or '')[-1].lower()


def low(s):
    return (s or '').lower()


def ago(e, **kw):
    return (dt(e.get('time_utc')) - timedelta(**kw)).isoformat()


def is_system_account(user):
    u = low(user)
    if not u:
        return True
    name = u.split('\\')[-1]
    return (name in ('system', 'local service', 'network service', 'anonymous logon', 'localsystem')
            or name.endswith('$') or name.startswith(('dwm-', 'umfd-')) or u.startswith(('nt authority\\', 'window manager\\', 'font driver host\\')))


def public_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified or a.is_reserved)
    except ValueError:
        return False


def any_in(text, needles):
    return next((n for n in needles if n in text), None)


SHELLS = {'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe',
          'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe', 'schtasks.exe', 'wmic.exe', 'msbuild.exe', 'installutil.exe'}
OFFICE = {'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'msaccess.exe', 'mspub.exe', 'onenote.exe',
          'visio.exe', 'acrord32.exe', 'acrobat.exe', 'foxitpdfreader.exe', 'hwp.exe'}
RECON = [
    (r'^whoami\.exe$', None), (r'^systeminfo\.exe$', None), (r'^hostname\.exe$', None), (r'^quser\.exe$', None),
    (r'^nltest\.exe$', None), (r'^dsquery\.exe$', None), (r'^klist\.exe$', None), (r'^tasklist\.exe$', None),
    (r'^net1?\.exe$', r'\b(user|group|localgroup|view|share|accounts|session|use)\b'),
    (r'^ipconfig\.exe$', r'/all'), (r'^arp\.exe$', r'-a'), (r'^route\.exe$', r'print'), (r'^netstat\.exe$', r'-\w*a'),
    (r'^query\.exe$', r'user|session'), (r'^cmdkey\.exe$', r'/list'), (r'^wmic\.exe$', r'useraccount|group|qfe|os |process|startup|product'),
    (r'^reg\.exe$', r'query'), (r'^sc\.exe$', r'query'), (r'^nslookup\.exe$', None),
]
USER_DIRS = ('\\desktop\\', '\\documents\\', '\\pictures\\', '\\downloads\\', '\\videos\\', '\\music\\')


def tags(e):
    """Cheap labels stored with the event so stateful rules can count them with SQL."""
    out = []
    if (e.get('channel'), int(e.get('event_id', 0))) in PROC:
        b, cmd = base(e.get('process')), low(e.get('command_line'))
        for img, args in RECON:
            if re.search(img, b) and (args is None or re.search(args, cmd)):
                out.append('recon')
                break
    if e.get('channel') == 'Sysmon' and int(e.get('event_id', 0)) in (11, 26):
        t = low(e.get('target'))
        if '\\users\\' in t and any_in(t, USER_DIRS):
            out.append('userfile')
    return ','.join(out)


# ============================================================================= 1. single-event rules
# ---- authentication / accounts (Security) -----------------------------------
@rule('SECURITY_LOG_CLEARED', 'Critical', 'T1070.001', 'Event log cleared', [('Security', 1102), ('System', 104)])
def _security_log_cleared(c, e):
    where = 'Security' if e['channel'] == 'Security' else (e.get('target') or 'System')
    return dict(summary='%s log was cleared by %s' % (where, e.get('username') or 'unknown'), key=where)


@rule('EVENTLOG_SERVICE_STOPPED', 'High', 'T1562.002', 'Event log service shut down', [('Security', 1100)])
def _eventlog_service_stopped(c, e):
    return dict(summary='Windows Event Log service was shut down (1100) - logging stops until restart')


@rule('AUDIT_POLICY_CHANGED', 'High', 'T1562.002', 'Audit policy changed', [('Security', 4719)])
def _audit_policy_changed(c, e):
    return dict(summary='Audit policy changed by %s (%s)' % (e.get('subject_user') or 'unknown', e.get('status') or e.get('target')),
                key=e.get('target'))


@rule('SPECIAL_PRIVILEGES_ASSIGNED', 'Low', 'T1078', 'Admin-level logon', [('Security', 4672)], window=240)
def _special_privileges_assigned(c, e):
    u = e.get('username')
    if is_system_account(u):
        return None
    return dict(summary='Logon with administrative privileges: %s (4672)' % u, key=low(u))


@rule('ACCOUNT_CREATED', 'High', 'T1136.001', 'Local account created', [('Security', 4720)])
def _account_created(c, e):
    return dict(summary='Account created: %s by %s (4720)' % (e.get('username') or 'unknown', e.get('subject_user') or 'unknown'),
                key=low(e.get('username')))


@rule('ACCOUNT_ENABLED', 'Medium', 'T1098', 'Account enabled', [('Security', 4722)])
def _account_enabled(c, e):
    return dict(summary='Account enabled: %s by %s (4722)' % (e.get('username') or 'unknown', e.get('subject_user') or 'unknown'),
                key=low(e.get('username')))


@rule('ACCOUNT_PASSWORD_CHANGED', 'Low', 'T1098', 'Password change attempt', [('Security', 4723)])
def _account_password_changed(c, e):
    return dict(summary='Password change attempt: %s (4723)' % (e.get('username') or 'unknown'), key=low(e.get('username')))


@rule('ACCOUNT_PASSWORD_RESET', 'Medium', 'T1098', 'Password reset by another account', [('Security', 4724)])
def _account_password_reset(c, e):
    return dict(summary='Password of %s reset by %s (4724)' % (e.get('username') or 'unknown', e.get('subject_user') or 'unknown'),
                key=low(e.get('username')))


@rule('ACCOUNT_DISABLED', 'Low', 'T1531', 'Account disabled', [('Security', 4725)])
def _account_disabled(c, e):
    return dict(summary='Account disabled: %s by %s (4725)' % (e.get('username') or 'unknown', e.get('subject_user') or 'unknown'),
                key=low(e.get('username')))


@rule('ACCOUNT_DELETED', 'Medium', 'T1531', 'Account deleted', [('Security', 4726)])
def _account_deleted(c, e):
    return dict(summary='Account deleted: %s by %s (4726)' % (e.get('username') or 'unknown', e.get('subject_user') or 'unknown'),
                key=low(e.get('username')))


@rule('ACCOUNT_LOCKOUT', 'Medium', 'T1110', 'Account locked out', [('Security', 4740)])
def _account_lockout(c, e):
    return dict(summary='Account locked out: %s (caller %s)' % (e.get('username') or 'unknown', e.get('target') or '?'),
                key=low(e.get('username')))


@rule('ACCOUNT_ADDED_GROUP', 'High', 'T1098', 'Account added to security group', [('Security', 4728), ('Security', 4732), ('Security', 4756)])
def _account_added_group(c, e):
    group = e.get('target') or 'a group'
    sev = 'Critical' if any_in(low(group), ('administrators', 'domain admins', 'enterprise admins', 'remote desktop users',
                                             'backup operators', 'remote management users')) else 'High'
    return dict(summary='%s added to %s by %s (%s)' % (e.get('username') or 'account', group, e.get('subject_user') or 'unknown',
                                                     e['event_id']), severity=sev, key=low(group) + '|' + low(e.get('username')))


# ---- persistence ------------------------------------------------------------
SUSPICIOUS_PATH = ('\\appdata\\', '\\temp\\', '\\users\\public\\', '\\programdata\\', '\\downloads\\', '\\perflogs\\', '\\windows\\tasks\\')
SUSPICIOUS_CMD = ('powershell', 'pwsh', 'cmd.exe /c', 'cmd /c', 'mshta', 'rundll32', 'regsvr32', 'wscript', 'cscript',
                  'certutil', 'bitsadmin', '-enc', 'http://', 'https://', '\\\\')


@rule('SERVICE_INSTALLED', 'Medium', 'T1543.003', 'New service installed', [('Security', 4697), ('System', 7045)])
def _service_installed(c, e):
    cmd = low(e.get('command_line'))
    bad = any_in(cmd, SUSPICIOUS_CMD) or any_in(cmd, SUSPICIOUS_PATH)
    return dict(summary='Service installed: %s -> %s%s' % (e.get('target') or '?', e.get('command_line') or '?',
                                                          '  [suspicious: %s]' % bad if bad else ''),
                severity='Critical' if bad else 'Medium', key=low(e.get('target')))


@rule('SCHEDULED_TASK_CREATED', 'Medium', 'T1053.005', 'Scheduled task created', [('Security', 4698), ('Security', 4702), ('TaskScheduler', 106)])
def _scheduled_task_created(c, e):
    cmd = low(e.get('command_line'))
    if e['channel'] == 'TaskScheduler' and low(e.get('target')).startswith('\\microsoft\\'):
        return None                       # Windows' own maintenance tasks
    bad = any_in(cmd, SUSPICIOUS_CMD) or any_in(cmd, SUSPICIOUS_PATH)
    return dict(summary='Scheduled task %s: %s%s' % ('updated' if e['event_id'] == 4702 else 'created', e.get('target') or '?',
                                                    (' -> ' + e['command_line']) if e.get('command_line') else '') + ('  [suspicious: %s]' % bad if bad else ''),
                severity='High' if bad else 'Medium', key=low(e.get('target')))


RUN_KEYS = ('\\currentversion\\run', '\\currentversion\\runonce', '\\winlogon\\shell', '\\winlogon\\userinit',
            '\\image file execution options\\', '\\currentversion\\explorer\\shell folders\\startup', '\\environment\\userinitmprlogonscript',
            '\\control\\lsa\\notification packages', '\\control\\lsa\\security packages', '\\appinit_dlls')


@rule('REGISTRY_PERSISTENCE', 'Medium', 'T1547.001', 'Autostart registry key modified', [('Sysmon', 13)])
def _registry_persistence(c, e):
    key = low(e.get('target'))
    hit = any_in(key, RUN_KEYS)
    if not hit:
        return None
    val = low(e.get('command_line'))
    bad = any_in(val, SUSPICIOUS_CMD) or any_in(val, SUSPICIOUS_PATH)
    return dict(summary='Autostart registry value set by %s: %s = %s' % (base(e.get('process')), e.get('target'), e.get('command_line')),
                severity='High' if bad else 'Medium', key=key)


@rule('DEFENDER_EXCLUSION_ADDED', 'High', 'T1562.001', 'Defender exclusion added', [('Sysmon', 13), ('Defender', 5007)])
def _defender_exclusion_added(c, e):
    blob = low(e.get('target')) + ' ' + low(e.get('command_line'))
    if '\\windows defender\\exclusions\\' not in blob:
        return None
    return dict(summary='Microsoft Defender exclusion added: %s' % (e.get('target') or e.get('command_line')), key=low(e.get('target')))


@rule('STARTUP_FOLDER_DROP', 'Medium', 'T1547.001', 'File dropped in Startup folder', [('Sysmon', 11)])
def _startup_folder_drop(c, e):
    t = low(e.get('target'))
    if '\\start menu\\programs\\startup\\' not in t or t.endswith('desktop.ini'):
        return None
    return dict(summary='File written to Startup folder by %s: %s' % (base(e.get('process')), e.get('target')), key=t)


@rule('WMI_PERSISTENCE', 'High', 'T1546.003', 'WMI event subscription', [('Sysmon', 19), ('Sysmon', 20), ('Sysmon', 21)])
def _wmi_persistence(c, e):
    return dict(summary='WMI persistence (%s): %s %s' % (e['event_id'], e.get('target'), e.get('command_line') or ''), key=low(e.get('target')))


@rule('UNSIGNED_DRIVER', 'High', 'T1543.003', 'Unsigned / invalid driver loaded', [('Sysmon', 6)])
def _unsigned_driver(c, e):
    st = low(e.get('status'))
    if 'signed=true' in st and 'valid' in st:
        return None
    return dict(summary='Driver with bad signature loaded: %s (%s)' % (e.get('target'), e.get('status')), key=low(e.get('target')))


# ---- execution (Sysmon 1 / Security 4688) -----------------------------------
@rule('OFFICE_SPAWNS_SHELL', 'High', 'T1204.002', 'Office / PDF app started a shell', PROC)
def _office_spawns_shell(c, e):
    p, child = base(e.get('parent_process')), base(e.get('process'))
    if p in OFFICE and child in SHELLS:
        return dict(summary='%s started %s: %s' % (p, child, e.get('command_line') or ''), key=p + '>' + child)


ENC = re.compile(r'\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+[a-z0-9+/=]{16,}', re.I)


@rule('ENCODED_POWERSHELL', 'High', 'T1027.010', 'Encoded PowerShell command', PROC)
def _encoded_powershell(c, e):
    if base(e.get('process')) in ('powershell.exe', 'pwsh.exe') and ENC.search(' ' + (e.get('command_line') or '')):
        return dict(summary='PowerShell with encoded command (parent %s): %s' % (base(e.get('parent_process')), (e.get('command_line') or '')[:300]),
                    key=low(e.get('parent_process')))


DOWNLOAD = ('downloadstring', 'downloadfile', 'downloaddata', 'invoke-webrequest', 'iwr ', 'invoke-restmethod', 'irm ',
            'net.webclient', 'start-bitstransfer', 'wget ', 'curl ')
EXEC = ('iex', 'invoke-expression', '| powershell', '|powershell', 'start-process')


@rule('POWERSHELL_DOWNLOAD_EXEC', 'High', 'T1105', 'PowerShell download-and-run', PROC)
def _powershell_download_exec(c, e):
    cmd = low(e.get('command_line'))
    if base(e.get('process')) in ('powershell.exe', 'pwsh.exe', 'cmd.exe') and any_in(cmd, DOWNLOAD) and any_in(cmd, EXEC):
        return dict(summary='Download-and-execute command: %s' % (e.get('command_line') or '')[:300], key=cmd[:120])


@rule('POWERSHELL_HIDDEN', 'Medium', 'T1564.003', 'Hidden / no-profile PowerShell', PROC, window=240)
def _powershell_hidden(c, e):
    cmd = low(e.get('command_line'))
    if base(e.get('process')) in ('powershell.exe', 'pwsh.exe') and re.search(r'-w(indowstyle)?\s+h(idden)?\b', cmd) \
            and re.search(r'-(nop|noprofile|ep\s+bypass|executionpolicy\s+bypass|noni)', cmd):
        return dict(summary='Hidden PowerShell with bypass flags (parent %s): %s' % (base(e.get('parent_process')), cmd[:300]),
                    key=low(e.get('parent_process')))


LOLBINS = [
    ('certutil.exe', r'-urlcache|-verifyctl|-decode|-decodehex', 'T1105'),
    ('bitsadmin.exe', r'/transfer|/addfile|/setnotifycmdline', 'T1197'),
    ('mshta.exe', r'https?:|javascript:|vbscript:', 'T1218.005'),
    ('regsvr32.exe', r'/i:\s*https?:|scrobj', 'T1218.010'),
    ('rundll32.exe', r'javascript:|url\.dll|zipfldr|advpack\.dll.*launchinf|pcwutl|\\appdata\\|\\temp\\|\\users\\public\\', 'T1218.011'),
    ('msiexec.exe', r'/q.*https?:|https?:.*/q', 'T1218.007'),
    ('wmic.exe', r'process\s+call\s+create|/node:', 'T1047'),
    ('msbuild.exe', r'\\appdata\\|\\temp\\|\\users\\public\\', 'T1127.001'),
    ('installutil.exe', r'/u|/logfile=', 'T1218.004'),
    ('cmstp.exe', r'/s|/au', 'T1218.003'),
]


@rule('LOLBIN_ABUSE', 'High', 'T1218', 'Windows binary used to download / proxy execution', PROC)
def _lolbin_abuse(c, e):
    b, cmd = base(e.get('process')), low(e.get('command_line'))
    for name, pat, technique in LOLBINS:
        if b == name and re.search(pat, cmd):
            return dict(summary='%s used suspiciously (%s): %s' % (name, technique, (e.get('command_line') or '')[:300]), key=b + '|' + cmd[:100])


INHIBIT = [r'vssadmin(\.exe)?\s+.*delete\s+shadows', r'vssadmin(\.exe)?\s+resize\s+shadowstorage', r'wmic(\.exe)?\s+shadowcopy\s+delete',
           r'wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup)', r'bcdedit(\.exe)?.*recoveryenabled\s+no',
           r'bcdedit(\.exe)?.*bootstatuspolicy\s+ignoreallfailures', r'win32_shadowcopy.*delete', r'remove-ciminstance.*shadow']


@rule('SHADOW_COPY_DELETION', 'Critical', 'T1490', 'Backups / shadow copies destroyed', PROC)
def _shadow_copy_deletion(c, e):
    cmd = low(e.get('command_line'))
    if any(re.search(p, cmd) for p in INHIBIT):
        return dict(summary='Recovery inhibited (ransomware precursor): %s' % e.get('command_line'), key=cmd[:100])


@rule('LOG_CLEAR_COMMAND', 'Critical', 'T1070.001', 'Command clearing event logs', PROC)
def _log_clear_command(c, e):
    cmd = low(e.get('command_line'))
    if re.search(r'wevtutil(\.exe)?\s+(cl|clear-log)\b', cmd) or 'clear-eventlog' in cmd or 'remove-eventlog' in cmd:
        return dict(summary='Event log clearing command: %s' % e.get('command_line'), key=cmd[:100])


DEFENDER_TAMPER = [r'set-mppreference.*-disable(realtimemonitoring|behaviormonitoring|ioavprotection|scriptscanning)\s+(\$true|1)',
                   r'add-mppreference.*-exclusion(path|process|extension)', r'sc(\.exe)?\s+(stop|config|delete)\s+windefend',
                   r'disableantispyware', r'disablerealtimemonitoring', r'mpcmdrun(\.exe)?.*-removedefinitions',
                   r'netsh\s+(advfirewall\s+set\s+\w+\s+state\s+off|firewall\s+set\s+opmode\s+disable)']


@rule('DEFENSE_TAMPERING_COMMAND', 'High', 'T1562.001', 'Command disabling Defender / firewall', PROC)
def _defense_tampering_command(c, e):
    cmd = low(e.get('command_line'))
    hit = next((p for p in DEFENDER_TAMPER if re.search(p, cmd)), None)
    if hit:
        return dict(summary='Security tool tampering: %s' % e.get('command_line'), key=cmd[:100])


CRED = [r'sekurlsa::|lsadump::|kerberos::|privilege::debug|mimikatz', r'procdump(64)?(\.exe)?.*\blsass', r'comsvcs(\.dll)?[, ]+#?24|comsvcs(\.dll)?[, ]+minidump',
        r'reg(\.exe)?\s+save\s+hklm\\(sam|system|security)', r'ntdsutil.*(ifm|ac\s+i\s+ntds)', r'vssadmin.*create\s+shadow',
        r'esentutl.*\\ntds\.dit|copy.*\\ntds\.dit', r'rdrleakdiag.*/fullmemdmp', r'sqldumper.*0x01100']


@rule('CREDENTIAL_DUMP_COMMAND', 'Critical', 'T1003', 'Credential dumping command', PROC)
def _credential_dump_command(c, e):
    cmd = low(e.get('command_line'))
    if any(re.search(p, cmd) for p in CRED):
        return dict(summary='Credential dumping attempt: %s' % (e.get('command_line') or '')[:300], key=cmd[:100])


@rule('ACCOUNT_MANIPULATION_COMMAND', 'High', 'T1136.001', 'net user / localgroup used to add accounts', PROC)
def _account_manipulation_command(c, e):
    cmd = low(e.get('command_line'))
    if base(e.get('process')) in ('net.exe', 'net1.exe') and re.search(r'\b(user|localgroup|group)\b.*\s/add\b', cmd):
        sev = 'Critical' if re.search(r'administrators|remote desktop users|domain admins', cmd) else 'High'
        return dict(summary='Account manipulation: %s' % e.get('command_line'), severity=sev, key=cmd[:100])


SYSTEM_BINARIES = {'svchost.exe', 'lsass.exe', 'csrss.exe', 'services.exe', 'smss.exe', 'winlogon.exe', 'wininit.exe',
                   'lsm.exe', 'spoolsv.exe', 'taskhostw.exe', 'conhost.exe', 'dllhost.exe', 'rundll32.exe', 'explorer.exe'}


@rule('PROCESS_MASQUERADING', 'High', 'T1036.005', 'Fake system process', PROC)
def _process_masquerading(c, e):
    path, b = low(e.get('process')), base(e.get('process'))
    if b not in SYSTEM_BINARIES or not path:
        return None
    ok_dirs = ('c:\\windows\\system32\\', 'c:\\windows\\syswow64\\', 'c:\\windows\\winsxs\\', '\\device\\harddiskvolume')
    if b == 'explorer.exe':
        ok_dirs += ('c:\\windows\\explorer.exe',)
    if not path.startswith(ok_dirs):
        return dict(summary='%s running from unexpected location: %s' % (b, e.get('process')), key=path)
    if b == 'svchost.exe' and e.get('parent_process') and base(e.get('parent_process')) not in ('services.exe', 'msmpeng.exe', 'svchost.exe'):
        return dict(summary='svchost.exe started by %s (expected services.exe)' % base(e.get('parent_process')), severity='Medium', key=low(e.get('parent_process')))


@rule('EXEC_FROM_SUSPICIOUS_PATH', 'Low', 'T1204.002', 'Program run from Temp / Public / Downloads', PROC, window=1440)
def _exec_from_suspicious_path(c, e):
    path = low(e.get('process'))
    if not path.endswith(('.exe', '.scr', '.com', '.pif')):
        return None
    if any_in(path, ('\\appdata\\local\\temp\\', '\\windows\\temp\\', '\\users\\public\\', '\\perflogs\\', '\\$recycle.bin\\')) \
            and not any_in(base(path), ('setup', 'install', 'update', 'unins', 'dismhost', 'msiexec')):
        return dict(summary='Executable run from %s (parent %s)' % (e.get('process'), base(e.get('parent_process'))), key=path)


# ---- Sysmon-only ------------------------------------------------------------
LSASS_RISKY = {'0x1010', '0x1410', '0x1438', '0x143a', '0x1fffff', '0x1f1fff', '0x1f3fff', '0x40', '0x147a', '0x1f0fff', '0x1418'}
LSASS_OK = {'msmpeng.exe', 'csrss.exe', 'wininit.exe', 'wmiprvse.exe', 'svchost.exe', 'lsm.exe', 'mrt.exe', 'vmtoolsd.exe',
            'taskmgr.exe', 'procexp64.exe', 'procexp.exe', 'mssense.exe', 'nissrv.exe', 'smartscreen.exe', 'lsass.exe',
            'securityhealthservice.exe', 'sgrmbroker.exe'}


@rule('LSASS_ACCESS', 'Critical', 'T1003.001', 'Process opened lsass.exe memory', [('Sysmon', 10)])
def _lsass_access(c, e):
    if base(e.get('target')) != 'lsass.exe':
        return None
    src, access = base(e.get('process')), low(e.get('status'))
    if src in LSASS_OK or access not in LSASS_RISKY:
        return None
    return dict(summary='%s opened lsass.exe with access %s (credential theft)' % (e.get('process'), access), key=low(e.get('process')))


INJECT_OK = {'csrss.exe', 'wininit.exe', 'services.exe', 'msmpeng.exe', 'svchost.exe', 'dwm.exe', 'vmtoolsd.exe', 'mssense.exe'}


@rule('REMOTE_THREAD_INJECTION', 'High', 'T1055', 'Thread created in another process', [('Sysmon', 8)])
def _remote_thread_injection(c, e):
    src, tgt = base(e.get('process')), base(e.get('target'))
    if src in INJECT_OK or not src or src == tgt:
        return None
    return dict(summary='%s injected a thread into %s' % (e.get('process'), e.get('target')), key=src + '>' + tgt)


@rule('PROCESS_TAMPERING', 'Medium', 'T1055.012', 'Process image tampered (hollowing)', [('Sysmon', 25)])
def _process_tampering(c, e):
    return dict(summary='Process tampering (%s): %s' % (e.get('status'), e.get('target') or e.get('process')), key=low(e.get('target')))


@rule('SYSMON_TAMPERING', 'High', 'T1562.001', 'Sysmon stopped or reconfigured', [('Sysmon', 4), ('Sysmon', 16)])
def _sysmon_tampering(c, e):
    st = low(e.get('status'))
    if e['event_id'] == 4 and 'started' in st:
        return None
    return dict(summary='Sysmon %s: %s' % ('state changed' if e['event_id'] == 4 else 'configuration changed', e.get('status') or ''),
                severity='High' if e['event_id'] == 4 else 'Medium')


SCRIPT_HOSTS = {'powershell.exe', 'pwsh.exe', 'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'certutil.exe', 'bitsadmin.exe',
                'wscript.exe', 'cscript.exe', 'msbuild.exe', 'installutil.exe', 'cmd.exe', 'notepad.exe', 'calc.exe'}


@rule('SCRIPT_HOST_NETWORK', 'Medium', 'T1071.001', 'Script host / LOLBin connected to the internet', [('Sysmon', 3)], window=240)
def _script_host_network(c, e):
    b = base(e.get('process'))
    if b in SCRIPT_HOSTS and e.get('status') == 'outbound' and public_ip(e.get('dest_ip')):
        return dict(summary='%s connected to %s:%s (%s)' % (b, e.get('dest_ip'), e.get('dest_port'), e.get('target')),
                    key=b + '|' + (e.get('dest_ip') or ''))


# ---- PowerShell script block (4104) -----------------------------------------
PS_BAD = [
    (r'amsiutils|amsiinitfailed|amsiscanbuffer|amsicontext', 'AMSI bypass', 'Critical', 'T1562.001'),
    (r'invoke-mimikatz|sekurlsa|kerberos::|lsadump', 'Mimikatz', 'Critical', 'T1003'),
    (r'virtualalloc.*createthread|virtualprotect.*marshal|invoke-shellcode|getdelegateforfunctionpointer', 'Shellcode loader', 'Critical', 'T1055'),
    (r'net\.sockets\.tcpclient.*getstream|system\.net\.sockets\.tcplistener', 'Reverse shell', 'High', 'T1059.001'),
    (r'\[reflection\.assembly\]::load|assembly\]::load\(', 'In-memory .NET assembly load', 'High', 'T1620'),
    (r'frombase64string.*(iex|invoke-expression)|(iex|invoke-expression).*frombase64string', 'Base64 decode + execute', 'High', 'T1027'),
    (r'(downloadstring|downloaddata|invoke-webrequest|iwr|invoke-restmethod).*(iex|invoke-expression)|(iex|invoke-expression).*(downloadstring|new-object\s+net\.webclient)', 'Download cradle', 'High', 'T1105'),
    (r'invoke-kerberoast|invoke-bloodhound|sharphound|powerview|get-domaintrust|invoke-userhunter', 'AD attack tooling', 'High', 'T1087.002'),
    (r'set-mppreference.*-disable|add-mppreference.*-exclusion', 'Defender tampering', 'High', 'T1562.001'),
]


@rule('POWERSHELL_MALICIOUS_SCRIPT', 'High', 'T1059.001', 'Malicious PowerShell script content', [('PowerShell', 4104)])
def _powershell_malicious_script(c, e):
    text = low(e.get('command_line'))
    for pat, label, sev, tech in PS_BAD:
        if re.search(pat, text, re.S):
            return dict(summary='PowerShell script: %s (%s) - %s' % (label, tech, (e.get('command_line') or '')[:200].replace('\n', ' ')),
                        severity=sev, key=label + '|' + (e.get('process_guid') or ''))
    if e.get('level') == 'Warning':      # PowerShell itself flags known-suspicious script blocks at level Warning
        return dict(summary='PowerShell flagged a suspicious script block: %s' % (e.get('command_line') or '')[:200].replace('\n', ' '),
                    severity='Medium', key='warning|' + (e.get('process_guid') or ''))


# ---- Defender ---------------------------------------------------------------
@rule('DEFENDER_MALWARE', 'High', 'T1204', 'Defender detected malware', [('Defender', 1116), ('Defender', 1117), ('Defender', 1118), ('Defender', 1119)])
def _defender_malware(c, e):
    failed = e['event_id'] in (1118, 1119)
    return dict(summary='Defender %s: %s in %s%s' % ('could NOT remediate' if failed else 'detected', e.get('target') or 'threat',
                                                     e.get('command_line') or '?', (' (process %s)' % e['process']) if e.get('process') else ''),
                severity='Critical' if failed else 'High', key=low(e.get('target')) + '|' + low(e.get('command_line')))


@rule('DEFENDER_DISABLED', 'High', 'T1562.001', 'Defender protection turned off', [('Defender', 5001), ('Defender', 5010), ('Defender', 5012)])
def _defender_disabled(c, e):
    return dict(summary='Microsoft Defender protection disabled (event %s)' % e['event_id'])


# ============================================================================= 2. stateful rules
@rule('FAILED_LOGIN_BURST', 'High', 'T1110.001', 'Failed-logon burst', [('Security', 4625)], window=30)
def _failed_login_burst(c, e):
    u, ip = e.get('username') or '', e.get('source_ip') or ''
    if not (u or ip):
        return None
    col = 'username' if u else 'source_ip'
    n = c.execute("SELECT COUNT(*) FROM events WHERE channel='Security' AND event_id=4625 AND time_utc>=? AND %s=?" % col,
                  (ago(e, minutes=5), u or ip)).fetchone()[0]
    if n >= 5:
        return dict(summary='%d failed logons in 5 minutes for %s%s' % (n, u or ip, (' from ' + ip) if (u and ip) else ''), key=low(u or ip))


@rule('SUCCESS_AFTER_FAILURES', 'Medium', 'T1110', 'Successful logon after failures', [('Security', 4624)])
def _success_after_failures(c, e):
    u = e.get('username')
    if not u or is_system_account(u):
        return None
    n = c.execute("SELECT COUNT(*) FROM events WHERE channel='Security' AND event_id=4625 AND username=? AND time_utc>=?",
                  (u, ago(e, minutes=10))).fetchone()[0]
    if n >= 3:
        sev = 'High' if n >= 10 else 'Medium'
        return dict(summary='Successful logon after %d failed attempts for %s%s' % (n, u, (' from ' + e['source_ip']) if e.get('source_ip') else ''),
                    severity=sev, key=low(u))


@rule('PASSWORD_SPRAY', 'High', 'T1110.003', 'Password spraying (many accounts, one source)', [('Security', 4625)], window=60)
def _password_spray(c, e):
    ip = e.get('source_ip') or ''
    if not ip:
        return None
    row = c.execute("SELECT COUNT(DISTINCT username), SUM(status LIKE '0xc0000064%') FROM events "
                    "WHERE channel='Security' AND event_id=4625 AND source_ip=? AND time_utc>=?", (ip, ago(e, minutes=10))).fetchone()
    users, unknown = row[0] or 0, row[1] or 0
    if users >= 5:
        return dict(summary='%d different accounts failed to log on from %s in 10 minutes (%d non-existent names)' % (users, ip, unknown), key=ip)


def _actor_key(e):
    lid = low(e.get('logon_id'))
    if lid and lid not in ('0x3e7', '0x3e4', '0x3e5', '0x0'):
        return 'logon_id', e['logon_id']
    if e.get('username') and not is_system_account(e['username']):
        return 'username', e['username']
    return None, None


@rule('RECON_BURST', 'Medium', 'T1082', 'Burst of discovery commands', PROC, window=60)
def _recon_burst(c, e):
    if 'recon' not in (e.get('tags') or ''):
        return None
    col, val = _actor_key(e)
    if not col:
        col, val = 'parent_process', e.get('parent_process') or ''
    rows = c.execute('SELECT DISTINCT command_line FROM events WHERE tags LIKE ? AND time_utc>=? AND %s=?' % col,
                     ('%recon%', ago(e, minutes=3), val)).fetchall()
    if len(rows) >= 4:
        cmds = ', '.join(sorted({base((r[0] or '').split(' ')[0].strip('"')) or (r[0] or '')[:20] for r in rows}))
        return dict(summary='%d discovery commands in 3 minutes by %s (%s)' % (len(rows), e.get('username') or val, cmds), key=low(val))


@rule('MASS_FILE_ACTIVITY', 'High', 'T1486', 'Mass file changes in user folders (ransomware)', [('Sysmon', 11), ('Sysmon', 26)], window=30)
def _mass_file_activity(c, e):
    if 'userfile' not in (e.get('tags') or '') or not e.get('process_guid'):
        return None
    if base(e.get('process')) in ('explorer.exe', 'onedrive.exe', 'dropbox.exe', 'googledrivefs.exe', 'msiexec.exe', 'trustedinstaller.exe',
                                  'msmpeng.exe', 'searchindexer.exe', 'backgroundtaskhost.exe'):
        return None
    n = c.execute("SELECT COUNT(*) FROM events WHERE channel='Sysmon' AND process_guid=? AND tags LIKE '%userfile%' AND time_utc>=?",
                  (e['process_guid'], ago(e, minutes=1))).fetchone()[0]
    if n >= 100:
        return dict(summary='%s created/deleted %d files in user folders within 1 minute' % (e.get('process'), n),
                    severity='Critical' if n >= 300 else 'High', key=e['process_guid'])


NOTE = re.compile(r'(readme|read_me|decrypt|restore|recover|how_to|howto|help_|instructions|ransom|!!!).*\.(txt|html?|hta|url)$')


@rule('RANSOM_NOTE', 'Critical', 'T1486', 'Ransom-note-like files dropped in many folders', [('Sysmon', 11)], window=60)
def _ransom_note(c, e):
    name = base(e.get('target'))
    if not NOTE.search(name) or 'userfile' not in (e.get('tags') or ''):
        return None
    n = c.execute("SELECT COUNT(DISTINCT target) FROM events WHERE channel='Sysmon' AND event_id=11 AND process_guid=? AND target LIKE ? AND time_utc>=?",
                  (e.get('process_guid') or '', '%' + name, ago(e, minutes=2))).fetchone()[0]
    if n >= 3:
        return dict(summary='%s wrote "%s" into %d folders' % (e.get('process'), name, n), key=(e.get('process_guid') or '') + name)


@rule('C2_BEACONING', 'Medium', 'T1071', 'Regular-interval connections (beaconing)', [('Sysmon', 3)], window=240)
def _c2_beaconing(c, e):
    if e.get('status') != 'outbound' or not public_ip(e.get('dest_ip')) or not e.get('process'):
        return None
    times = [dt(r[0]) for r in c.execute("SELECT time_utc FROM events WHERE channel='Sysmon' AND event_id=3 AND process=? AND dest_ip=? "
                                         "AND time_utc>=? ORDER BY time_utc", (e['process'], e['dest_ip'], ago(e, minutes=60))).fetchall()]
    if len(times) < 8:
        return None
    gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
    mean = statistics.mean(gaps)
    if mean < 10 or statistics.pstdev(gaps) / mean > 0.15:
        return None
    return dict(summary='%s contacted %s every ~%ds (%d times in 1h) - possible C2 beacon' % (base(e['process']), e['dest_ip'], round(mean), len(times)),
                key=low(e['process']) + '|' + e['dest_ip'])


# ============================================================================= 3. baseline / anomaly
BASELINE_DAYS_DEFAULT = 7
ANOMALIES = {
    'parent_child': ('ANOMALY_NEW_PARENT_CHILD', 'Low', 'T1059', 'Never-seen parent -> child process pair'),
    'rdp_source': ('ANOMALY_NEW_RDP_SOURCE', 'Medium', 'T1021.001', 'RDP logon from a new source'),
    'net_process': ('ANOMALY_NEW_NET_PROCESS', 'Low', 'T1071', 'Process talking to the internet for the first time'),
}
for _kind, (_rid, _sev, _mitre, _title) in ANOMALIES.items():
    SEVERITY[_rid] = _sev
RULE_EVENTS.update({'ANOMALY_NEW_PARENT_CHILD': sorted(PROC),
                    'ANOMALY_NEW_RDP_SOURCE': [('RDP-Auth', 1149), ('Security', 4624)],
                    'ANOMALY_NEW_NET_PROCESS': [('Sysmon', 3)]})


def baseline_keys(e):
    ch, eid = e.get('channel'), int(e.get('event_id', 0))
    out = []
    if (ch, eid) in PROC and e.get('parent_process'):
        out.append(('parent_child', base(e['parent_process']) + ' > ' + base(e.get('process'))))
    if (ch == 'Security' and eid == 4624 and (e.get('logon_type') or '').startswith('10') and e.get('source_ip')) or \
            (ch == 'RDP-Auth' and eid == 1149 and e.get('source_ip')):
        out.append(('rdp_source', low(e.get('username')) + ' @ ' + e['source_ip']))
    if ch == 'Sysmon' and eid == 3 and e.get('status') == 'outbound' and public_ip(e.get('dest_ip')):
        out.append(('net_process', low(e.get('process'))))
    return out


def _state(c, key, default=None):
    r = c.execute('SELECT value FROM collector_state WHERE key=?', (key,)).fetchone()
    return r[0] if r else default


def learning_until(c, now=None):
    """UTC datetime when the learning period ends (starts at the first live event)."""
    start = _state(c, 'baseline_start')
    if not start:
        start = (now or datetime.now(timezone.utc)).isoformat()
        c.execute("INSERT OR IGNORE INTO collector_state(key,value) VALUES('baseline_start',?)", (start,))
    days = float(_state(c, 'baseline_days', BASELINE_DAYS_DEFAULT))
    return dt(start) + timedelta(days=days)


def _baseline(c, e):
    if e.get('is_demo'):
        return []
    keys = baseline_keys(e)
    if not keys:
        return []
    learning = dt(e.get('time_utc')) < learning_until(c, dt(e.get('time_utc')))
    out = []
    for kind, key in keys:
        seen = c.execute('SELECT 1 FROM baseline WHERE kind=? AND key=?', (kind, key)).fetchone()
        c.execute('INSERT INTO baseline(kind,key,first_seen,last_seen,count) VALUES(?,?,?,?,1) '
                  'ON CONFLICT(kind,key) DO UPDATE SET last_seen=excluded.last_seen, count=count+1',
                  (kind, key, e['time_utc'], e['time_utc']))
        if not seen and not learning:
            rid, sev, mitre, title = ANOMALIES[kind]
            what = {'parent_child': 'New process chain on this machine: %s  (%s)' % (key, (e.get('command_line') or '')[:150]),
                    'rdp_source': 'First RDP logon ever seen for %s' % key,
                    'net_process': 'First internet connection by %s -> %s:%s' % (e.get('process'), e.get('dest_ip'), e.get('dest_port'))}[kind]
            out.append(dict(rule_id=rid, severity=sev, mitre=mitre, summary=what, key=key, window=1440))
    return out


# ============================================================================= allowlist + entry point
ALLOW_FIELDS = ('process', 'parent_process', 'command_line', 'target', 'username', 'source_ip', 'dest_ip', 'computer')


def allowed(c, rule_id, e):
    """True if a user allowlist entry suppresses this rule for this event."""
    try:
        rows = c.execute("SELECT field, pattern FROM allowlist WHERE rule_id IN (?, '*')", (rule_id,)).fetchall()
    except sqlite3.OperationalError:
        return False
    for field, pattern in rows:
        if field in ALLOW_FIELDS and pattern and low(pattern) in low(str(e.get(field) or '')):
            return True
    return False


def evaluate(conn, e):
    """Run every rule that listens to this event. Returns a list of detections:
    dict(rule_id, severity, mitre, summary, key, window)."""
    e = dict(e)
    e.setdefault('channel', 'Security')
    e['event_id'] = int(e.get('event_id', 0))
    e['time_utc'] = e.get('time_utc') or datetime.now(timezone.utc).isoformat()
    for k in ('username', 'source_ip', 'process', 'parent_process', 'command_line', 'target', 'status', 'logon_id', 'process_guid', 'tags'):
        e[k] = str(e.get(k) or '').strip()
    ev = (e['channel'], e['event_id'])
    out = []
    for r in RULES.values():
        if ev not in r['events']:
            continue
        try:
            hit = r['fn'](conn, e)
        except sqlite3.OperationalError:
            hit = None              # minimal schema (e.g. unit tests) - skip stateful lookups that need it
        if hit:
            out.append(dict(rule_id=r['id'], severity=hit.get('severity', r['severity']), mitre=r['mitre'],
                            summary=hit['summary'], key=str(hit.get('key') or r['id']), window=r['window']))
    try:
        out += _baseline(conn, e)
    except sqlite3.OperationalError:
        pass
    return [d for d in out if not allowed(conn, d['rule_id'], e)]
