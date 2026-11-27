"""MiniSOC response engine: turn alerts into actions on this computer.

Design rules
  * Everything an action targets (IP, user, PID, path, service, task, registry key) comes from event
    logs, i.e. it may be attacker-controlled. Every value is validated against a strict format and a
    protection list BEFORE it is used, and commands are always run as argument lists (never a shell).
  * Manual by default. Auto-response only for Critical alerts of the rules in AUTO_POLICY, and only
    for the actions listed there (kill the culprit, isolate the host).
  * Reversible actions store what is needed to undo them. IP blocks expire.
  * DEMO events never touch the system ("Simulated"); dry-run mode logs commands without running them.
"""
import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import database as db

WINDOWS = platform.system() == 'Windows'
QUARANTINE = Path(os.environ.get('ProgramData', str(Path.home()))) / 'MiniSOC' / 'quarantine'
ISOLATE_RULES = ('MiniSOC-Isolate-In', 'MiniSOC-Isolate-Out')
ALL_BUT_LOOPBACK = '0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255,::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
_NO_WINDOW = 0x08000000

ACTIONS = {
    'kill_process': ('Kill process (and its children)', False),
    'block_ip': ('Block IP in Windows Firewall', True),
    'disable_account': ('Disable local account', True),
    'quarantine_file': ('Quarantine file', True),
    'remove_run_key': ('Remove autostart registry value', True),
    'disable_service': ('Stop and disable service', True),
    'disable_task': ('Disable scheduled task', True),
    'isolate_host': ('Isolate this computer from the network', True),
}

# Critical alerts of these rules are answered automatically (when auto-response is On).
AUTO_POLICY = {
    'SHADOW_COPY_DELETION': ('kill_parent', 'isolate_host'),
    'MASS_FILE_ACTIVITY': ('kill_process', 'isolate_host'),
    'RANSOM_NOTE': ('kill_process', 'isolate_host'),
    'LSASS_ACCESS': ('kill_process',),
    'CREDENTIAL_DUMP_COMMAND': ('kill_process',),
}

PROTECTED_IMAGES = {
    'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe', 'lsass.exe', 'lsaiso.exe',
    'svchost.exe', 'explorer.exe', 'dwm.exe', 'fontdrvhost.exe', 'sihost.exe', 'msmpeng.exe', 'nissrv.exe',
    'mssense.exe', 'sysmon.exe', 'sysmon64.exe', 'sysmon64a.exe', 'securityhealthservice.exe', 'registry', 'memcompression',
}
PROTECTED_SERVICES = {
    'eventlog', 'windefend', 'wdnissvc', 'sense', 'mpssvc', 'bfe', 'rpcss', 'dcomlaunch', 'lsm', 'samss', 'sysmon',
    'sysmon64', 'sysmon64a', 'sysmondrv', 'wuauserv', 'cryptsvc', 'winmgmt', 'schedule', 'termservice', 'dhcp', 'dnscache',
}
SYSTEM_ACCOUNTS = {'system', 'localsystem', 'local service', 'network service', 'administrator', 'defaultaccount', 'wdagutilityaccount'}
RUN_KEYS = re.compile(r'\\software\\(wow6432node\\)?microsoft\\windows\\currentversion\\(run|runonce|policies\\explorer\\run)$', re.I)

RULE_ACTIONS = {    # what to suggest for each rule (manual)
    'FAILED_LOGIN_BURST': ['block_ip'], 'PASSWORD_SPRAY': ['block_ip'], 'ANOMALY_NEW_RDP_SOURCE': ['block_ip', 'disable_account'],
    'SUCCESS_AFTER_FAILURES': ['block_ip', 'disable_account'], 'ACCOUNT_CREATED': ['disable_account'],
    'C2_BEACONING': ['kill_process', 'block_ip', 'isolate_host'], 'SCRIPT_HOST_NETWORK': ['kill_process', 'block_ip'],
    'ANOMALY_NEW_NET_PROCESS': ['kill_process', 'block_ip'],
    'LSASS_ACCESS': ['kill_process', 'quarantine_file'], 'CREDENTIAL_DUMP_COMMAND': ['kill_process'],
    'REMOTE_THREAD_INJECTION': ['kill_process', 'quarantine_file'], 'PROCESS_TAMPERING': ['kill_process'],
    'ENCODED_POWERSHELL': ['kill_process'], 'POWERSHELL_DOWNLOAD_EXEC': ['kill_process'], 'POWERSHELL_HIDDEN': ['kill_process'],
    'OFFICE_SPAWNS_SHELL': ['kill_process'], 'LOLBIN_ABUSE': ['kill_process'], 'PROCESS_MASQUERADING': ['kill_process', 'quarantine_file'],
    'EXEC_FROM_SUSPICIOUS_PATH': ['kill_process', 'quarantine_file'], 'ANOMALY_NEW_PARENT_CHILD': ['kill_process'],
    'SHADOW_COPY_DELETION': ['kill_parent', 'isolate_host'], 'LOG_CLEAR_COMMAND': ['kill_parent'],
    'DEFENSE_TAMPERING_COMMAND': ['kill_parent'], 'MASS_FILE_ACTIVITY': ['kill_process', 'isolate_host'],
    'RANSOM_NOTE': ['kill_process', 'isolate_host'], 'REGISTRY_PERSISTENCE': ['remove_run_key', 'quarantine_file'],
    'SERVICE_INSTALLED': ['disable_service', 'quarantine_file'], 'SCHEDULED_TASK_CREATED': ['disable_task'],
}


class Refused(Exception):
    """A guard rejected the action."""


def now():
    return datetime.now(timezone.utc)


# ----------------------------------------------------------------------------- validation (pure, testable)
def check_ip(ip):
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        raise Refused('not a valid IP address: %r' % ip)
    if a.is_loopback or a.is_unspecified or a.is_multicast or a.is_link_local or a.is_reserved:
        raise Refused('refusing to block special address %s' % a)
    if str(a) in local_addresses():
        raise Refused('%s belongs to this computer or its gateway / DNS' % a)
    return str(a)


def check_account(user):
    user = str(user or '').strip()
    domain, _, name = user.rpartition('\\')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._ -]{0,19}', name) or re.match(r'S-1-\d', name, re.I):
        raise Refused('not a valid local account name: %r' % user)
    computer = os.environ.get('COMPUTERNAME', '').lower()
    if domain and domain.lower() not in (computer, '.', ''):
        raise Refused('%s is a domain account - disable it on the domain controller' % user)
    if name.lower() in SYSTEM_ACCOUNTS or name.endswith('$'):
        raise Refused('refusing to disable built-in account %s' % name)
    if name.lower() == os.environ.get('USERNAME', '').lower():
        raise Refused('refusing to disable the account you are logged in with')
    return name


def check_pid(pid, image):
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        raise Refused('no process ID recorded for this event')
    base = re.split(r'[\\/]', image or '')[-1].lower()
    if pid <= 4 or base in PROTECTED_IMAGES:
        raise Refused('%s is a protected system process' % (base or pid))
    if pid in (os.getpid(), os.getppid()):
        raise Refused('refusing to kill MiniSOC itself')
    if not image:
        raise Refused('process image unknown - cannot verify the PID was not reused')
    return pid, image


def check_path(path):
    p = str(path or '').strip().strip('"')
    if not re.match(r'^[A-Za-z]:\\', p) or '..' in p.split('\\'):
        raise Refused('not an absolute local path: %r' % path)
    low = p.lower()
    system_root = os.environ.get('SystemRoot', r'C:\Windows').lower().rstrip('\\') + '\\'
    if low.startswith(system_root) or low.startswith(str(QUARANTINE).lower()) or low.startswith(str(Path(__file__).parent).lower()):
        raise Refused('refusing to quarantine files under %s' % (system_root if low.startswith(system_root) else 'MiniSOC folders'))
    return p


def check_service(name):
    name = str(name or '').strip()
    if not re.fullmatch(r'[A-Za-z0-9_.\- ]{1,80}', name):
        raise Refused('not a valid service name: %r' % name)
    if name.lower() in PROTECTED_SERVICES:
        raise Refused('%s is a protected service' % name)
    return name


def check_task(name):
    name = str(name or '').strip()
    if not re.fullmatch(r'\\?[A-Za-z0-9_.\- \\]{1,200}', name) or '..' in name:
        raise Refused('not a valid task name: %r' % name)
    if name.lower().lstrip('\\').startswith('microsoft\\'):
        raise Refused('refusing to touch Windows built-in tasks')
    return name


HIVES = {'HKLM': 'HKEY_LOCAL_MACHINE', 'HKU': 'HKEY_USERS', 'HKCU': 'HKEY_CURRENT_USER'}


def check_run_key(target):
    """'HKU\\S-1-5-21..\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\name' -> (hive, subkey, value)."""
    t = str(target or '').strip()
    hive, _, rest = t.partition('\\')
    subkey, _, value = rest.rpartition('\\')
    if hive.upper() not in HIVES or not value or not RUN_KEYS.search('\\' + subkey):
        raise Refused('only Run / RunOnce autostart values can be removed automatically: %r' % t)
    return hive.upper(), subkey, value


# ----------------------------------------------------------------------------- planning
def _pid(data, *keys):
    for k in keys:
        v = str(data.get(k) or '').strip()
        if v:
            try:
                return int(v, 16) if v.lower().startswith('0x') else int(v)
            except ValueError:
                pass
    return None


def plan_for(action, ev, alert=None):
    """Build one plan from an event row (sqlite Row or dict). Returns dict or None if not applicable."""
    ev = dict(ev) if ev is not None else {}
    data = {}
    try:
        data = json.loads(ev.get('data_json') or '{}')
    except ValueError:
        pass
    ch, eid = ev.get('channel'), ev.get('event_id')
    p = None
    if action == 'kill_process':
        pid = _pid(data, 'SourceProcessId', 'ProcessId') if ch == 'Sysmon' else _pid(data, 'NewProcessId') if eid == 4688 else None
        image = ev.get('process')
        if image:
            p = dict(action='kill_process', params=dict(pid=pid, image=image), target='%s (PID %s)' % (image, pid if pid else '?'))
    elif action == 'kill_parent':
        pid = _pid(data, 'ParentProcessId') if ch == 'Sysmon' else _pid(data, 'ProcessId') if eid == 4688 else None
        image = ev.get('parent_process')
        if image:
            p = dict(action='kill_process', params=dict(pid=pid, image=image), target='%s (PID %s, parent)' % (image, pid if pid else '?'))
    elif action == 'block_ip':
        ip = ev.get('source_ip') if ch != 'Sysmon' else ev.get('dest_ip')
        if ip:
            p = dict(action='block_ip', params=dict(ip=ip), target=ip)
    elif action == 'disable_account':
        user = ev.get('username')
        if user and not user.upper().startswith('S-1-'):
            p = dict(action='disable_account', params=dict(user=user), target=user)
    elif action == 'quarantine_file':
        path = ev.get('process') if ch == 'Sysmon' and eid in (1, 8, 10) else ''
        if ch in ('System', 'Security') and eid in (7045, 4697):
            m = re.match(r'"?([A-Za-z]:\\[^"]+?\.(exe|dll|sys|scr|bat|ps1))', ev.get('command_line') or '', re.I)
            path = m.group(1) if m else ''
        if ch == 'Sysmon' and eid == 13:
            m = re.match(r'"?([A-Za-z]:\\[^"]+?\.(exe|dll|scr|bat|ps1|vbs|hta))', ev.get('command_line') or '', re.I)
            path = m.group(1) if m else ''
        if path:
            p = dict(action='quarantine_file', params=dict(path=path), target=path)
    elif action == 'remove_run_key' and ev.get('target'):
        p = dict(action='remove_run_key', params=dict(key=ev['target']), target=ev['target'])
    elif action == 'disable_service' and ev.get('target'):
        p = dict(action='disable_service', params=dict(name=ev['target']), target=ev['target'])
    elif action == 'disable_task' and ev.get('target'):
        p = dict(action='disable_task', params=dict(name=ev['target']), target=ev['target'])
    elif action == 'isolate_host':
        p = dict(action='isolate_host', params={}, target=ev.get('computer') or 'this computer')
    if p:
        p['label'] = ACTIONS[p['action']][0]
        p['reversible'] = ACTIONS[p['action']][1]
        p['demo'] = bool(ev.get('is_demo'))
        p['alert_id'] = alert['id'] if alert else None
        p['rule_id'] = alert['rule_id'] if alert else ''
        p['blocked'] = ''
        if not p['demo']:
            try:
                validate(p)
            except Refused as e:
                p['blocked'] = str(e)
        p['preview'] = preview(p)
    return p


def suggest_for_alert(alert):
    ev = db.event(alert['event_record_id']) if alert['event_record_id'] else None
    if ev is None:
        return []
    out = []
    for a in RULE_ACTIONS.get(alert['rule_id'], []):
        p = plan_for(a, ev, alert)
        if p:
            out.append(p)
    return out


def suggest_for_incident(iid):
    seen, out = set(), []
    for a in db.incident_alerts(iid):
        for p in suggest_for_alert(a):
            key = (p['action'], json.dumps(p['params'], sort_keys=True))
            if key not in seen:
                seen.add(key)
                out.append(p)
    return out


def validate(p):
    a, k = p['action'], p['params']
    if a == 'kill_process':
        check_pid(k.get('pid'), k.get('image'))
    elif a == 'block_ip':
        check_ip(k.get('ip'))
    elif a == 'disable_account':
        check_account(k.get('user'))
    elif a == 'quarantine_file':
        check_path(k.get('path'))
    elif a == 'remove_run_key':
        check_run_key(k.get('key'))
    elif a == 'disable_service':
        check_service(k.get('name'))
    elif a == 'disable_task':
        check_task(k.get('name'))
    elif a != 'isolate_host':
        raise Refused('unknown action %s' % a)


def preview(p):
    """Human readable description of exactly what will be run."""
    a, k = p['action'], p['params']
    if p.get('blocked'):
        return 'NOT ALLOWED: ' + p['blocked']
    if p.get('demo'):
        return 'SIMULATED (DEMO event): %s -> %s' % (p['label'], p['target'])
    if a == 'kill_process':
        return 'taskkill /PID %s /T /F   (only if PID %s is still %s)' % (k['pid'], k['pid'], k['image'])
    if a == 'block_ip':
        return 'netsh advfirewall firewall add rule name=MiniSOC-Block-%s dir=in+out action=block remoteip=%s' % (k['ip'], k['ip'])
    if a == 'disable_account':
        return 'net user %s /active:no' % check_account(k['user'])
    if a == 'quarantine_file':
        return 'move "%s" -> %s\\<time>_<name>.quarantine  (SHA-256 recorded)' % (k['path'], QUARANTINE)
    if a == 'remove_run_key':
        return 'export then delete registry value %s' % k['key']
    if a == 'disable_service':
        return 'sc stop "%s"  +  sc config "%s" start= disabled' % (k['name'], k['name'])
    if a == 'disable_task':
        return 'schtasks /Change /TN "%s" /DISABLE' % k['name']
    if a == 'isolate_host':
        return 'Windows Firewall on + block ALL inbound/outbound traffic except loopback (rules %s)' % ', '.join(ISOLATE_RULES)
    return a


# ----------------------------------------------------------------------------- system helpers (patched in tests)
def _run(args):
    r = subprocess.run(args, capture_output=True, text=True, timeout=60, creationflags=_NO_WINDOW if WINDOWS else 0)
    out = ((r.stdout or '') + (r.stderr or '')).strip()
    if r.returncode != 0:
        raise RuntimeError('%s failed (%s): %s' % (args[0], r.returncode, out[:300]))
    return out


def _ps(script):
    """PowerShell with a FIXED script (never pass event data in here)."""
    return _run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script])


_local_cache = {}


def local_addresses():
    """IPs of this computer, its default gateways and DNS servers (cached 5 min)."""
    if _local_cache.get('t') and (now() - _local_cache['t']).total_seconds() < 300:
        return _local_cache['ips']
    ips = set()
    try:
        ips |= set(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    if WINDOWS:
        try:
            out = _ps('(Get-NetIPConfiguration | ForEach-Object { $_.IPv4Address.IPAddress; $_.IPv4DefaultGateway.NextHop; '
                      '$_.DNSServer.ServerAddresses }) -join ","')
            ips |= {x.strip() for x in out.split(',') if x.strip()}
        except Exception:
            pass
    _local_cache.update(t=now(), ips=ips)
    return ips


def image_of(pid):
    """Full image path of a running PID (Windows), or None."""
    import ctypes
    k32 = ctypes.windll.kernel32
    h = k32.OpenProcess(0x1000, False, int(pid))         # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return None
    try:
        buf = ctypes.create_unicode_buffer(32768)
        size = ctypes.c_ulong(32768)
        return buf.value if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)) else None
    finally:
        k32.CloseHandle(h)


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _winreg():
    import winreg
    return winreg


# ----------------------------------------------------------------------------- executors
def _kill(k):
    pid, image = check_pid(k['pid'], k['image'])
    live = image_of(pid)
    if not live:
        return 'Process %s already exited' % pid, None
    if live.lower() != image.lower():
        raise Refused('PID %s is now %s (not %s) - PID was reused, nothing killed' % (pid, live, image))
    protected = protected_descendants(pid)
    if protected:     # taskkill /T would take these down too: kill only the culprit itself
        return _run(['taskkill', '/PID', str(pid), '/F']) + ' (children left running: %s is protected)' % ', '.join(protected), None
    return _run(['taskkill', '/PID', str(pid), '/T', '/F']), None


def protected_descendants(pid):
    """Protected image names in the process tree under pid. Unknown tree -> ['unknown'] (fail safe: no /T)."""
    try:
        procs = json.loads(_ps('Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name | ConvertTo-Json -Compress') or '[]')
    except Exception:
        return ['unknown']
    if isinstance(procs, dict):
        procs = [procs]
    kids = {}
    for p in procs:
        if isinstance(p, dict) and 'ProcessId' in p:
            kids.setdefault(p.get('ParentProcessId'), []).append(p)
    found, todo, seen = [], [pid], {pid}
    while todo:
        for child in kids.get(todo.pop(), []):
            cpid = child['ProcessId']
            if cpid in seen:          # PID reuse can create loops
                continue
            seen.add(cpid)
            todo.append(cpid)
            if str(child.get('Name') or '').lower() in PROTECTED_IMAGES:
                found.append(child['Name'])
    return found


def _block(k, ttl_hours):
    ip = check_ip(k['ip'])
    name = 'MiniSOC-Block-' + ip
    try:
        for direction in ('in', 'out'):
            _run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=' + name, 'dir=' + direction, 'action=block', 'remoteip=' + ip])
    except Exception:
        try:                          # don't leave a half block that has no undo record and never expires
            _run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=' + name])
        except Exception:
            pass
        raise
    expires = (now() + timedelta(hours=ttl_hours)).isoformat(timespec='seconds') if ttl_hours else None
    return 'Blocked %s inbound and outbound%s' % (ip, (' until ' + expires) if expires else ''), dict(rule=name, expires=expires)


def _unblock(u):
    _run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=' + u['rule']])
    return 'Firewall rule %s removed' % u['rule']


def _disable_account(k):
    name = check_account(k['user'])
    return _run(['net', 'user', name, '/active:no']), dict(user=name)


def _enable_account(u):
    return _run(['net', 'user', check_account(u['user']), '/active:yes'])


def _quarantine(k):
    src = Path(check_path(k['path']))
    if not src.is_file():
        raise Refused('file not found: %s' % src)
    with open(src, 'rb') as f:
        digest = hashlib.file_digest(f, 'sha256').hexdigest()     # streamed: large files don't fill RAM
    QUARANTINE.mkdir(parents=True, exist_ok=True)
    dst = QUARANTINE / ('%s_%s.quarantine' % (now().strftime('%Y%m%d%H%M%S'), src.name))
    shutil.move(str(src), str(dst))
    return 'Moved to %s (SHA-256 %s)' % (dst, digest), dict(src=str(src), dst=str(dst), sha256=digest)


def _restore_file(u):
    src, dst = Path(u['dst']), Path(u['src'])
    if dst.exists():
        raise Refused('%s exists again - not overwriting it' % dst)
    shutil.move(str(src), str(dst))
    return 'Restored %s' % dst


def _remove_run_key(k):
    hive, subkey, value = check_run_key(k['key'])
    wr = _winreg()
    root = getattr(wr, HIVES[hive])
    with wr.OpenKey(root, subkey, 0, wr.KEY_READ | wr.KEY_SET_VALUE | wr.KEY_WOW64_64KEY) as h:
        data, kind = wr.QueryValueEx(h, value)
        wr.DeleteValue(h, value)
    return 'Deleted %s (was: %s)' % (k['key'], data), dict(key=k['key'], data=data, kind=kind)


def _restore_run_key(u):
    hive, subkey, value = check_run_key(u['key'])
    wr = _winreg()
    with wr.OpenKey(getattr(wr, HIVES[hive]), subkey, 0, wr.KEY_SET_VALUE | wr.KEY_WOW64_64KEY) as h:
        wr.SetValueEx(h, value, 0, u['kind'], u['data'])
    return 'Restored %s' % u['key']


START_NAMES = {0: 'boot', 1: 'system', 2: 'auto', 3: 'demand', 4: 'disabled'}


def _disable_service(k):
    name = check_service(k['name'])
    wr = _winreg()
    with wr.OpenKey(wr.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services' + '\\' + name) as h:
        start = wr.QueryValueEx(h, 'Start')[0]
    try:
        _run(['sc', 'stop', name])
    except RuntimeError:
        pass                                     # already stopped
    _run(['sc', 'config', name, 'start=', 'disabled'])
    return 'Service %s stopped and disabled (was start=%s)' % (name, START_NAMES.get(start, start)), dict(name=name, start=start)


def _restore_service(u):
    name = check_service(u['name'])
    _run(['sc', 'config', name, 'start=', START_NAMES.get(int(u['start']), 'demand')])
    return 'Service %s start type restored to %s (not started)' % (name, START_NAMES.get(int(u['start'])))


def _disable_task(k):
    name = check_task(k['name'])
    return _run(['schtasks', '/Change', '/TN', name, '/DISABLE']), dict(name=name)


def _enable_task(u):
    return _run(['schtasks', '/Change', '/TN', check_task(u['name']), '/ENABLE'])


def _isolate(_k):
    before = json.loads(_ps('Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress') or '[]')
    if isinstance(before, dict):
        before = [before]
    _run(['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'on'])
    for name, direction in zip(ISOLATE_RULES, ('in', 'out')):
        _run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=' + name, 'dir=' + direction, 'action=block',
              'remoteip=' + ALL_BUT_LOOPBACK])
    return 'Computer isolated: all network traffic blocked except loopback', dict(profiles=before)


def _release(u):
    for name in ISOLATE_RULES:
        try:
            _run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=' + name])
        except RuntimeError:
            pass
    for prof in u.get('profiles') or []:
        if prof.get('Enabled') in (False, 0, 'False'):
            pname = {'Domain': 'domainprofile', 'Private': 'privateprofile', 'Public': 'publicprofile'}.get(str(prof.get('Name')))
            if pname:
                _run(['netsh', 'advfirewall', 'set', pname, 'state', 'off'])
    return 'Isolation released - network restored'


def execute(p, mode='live', ttl_hours=24):
    """Run a plan. Returns (status, result_text, undo_dict, expires)."""
    if p.get('demo'):
        return 'Simulated', 'DEMO event - nothing executed (would: %s -> %s)' % (p['label'], p['target']), None, None
    try:
        validate(p)
    except Refused as e:
        return 'Refused', str(e), None, None
    if mode == 'dry-run':
        return 'Dry-run', 'Dry-run - would run: ' + preview(p), None, None
    if not WINDOWS:
        return 'Failed', 'Response actions require Windows', None, None
    if not is_admin():
        return 'Failed', 'MiniSOC must run as Administrator to respond', None, None
    a, k = p['action'], p['params']
    try:
        if a == 'kill_process':
            text, undo = _kill(k)
        elif a == 'block_ip':
            text, undo = _block(k, ttl_hours)
        elif a == 'disable_account':
            text, undo = _disable_account(k)
        elif a == 'quarantine_file':
            text, undo = _quarantine(k)
        elif a == 'remove_run_key':
            text, undo = _remove_run_key(k)
        elif a == 'disable_service':
            text, undo = _disable_service(k)
        elif a == 'disable_task':
            text, undo = _disable_task(k)
        elif a == 'isolate_host':
            text, undo = _isolate(k)
        else:
            return 'Refused', 'unknown action', None, None
    except Refused as e:
        return 'Refused', str(e), None, None
    except Exception as e:                # command failed
        return 'Failed', str(e), None, None
    expires = undo.pop('expires', None) if undo else None
    return 'Executed', text or 'done', undo, expires


UNDO = {'block_ip': _unblock, 'disable_account': _enable_account, 'quarantine_file': _restore_file,
        'remove_run_key': _restore_run_key, 'disable_service': _restore_service, 'disable_task': _enable_task,
        'isolate_host': _release}


def undo(action, undo_params):
    if action not in UNDO or not undo_params:
        return 'Failed', 'This action cannot be undone'
    if not WINDOWS:
        return 'Failed', 'Undo requires Windows'
    try:
        return 'Undone', UNDO[action](undo_params)
    except Exception as e:
        return 'Failed', str(e)


# ----------------------------------------------------------------------------- orchestration (DB)
def settings():
    # dry-run until the user turns it on: a false positive in 'on' kills processes / cuts the network
    return db.setting('auto_response', 'dry-run'), int(db.setting('block_ttl_hours', 24))


def run_request(rid):
    """Execute an approved request. Returns the new status."""
    r = db.response_request(rid)
    p = json.loads(r['plan_json'] or '{}')
    if not p:
        db.finish_response(rid, 'Approved (Manual)', 'Record-only request - nothing to execute', None, None)
        return 'Approved (Manual)'
    if p['action'] == 'isolate_host' and db.isolation_active():
        db.finish_response(rid, 'Refused', 'Computer is already isolated', None, None)
        return 'Refused'
    mode, ttl = settings()
    status, text, undo_params, expires = execute(p, 'dry-run' if mode == 'dry-run' else 'live', ttl)
    db.finish_response(rid, status, text, undo_params, expires)
    return status


def undo_request(rid):
    r = db.response_request(rid)
    if r['status'] != 'Executed':
        return 'Failed', 'Only executed actions can be undone'
    p = json.loads(r['plan_json'] or '{}')
    status, text = undo(p.get('action'), json.loads(r['undo_json'] or 'null'))
    db.mark_undone(rid, status, text)
    return status, text


def auto_respond(alert_ids):
    """Answer Critical alerts of AUTO_POLICY rules. Returns [(request id, status, text)]."""
    mode, ttl = settings()
    if mode == 'off' or not alert_ids:
        return []
    done = []
    killed = set()
    for aid in alert_ids:
        a = db.alert(aid)
        if not a or a['severity'] != 'Critical' or a['rule_id'] not in AUTO_POLICY:
            continue
        ev = db.event(a['event_record_id']) if a['event_record_id'] else None
        for action in AUTO_POLICY[a['rule_id']]:
            p = plan_for(action, ev, a)
            if not p:
                continue
            if p['action'] == 'isolate_host' and db.isolation_active():
                continue
            key = (p['params'].get('pid'), p['params'].get('image'))
            if p['action'] == 'kill_process' and key in killed:
                continue
            killed.add(key)
            rid = db.add_response(a['incident_id'], p, 'Auto-response to Critical alert #%s %s' % (aid, a['rule_id']), mode='auto')
            status, text, undo_params, expires = execute(p, 'dry-run' if mode == 'dry-run' else 'live', ttl)
            db.finish_response(rid, status, text, undo_params, expires)
            done.append((rid, status, '%s: %s' % (p['label'], p['target'])))
    return done


def expire_blocks():
    """Remove IP blocks whose time is up. Returns number removed."""
    n = 0
    for r in db.expired_blocks():
        status, text = undo('block_ip', json.loads(r['undo_json'] or 'null'))
        if status != 'Undone':
            text += ' - remove the firewall rule %s manually' % (json.loads(r['undo_json'] or '{}') or {}).get('rule', '')
        db.mark_undone(r['id'], 'Expired' if status == 'Undone' else 'Failed', text)
        n += status == 'Undone'
    return n
