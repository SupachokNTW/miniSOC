"""Read-only, multi-channel Windows event reader (Windows 10/11 + pywin32).

Uses the modern Event Log API (EvtQuery / EvtNext / EvtRender) so it can read
Security, System AND the "Applications and Services Logs" channels
(Sysmon, PowerShell, Defender, Task Scheduler, RDP). Events are rendered as
XML, so every field arrives with its name instead of a positional insert string.

Reading is FORWARD from a per-channel cursor (EventRecordID), bounded by the
newest record that existed when the poll started. Nothing is skipped: if a
channel has more new events than one poll may take, the cursor only advances
as far as what was actually read and the rest is picked up next poll.
"""
import csv
import os
import platform
import subprocess
import tempfile

from event_catalog import CATALOG, SHORT_TO_PATH, event_from_xml

ERR_ACCESS_DENIED = 5
ERR_CHANNEL_NOT_FOUND = 15007
ERR_INVALID_QUERY = 15001
IDS_PER_QUERY = 12          # the event-log XPath engine rejects queries with too many terms
BATCH = 200


def _api():
    if platform.system() != 'Windows':
        raise RuntimeError('Live collection requires Windows 10/11.')
    try:
        import win32evtlog
    except ImportError as e:
        raise RuntimeError('pywin32 is missing. Run install_windows.bat') from e
    return win32evtlog


def _winerror(exc):
    return getattr(exc, 'winerror', None) or (exc.args[0] if getattr(exc, 'args', None) and isinstance(exc.args[0], int) else None)


def _describe(exc):
    code = _winerror(exc)
    if code == ERR_CHANNEL_NOT_FOUND:
        return 'missing'
    if code == ERR_ACCESS_DENIED:
        return 'access denied (run as Administrator)'
    return 'error: %s' % exc


def _iter_query(api, path, xpath, reverse=False, batch_size=BATCH):
    flags = api.EvtQueryChannelPath | (api.EvtQueryReverseDirection if reverse else api.EvtQueryForwardDirection)
    handle = api.EvtQuery(path, flags, xpath)
    while True:
        batch = api.EvtNext(handle, batch_size)
        if not batch:
            return
        for ev in batch:
            yield api.EvtRender(ev, api.EvtRenderEventXml)


def latest_record(short='Security'):
    """Newest EventRecordID in a channel (0 if empty)."""
    api = _api()
    for xml in _iter_query(api, SHORT_TO_PATH.get(short, short), '*', reverse=True, batch_size=1):
        e = event_from_xml(xml)
        return e['record_id'] if e else 0
    return 0


def channel_status(short):
    """'ok' | 'missing' | 'access denied ...' | 'error: ...'"""
    try:
        latest_record(short)
        return 'ok'
    except Exception as e:      # pywintypes.error
        return _describe(e)


def _xpath(ids, after, upto, backfill_ms=None):
    terms = ' or '.join('EventID=%d' % i for i in ids)
    cond = '(%s) and EventRecordID>%d and EventRecordID<=%d' % (terms, after, upto)
    if backfill_ms:
        cond += ' and TimeCreated[timediff(@SystemTime) <= %d]' % backfill_ms
    return '*[System[%s]]' % cond


def read_channel(short, cursor, max_records=2000, backfill_hours=0):
    """Read one channel.

    cursor None  -> first run: start at the newest record (or backfill N hours).
    Returns (events oldest->newest, new_cursor).
    """
    api = _api()
    path = SHORT_TO_PATH[short]
    upto = latest_record(short)
    if cursor is None:
        if not backfill_hours:
            return [], upto
        cursor, backfill_ms = 0, int(backfill_hours * 3600 * 1000)
    else:
        backfill_ms = None
        if upto < cursor:            # log was cleared / recreated -> start again from the beginning
            cursor = 0
    if upto <= cursor:
        return [], upto
    ids = sorted(CATALOG[short])
    events, safe = [], upto
    for i in range(0, len(ids), IDS_PER_QUERY):
        got = []
        for xml in _iter_query(api, path, _xpath(ids[i:i + IDS_PER_QUERY], cursor, upto, backfill_ms)):
            e = event_from_xml(xml)
            if e:
                got.append(e)
            if len(got) >= max_records:
                safe = min(safe, got[-1]['record_id'])   # this chunk was cut short
                break
        events += got
    events = [e for e in events if e['record_id'] <= safe]
    events.sort(key=lambda x: x['record_id'])
    return events, safe


def read_new(cursors, max_records=2000, backfill_hours=0, channels=None):
    """Read every channel.

    cursors: {short_channel: last record id or None}
    Returns (events, new_cursors, status) where status = {short: 'ok' | 'missing' | ...}.
    A missing channel (e.g. Sysmon not installed) is reported, never fatal.
    """
    _api()
    events, new_cursors, status = [], dict(cursors), {}
    for short in channels or CATALOG:
        try:
            got, cur = read_channel(short, cursors.get(short), max_records, backfill_hours)
            events += got
            new_cursors[short] = cur
            status[short] = 'ok'
        except Exception as e:
            status[short] = _describe(e)
    events.sort(key=lambda x: x['time_utc'])
    return events, new_cursors, status


# ----------------------------------------------------------------------------- health checks
# Audit sub-categories (GUIDs are language independent, unlike their names).
AUDIT_SUBCATEGORIES = {
    '{0CCE9215-69AE-11D9-BED3-505054503030}': ('Logon', '4624 4625', 3),
    '{0CCE9216-69AE-11D9-BED3-505054503030}': ('Logoff', '4634 4647', 1),
    '{0CCE921B-69AE-11D9-BED3-505054503030}': ('Special Logon', '4672', 1),
    '{0CCE922B-69AE-11D9-BED3-505054503030}': ('Process Creation', '4688', 1),
    '{0CCE9211-69AE-11D9-BED3-505054503030}': ('Security System Extension', '4697', 1),
    '{0CCE9227-69AE-11D9-BED3-505054503030}': ('Other Object Access Events', '4698 4699 4702', 1),
    '{0CCE922F-69AE-11D9-BED3-505054503030}': ('Audit Policy Change', '4719', 1),
    '{0CCE9235-69AE-11D9-BED3-505054503030}': ('User Account Management', '4720-4740', 1),
    '{0CCE9237-69AE-11D9-BED3-505054503030}': ('Security Group Management', '4728 4732 4756', 1),
    '{0CCE923F-69AE-11D9-BED3-505054503030}': ('Credential Validation', '4776', 3),
}
_NO_WINDOW = 0x08000000


def _run(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=30, creationflags=_NO_WINDOW)


def audit_policy():
    """{guid: setting} where setting 0=none 1=success 2=failure 3=both; None if unreadable."""
    path = os.path.join(tempfile.mkdtemp(), 'auditpol.csv')
    try:
        r = _run(['auditpol', '/backup', '/file:' + path])
        if r.returncode != 0 or not os.path.exists(path):
            return None
        out = {}
        with open(path, newline='', encoding='utf-8-sig', errors='replace') as f:
            for row in csv.DictReader(f):
                guid = (row.get('Subcategory GUID') or '').upper()
                try:
                    out[guid] = int(row.get('Setting Value') or 0)
                except ValueError:
                    pass
        return out
    except Exception:
        return None
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def _reg(path, name):
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def health():
    """List of (area, check, state, detail, fix). state: OK | Missing | Warning | Unknown."""
    _api()
    rows = []
    admin = is_admin()
    rows.append(('Collector', 'Running as Administrator', 'OK' if admin else 'Warning',
                 'yes' if admin else 'no - Security and Sysmon channels may be unreadable', 'Right-click run_windows.bat > Run as administrator'))
    for short in CATALOG:
        st = channel_status(short)
        fix = {'Sysmon': 'Run install_sysmon.bat as Administrator',
               'PowerShell': 'Channel exists on every Windows 10/11; run as Administrator'}.get(short, 'Run as Administrator')
        rows.append(('Channel', short, 'OK' if st == 'ok' else 'Missing', st, '' if st == 'ok' else fix))
    pol = audit_policy()
    for guid, (name, ids, want) in AUDIT_SUBCATEGORIES.items():
        if pol is None:
            rows.append(('Audit policy', name, 'Unknown', 'auditpol needs Administrator', 'Run enable_auditing.bat'))
            continue
        have = pol.get(guid, 0)
        ok = (have & want) == want
        label = {0: 'No auditing', 1: 'Success', 2: 'Failure', 3: 'Success and Failure'}.get(have, str(have))
        rows.append(('Audit policy', '%s (%s)' % (name, ids), 'OK' if ok else 'Missing', label, '' if ok else 'Run enable_auditing.bat'))
    cmd = _reg(r'Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit', 'ProcessCreationIncludeCmdLine_Enabled')
    rows.append(('Registry', 'Command line in 4688', 'OK' if cmd == 1 else 'Missing', 'enabled' if cmd == 1 else 'disabled',
                 '' if cmd == 1 else 'Run enable_auditing.bat'))
    sb = _reg(r'Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging', 'EnableScriptBlockLogging')
    rows.append(('Registry', 'PowerShell Script Block Logging (4104)', 'OK' if sb == 1 else 'Missing', 'enabled' if sb == 1 else 'disabled',
                 '' if sb == 1 else 'Run enable_auditing.bat'))
    size = _reg(r'SYSTEM\CurrentControlSet\Services\EventLog\Security', 'MaxSize')
    mb = (size or 0) // (1024 * 1024)
    rows.append(('Log size', 'Security log max size', 'OK' if mb >= 128 else 'Warning', '%d MB' % mb if size else 'default (20 MB)',
                 '' if mb >= 128 else 'Run enable_auditing.bat (sets 200 MB)'))
    return rows
