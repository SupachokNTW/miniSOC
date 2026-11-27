"""Event catalog + parsing helpers (pure Python, no Windows dependency).

Everything that describes *what MiniSOC knows about an event* lives here:
channels, event names, categories, level mapping, XML parsing and the
normalisation of named EventData fields into MiniSOC's common columns.
"""
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

# --------------------------------------------------------------------------
# Channels (full Windows channel path -> short name used in the UI / DB)
# --------------------------------------------------------------------------
CHANNELS = {
    'Security': 'Security',
    'System': 'System',
    'Microsoft-Windows-Sysmon/Operational': 'Sysmon',
    'Microsoft-Windows-PowerShell/Operational': 'PowerShell',
    'Microsoft-Windows-Windows Defender/Operational': 'Defender',
    'Microsoft-Windows-TaskScheduler/Operational': 'TaskScheduler',
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational': 'RDP-Session',
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational': 'RDP-Auth',
}
SHORT_TO_PATH = {v: k for k, v in CHANNELS.items()}

# --------------------------------------------------------------------------
# Event IDs collected, per channel: id -> (name, category)
# --------------------------------------------------------------------------
CATALOG = {
    'Security': {
        4624: ('Successful logon', 'Logon / Logoff'),
        4625: ('Failed logon', 'Logon / Logoff'),
        4634: ('Account logoff', 'Logon / Logoff'),
        4647: ('User-initiated logoff', 'Logon / Logoff'),
        4648: ('Logon with explicit credentials', 'Logon / Logoff'),
        4672: ('Special privileges assigned to new logon', 'Privilege Use'),
        4688: ('Process created', 'Execution'),
        4697: ('Service installed', 'Persistence'),
        4698: ('Scheduled task created', 'Persistence'),
        4699: ('Scheduled task deleted', 'Persistence'),
        4702: ('Scheduled task updated', 'Persistence'),
        4719: ('System audit policy changed', 'Defence Evasion'),
        4720: ('User account created', 'Account Management'),
        4722: ('User account enabled', 'Account Management'),
        4723: ('Password change attempt', 'Account Management'),
        4724: ('Password reset attempt', 'Account Management'),
        4725: ('User account disabled', 'Account Management'),
        4726: ('User account deleted', 'Account Management'),
        4728: ('Member added to global security group', 'Account Management'),
        4729: ('Member removed from global security group', 'Account Management'),
        4732: ('Member added to local security group', 'Account Management'),
        4733: ('Member removed from local security group', 'Account Management'),
        4738: ('User account changed', 'Account Management'),
        4740: ('User account locked out', 'Account Management'),
        4756: ('Member added to universal security group', 'Account Management'),
        4768: ('Kerberos TGT requested', 'Kerberos'),
        4769: ('Kerberos service ticket requested', 'Kerberos'),
        4771: ('Kerberos pre-authentication failed', 'Kerberos'),
        4776: ('NTLM credential validation', 'Credential Validation'),
        1100: ('Event logging service shut down', 'Log Tampering'),
        1102: ('Audit log cleared', 'Log Tampering'),
    },
    'System': {
        104: ('Event log cleared', 'Log Tampering'),
        7040: ('Service start type changed', 'Persistence'),
        7045: ('Service installed', 'Persistence'),
        6005: ('Event log service started (boot)', 'System'),
        6006: ('Event log service stopped (shutdown)', 'System'),
        6008: ('Unexpected shutdown', 'System'),
    },
    'Sysmon': {
        1: ('Process created', 'Execution'),
        2: ('File creation time changed', 'Defence Evasion'),
        3: ('Network connection', 'Network'),
        4: ('Sysmon service state changed', 'Sensor'),
        6: ('Driver loaded', 'Persistence'),
        8: ('CreateRemoteThread', 'Injection'),
        10: ('Process accessed', 'Credential Access'),
        11: ('File created', 'File'),
        12: ('Registry key created/deleted', 'Registry'),
        13: ('Registry value set', 'Registry'),
        14: ('Registry key/value renamed', 'Registry'),
        16: ('Sysmon configuration changed', 'Sensor'),
        19: ('WMI event filter', 'Persistence'),
        20: ('WMI event consumer', 'Persistence'),
        21: ('WMI consumer bound to filter', 'Persistence'),
        22: ('DNS query', 'Network'),
        25: ('Process tampering', 'Injection'),
        26: ('File deleted', 'File'),
    },
    'PowerShell': {
        4104: ('PowerShell script block', 'Execution'),
    },
    'Defender': {
        1116: ('Malware detected', 'Antivirus'),
        1117: ('Malware action taken', 'Antivirus'),
        1118: ('Malware action failed (non-critical)', 'Antivirus'),
        1119: ('Malware action failed (critical)', 'Antivirus'),
        5001: ('Real-time protection disabled', 'Defence Evasion'),
        5007: ('Defender configuration changed', 'Defence Evasion'),
        5010: ('Malware scanning disabled', 'Defence Evasion'),
        5012: ('Virus scanning disabled', 'Defence Evasion'),
    },
    'TaskScheduler': {
        106: ('Scheduled task registered', 'Persistence'),
        140: ('Scheduled task updated', 'Persistence'),
        141: ('Scheduled task deleted', 'Persistence'),
    },
    'RDP-Session': {
        21: ('RDP session logon', 'Remote Access'),
        23: ('RDP session logoff', 'Remote Access'),
        24: ('RDP session disconnected', 'Remote Access'),
        25: ('RDP session reconnected', 'Remote Access'),
    },
    'RDP-Auth': {
        1149: ('RDP network authentication succeeded', 'Remote Access'),
    },
}

# Backwards-compatible flat view of the Security channel (used by v2.2 code / tests).
EVENTS = CATALOG['Security']
SUPPORTED = set(EVENTS)

# Useful events still NOT collected (shown as gaps in the Coverage page).
GAPS = {
    ('Security', 5140): ('Network share accessed', 'Object Access', 'Noisy; enable "Audit File Share" if needed'),
    ('Security', 4663): ('Object access attempt', 'Object Access', 'Needs SACLs on the files you care about'),
    ('Security', 5156): ('WFP connection allowed', 'Network', 'Very noisy; Sysmon 3 is used instead'),
    ('Sysmon', 7): ('Image (DLL) loaded', 'Execution', 'Very noisy; disabled in the bundled Sysmon config'),
    ('Sysmon', 17): ('Named pipe created', 'Lateral Movement', 'Disabled in the bundled Sysmon config'),
}

# --------------------------------------------------------------------------
# Level
# --------------------------------------------------------------------------
LEVELS = ['Audit Success', 'Audit Failure', 'Critical', 'Error', 'Warning', 'Information', 'Verbose']
_EVENT_TYPE = {1: 'Error', 2: 'Warning', 4: 'Information', 8: 'Audit Success', 16: 'Audit Failure'}
_SYSTEM_LEVEL = {0: 'Information', 1: 'Critical', 2: 'Error', 3: 'Warning', 4: 'Information', 5: 'Verbose'}
KW_AUDIT_SUCCESS = 0x0020000000000000
KW_AUDIT_FAILURE = 0x0010000000000000


def level_name(event_type, event_id=0):
    """Map the legacy Win32 EventType value to a readable level; fall back on the event ID."""
    try:
        name = _EVENT_TYPE.get(int(event_type))
    except (TypeError, ValueError):
        name = None
    if name:
        return name
    return 'Audit Failure' if int(event_id) == 4625 else 'Audit Success'


def level_from_system(level, keywords, event_id=0):
    """Level as Event Viewer shows it: audit keywords win over the numeric level."""
    try:
        kw = int(str(keywords or '0'), 16) if str(keywords or '').lower().startswith('0x') else int(keywords or 0)
    except ValueError:
        kw = 0
    if kw & KW_AUDIT_FAILURE:
        return 'Audit Failure'
    if kw & KW_AUDIT_SUCCESS:
        return 'Audit Success'
    try:
        return _SYSTEM_LEVEL.get(int(level), 'Information')
    except (TypeError, ValueError):
        return level_name(None, event_id)


def event_name(event_id, channel='Security'):
    return CATALOG.get(channel or 'Security', {}).get(int(event_id), ('Event %s' % event_id, 'Other'))[0]


def event_category(event_id, channel='Security'):
    return CATALOG.get(channel or 'Security', {}).get(int(event_id), ('', 'Other'))[1]


# --------------------------------------------------------------------------
# XML parsing (output of EvtRender(..., EvtRenderEventXml))
# --------------------------------------------------------------------------
_NS = '{http://schemas.microsoft.com/win/2004/08/events/event}'


def _local(tag):
    return tag.rsplit('}', 1)[-1]


def parse_xml(xml_text):
    """Return dict(channel, provider, event_id, record_id, time_utc, level, computer, data) or None."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    system = root.find(_NS + 'System')
    if system is None:
        return None

    def text(tag):
        el = system.find(_NS + tag)
        return (el.text or '').strip() if el is not None and el.text else ''

    provider = system.find(_NS + 'Provider')
    created = system.find(_NS + 'TimeCreated')
    channel_path = text('Channel')
    event_id = int(text('EventID') or 0)
    data = {}
    event_data = root.find(_NS + 'EventData')
    if event_data is not None:
        for i, d in enumerate(event_data):
            name = d.get('Name') or 'Data%d' % i
            data[name] = (d.text or '').strip()
    user_data = root.find(_NS + 'UserData')
    if user_data is not None:
        for wrapper in user_data:               # e.g. <LogFileCleared>, <EventXML>
            for child in wrapper:
                data[_local(child.tag)] = (child.text or '').strip()
    return {
        'channel': CHANNELS.get(channel_path, channel_path),
        'provider': provider.get('Name', '') if provider is not None else '',
        'event_id': event_id,
        'record_id': int(text('EventRecordID') or 0),
        'time_utc': to_utc_iso(created.get('SystemTime')) if created is not None and created.get('SystemTime') else to_utc_iso(None),
        'level': level_from_system(text('Level') or 0, text('Keywords'), event_id),
        'computer': text('Computer'),
        'data': data,
    }


# --------------------------------------------------------------------------
# Normalisation of named fields into common columns
# --------------------------------------------------------------------------
LOGON_TYPES = {
    '2': 'Interactive', '3': 'Network', '4': 'Batch', '5': 'Service', '7': 'Unlock',
    '8': 'NetworkCleartext', '9': 'NewCredentials', '10': 'RemoteInteractive (RDP)',
    '11': 'CachedInteractive',
}
FAILURE_REASONS = {
    '0xc0000064': 'user does not exist', '0xc000006a': 'wrong password', '0xc000006d': 'bad user name or password',
    '0xc000006f': 'outside allowed hours', '0xc0000070': 'workstation restriction', '0xc0000071': 'password expired',
    '0xc0000072': 'account disabled', '0xc0000193': 'account expired', '0xc0000224': 'must change password',
    '0xc0000234': 'account locked out', '0xc000015b': 'logon type not granted',
}
_LOOPBACK = {'', '-', '127.0.0.1', '::1', '0:0:0:0:0:0:0:1'}
COLUMNS = ('username', 'subject_user', 'source_ip', 'logon_type', 'logon_id', 'process', 'parent_process',
           'command_line', 'process_guid', 'parent_guid', 'target', 'dest_ip', 'dest_port', 'status', 'hash')
MAX_TEXT = 8000


def _clean(value):
    value = (value or '').strip()
    return '' if value in ('-', '(null)', 'NULL', '%%1793') else value


def _account(name, domain=''):
    name, domain = _clean(name), _clean(domain)
    return (domain + '\\' + name) if (name and domain) else name


def _ip(value):
    v = _clean(value)
    if v.startswith('::ffff:'):
        v = v[7:]
    return '' if v in _LOOPBACK else v


def _ltype(code):
    code = _clean(code)
    return ('%s - %s' % (code, LOGON_TYPES[code])) if code in LOGON_TYPES else code


def _task_command(task_xml):
    """Pull <Command> + <Arguments> out of a scheduled-task XML definition."""
    cmd = re.findall(r'<Command>(.*?)</Command>', task_xml or '', re.S)
    args = re.findall(r'<Arguments>(.*?)</Arguments>', task_xml or '', re.S)
    return ' '.join(x.strip() for x in cmd + args)


def normalize(channel, event_id, d):
    """Map a channel's named fields (dict d) to MiniSOC's common columns."""
    g = lambda *keys: next((_clean(d.get(k)) for k in keys if _clean(d.get(k))), '')
    out = dict.fromkeys(COLUMNS, '')
    eid = int(event_id)
    if channel == 'Security':
        out['subject_user'] = _account(d.get('SubjectUserName'), d.get('SubjectDomainName'))
        out['logon_id'] = g('TargetLogonId', 'SubjectLogonId')
        if eid in (4624, 4625, 4634, 4647, 4648, 4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740,
                   4768, 4769, 4771, 4776, 4798, 4799):
            out['username'] = _account(d.get('TargetUserName'), d.get('TargetDomainName'))
        if eid in (4624, 4625, 4648, 4768, 4769, 4771):
            out['source_ip'] = _ip(d.get('IpAddress'))
        if eid in (4624, 4625, 4634):
            out['logon_type'] = _ltype(d.get('LogonType'))
        if eid in (4624, 4625, 4648):
            out['process'] = g('ProcessName')
            out['target'] = g('TargetServerName', 'WorkstationName')
        if eid == 4625:
            status = (g('SubStatus') if g('SubStatus') not in ('', '0x0') else g('Status')).lower()
            out['status'] = ('%s (%s)' % (status, FAILURE_REASONS[status])) if status in FAILURE_REASONS else status
        if eid in (4648, 4672, 4720, 4722, 4723, 4724, 4725, 4726, 4738, 4688, 4697, 4698, 4699, 4702, 4719, 4728, 4729, 4732, 4733, 4756):
            out['logon_id'] = g('SubjectLogonId', 'TargetLogonId')
        if eid == 4672:
            out['username'] = out['subject_user']
            out['target'] = g('PrivilegeList')
        if eid == 4688:
            out['username'] = _account(d.get('TargetUserName'), d.get('TargetDomainName')) or out['subject_user']
            out['process'] = g('NewProcessName')
            out['parent_process'] = g('ParentProcessName')
            out['command_line'] = g('CommandLine')
        if eid in (4728, 4729, 4732, 4733, 4756):
            out['username'] = g('MemberName', 'MemberSid')
            out['target'] = _account(d.get('TargetUserName'), d.get('TargetDomainName'))   # the group
        if eid == 4697:
            out['target'] = g('ServiceName')
            out['command_line'] = g('ServiceFileName')
            out['username'] = g('ServiceAccount')
        if eid in (4698, 4699, 4702):
            out['target'] = g('TaskName')
            out['command_line'] = _task_command(d.get('TaskContent') or d.get('TaskContentNew'))
        if eid == 4719:
            out['target'] = g('SubcategoryGuid', 'CategoryId')
            out['status'] = g('AuditPolicyChanges')
        if eid == 4740:
            out['target'] = g('TargetDomainName')   # caller computer
        if eid == 4769:
            out['target'] = g('ServiceName')
        if eid in (4768, 4769, 4771, 4776):
            out['status'] = g('Status')
            if eid == 4776:
                out['target'] = g('Workstation')
        if eid in (1102, 1100):
            out['username'] = out['subject_user']
    elif channel == 'System':
        if eid == 7045:
            out['target'] = g('ServiceName')
            out['command_line'] = g('ImagePath')
            out['username'] = g('AccountName')
        elif eid == 7040:
            out['target'] = g('param1', 'Data0')
            out['status'] = '%s -> %s' % (g('param2', 'Data1'), g('param3', 'Data2'))
        elif eid == 104:
            out['username'] = _account(d.get('SubjectUserName'), d.get('SubjectDomainName'))
            out['target'] = g('Channel')
    elif channel == 'Sysmon':
        out['process'] = g('Image', 'SourceImage')
        out['process_guid'] = g('ProcessGuid', 'SourceProcessGuid')
        out['username'] = g('User', 'SourceUser')
        out['logon_id'] = g('LogonId')
        out['hash'] = g('Hashes', 'Hash')
        if eid == 1:
            out['command_line'] = g('CommandLine')
            out['parent_process'] = g('ParentImage')
            out['parent_guid'] = g('ParentProcessGuid')
        elif eid == 3:
            out['dest_ip'] = _ip(d.get('DestinationIp'))
            out['dest_port'] = g('DestinationPort')
            out['source_ip'] = _ip(d.get('SourceIp'))
            out['target'] = g('DestinationHostname') or out['dest_ip']
            out['status'] = 'inbound' if g('Initiated').lower() == 'false' else 'outbound'
        elif eid in (8, 10):
            out['target'] = g('TargetImage')
            out['status'] = g('GrantedAccess', 'StartFunction')
        elif eid in (2, 11, 23, 26):
            out['target'] = g('TargetFilename')
        elif eid in (12, 13, 14):
            out['target'] = g('TargetObject')
            out['command_line'] = g('Details', 'NewName')
            out['status'] = g('EventType')
        elif eid == 6:
            out['process'] = g('ImageLoaded')
            out['target'] = g('ImageLoaded')
            out['status'] = 'signed=%s %s' % (g('Signed'), g('SignatureStatus'))
        elif eid in (19, 20, 21):
            out['target'] = g('Name', 'Consumer')
            out['command_line'] = g('Query', 'Destination')
            out['status'] = g('Operation')
        elif eid == 22:
            out['target'] = g('QueryName')
            out['status'] = g('QueryStatus')
            out['dest_ip'] = ''
        elif eid == 25:
            out['target'] = g('Image')
            out['status'] = g('Type')
        elif eid in (4, 16):
            out['status'] = g('State', 'Configuration')
    elif channel == 'PowerShell':
        out['command_line'] = g('ScriptBlockText')
        out['target'] = g('Path')
        out['process_guid'] = g('ScriptBlockId')
    elif channel == 'Defender':
        out['target'] = g('Threat Name', 'New Value', 'Feature Name')
        out['process'] = g('Process Name')
        out['command_line'] = g('Path', 'Old Value')
        out['username'] = g('Detection User', 'User')
        out['status'] = g('Action Name', 'Severity Name')
    elif channel == 'TaskScheduler':
        out['target'] = g('TaskName')
        out['username'] = g('UserContext', 'UserName')
    elif channel == 'RDP-Session':
        out['username'] = g('User')
        out['source_ip'] = _ip(d.get('Address'))
        out['target'] = ('session ' + g('SessionID')) if g('SessionID') else ''
    elif channel == 'RDP-Auth':
        out['username'] = _account(d.get('Param1'), d.get('Param2'))
        out['source_ip'] = _ip(d.get('Param3'))
    for k in ('command_line', 'target'):
        if len(out[k]) > MAX_TEXT:
            out[k] = out[k][:MAX_TEXT] + ' …[truncated]'
    return out


def event_from_xml(xml_text):
    """Full MiniSOC event dict built from one rendered XML event (or None)."""
    p = parse_xml(xml_text)
    if not p:
        return None
    norm = normalize(p['channel'], p['event_id'], p['data'])
    e = {k: p[k] for k in ('channel', 'event_id', 'record_id', 'time_utc', 'level', 'computer')}
    e.update(norm)
    e['data_json'] = json.dumps(p['data'], ensure_ascii=False)
    e['raw'] = ''
    e['is_demo'] = 0
    return e


# --------------------------------------------------------------------------
# Legacy positional parser (v2.2 StringInserts). Kept for old rows / tests.
# --------------------------------------------------------------------------
FIELDS = {
    4624: dict(user=5, domain=6, ip=18, ltype=8),
    4625: dict(user=5, domain=6, ip=19, ltype=10),
    4634: dict(user=1, domain=2, ltype=4),
    4647: dict(user=1, domain=2),
    4648: dict(user=5, domain=6, ip=12),
    4672: dict(user=1, domain=2),
    4720: dict(user=0, domain=1),
    4722: dict(user=0, domain=1),
    4723: dict(user=0, domain=1),
    4724: dict(user=0, domain=1),
    4728: dict(user=0, alt_user=6, alt_domain=7),
    4732: dict(user=0, alt_user=6, alt_domain=7),
    1102: dict(user=1, domain=2),
}


def _legacy_guess(inserts):
    user = ip = ''
    for x in inserts:
        if '\\' in x and len(x) < 180:
            user = x
            break
    for x in inserts:
        if (x.count('.') == 3 or ':' in x) and x not in _LOOPBACK and len(x) < 80:
            ip = x
            break
    return user, ip


def parse_event(event_id, inserts):
    """Return {'username','source_ip','logon_type'} extracted from legacy StringInserts."""
    inserts = [str(x) for x in (inserts or [])]
    spec = FIELDS.get(int(event_id))

    def get(i):
        return _clean(inserts[i]) if isinstance(i, int) and i < len(inserts) else ''

    user = ip = ltype = ''
    if spec:
        name, domain = get(spec.get('user')), get(spec.get('domain'))
        if not name and 'alt_user' in spec:
            name, domain = get(spec['alt_user']), get(spec.get('alt_domain'))
        user = (domain + '\\' + name) if (name and domain) else name
        ip = get(spec.get('ip'))
        if ip in _LOOPBACK:
            ip = ''
        code = get(spec.get('ltype'))
        if code:
            ltype = _ltype(code)
    if not user and not spec:
        user, ip = _legacy_guess(inserts)
    elif not user:
        user = _legacy_guess(inserts)[0]
    return {'username': user, 'source_ip': ip, 'logon_type': ltype}


# --------------------------------------------------------------------------
# Time handling: everything stored as 'YYYY-MM-DDTHH:MM:SS+00:00' so that
# plain text ordering in SQLite == chronological ordering.
# --------------------------------------------------------------------------
# Only used for legacy naive datetimes. XML SystemTime is always UTC.
NAIVE_TIME_IS_LOCAL = True
_FRACTION = re.compile(r'(\.\d+)')


def to_dt(value):
    """Parse str/datetime into an aware UTC datetime (never raises)."""
    try:
        if isinstance(value, datetime):
            x = value
        else:
            s = str(value).strip().replace('Z', '+00:00')
            # SystemTime has 7 fraction digits; Python 3.10 only accepts exactly 3 or 6
            s = _FRACTION.sub(lambda m: '.' + m.group(1)[1:7].ljust(6, '0'), s, count=1)
            x = datetime.fromisoformat(s)
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)
    if x.tzinfo is None:
        x = x.astimezone() if NAIVE_TIME_IS_LOCAL else x.replace(tzinfo=timezone.utc)
    return x.astimezone(timezone.utc)


def to_utc_iso(value):
    if value is None:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    return to_dt(value).replace(microsecond=0).isoformat()


def format_time(value, local=False):
    """Human readable time for the UI."""
    if not value:
        return ''
    x = to_dt(value)
    if local:
        x = x.astimezone()
    return x.strftime('%Y-%m-%d %H:%M:%S')
