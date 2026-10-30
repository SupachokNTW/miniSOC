"""Parsers that turn uploaded log files into MiniSOC events.

Supported inputs
- Sangfor AF / NGAF security log reports exported as .xlsx or .csv (IPS, WAF, botnet, DoS ...)
- Generic tables: CSV / TSV / Excel with a header row (firewall, SIEM or Event Viewer exports)
- JSON array, JSON Lines, Elastic/Winlogbeat style JSON
- Windows Event XML (Event Viewer "Save as XML" or `wevtutil qe Security /f:xml`)
- Linux auth.log / secure / syslog
- Any other text log (one event per line, keyword based classification)

Every parser returns plain dictionaries in the same shape that database.insert_event() accepts.
Parsing is read-only: uploaded content is never executed, and decoded payloads are only shown as text.
"""
import base64
import csv
import io
import ipaddress
import json
import re
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

try:
    import config as _config
    MAX_EVENTS = _config.MAX_EVENTS_PER_IMPORT
    MAX_DECOMPRESSED = _config.MAX_DECOMPRESSED_BYTES
except ImportError:  # pragma: no cover
    MAX_EVENTS = 50000
    MAX_DECOMPRESSED = 80 * 1024 * 1024
MAX_EXTRA_TEXT = 4000

FORMAT_LABELS = {
    "auto": "Auto-detect",
    "xlsx": "Excel workbook (.xlsx)",
    "csv": "CSV / TSV table",
    "json": "JSON / JSON Lines",
    "winxml": "Windows Event XML",
    "syslog": "Linux auth.log / syslog",
    "access": "Web server access log (Apache / Nginx)",
    "text": "Plain text (one event per line)",
}

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_RANK = {name: i for i, name in enumerate(reversed(SEVERITIES))}  # Info=0 ... Critical=4

EMPTY_VALUES = {"", "-", "#", "n/a", "na", "null", "(null)", "none", "nil", "--"}


class ParseError(ValueError):
    """Raised for files that cannot be parsed; the message is shown to the user."""


# ---------------------------------------------------------------- small helpers

def clean(value):
    if value is None:
        return ""
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    text = str(value).strip()
    return "" if text.lower() in EMPTY_VALUES else text


def norm_key(name):
    return re.sub(r"[^a-z0-9]", "", str(name or "").lower())


def is_ip(value):
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10")]


def is_internal(value):
    """RFC 1918 / CGNAT / loopback / link-local / ULA. Documentation ranges count as external."""
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return any(ip.version == net.version and ip in net for net in INTERNAL_NETWORKS)


def truncate(text, limit=MAX_EXTRA_TEXT):
    text = str(text or "")
    return text if len(text) <= limit else text[:limit] + " …[truncated]"


def normalize_severity(value):
    text = clean(value).lower()
    if not text:
        return ""
    table = [
        (("critical", "crit", "fatal", "emerg", "emergency", "alert", "severe", "very high"), "Critical"),
        (("high", "error", "err", "major"), "High"),
        (("medium", "moderate", "warning", "warn", "audit failure", "middle"), "Medium"),
        (("low", "notice", "minor"), "Low"),
        (("info", "information", "informational", "debug", "verbose", "audit success", "trace"), "Info"),
    ]
    for keys, label in table:
        if text in keys:
            return label
    for keys, label in table:
        if any(text.startswith(k) for k in keys):
            return label
    if text.isdigit():  # syslog-style 0..7 or 1..5 scales are ambiguous; keep a conservative mapping
        n = int(text)
        return {0: "Critical", 1: "Critical", 2: "Critical", 3: "High", 4: "Medium", 5: "Low"}.get(n, "Info")
    return ""


def normalize_action(value):
    text = clean(value).lower()
    if not text:
        return ""
    if any(k in text for k in ("deny", "denied", "block", "drop", "reject", "reset", "prevent", "quarantin", "intercept")):
        return "Block"
    if any(k in text for k in ("allow", "accept", "permit", "pass", "detect", "monitor", "log only", "alert")):
        return "Allow"
    return clean(value)[:40]


def build_tz(option):
    """'local' -> None (use this computer's zone); 'UTC' or '+07:00' -> fixed offset."""
    option = (option or "local").strip()
    if option.lower() == "local":
        return None
    if option.upper() == "UTC":
        return timezone.utc
    m = re.fullmatch(r"([+-])(\d{1,2}):?(\d{2})", option)
    if not m:
        return None
    minutes = int(m.group(2)) * 60 + int(m.group(3))
    return timezone(timedelta(minutes=minutes if m.group(1) == "+" else -minutes))


class TimeParser:
    """Parses the many timestamp styles found in exports (incl. Thai Buddhist-era years)."""

    BASE_FORMATS = [
        "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M",
        "%Y-%m-%dT%H:%M:%S", "%d/%b/%Y:%H:%M:%S %z", "%d-%b-%Y %H:%M:%S", "%b %d %Y %H:%M:%S",
        "%a %b %d %H:%M:%S %Y", "%d.%m.%Y %H:%M:%S", "%Y%m%d%H%M%S", "%Y-%m-%d",
    ]
    DAY_FIRST = ["%d/%m/%Y %H:%M:%S", "%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M", "%d-%m-%Y %H:%M:%S", "%d/%m/%Y"]
    MONTH_FIRST = ["%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M", "%m-%d-%Y %H:%M:%S", "%m/%d/%Y"]

    def __init__(self, tzinfo=None, dayfirst=True):
        self.tzinfo = tzinfo
        self.dayfirst = dayfirst

    def learn(self, samples):
        for value in samples:
            m = re.match(r"\s*(\d{1,2})[/.-](\d{1,2})[/.-]\d{2,4}", str(value or ""))
            if not m:
                continue
            first, second = int(m.group(1)), int(m.group(2))
            if first > 12:
                self.dayfirst = True
                return
            if second > 12:
                self.dayfirst = False
                return

    def _finish(self, dt):
        if dt.year > 2400:  # Thai Buddhist Era (e.g. 2569 -> 2026)
            dt = dt.replace(year=dt.year - 543)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=self.tzinfo) if self.tzinfo else dt.astimezone()
        return dt.isoformat(timespec="seconds")

    def parse(self, value):
        if value is None or value == "":
            return None
        if isinstance(value, datetime):
            return self._finish(value)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            number = float(value)
            if number > 1e11:  # milliseconds
                number /= 1000.0
            if 1e8 < number < 4e9:
                return datetime.fromtimestamp(number, tz=timezone.utc).isoformat(timespec="seconds")
            return None
        text = clean(value)
        if not text:
            return None
        if re.fullmatch(r"\d{10}(\.\d+)?|\d{13}", text):
            return self.parse(float(text))
        iso = text.replace("Z", "+00:00")
        iso = re.sub(r"(\.\d{6})\d+", r"\1", iso)  # trim >6 fractional digits (Windows SystemTime)
        try:
            return self._finish(datetime.fromisoformat(iso))
        except ValueError:
            pass
        text = re.sub(r"\.\d+(?=\s|$|[+-]\d)", "", text)  # drop fractional seconds for strptime
        ordered = self.BASE_FORMATS + (self.DAY_FIRST + self.MONTH_FIRST if self.dayfirst else self.MONTH_FIRST + self.DAY_FIRST)
        for fmt in ordered:
            try:
                return self._finish(datetime.strptime(text, fmt))
            except ValueError:
                continue
        return None


# ---------------------------------------------------------------- classification

TYPE_PATTERNS = [
    (r"brute[\s_-]*force|password guess|dictionary attack|credential stuffing", "BruteForce", "High"),
    (r"malware|trojan|botnet|\bc2\b|\bcnc\b|command[\s-]+and[\s-]+control|coin\s?miner|\bminer\b|ransomware|backdoor|virus|worm", "MalwareTraffic", "Critical"),
    (r"\bweb\b|sql|xss|cross[\s-]site|injection|traversal|webshell|deserializ|\bwaf\b", "WebAttack", "High"),
    (r"vulnerab|exploit|overflow|\brce\b|remote code|cve-\d{4}", "ExploitAttempt", "High"),
    (r"port\s?scan|\bscan|probe|recon|sweep", "Scan", "Medium"),
    (r"\bdos\b|ddos|flood", "DoS", "High"),
    (r"failed password|authentication fail|logon fail|login fail|failed log[io]n|invalid password|bad password|an account failed to log on", "FailedLogin", "Medium"),
    (r"accepted (password|publickey|keyboard)|successfully logged on|login success|successful(ly)? log[io]n|logon success", "LoginSuccess", "Info"),
    (r"log (file )?(was )?cleared|audit log was cleared|security log cleared", "LogCleared", "High"),
    (r"scheduled task|autorun|persistence|new service|service was installed", "Persistence", "High"),
    (r"phish|spam|email|e-mail|mail protection", "EmailThreat", "Medium"),
    (r"url filter|website access|web filter|browsing|blocked site", "WebFiltering", "Low"),
]
NETWORK_TYPES = {"BruteForce", "MalwareTraffic", "WebAttack", "ExploitAttempt", "Scan", "DoS",
                 "EmailThreat", "WebFiltering", "IntrusionEvent", "FirewallEvent"}


def infer_type(*texts):
    for text in texts:
        low = str(text or "").lower()
        if not low:
            continue
        for pattern, etype, sev in TYPE_PATTERNS:
            if re.search(pattern, low):
                return etype, sev
    return None


WINDOWS_EVENTS = {
    "4624": ("LoginSuccess", "Info", "Successful logon"),
    "4625": ("FailedLogin", "Medium", "Failed logon"),
    "4634": ("Logoff", "Info", "Logoff"),
    "4648": ("ExplicitCredentialLogon", "Low", "Logon with explicit credentials"),
    "4672": ("PrivilegedLogon", "Low", "Special privileges assigned to new logon"),
    "4688": ("ProcessStart", "Info", "New process created"),
    "4697": ("ServiceInstalled", "High", "Service installed in the system (persistence review)"),
    "7045": ("ServiceInstalled", "High", "New service installed (persistence review)"),
    "4698": ("ScheduledTaskCreated", "High", "Scheduled task created"),
    "4720": ("AccountCreated", "Medium", "User account created"),
    "4722": ("AccountEnabled", "Low", "User account enabled"),
    "4724": ("PasswordReset", "Medium", "Password reset attempt"),
    "4728": ("GroupMemberAdded", "High", "Member added to security-enabled global group"),
    "4732": ("GroupMemberAdded", "High", "Member added to security-enabled local group"),
    "4756": ("GroupMemberAdded", "High", "Member added to security-enabled universal group"),
    "4740": ("AccountLockout", "Medium", "User account locked out"),
    "1102": ("LogCleared", "High", "Security audit log was cleared"),
    "104": ("LogCleared", "High", "Event log was cleared"),
    "4104": ("PowerShellScript", "Low", "PowerShell script block logged"),
}
PRIVILEGED_GROUPS = ("admin", "domain admins", "enterprise admins", "schema admins", "sudo", "wheel", "root", "backup operators")


# ---------------------------------------------------------------- payload helpers (IOC extraction)

URL_RE = re.compile(r"(?:https?|ftp|tftp)://[^\s'\"`<>|;(){}\\]+", re.I)
BARE_PATH_RE = re.compile(r"(?<![\w./])(\d{1,3}(?:\.\d{1,3}){3}(?::\d{2,5})?/[\w./-]*\.(?:sh|bin|elf|exe|dll|ps1|mips|mpsl|arm\d*|x86(?:_64)?|py|pl|jar|m)\b)", re.I)
DOWNLOAD_VERBS = re.compile(r"(wget|curl|tftp|ftpget|fetch|busybox|invoke-webrequest|iwr|downloadstring|downloadfile|bitsadmin|certutil|powershell)", re.I)
EXEC_EXT = re.compile(r"\.(sh|bin|elf|exe|dll|ps1|mips|mpsl|arm\d*|x86(_64)?|py|pl|jar|m)(\b|$)", re.I)
B64_RE = re.compile(r"(?:echo[,\s]+|base64[^A-Za-z0-9+/]{0,6}|-enc(?:odedcommand)?\s+)([A-Za-z0-9+/]{20,}={0,2})", re.I)
SCANNER_MARKERS = [
    "ctm360", "hackerview", "censys", "shodan", "qualys", "nessus", "tenable", "rapid7", "nuclei", "zgrab",
    "masscan", "nmap", "sqlmap", "nikto", "acunetix", "netsparker", "openvas", "expanse", "xpanse",
    "internet-measurement", "l9explore", "leakix", "wpscan", "dirbuster", "gobuster", "burp",
]


def _printable_ratio(text):
    if not text:
        return 0.0
    good = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return good / len(text)


def decode_hex_payload(packet):
    compact = re.sub(r"\s+", "", packet or "")
    if len(compact) < 16 or not re.fullmatch(r"[0-9A-Fa-f]+", compact):
        return ""
    try:
        text = bytes.fromhex(compact[: len(compact) // 2 * 2]).decode("utf-8", "replace")
    except ValueError:
        return ""
    return text if _printable_ratio(text) > 0.85 else ""


def decode_base64_blobs(text):
    found = []
    for blob in B64_RE.findall(text or ""):
        padded = blob + "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(padded, validate=False)
        except (ValueError, base64.binascii.Error):
            continue
        for enc in ("utf-8", "utf-16-le"):
            try:
                decoded = raw.decode(enc)
            except UnicodeDecodeError:
                continue
            if _printable_ratio(decoded) > 0.9 and len(decoded.strip()) >= 6:
                found.append(decoded.strip())
                break
    return found


def _request_part(packet):
    """Only the attacker's request is scanned for IOCs; responses contain the victim's own content."""
    text = packet or ""
    text = re.split(r"\n\s*RESPONSE:", text, maxsplit=1)[0]
    return text


def analyse_payload(url, packet, message, exclude_hosts=()):
    """Return (iocs, decoded, http_status, user_agent, scanner) from a request payload."""
    request = _request_part(packet)
    host_header = re.findall(r"^Host:\s*([^\s:]+)", request, re.I | re.M)
    url_host = re.match(r"^([\w.-]+)(?::\d+)?/", url or "")
    exclude = {h.lower() for h in list(exclude_hosts) + host_header + ([url_host.group(1)] if url_host else []) if h}

    hex_text = decode_hex_payload(packet)
    decoded = []
    if hex_text:
        decoded.append(hex_text)
    unquoted = urllib.parse.unquote(urllib.parse.unquote(" ".join([url or "", request])))
    decoded.extend(decode_base64_blobs(unquoted))
    corpus = "\n".join([unquoted] + decoded)

    iocs = []
    seen = set()

    def add(value, kind):
        value = value.strip().strip("`'\".,)")
        host_match = re.match(r"^(?:[a-z]+://)?([^/:\s]+)", value, re.I)
        host = host_match.group(1).lower() if host_match else ""
        if not host or "%" in host or host in exclude or "$" in host:
            return
        if is_ip(host) and is_internal(host):
            return
        key = value.lower()
        if key in seen:
            return
        seen.add(key)
        iocs.append({"type": kind, "value": value, "host": host})

    for m in URL_RE.finditer(corpus):
        before = corpus[max(0, m.start() - 80): m.start()]
        if DOWNLOAD_VERBS.search(before) or EXEC_EXT.search(m.group(0)):
            add(m.group(0), "url")
    for m in BARE_PATH_RE.finditer(corpus):
        add(m.group(1), "url")
    for item in list(iocs):
        if is_ip(item["host"]):
            add(item["host"], "ip")
        else:
            add(item["host"], "domain")

    status_match = re.search(r"RESPONSE:\s*\r?\n\s*HTTP/[\d.]+\s+(\d{3})", packet or "")
    ua_match = re.search(r"^User-Agent:\s*([^\r\n]+)", request, re.I | re.M)
    scanner_header = re.search(r"^X-Scanner:\s*([^\r\n]+)", request, re.I | re.M)
    user_agent = ua_match.group(1).strip() if ua_match else ""
    scanner = scanner_header.group(1).strip() if scanner_header else ""
    if not scanner:
        low = user_agent.lower()
        scanner = next((name for name in SCANNER_MARKERS if name in low), "")
    return iocs, [truncate(d, 1500) for d in decoded], (status_match.group(1) if status_match else ""), user_agent, scanner


# ---------------------------------------------------------------- field mapping for tables / JSON

FIELD_SYNONYMS = {
    "timestamp": ["time", "timestamp", "datetime", "dateandtime", "timecreated", "eventtime", "generatedtime",
                  "logtime", "receivedtime", "receivetime", "starttime", "createdat", "occurred", "eventdate",
                  "systemtime", "devicetime", "timegenerated", "timegeneratedutc"],
    "date": ["date", "logdate"],
    "src_ip": ["srcaddress", "srcip", "sourceip", "sourceaddress", "src", "clientip", "remoteip", "ipaddress",
               "sourcenetworkaddress", "attackerip", "attackip", "remoteaddr", "remoteaddress", "srcipaddress", "rhost"],
    "src_port": ["srcport", "sourceport", "sport", "clientport", "ipport"],
    "dst_ip": ["dstaddress", "dstip", "destinationip", "destinationaddress", "destip", "dst", "serverip", "targetip",
               "victimip", "dstipaddress"],
    "dst_port": ["dstport", "destinationport", "destport", "dport", "serverport", "targetport"],
    "action": ["action", "disposition", "verdict", "result", "actiontaken"],
    "severity": ["threatlevel", "severity", "level", "risklevel", "risk", "priority", "leveldisplayname", "loglevel",
                 "alertlevel", "severitylevel"],
    "category": ["attacktype", "category", "threattype", "eventcategory", "subtype", "taskcategory", "threatcategory",
                 "attackcategory"],
    "module": ["type", "logtype", "module", "eventsource"],
    "signature": ["vulnname", "signature", "rulename", "threatname", "attackname", "eventname", "alertname", "name",
                  "threat", "signaturename", "attack"],
    "event_code": ["eventid", "id", "eventcode", "vulnid", "ruleid", "signatureid", "sid", "winlogeventid", "threatid"],
    "username": ["username", "user", "account", "accountname", "targetusername", "srcuser", "login", "subjectusername"],
    "host": ["host", "hostname", "computer", "machinename", "device", "devicename", "computername", "agentname",
             "workstationname", "workstation"],
    "message": ["message", "description", "details", "msg", "eventdescription", "info", "summary", "detail"],
    "url": ["url", "urldirectory", "uri", "request", "requesturl", "path"],
    "protocol": ["protocol", "proto", "app", "application", "service"],
    "reference": ["reference", "cve", "cveid", "references"],
    "packet": ["datapacket", "payload", "packet", "rawdata", "httppayload"],
    "src_location": ["srciplocation", "srccountry", "sourcecountry", "srcgeo", "srclocation", "country", "geo"],
    "dst_location": ["dstiplocation", "dstcountry", "destinationcountry"],
    "src_zone": ["srczone", "sourcezone", "fromzone", "inzone", "srcintf", "srcinterface"],
    "dst_zone": ["dstzone", "destinationzone", "tozone", "outzone", "dstintf", "dstinterface"],
    "policy": ["matchedpolicy", "policy", "policyname", "rule", "policyid"],
    "recommendation": ["recommendation", "solution", "remediation", "suggestion"],
    "xff": ["xffip", "xforwardedfor", "xff"],
    "event_type": ["eventtype", "eventaction", "eventname", "activity", "operation"],
    "http_status": ["status", "statuscode", "httpstatus", "responsecode", "httpresponsestatuscode", "scstatus",
                    "httpstatuscode", "responsestatus", "elbstatuscode"],
    "bytes_out": ["bytes", "bytessent", "responselength", "responsebytes", "bodybytessent", "httpresponsebytes",
                  "httpresponsebodybytes", "scbytes", "sentbytes", "responsesize", "bytesout"],
    "http_method": ["method", "httpmethod", "requestmethod", "httprequestmethod", "csmethod", "verb"],
    "url_path": ["endpoint", "resourcepath", "requestpath", "urlpath", "uripath", "csuristem", "route"],
    "user_agent": ["useragent", "httpuseragent", "useragentoriginal", "csuseragent", "ua"],
    "country": ["countrycode", "geocountry", "sourcegeocountryisocode", "clientcountry", "geoipcountry", "countryname"],
    "token": ["apikey", "apikeyid", "clientid", "tokenid", "token", "appid", "accesskeyid"],
    "email": ["email", "useremail", "mail"],
    "process": ["process", "processname", "image", "newprocessname", "program", "appname"],
    "command": ["commandline", "command", "cmdline"],
}
SYNONYM_LOOKUP = {}
for _field, _names in FIELD_SYNONYMS.items():
    for _name in _names:
        SYNONYM_LOOKUP.setdefault(_name, _field)


def map_columns(headers):
    """Return {column_index: field} for a header row (first matching column wins)."""
    mapping, used = {}, set()
    for idx, header in enumerate(headers):
        field = SYNONYM_LOOKUP.get(norm_key(header))
        if field and field not in used:
            mapping[idx] = field
            used.add(field)
    if "message" not in used:  # Event Viewer CSV exports put the message in an unnamed last column
        for idx, header in enumerate(headers):
            if norm_key(header) == "" and idx not in mapping and idx > 0:
                mapping[idx] = "message"
                break
    return mapping


def header_score(row):
    return sum(1 for cell in row if SYNONYM_LOOKUP.get(norm_key(cell)))


class Context:
    def __init__(self, tz_option="local", keep_unmatched=True, default_host="imported-log"):
        self.tz_label = tz_option or "local"
        self.time = TimeParser(build_tz(tz_option))
        self.keep_unmatched = keep_unmatched
        self.default_host = default_host
        self.vendor = ""
        self.windows = False
        self.warnings = []
        self.skipped = 0
        self.total = 0
        self.no_time_rows = 0
        self.bad_time_rows = 0
        self.truncated = False

    def warn(self, message):
        if message not in self.warnings and len(self.warnings) < 25:
            self.warnings.append(message)


def _windows_message_fields(message):
    """Pull account / IP / workstation out of an English Windows event message (Event Viewer CSV/TXT)."""
    out = {}
    accounts = [a for a in re.findall(r"Account Name:\s*([^\r\n\t]+)", message or "") if clean(a)]
    if accounts:
        out["username"] = clean(accounts[-1])
    ip = re.search(r"Source Network Address:\s*([^\s]+)", message or "")
    if ip and clean(ip.group(1)):
        out["src_ip"] = clean(ip.group(1))
    ws = re.search(r"Workstation Name:\s*([^\r\n\t]+)", message or "")
    if ws and clean(ws.group(1)):
        out["workstation"] = clean(ws.group(1))
    return out


APP_ACTIONS = [
    (r"login[_.\s-]?(fail|failure|failed|denied|error)|authentication[_.\s-]?fail|sign[_-]?in[_.\s-]?fail|invalid[_.\s-]?(password|credentials)|bad[_.\s-]?password|consoleloginfailure", "FailedLogin", "Medium"),
    (r"(login|logon|sign[_-]?in|authentication)[_.\s-]?(success|succeeded|ok)$|^(user[_.])?(login|logon|signin)$", "LoginSuccess", "Info"),
    (r"mfa[_.\s-]?(disable|disabled|removed|reset|delete)|2fa[_.\s-]?(disable|off)|deactivatemfadevice", "MFADisabled", "Medium"),
    (r"password[_.\s-]?(change|changed|reset|update)", "PasswordChange", "Low"),
    (r"email[_.\s-]?(change|changed|update)", "EmailChange", "Low"),
    (r"(role|permission|privilege|grant|scope|group)[_.\s-]?(change|changed|update|updated|grant|granted|assign|assigned|add|added|elevat)|make[_.\s-]?admin|add[_.\s-]?admin", "PrivilegeChange", "Medium"),
    (r"(user|account)[_.\s-]?(create|created|signup|register|registered)|^signup$|^register$", "AccountCreated", "Low"),
    (r"^admin[_.]|admin[_.\s-]?action|config[_.\s-]?(change|update)|settings?[_.\s-]?update", "AdminAction", "Low"),
    (r"^api[_.\s-]?(request|call)$|^request$|^http[_.]request$", "ApiRequest", "Info"),
    (r"^(transaction|payment|transfer|withdraw|order)([_.\s-]|$)", "Transaction", "Info"),
    (r"(export|bulk[_.\s-]?download)", "DataExport", "Low"),
    (r"^(logout|signout|sign[_-]out)$", "Logout", "Info"),
]

WEB_ATTACK_PATTERNS = [
    ("sqli", re.compile(r"(\bunion\b.{0,20}\bselect\b|'\s*or\s*'?1'?\s*=\s*'?1|\bor\s+1=1|sleep\(\d+\)|benchmark\(|information_schema|' --|\bxp_cmdshell\b)", re.I)),
    ("xss", re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=|<svg[^>]*on\w+=|alert\()", re.I)),
    ("traversal", re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|win\.ini|boot\.ini)", re.I)),
    ("cmdi", re.compile(r"(;\s*(wget|curl|nc|bash|sh)\b|\|\s*(sh|bash)\b|\$\(|`[^`]+`|/bin/(sh|bash)|cmd\.exe|powershell)", re.I)),
    ("lfi_rfi", re.compile(r"(php://|file://|expect://|data://text|=https?://[^&]+\.(txt|php))", re.I)),
    ("sensitive_file", re.compile(r"/(\.env|\.git/|wp-config\.php|\.aws/credentials|id_rsa|\.htpasswd|phpinfo\.php)", re.I)),
    ("log4shell", re.compile(r"\$\{jndi:", re.I)),
]
ATTACK_TOOLS = ("sqlmap", "nikto", "nmap", "masscan", "nuclei", "zgrab", "gobuster", "dirbuster", "wpscan",
                "acunetix", "netsparker", "hydra", "wfuzz", "ffuf", "feroxbuster", "libredtail")


def map_app_action(*values):
    for value in values:
        text = clean(value).lower()
        if not text:
            continue
        for pattern, etype, sev in APP_ACTIONS:
            if re.search(pattern, text):
                return etype, sev
    return None


def detect_web_attack(path, user_agent=""):
    """Return the name of the first attack pattern found in a request path / user agent."""
    if path:
        unquoted = urllib.parse.unquote_plus(urllib.parse.unquote(str(path)))
        for name, pattern in WEB_ATTACK_PATTERNS:
            if pattern.search(unquoted):
                return name
    ua = (user_agent or "").lower()
    tool = next((t for t in ATTACK_TOOLS if t in ua), None)
    return f"tool:{tool}" if tool else ""


def _to_int(value):
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return None


def make_event(fields, raw, ctx):
    """Build a MiniSOC event from mapped fields. Returns None when the record must be skipped."""
    f = {k: clean(v) if not isinstance(v, datetime) else v for k, v in fields.items()}
    time_value = fields.get("timestamp")
    if f.get("date") and isinstance(time_value, str) and re.fullmatch(r"\d{1,2}:\d{2}(:\d{2})?(\.\d+)?", time_value.strip()):
        time_value = f"{f['date']} {time_value.strip()}"
    elif not time_value and f.get("date"):
        time_value = fields.get("date")
    timestamp = ctx.time.parse(time_value) if time_value not in (None, "") else None
    if timestamp is None:
        if time_value in (None, ""):
            ctx.no_time_rows += 1
            timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        else:
            ctx.bad_time_rows += 1
            return None

    message = f.get("message", "")
    code = f.get("event_code", "")
    if not f.get("username") and f.get("email"):
        f["username"] = f["email"]
    src, dst = f.get("src_ip", ""), f.get("dst_ip", "")
    if ctx.windows and message and (not src or not f.get("username")):
        extra_fields = _windows_message_fields(message)
        src = src or extra_fields.get("src_ip", "")
        f.setdefault("username", extra_fields.get("username", ""))
        if not f.get("username"):
            f["username"] = extra_fields.get("username", "")
    src = src if is_ip(src) else src  # keep non-IP values (hostnames) as-is
    severity = normalize_severity(f.get("severity"))
    action = normalize_action(f.get("action"))
    category = f.get("category") or f.get("module")
    signature = f.get("signature", "")

    etype, default_sev, win_desc = "", "", ""
    raw_action = f.get("action", "") if not action or action not in ("Allow", "Block") else ""
    mapped = map_app_action(f.get("event_type"), raw_action)
    if mapped:
        etype, default_sev = mapped
        if raw_action:
            action = ""
    if not etype and f.get("event_type"):
        etype = re.sub(r"[^A-Za-z0-9_-]", "", f["event_type"].title().replace(" ", ""))[:40]
    if not etype and code in WINDOWS_EVENTS and (ctx.windows or (len(code) == 4 and not dst)):
        etype, default_sev, win_desc = WINDOWS_EVENTS[code]
    if not etype:
        guessed = infer_type(category, signature, f.get("module"))
        if not guessed and not (src and dst):
            guessed = infer_type(message)
        if guessed:
            etype, default_sev = guessed
    if not etype:
        if src and dst:
            etype, default_sev = ("IntrusionEvent" if signature or category else "FirewallEvent"), "Low"
        else:
            if not ctx.keep_unmatched:
                ctx.skipped += 1
                return None
            etype, default_sev = "LogEntry", "Info"
    http_status = _to_int(f.get("http_status"))
    bytes_out = _to_int(f.get("bytes_out"))
    url_path = f.get("url_path", "")
    if not url_path and f.get("url") and not (src and dst):
        url_path = re.sub(r"^[a-z]+://[^/]+", "", f["url"], flags=re.I)
    http_method = f.get("http_method", "").upper()[:10]
    if http_status and etype in ("LogEntry", ""):
        etype, default_sev = "ApiRequest" if ("api" in url_path.lower() or f.get("token")) else "WebRequest", "Info"
        if http_status == 401:
            etype, default_sev = "FailedLogin", "Medium"
    attack = detect_web_attack(url_path, f.get("user_agent", "")) if etype in ("WebRequest", "ApiRequest", "LogEntry") else ""
    if attack:
        etype, default_sev = "WebAttack", "High" if attack in ("log4shell", "cmdi") else "Medium"
        if not severity or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK.get(default_sev, 0):
            severity = default_sev
    severity = severity or default_sev or "Info"

    if src and dst and is_internal(dst) and not is_internal(src):
        direction = "inbound"
    elif src and dst and is_internal(src) and not is_internal(dst):
        direction = "outbound"
    elif src and dst and is_internal(src) and is_internal(dst):
        direction = "internal"
    elif src and dst:
        direction = "external"
    else:
        direction = ""
    if direction == "inbound":
        host = dst
    elif direction == "outbound":
        host = src
    else:
        host = f.get("host") or dst or ctx.default_host

    extra = {}
    for key, value in raw.items():
        value = clean(value) if not isinstance(value, datetime) else value.isoformat()
        if value and key not in ("", None):
            extra[str(key).strip()] = truncate(value, 1000 if norm_key(key) not in ("datapacket", "payload", "packet") else MAX_EXTRA_TEXT)
    if direction:
        extra["_direction"] = direction
    for key in ("src_location", "dst_location", "src_zone", "dst_zone", "policy", "protocol", "url", "reference", "src_port", "module", "category"):
        if f.get(key):
            extra["_" + key] = f[key][:500]
    attempts = re.search(r"Attempts:\s*(\d+)", message)
    if attempts:
        extra["_attempts"] = int(attempts.group(1))
    duration = re.search(r"Duration:\s*(\d+)\s*sec", message)
    if duration:
        extra["_duration_s"] = int(duration.group(1))
    started = re.search(r"Attack started:\s*([\d-]+ [\d:]+)", message)
    if started:
        extra["_attack_started"] = ctx.time.parse(started.group(1)) or started.group(1)
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", " ".join([signature, f.get("reference", ""), message]), re.I)))
    if cves:
        extra["_cves"] = [c.upper() for c in cves]
    if f.get("packet") or f.get("url"):
        iocs, decoded, status, ua, scanner = analyse_payload(f.get("url", ""), fields.get("packet") or "", message, (src, dst))
        if iocs:
            extra["_iocs"] = iocs
        if decoded:
            extra["_decoded"] = decoded
        if status:
            extra["_http_status"] = status
        if ua:
            extra["_user_agent"] = ua[:300]
        if scanner:
            extra["_scanner"] = scanner[:120]
    if f.get("command"):
        extra["_command"] = f["command"][:1500]
    if attack:
        extra["_attack_pattern"] = attack
    if f.get("user_agent"):
        extra["_user_agent"] = f["user_agent"][:300]
    if f.get("token"):
        extra["_token"] = f["token"][:120]
    if f.get("email"):
        extra["_email"] = f["email"][:200]

    if (http_status or url_path) and not (src and dst):
        parts = [f"{http_method or 'REQ'} {truncate(url_path or '/', 200)} → {http_status or '-'}"]
        if bytes_out:
            parts.append(f"{bytes_out:,} B")
        if f.get("username"):
            parts.append(f"User={f['username']}")
        if attack:
            parts.append(f"Pattern={attack}")
        if message:
            parts.append(truncate(re.sub(r"\s+", " ", message), 200))
        details = " | ".join(parts)
    elif src or dst:
        parts = [signature or category or etype]
        flow = f"{src or '?'}{':' + f['src_port'] if f.get('src_port') else ''} → {dst or '?'}{':' + f['dst_port'] if f.get('dst_port') else ''}"
        parts.append(flow)
        if action:
            parts.append(f"Action={action}")
        if f.get("url"):
            parts.append(truncate(f["url"], 160))
        if "_attempts" in extra:
            parts.append(f"Attempts={extra['_attempts']}")
        details = " | ".join(parts)
    else:
        parts = []
        if win_desc:
            parts.append(f"Windows Event ID {code}: {win_desc}")
        if message:
            parts.append(truncate(re.sub(r"\s+", " ", message), 400))
        elif signature:
            parts.append(signature)
        if f.get("username"):
            parts.append(f"User={f['username']}")
        if f.get("command"):
            parts.append(f"Command={truncate(f['command'], 200)}")
        details = " | ".join(parts) or "Imported log record"

    return {
        "timestamp": timestamp,
        "event_type": etype,
        "severity": severity,
        "host": (host or ctx.default_host)[:200],
        "username": f.get("username", "")[:200],
        "source_ip": src[:100],
        "dest_ip": dst[:100],
        "dest_port": f.get("dst_port", "")[:10],
        "action": action,
        "signature": (signature or category)[:300],
        "event_code": code[:40],
        "details": details[:1200],
        "extra": extra,
        "dataset": _dataset(etype, ctx, src and dst, http_status or url_path),
        "country": (f.get("country") or f.get("src_location") or "")[:80],
        "http_status": http_status,
        "bytes_out": bytes_out,
        "http_method": http_method,
        "url_path": url_path[:500],
    }


AUTH_TYPES = {"FailedLogin", "LoginSuccess", "MFADisabled", "PasswordChange", "EmailChange", "Logout", "InvalidUser"}
IAM_TYPES = {"PrivilegeChange", "AccountCreated", "GroupMemberAdded", "AdminAction", "AccountEnabled", "PasswordReset", "AccountLockout"}


def _dataset(etype, ctx, network, web):
    if ctx.vendor.startswith("AWS"):
        return "cloud"
    if etype in AUTH_TYPES:
        return "auth"
    if etype in IAM_TYPES:
        return "iam"
    if etype in ("ApiRequest", "Transaction", "DataExport"):
        return "api"
    if web or etype in ("WebRequest", "WebAttack"):
        return "web"
    if network:
        return "network"
    if ctx.windows:
        return "windows"
    if ctx.vendor == "Linux syslog":
        return "linux"
    return "app"


# ---------------------------------------------------------------- table parsers (CSV / XLSX)

def _detect_vendor(headers, meta_rows):
    keys = {norm_key(h) for h in headers}
    title = " ".join(str(c) for row in meta_rows for c in row if c).lower()
    if "sangforsecuritywiki" in keys or "sangfor" in title or {"srcaddress", "dstaddress", "threatlevel", "attacktype"} <= keys:
        return "Sangfor AF"
    if {"taskcategory", "eventid"} <= keys or {"leveldisplayname", "machinename"} <= keys:
        return "Windows Event Export"
    return ""


def _parse_table(sheet_rows, ctx, sheet_name=""):
    rows = [list(r) for r in sheet_rows]
    header_idx, best = None, 0
    for idx, row in enumerate(rows[:60]):
        score = header_score(row)
        if score > best and score >= 2:
            header_idx, best = idx, score
            if score >= 5:
                break
    if header_idx is None:
        return [], {}
    headers = [str(h).strip() if h is not None else "" for h in rows[header_idx]]
    meta_rows = rows[:header_idx]
    meta = {}
    for row in meta_rows:
        cells = [c for c in row if clean(c)]
        if not cells:
            continue
        first = str(cells[0]).strip()
        if len(cells) >= 2 and first.endswith(":"):
            meta[first.rstrip(": ").strip()] = str(cells[1]).strip()
        elif "title" not in meta and len(cells) == 1:
            meta["title"] = first[:300]
    vendor = _detect_vendor(headers, meta_rows)
    if vendor:
        ctx.vendor = ctx.vendor or vendor
    if vendor == "Windows Event Export":
        ctx.windows = True
    mapping = map_columns(headers)
    if "timestamp" in mapping.values():
        ts_idx = next(i for i, f in mapping.items() if f == "timestamp")
        ctx.time.learn(r[ts_idx] for r in rows[header_idx + 1: header_idx + 200] if len(r) > ts_idx)
    events = []
    for row in rows[header_idx + 1:]:
        if not any(clean(c) for c in row):
            continue
        if ctx.total >= MAX_EVENTS:
            ctx.truncated = True
            break
        ctx.total += 1
        raw = {headers[i] if i < len(headers) else f"col{i}": row[i] for i in range(len(row))}
        fields = {field: row[idx] for idx, field in mapping.items() if idx < len(row)}
        event = make_event(fields, raw, ctx)
        if event:
            events.append(event)
    if sheet_name:
        meta["sheet"] = sheet_name
    return events, meta


def _read_xlsx(data):
    try:
        import openpyxl
    except ImportError as exc:
        raise ParseError("Reading .xlsx needs the openpyxl package. Run: pip install openpyxl (run.bat installs it).") from exc
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
        except Exception as exc:  # zip/xml errors from damaged files
            raise ParseError(f"Could not open the Excel workbook: {exc}") from exc
        sheets = [(ws.title, list(ws.iter_rows(values_only=True))) for ws in wb.worksheets]
        wb.close()
    return sheets


def _read_csv(text):
    sample = text[:20000]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        delimiter = dialect.delimiter
    except csv.Error:
        delimiter = "\t" if sample.count("\t") > sample.count(",") else ","
    csv.field_size_limit(min(2 ** 31 - 1, 50 * 1024 * 1024))
    return list(csv.reader(io.StringIO(text), delimiter=delimiter))


# ---------------------------------------------------------------- JSON

def _flatten(obj, prefix="", out=None):
    out = {} if out is None else out
    if isinstance(obj, dict):
        for key, value in obj.items():
            _flatten(value, f"{prefix}.{key}" if prefix else str(key), out)
    elif isinstance(obj, list) and obj and all(not isinstance(v, (dict, list)) for v in obj):
        out[prefix] = ", ".join(str(v) for v in obj)
    elif isinstance(obj, list):
        out[prefix] = json.dumps(obj, ensure_ascii=False)[:2000]
    else:
        out[prefix] = obj
    return out


def _json_records(text):
    stripped = text.strip()
    try:
        doc = json.loads(stripped)
    except ValueError:
        doc = None
    if doc is None:
        records = []
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except ValueError:
                records.append({"message": line})
                continue
            records.append(item if isinstance(item, dict) else {"message": str(item)})
        return records
    if isinstance(doc, list):
        return [d if isinstance(d, dict) else {"message": str(d)} for d in doc]
    if isinstance(doc, dict):
        hits = doc.get("hits", {}).get("hits") if isinstance(doc.get("hits"), dict) else None
        if isinstance(hits, list):
            return [h.get("_source", h) for h in hits if isinstance(h, dict)]
        for key in ("Records", "events", "records", "data", "logs", "items", "results", "Events"):
            if isinstance(doc.get(key), list):
                return [d for d in doc[key] if isinstance(d, dict)]
        return [doc]
    raise ParseError("JSON content is not an object or array of objects.")


CLOUDTRAIL_MAP = {
    "StopLogging": ("LogCleared", "High"), "DeleteTrail": ("LogCleared", "High"), "UpdateTrail": ("AdminAction", "Medium"),
    "PutEventSelectors": ("AdminAction", "Medium"), "DeleteFlowLogs": ("LogCleared", "High"),
    "CreateUser": ("AccountCreated", "Low"), "CreateLoginProfile": ("AccountCreated", "Low"),
    "AttachUserPolicy": ("PrivilegeChange", "Medium"), "AttachRolePolicy": ("PrivilegeChange", "Medium"),
    "PutUserPolicy": ("PrivilegeChange", "Medium"), "PutRolePolicy": ("PrivilegeChange", "Medium"),
    "AddUserToGroup": ("PrivilegeChange", "Medium"), "CreateAccessKey": ("PrivilegeChange", "Medium"),
    "UpdateAssumeRolePolicy": ("PrivilegeChange", "Medium"), "DeactivateMFADevice": ("MFADisabled", "Medium"),
    "DeleteVirtualMFADevice": ("MFADisabled", "Medium"), "PutBucketPolicy": ("AdminAction", "Medium"),
    "PutBucketAcl": ("AdminAction", "Medium"), "AuthorizeSecurityGroupIngress": ("AdminAction", "Medium"),
}


def _cloudtrail_event(rec, ctx):
    name = str(rec.get("eventName") or "")
    identity = rec.get("userIdentity") or {}
    user = identity.get("userName") or (identity.get("arn") or "").split("/")[-1] or identity.get("type") or ""
    if name == "ConsoleLogin":
        outcome = ((rec.get("responseElements") or {}).get("ConsoleLogin") or "").lower()
        etype, sev = ("LoginSuccess", "Info") if outcome == "success" else ("FailedLogin", "Medium")
    elif rec.get("errorCode") in ("AccessDenied", "UnauthorizedOperation", "Client.UnauthorizedOperation"):
        etype, sev = "AccessDenied", "Low"
    else:
        etype, sev = CLOUDTRAIL_MAP.get(name, ("CloudApiCall", "Info"))
    params = json.dumps(rec.get("requestParameters") or {}, ensure_ascii=False)[:600]
    if etype == "PrivilegeChange" and re.search(r"AdministratorAccess|\*:\*|iam:\*", params):
        sev = "High"
    ts = ctx.time.parse(rec.get("eventTime"))
    if not ts:
        ctx.bad_time_rows += 1
        return None
    src = clean(rec.get("sourceIPAddress"))
    details = f"AWS {rec.get('eventSource', '')} {name} by {user} from {src or '?'}"
    if rec.get("errorCode"):
        details += f" | error={rec.get('errorCode')}"
    if params not in ("{}", "null"):
        details += f" | {params[:300]}"
    host = f"aws:{identity.get('accountId')}" if identity.get("accountId") else (rec.get("awsRegion") or "aws")
    return {"timestamp": ts, "event_type": etype, "severity": sev, "host": host,
            "username": user[:200], "source_ip": src if is_ip(src) else "", "dest_ip": "", "dest_port": "",
            "action": "", "signature": f"{rec.get('eventSource', '')}:{name}"[:300], "event_code": name[:40],
            "details": details[:1200], "dataset": "cloud", "country": "", "http_status": None, "bytes_out": None,
            "http_method": "", "url_path": "",
            "extra": {"_user_agent": str(rec.get("userAgent") or "")[:300], "_account": identity.get("accountId"),
                      "_identity_type": identity.get("type"), "_mfa": (rec.get("additionalEventData") or {}).get("MFAUsed")}}


def _parse_json(text, ctx):
    events = []
    records = _json_records(text)
    if records and isinstance(records[0], dict) and "eventName" in records[0] and "eventSource" in records[0]:
        ctx.vendor = "AWS CloudTrail"
        for rec in records[:MAX_EVENTS]:
            ctx.total += 1
            event = _cloudtrail_event(rec, ctx)
            if event:
                events.append(event)
        ctx.truncated = len(records) > MAX_EVENTS
        return events, {}
    for record in records:
        if ctx.total >= MAX_EVENTS:
            ctx.truncated = True
            break
        ctx.total += 1
        flat = _flatten(record)
        if any(k.startswith("winlog") for k in flat) or "EventID" in flat or "Channel" in flat:
            ctx.windows = True
        fields = {}
        for key, value in flat.items():  # full dotted key first
            field = SYNONYM_LOOKUP.get(norm_key(key))
            if field and field not in fields:
                fields[field] = value
        for key, value in flat.items():  # then the last path segment (e.g. winlog.event_data.IpAddress)
            field = SYNONYM_LOOKUP.get(norm_key(key.split(".")[-1]))
            if field and field not in fields:
                fields[field] = value
        event = make_event(fields, flat, ctx)
        if event:
            events.append(event)
    if ctx.windows:
        ctx.vendor = ctx.vendor or "Windows (JSON)"
    return events, {}


# ---------------------------------------------------------------- Windows Event XML

def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _child(elem, name):
    for c in list(elem):
        if _local(c.tag) == name:
            return c
    return None


def _parse_winxml(text, ctx):
    if re.search(r"<!DOCTYPE|<!ENTITY", text, re.I):
        raise ParseError("XML files with DOCTYPE/ENTITY declarations are not accepted.")
    body = re.sub(r"^\s*<\?xml[^>]*\?>", "", text.strip())
    if not re.match(r"\s*<Events[\s>]", body):
        body = f"<Events>{body}</Events>"
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise ParseError(f"Invalid Windows Event XML: {exc}") from exc
    ctx.windows = True
    ctx.vendor = "Windows Event XML"
    events = []
    for ev in root.iter():
        if _local(ev.tag) != "Event":
            continue
        if ctx.total >= MAX_EVENTS:
            ctx.truncated = True
            break
        ctx.total += 1
        system = _child(ev, "System")
        if system is None:
            ctx.skipped += 1
            continue
        get = lambda name: _child(system, name)
        code = (get("EventID").text or "").strip() if get("EventID") is not None else ""
        time_el = get("TimeCreated")
        timestamp = time_el.get("SystemTime") if time_el is not None else ""
        computer = (get("Computer").text or "").strip() if get("Computer") is not None else ""
        channel = (get("Channel").text or "").strip() if get("Channel") is not None else ""
        record_id = (get("EventRecordID").text or "").strip() if get("EventRecordID") is not None else ""
        provider_el = get("Provider")
        provider = provider_el.get("Name", "") if provider_el is not None else ""
        data = {}
        for section in ("EventData", "UserData"):
            sec = _child(ev, section)
            if sec is None:
                continue
            for el in sec.iter():
                if el is sec or list(el):
                    continue
                key = el.get("Name") or _local(el.tag)
                if el.text and el.text.strip():
                    data[key] = el.text.strip()
        rendering = _child(ev, "RenderingInfo")
        message = ""
        if rendering is not None and _child(rendering, "Message") is not None:
            message = _child(rendering, "Message").text or ""

        if code == "1" and "sysmon" in provider.lower():
            etype, sev, desc = "ProcessStart", "Info", "Sysmon process creation"
        else:
            etype, sev, desc = WINDOWS_EVENTS.get(code, ("WindowsEvent", "Info", f"{channel or 'Windows'} event {code}"))
        username = clean(data.get("TargetUserName")) or clean(data.get("SubjectUserName")) or clean(data.get("User"))
        src_ip = clean(data.get("IpAddress"))
        parts = [f"Windows Event ID {code}: {desc}"]
        if code in ("4624", "4625"):
            for key, label in (("TargetUserName", "TargetUser"), ("IpAddress", "IpAddress"), ("WorkstationName", "Workstation"),
                               ("LogonType", "LogonType"), ("Status", "Status"), ("SubStatus", "SubStatus")):
                if clean(data.get(key)):
                    parts.append(f"{label}={clean(data.get(key))}")
        elif code in ("4728", "4732", "4756"):
            group = clean(data.get("TargetUserName"))
            member = clean(data.get("MemberName")) or clean(data.get("MemberSid"))
            username = member or username
            parts.append(f"Group={group} Member={member} By={clean(data.get('SubjectUserName'))}")
            if not any(g in group.lower() for g in PRIVILEGED_GROUPS):
                sev = "Medium"
        elif code == "4720":
            parts.append(f"NewAccount={clean(data.get('TargetUserName'))} CreatedBy={clean(data.get('SubjectUserName'))}")
        elif code in ("4698",):
            parts.append(f"TaskName={clean(data.get('TaskName'))} By={clean(data.get('SubjectUserName'))}")
        elif code in ("7045", "4697"):
            parts.append(f"Service={clean(data.get('ServiceName'))} Image={clean(data.get('ImagePath') or data.get('ServiceFileName'))}")
        elif code in ("4688",) or etype == "ProcessStart":
            parts.append(f"Process={clean(data.get('NewProcessName') or data.get('Image'))}")
            if clean(data.get("CommandLine")):
                parts.append(f"CommandLine={truncate(clean(data.get('CommandLine')), 300)}")
        elif code == "4104":
            parts.append(f"Script={truncate(clean(data.get('ScriptBlockText')), 300)}")
        elif code == "1102":
            parts.append(f"ClearedBy={clean(data.get('SubjectUserName'))}")
        elif message:
            parts.append(truncate(re.sub(r"\s+", " ", message), 300))
        ts = ctx.time.parse(timestamp)
        if ts is None:
            ctx.bad_time_rows += 1
            continue
        extra = {k: truncate(v, 1500) for k, v in data.items()}
        extra.update({"_channel": channel, "_provider": provider, "_record_id": record_id})
        if clean(data.get("CommandLine")):
            extra["_command"] = clean(data.get("CommandLine"))[:1500]
        events.append({
            "timestamp": ts, "event_type": etype, "severity": sev, "host": computer or ctx.default_host,
            "username": username, "source_ip": src_ip, "dest_ip": "", "dest_port": "", "action": "",
            "signature": desc, "event_code": code, "details": " | ".join(parts)[:1200], "extra": extra,
        })
    return events, {}


# ---------------------------------------------------------------- Linux auth.log / syslog

SYSLOG_RE = re.compile(
    r"^(?:<\d+>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
SSH_FAILED = re.compile(r"Failed (?:password|publickey|keyboard-interactive/pam|none) for (?:invalid user )?(?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)(?: port (?P<port>\d+))?")
SSH_ACCEPTED = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)(?: port (?P<port>\d+))?")
SSH_INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)")
SSH_MAXAUTH = re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)")
PAM_FAIL = re.compile(r"authentication failure;.*?(?:rhost=(?P<ip>\S*))?\s+user=(?P<user>\S+)")
SUDO_CMD = re.compile(r"^\s*(?P<user>\S+) : .*?COMMAND=(?P<cmd>.*)$")
USERADD = re.compile(r"new user: name=(?P<user>[^,\s]+)")
GROUPADD = re.compile(r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")


def _syslog_time(ts_text, ctx, year_hint):
    if re.match(r"\d{4}-", ts_text):
        return ctx.time.parse(ts_text)
    try:
        dt = datetime.strptime(f"{year_hint} {re.sub(r'\s+', ' ', ts_text)}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    return ctx.time._finish(dt)


def _parse_syslog(text, ctx):
    events = []
    now = datetime.now()
    ctx.vendor = "Linux syslog"
    for line in text.splitlines():
        line = line.rstrip()
        if not line.strip():
            continue
        if ctx.total >= MAX_EVENTS:
            ctx.truncated = True
            break
        ctx.total += 1
        m = SYSLOG_RE.match(line)
        if not m:
            ctx.skipped += 1
            continue
        ts = _syslog_time(m.group("ts"), ctx, now.year)
        if ts and ts[:10] > (now + timedelta(days=1)).strftime("%Y-%m-%d"):
            ts = _syslog_time(m.group("ts"), ctx, now.year - 1)  # syslog has no year; Dec logs read in Jan
        if not ts:
            ctx.bad_time_rows += 1
            continue
        host, proc, msg = m.group("host"), m.group("proc"), m.group("msg")
        event = {"timestamp": ts, "host": host, "username": "", "source_ip": "", "dest_ip": "", "dest_port": "",
                 "action": "", "signature": proc, "event_code": proc, "extra": {"_process": proc, "_raw": truncate(line, 1500)}}
        etype = sev = ""
        if (mm := SSH_FAILED.search(msg)):
            etype, sev = "FailedLogin", "Medium"
            event.update(username=mm.group("user"), source_ip=mm.group("ip"), dest_port="22")
            if "invalid user" in msg:
                event["extra"]["_invalid_user"] = True
        elif (mm := SSH_ACCEPTED.search(msg)):
            etype, sev = "LoginSuccess", "Info"
            event.update(username=mm.group("user"), source_ip=mm.group("ip"), dest_port="22")
            event["extra"]["_auth_method"] = mm.group("method")
        elif (mm := SSH_MAXAUTH.search(msg)):
            etype, sev = "BruteForce", "Medium"
            event.update(username=mm.group("user"), source_ip=mm.group("ip"))
        elif (mm := SSH_INVALID.search(msg)):
            etype, sev = "InvalidUser", "Low"
            event.update(username=mm.group("user"), source_ip=mm.group("ip"))
        elif proc != "sshd" and (mm := PAM_FAIL.search(msg)):
            etype, sev = "FailedLogin", "Medium"
            event.update(username=mm.group("user"), source_ip=clean(mm.group("ip")))
        elif proc == "sudo" and (mm := SUDO_CMD.search(msg)):
            etype, sev = "SudoCommand", "Low"
            event.update(username=mm.group("user"))
            event["extra"]["_command"] = mm.group("cmd")[:1500]
        elif (mm := USERADD.search(msg)):
            etype, sev = "AccountCreated", "Medium"
            event.update(username=mm.group("user"))
        elif (mm := GROUPADD.search(msg)):
            group = mm.group("group")
            etype = "GroupMemberAdded"
            sev = "High" if any(g == group.lower() for g in PRIVILEGED_GROUPS) else "Medium"
            event.update(username=mm.group("user"))
            event["extra"]["_group"] = group
        else:
            guessed = infer_type(msg)
            if guessed:
                etype, sev = guessed
            elif ctx.keep_unmatched:
                etype, sev = "Syslog", "Info"
            else:
                ctx.skipped += 1
                continue
        event.update(event_type=etype, severity=sev, details=f"{proc}: {truncate(msg, 600)}")
        events.append(event)
    return events, {}


# ---------------------------------------------------------------- web access logs (Apache / Nginx combined)

ACCESS_RE = re.compile(
    r'^(?P<ip>[0-9a-fA-F:.]+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>[A-Z]{3,10}|-)\s*(?P<path>[^"]*?)'
    r'(?:\s+(?P<proto>HTTP/[\d.]+))?"\s+(?P<status>\d{3}|-)\s+(?P<bytes>\d+|-)(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?(?P<rest>.*)$')
VHOST_ACCESS_RE = re.compile(r"^(?P<vhost>[\w.-]+(?::\d+)?)\s+(?P<line>\S+\s+\S+\s+\S+\s+\[.*)$")
LOGIN_PATH_RE = re.compile(r"/(login|signin|sign-in|auth|oauth/token|token|session|wp-login\.php|api/(v\d+/)?(auth|login|token))\b", re.I)


def _match_access(line):
    m = ACCESS_RE.match(line)
    vhost = ""
    if not m:
        vm = VHOST_ACCESS_RE.match(line)
        if vm:
            m = ACCESS_RE.match(vm.group("line"))
            vhost = vm.group("vhost")
    return m, vhost


def _parse_access(text, ctx):
    events = []
    ctx.vendor = "Web access log"
    for line in text.splitlines():
        if not line.strip():
            continue
        if ctx.total >= MAX_EVENTS:
            ctx.truncated = True
            break
        ctx.total += 1
        m, vhost = _match_access(line)
        if not m:
            ctx.skipped += 1
            continue
        ts = ctx.time.parse(m.group("ts"))
        if not ts:
            ctx.bad_time_rows += 1
            continue
        status = _to_int(m.group("status"))
        size = _to_int(m.group("bytes"))
        path = m.group("path") or "/"
        method = m.group("method") if m.group("method") != "-" else ""
        ua = m.group("ua") or ""
        user = clean(m.group("user"))
        attack = detect_web_attack(path, ua)
        if attack:
            etype, sev = "WebAttack", "High" if attack in ("log4shell", "cmdi") else "Medium"
        elif status in (401, 403) and LOGIN_PATH_RE.search(path) and method in ("POST", "PUT"):
            etype, sev = "FailedLogin", "Medium"
        elif status == 401:
            etype, sev = "FailedLogin", "Medium"
        else:
            etype, sev = ("ApiRequest" if "/api/" in path.lower() else "WebRequest"), "Info"
        extra = {"_user_agent": ua[:300], "_raw": truncate(line, 1500)}
        if m.group("ref") and m.group("ref") != "-":
            extra["_referer"] = m.group("ref")[:300]
        if attack:
            extra["_attack_pattern"] = attack
        details = f"{method or 'REQ'} {truncate(path, 200)} → {status or '-'}" + (f" | {size:,} B" if size else "")
        if attack:
            details += f" | Pattern={attack}"
        events.append({
            "timestamp": ts, "event_type": etype, "severity": sev, "host": vhost or ctx.default_host,
            "username": user, "source_ip": m.group("ip"), "dest_ip": "", "dest_port": "", "action": "",
            "signature": attack or "", "event_code": str(status or ""), "details": details, "extra": extra,
            "dataset": "auth" if etype == "FailedLogin" else ("api" if etype == "ApiRequest" else "web"),
            "country": "", "http_status": status, "bytes_out": size, "http_method": method, "url_path": path[:500],
        })
    return events, {}


# ---------------------------------------------------------------- plain text

LINE_TS_RE = re.compile(r"^\s*\[?(\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|\s?[+-]\d{2}:?\d{2})?)\]?")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _parse_text(text, ctx):
    events = []
    for line in text.splitlines():
        if not line.strip():
            continue
        if ctx.total >= MAX_EVENTS:
            ctx.truncated = True
            break
        ctx.total += 1
        m = LINE_TS_RE.match(line)
        ts = ctx.time.parse(m.group(1).replace(",", ".").replace("/", "-")) if m else None
        if ts is None:
            ctx.no_time_rows += 1
            ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        guessed = infer_type(line)
        if not guessed and not ctx.keep_unmatched:
            ctx.skipped += 1
            continue
        etype, sev = guessed or ("LogEntry", "Info")
        level = re.search(r"\b(CRITICAL|FATAL|ERROR|WARN(?:ING)?|NOTICE|INFO|DEBUG)\b", line)
        if level and not guessed:
            sev = normalize_severity(level.group(1)) or sev
        ips = [ip for ip in IP_RE.findall(line) if is_ip(ip)]
        events.append({
            "timestamp": ts, "event_type": etype, "severity": sev, "host": ctx.default_host, "username": "",
            "source_ip": ips[0] if ips else "", "dest_ip": ips[1] if len(ips) > 1 else "", "dest_port": "",
            "action": "", "signature": "", "event_code": "", "details": truncate(line.strip(), 1000),
            "extra": {"_raw": truncate(line, 1500)},
        })
    return events, {}


# ---------------------------------------------------------------- entry points

def decode_text(data):
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", "replace")
    if len(data) > 4 and data[1:2] == b"\x00" and data[3:4] == b"\x00":
        return data.decode("utf-16-le", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        return data.decode("cp874")  # Thai Windows ANSI code page
    except UnicodeDecodeError:
        return data.decode("latin-1")


def detect_format(filename, data):
    name = (filename or "").lower()
    if data[:4] == b"PK\x03\x04":
        return "xlsx"
    if data[:8] == b"ElfFile\x00":
        return "evtx"
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "xls"
    text = decode_text(data[:200000])
    head = text.lstrip()[:5000]
    if head.startswith("<") and re.search(r"<Event[\s>]", head):
        return "winxml"
    if head.startswith("[") or head.startswith("{"):
        return "json"
    lines = [l for l in text.splitlines()[:30] if l.strip()]
    if lines and sum(1 for l in lines if SYSLOG_RE.match(l)) >= max(1, len(lines) // 2):
        return "syslog"
    if lines and sum(1 for l in lines if _match_access(l)[0]) >= max(1, len(lines) // 2):
        return "access"
    if name.endswith((".csv", ".tsv")):
        return "csv"
    if lines and len(lines) >= 2:
        for delim in (",", "\t", ";", "|"):
            counts = [l.count(delim) for l in lines[:10]]
            if min(counts) >= 2 and max(counts) - min(counts) <= 2:
                return "csv"
    if name.endswith(".json") or name.endswith(".jsonl") or name.endswith(".ndjson"):
        return "json"
    return "text"


def _sort_key(value):
    try:
        return datetime.fromisoformat(value).astimezone(timezone.utc)
    except (TypeError, ValueError):
        return datetime.min.replace(tzinfo=timezone.utc)


def parse_file(filename, data, fmt="auto", tz_option="local", keep_unmatched=True):
    """Parse an uploaded file. Returns a dict with events, meta, warnings and counters."""
    if not data:
        raise ParseError("The uploaded file is empty.")
    if data[:2] == b"\x1f\x8b":  # gzip (the browser compresses large uploads; .gz files are accepted too)
        import zlib
        inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            data = inflater.decompress(data, MAX_DECOMPRESSED)
        except zlib.error as exc:
            raise ParseError(f"Could not decompress the gzip file: {exc}") from exc
        if inflater.unconsumed_tail:
            raise ParseError(f"Decompressed file is larger than {MAX_DECOMPRESSED // (1024 * 1024)} MB.")
        if filename and filename.lower().endswith(".gz"):
            filename = filename[:-3]
    detected = detect_format(filename, data) if fmt in ("", "auto", None) else fmt
    if detected == "evtx":
        raise ParseError("Binary .evtx files are not supported yet. In Event Viewer use 'Save All Events As… → XML', "
                         "or run: wevtutil qe Security /c:5000 /rd:true /f:xml > security.xml, then import the XML.")
    if detected == "xls":
        raise ParseError("Legacy .xls workbooks are not supported. Open the file in Excel and save it as .xlsx or CSV.")
    ctx = Context(tz_option, keep_unmatched)
    meta = {}
    if detected == "xlsx":
        events = []
        for sheet_name, rows in _read_xlsx(data):
            sheet_events, sheet_meta = _parse_table(rows, ctx, sheet_name)
            events.extend(sheet_events)
            if sheet_meta and (sheet_events or not meta):
                meta = meta or sheet_meta
        if not events and ctx.total == 0:
            raise ParseError("No header row was recognised in the workbook. Make sure one row contains column names such as Time, Src IP, Dst IP, Severity or Message.")
    else:
        text = decode_text(data)
        if detected == "csv":
            events, meta = _parse_table(_read_csv(text), ctx)
            if not events and ctx.total == 0:
                ctx = Context(tz_option, keep_unmatched)
                events, meta = _parse_text(text, ctx)
                detected = "text"
        elif detected == "json":
            events, meta = _parse_json(text, ctx)
        elif detected == "winxml":
            events, meta = _parse_winxml(text, ctx)
        elif detected == "access":
            events, meta = _parse_access(text, ctx)
        elif detected == "syslog":
            events, meta = _parse_syslog(text, ctx)
        else:
            events, meta = _parse_text(text, ctx)
            detected = "text"

    if ctx.truncated:
        ctx.warn(f"Only the first {MAX_EVENTS:,} records were imported. Split large files or filter the export.")
    if ctx.bad_time_rows:
        ctx.warn(f"{ctx.bad_time_rows} record(s) skipped because the timestamp could not be read.")
    if ctx.no_time_rows:
        ctx.warn(f"{ctx.no_time_rows} record(s) had no timestamp; the import time was used instead.")
    if ctx.skipped:
        ctx.warn(f"{ctx.skipped} record(s) were not recognised and were skipped.")
    if not events:
        raise ParseError("No events could be read from this file. Check the format option or try exporting as CSV.")
    events.sort(key=lambda e: _sort_key(e["timestamp"]))
    return {
        "format": detected,
        "vendor": ctx.vendor,
        "events": events,
        "meta": meta,
        "warnings": ctx.warnings,
        "total_records": ctx.total,
        "skipped": ctx.skipped + ctx.bad_time_rows,
        "timezone": ctx.tz_label,
    }
