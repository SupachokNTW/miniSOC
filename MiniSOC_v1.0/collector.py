"""Local Windows Security Event Log collector; read-only and opt-in."""
import platform
from datetime import datetime, timezone

WATCHED_IDS = {"4624", "4625", "1102"}


def _read_records(max_scan=500):
    try:
        import win32evtlog
    except ImportError as exc:
        raise RuntimeError("pywin32 is not installed. Run pip install pywin32.") from exc
    handle = win32evtlog.OpenEventLog("localhost", "Security")
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    found = []
    try:
        while len(found) < max_scan:
            batch = win32evtlog.ReadEventLog(handle, flags, 0)
            if not batch:
                break
            found.extend(batch)
    finally:
        win32evtlog.CloseEventLog(handle)
    return found[:max_scan]


def _insert(record, index, default=""):
    values = record.StringInserts or []
    if len(values) <= index or values[index] is None:
        return default
    value = str(values[index]).strip()
    return value if value and value not in {"-", "N/A", "(null)"} else default


def _to_event(record):
    code = str(record.EventID & 0xFFFF)
    if code not in WATCHED_IDS:
        return None
    event_type, severity = {
        "4624": ("LoginSuccess", "Info"),
        "4625": ("FailedLogin", "Medium"),
        "1102": ("LogCleared", "High"),
    }[code]
    try:
        timestamp = record.TimeGenerated.astimezone().isoformat(timespec="seconds")
    except Exception:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # Windows Security event field layouts differ by Event ID.
    # For 4624, TargetUserName is field 5 and IpAddress is field 18.
    # For 4625, TargetUserName is field 5 and IpAddress is field 19.
    if code in {"4624", "4625"}:
        username = _insert(record, 5)
        ip_index = 18 if code == "4624" else 19
        source_ip = _insert(record, ip_index)
        workstation_index = 11 if code == "4624" else 13
        workstation = _insert(record, workstation_index)
        logon_type_index = 8 if code == "4624" else 10
        logon_type = _insert(record, logon_type_index)
        detail_parts = [f"Windows Event ID {code}"]
        if username:
            detail_parts.append(f"TargetUser={username}")
        if source_ip:
            detail_parts.append(f"IpAddress={source_ip}")
        if workstation:
            detail_parts.append(f"Workstation={workstation}")
        if logon_type:
            detail_parts.append(f"LogonType={logon_type}")
        details = " | ".join(detail_parts)
    else:
        username = ""
        source_ip = ""
        details = "Windows Event ID 1102. Security audit log was cleared."

    return {
        "timestamp": timestamp,
        "source": "Windows Security",
        "event_type": event_type,
        "severity": severity,
        "host": platform.node(),
        "username": username,
        "source_ip": source_ip,
        "details": details,
        "event_code": code,
        "source_record_id": f"Security:{record.RecordNumber}",
    }


def _store(records):
    import pipeline
    from db import get_db, transaction
    events = [e for e in (_to_event(r) for r in sorted(records, key=lambda r: int(r.RecordNumber))) if e]
    if not events:
        return 0
    db = get_db()
    fresh = []
    for e in events:  # the Security log is read repeatedly; skip records already stored
        if not db.one("SELECT id FROM events WHERE source_record_id=?", (e["source_record_id"],)):
            fresh.append(e)
    if fresh:
        with transaction():
            pipeline.process_batch(fresh, "Windows Security")
    return len(fresh)


def collect_recent_windows_events(max_events=100):
    if platform.system() != "Windows":
        raise RuntimeError("Windows Event Log collection is only available on Windows.")
    records = _read_records(max_scan=max_events * 5)
    return _store(records) if records else 0


def poll_windows_events(max_scan=500):
    if platform.system() != "Windows":
        return 0
    records = _read_records(max_scan=max_scan)
    if not records:
        return 0
    from database import get_collector_state, set_collector_state
    from db import transaction
    key = "auto_security_last_record"
    last = int(get_collector_state(key, "0") or "0")
    newest = max(int(r.RecordNumber) for r in records)
    if last == 0:
        with transaction():
            set_collector_state(key, newest)
        return 0
    fresh = [r for r in records if int(r.RecordNumber) > last]
    count = _store(fresh) if fresh else 0
    with transaction():
        set_collector_state(key, max(last, newest))
    return count


def start_background_collector(interval_seconds=30):
    import threading
    import time
    if platform.system() != "Windows":
        return None
    try:
        import win32evtlog  # noqa: F401
    except ImportError:
        return None
    name = "minisoc-windows-event-collector"
    if any(t.name == name for t in threading.enumerate()):
        return None

    def worker():
        try:
            poll_windows_events()
        except Exception as exc:
            print(f"[MiniSOC collector] Initial poll failed: {exc}")
        while True:
            time.sleep(max(10, int(interval_seconds)))
            try:
                count = poll_windows_events()
                if count:
                    print(f"[MiniSOC collector] Imported {count} new event(s).")
            except Exception as exc:
                print(f"[MiniSOC collector] Poll failed: {exc}")

    thread = threading.Thread(target=worker, name=name, daemon=True)
    thread.start()
    return thread
