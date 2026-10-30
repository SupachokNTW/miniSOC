"""Data access for MiniSOC (works on SQLite and PostgreSQL through db.py)."""
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone

import config
from db import get_db, init_schema

LEGACY_RULES = [
    ("Failed Login Burst", "Legacy v0.4 rule (now rules/auth-failed-login-burst.yml).", "Medium", 1),
]


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def to_utc_iso(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")


def clean_text(value, limit=None):
    """Strip NUL bytes (PostgreSQL rejects them) and optionally truncate."""
    if value is None:
        return None
    text = str(value).replace("\x00", "")
    return text[:limit] if limit else text


def _json(value):
    if value is None:
        return None
    return clean_text(json.dumps(value, ensure_ascii=False, default=str))


def _load(value, default):
    try:
        return json.loads(value) if value else default
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------- init & settings

def init_db():
    db = get_db()
    init_schema(db)
    for name, desc, sev, enabled in LEGACY_RULES:
        db.execute("INSERT INTO detection_rules(name, description, severity, enabled) VALUES(?,?,?,?) "
                   "ON CONFLICT(name) DO NOTHING", (name, desc, sev, enabled))
    for key, value in config.DEFAULT_SETTINGS.items():
        if key == "feed_token" and not value:
            value = secrets.token_urlsafe(24)
        db.execute("INSERT INTO settings(key, value) VALUES(?,?) ON CONFLICT(key) DO NOTHING", (key, value))
    rows = db.query("SELECT id, timestamp FROM events WHERE ts_utc IS NULL LIMIT 50000")
    for r in rows:
        db.execute("UPDATE events SET ts_utc=? WHERE id=?", (to_utc_iso(r["timestamp"]), r["id"]))
    db.commit()


def get_settings():
    try:
        from flask import g, has_app_context
        if has_app_context() and "minisoc_settings" in g:
            return g.minisoc_settings
    except ImportError:
        has_app_context = lambda: False  # noqa: E731
    values = dict(config.DEFAULT_SETTINGS)
    for row in get_db().query("SELECT key, value FROM settings"):
        values[row["key"]] = row["value"]
    try:
        from flask import g, has_app_context
        if has_app_context():
            g.minisoc_settings = values
    except ImportError:
        pass
    return values


def get_setting(key, default=None):
    return get_settings().get(key, default)


def set_settings(values):
    db = get_db()
    for key, value in values.items():
        db.execute("INSERT INTO settings(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                   (key, str(value)))
    try:
        from flask import g
        g.pop("minisoc_settings", None)
    except Exception:
        pass


# ---------------------------------------------------------------- events

EVENT_FIELDS = ["timestamp", "source", "event_type", "severity", "host", "username", "source_ip", "details",
                "event_code", "created_at", "source_record_id", "dest_ip", "dest_port", "action", "signature",
                "import_id", "ts_utc", "extra", "dataset", "country", "http_status", "bytes_out", "http_method",
                "url_path", "hits"]


def _int_or_none(value):
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _event_row(event, now, import_id=None):
    extra = event.get("extra")
    return (
        clean_text(event.get("timestamp") or now), clean_text(event.get("source") or "Manual", 200),
        clean_text(event.get("event_type") or "General", 60), event.get("severity") or "Info",
        clean_text(event.get("host") or "localhost", 200), clean_text(event.get("username"), 200),
        clean_text(event.get("source_ip"), 100), clean_text(event.get("details") or "", 2000),
        clean_text(event.get("event_code") or "", 60), now,
        clean_text(event.get("source_record_id")) if event.get("source_record_id") else None,
        clean_text(event.get("dest_ip"), 100), clean_text(event.get("dest_port") or "", 10) or None,
        clean_text(event.get("action"), 40), clean_text(event.get("signature"), 300),
        import_id if import_id is not None else event.get("import_id"),
        to_utc_iso(event.get("timestamp") or now),
        _json(extra) if extra is not None and not isinstance(extra, str) else clean_text(extra),
        clean_text(event.get("dataset"), 30), clean_text(event.get("country"), 80),
        _int_or_none(event.get("http_status")), _int_or_none(event.get("bytes_out")),
        clean_text(event.get("http_method"), 12), clean_text(event.get("url_path"), 500),
        int(event.get("hits") or 1),
    )


def insert_event(event):
    db = get_db()
    rid = event.get("source_record_id")
    if rid:
        existing = db.one("SELECT id FROM events WHERE source_record_id=?", (str(rid),))
        if existing:
            return existing["id"]
    return db.insert_many("events", EVENT_FIELDS, [_event_row(event, now_iso())])[0]


def insert_events_bulk(events, import_id=None):
    now = now_iso()
    return get_db().insert_many("events", EVENT_FIELDS, [_event_row(e, now, import_id) for e in events])


def _decode_event(row):
    item = dict(row)
    item["extra"] = _load(item.get("extra"), {}) if isinstance(item.get("extra"), (str, type(None))) else item["extra"]
    item["hits"] = int(item.get("hits") or 1)
    return item


def list_events(limit=200, severity="", query="", import_id=None, dataset="", event_type=""):
    sql = "SELECT * FROM events WHERE 1=1"
    args = []
    if severity:
        sql += " AND severity = ?"
        args.append(severity)
    if import_id:
        sql += " AND import_id = ?"
        args.append(import_id)
    if dataset:
        sql += " AND dataset = ?"
        args.append(dataset)
    if event_type:
        sql += " AND event_type = ?"
        args.append(event_type)
    if query:
        sql += (" AND (details LIKE ? OR event_type LIKE ? OR source LIKE ? OR username LIKE ? OR source_ip LIKE ?"
                " OR dest_ip LIKE ? OR signature LIKE ? OR event_code LIKE ? OR url_path LIKE ? OR host LIKE ?)")
        args.extend([f"%{query}%"] * 10)
    sql += " ORDER BY ts_utc DESC, id DESC LIMIT ?"
    args.append(limit)
    return [_decode_event(r) for r in get_db().query(sql, args)]


def get_events_by_ids(ids):
    ids = [int(i) for i in ids if i][:500]
    if not ids:
        return []
    marks = ",".join("?" * len(ids))
    return [_decode_event(r) for r in get_db().query(f"SELECT * FROM events WHERE id IN ({marks}) ORDER BY ts_utc, id", ids)]


def list_import_events(import_id):
    return [_decode_event(r) for r in get_db().query("SELECT * FROM events WHERE import_id=? ORDER BY ts_utc, id", (import_id,))]


def events_in_window(start_utc, end_utc, limit=30000):
    rows = get_db().query("SELECT * FROM events WHERE ts_utc >= ? AND ts_utc <= ? ORDER BY ts_utc LIMIT ?",
                          (start_utc, end_utc, limit))
    return [_decode_event(r) for r in rows]


def user_login_history(username, before_utc, days=90, limit=2000):
    start = (datetime.fromisoformat(before_utc) - timedelta(days=days)).isoformat(timespec="seconds")
    return get_db().query(
        "SELECT ts_utc, timestamp, country, source_ip FROM events WHERE username=? AND event_type='LoginSuccess' "
        "AND ts_utc >= ? AND ts_utc < ? ORDER BY ts_utc DESC LIMIT ?", (username, start, before_utc, limit))


def entity_bytes_history(field, value, start_utc, end_utc):
    if field not in ("username", "source_ip"):
        return []
    return get_db().query(
        f"SELECT ts_utc, bytes_out, hits FROM events WHERE {field}=? AND bytes_out IS NOT NULL "
        "AND ts_utc >= ? AND ts_utc < ? ORDER BY ts_utc", (value, start_utc, end_utc))


def error_history(start_utc, end_utc):
    return get_db().query(
        "SELECT ts_utc, hits, http_status FROM events WHERE http_status >= 500 AND ts_utc >= ? AND ts_utc < ?",
        (start_utc, end_utc))


# ---------------------------------------------------------------- imports

def find_import_by_hash(sha256):
    return get_db().one("SELECT * FROM imports WHERE sha256=? ORDER BY id DESC LIMIT 1", (sha256,))


def create_import(filename, file_format, vendor, sha256, size_bytes, tz_label, total_records, skipped, meta,
                  warnings, options=None, user=None):
    return get_db().insert("""
        INSERT INTO imports(filename, file_format, vendor, sha256, size_bytes, timezone, total_records, skipped,
                            meta, warnings, created_at, options, uploaded_by, raw_records)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (clean_text(filename, 200), file_format, vendor, sha256, size_bytes, tz_label, total_records, skipped,
         _json(meta or {}), _json(warnings or []), now_iso(), _json(options or {}), user, total_records))


def finish_import(import_id, stored, summarized, signals, incidents):
    db = get_db()
    stats = db.one("SELECT COUNT(*) AS n, MIN(ts_utc) AS first_ts, MAX(ts_utc) AS last_ts FROM events WHERE import_id=?",
                   (import_id,))
    alerts = db.scalar("SELECT COUNT(DISTINCT alert_id) AS n FROM signals WHERE import_id=? AND alert_id IS NOT NULL",
                       (import_id,), 0)
    db.execute("""UPDATE imports SET event_count=?, alert_count=?, first_seen=?, last_seen=?, stored_events=?,
                  summarized=?, signal_count=?, incident_count=? WHERE id=?""",
               (stats["n"], alerts, stats["first_ts"], stats["last_ts"], stored, summarized, signals, incidents, import_id))


def _decode_import(row):
    item = dict(row)
    item["meta"] = _load(item.get("meta"), {})
    item["warnings"] = _load(item.get("warnings"), [])
    item["options"] = _load(item.get("options"), {})
    return item


def get_import(import_id):
    row = get_db().one("SELECT * FROM imports WHERE id=?", (import_id,))
    return _decode_import(row) if row else None


def list_imports(limit=100):
    return [_decode_import(r) for r in get_db().query("SELECT * FROM imports ORDER BY id DESC LIMIT ?", (limit,))]


def delete_import(import_id):
    db = get_db()
    alert_ids = [r["alert_id"] for r in db.query(
        "SELECT DISTINCT alert_id FROM signals WHERE import_id=? AND alert_id IS NOT NULL", (import_id,))]
    db.execute("DELETE FROM signals WHERE import_id=?", (import_id,))
    db.execute("DELETE FROM alerts WHERE event_id IN (SELECT id FROM events WHERE import_id=?) AND rule_id IS NULL", (import_id,))
    db.execute("DELETE FROM events WHERE import_id=?", (import_id,))
    db.execute("DELETE FROM imports WHERE id=?", (import_id,))
    for alert_id in alert_ids:  # drop incidents that no longer have any evidence
        if not db.scalar("SELECT COUNT(*) AS n FROM signals WHERE alert_id=?", (alert_id,), 0):
            delete_incident(alert_id)
        else:
            refresh_incident_stats(alert_id)


# ---------------------------------------------------------------- signals & incidents

SIGNAL_FIELDS = ["rule_id", "rule_title", "level", "event_id", "import_id", "ts", "ts_utc", "entity_type",
                 "entity_value", "base_score", "risk_score", "mitre", "message", "alert_id", "direct_alert", "created_at"]


def insert_signals(signals):
    now = now_iso()
    rows = [(s["rule_id"], clean_text(s["rule_title"], 200), s["level"], s.get("event_id"), s.get("import_id"),
             s["ts"], to_utc_iso(s["ts"]), s["entity_type"], clean_text(s["entity_value"], 300),
             float(s.get("base_score", 0)), float(s.get("risk_score", 0)), s.get("mitre", ""),
             clean_text(s.get("message", ""), 1000), s.get("alert_id"), 1 if s.get("direct_alert") else 0, now)
            for s in signals]
    return get_db().insert_many("signals", SIGNAL_FIELDS, rows)


def last_signal_time(rule_id, entity_type, entity_value, start_utc, end_utc):
    return get_db().scalar(
        "SELECT MAX(ts_utc) AS t FROM signals WHERE rule_id=? AND entity_type=? AND entity_value=? AND ts_utc >= ? AND ts_utc <= ?",
        (rule_id, entity_type, entity_value, start_utc, end_utc))


def entity_signals(entity_type, entity_value, start_utc, end_utc, unattached_only=False):
    sql = ("SELECT s.* FROM signals s LEFT JOIN alerts a ON a.id = s.alert_id WHERE s.entity_type=? AND s.entity_value=? "
           "AND s.ts_utc >= ? AND s.ts_utc <= ? AND (s.alert_id IS NULL OR a.status != 'Resolved')")
    if unattached_only:
        sql += " AND s.alert_id IS NULL"
    return get_db().query(sql + " ORDER BY s.ts_utc", (entity_type, entity_value, start_utc, end_utc))


def attach_signals(signal_ids, alert_id):
    db = get_db()
    for start in range(0, len(signal_ids), 400):
        part = signal_ids[start:start + 400]
        db.execute(f"UPDATE signals SET alert_id=? WHERE id IN ({','.join('?' * len(part))})", [alert_id] + part)


def signals_for_alert(alert_id):
    return get_db().query("SELECT * FROM signals WHERE alert_id=? ORDER BY ts_utc, id", (alert_id,))


def signals_for_import(import_id):
    return get_db().query("SELECT * FROM signals WHERE import_id=? ORDER BY ts_utc, id", (import_id,))


def list_import_alerts(import_id):
    return get_db().query("""SELECT DISTINCT a.id, a.title, a.rule_name, a.severity, a.explanation, a.status,
                             a.first_event_ts AS event_time, a.entity_value, a.risk_score, a.signal_count
                             FROM alerts a JOIN signals s ON s.alert_id = a.id WHERE s.import_id=? ORDER BY a.id""", (import_id,))


def open_incident_for_entity(entity_type, entity_value, since_utc, until_utc=None):
    """Open incident for the entity whose activity window overlaps [since, until] (event time).

    Overlap matters for historical imports: an old log must not be merged into today's incident."""
    until_utc = until_utc or "9999"
    return get_db().one(
        "SELECT * FROM alerts WHERE entity_type=? AND entity_value=? AND status != 'Resolved' AND "
        "(last_event_ts IS NULL OR last_event_ts >= ?) AND (first_event_ts IS NULL OR first_event_ts <= ?) "
        "ORDER BY id DESC LIMIT 1", (entity_type, entity_value, since_utc, until_utc))


def create_incident(event_id, rule_id, rule_name, severity, title, explanation, entity_type, entity_value,
                    risk_score, first_ts, last_ts, mitre, context=None):
    now = now_iso()
    return get_db().insert("""
        INSERT INTO alerts(event_id, rule_name, severity, title, explanation, status, created_at, rule_id, entity_type,
                           entity_value, risk_score, signal_count, first_event_ts, last_event_ts, mitre, updated_at, context)
        VALUES(?,?,?,?,?,'New',?,?,?,?,?,0,?,?,?,?,?)""",
        (event_id, clean_text(rule_name, 200), severity, clean_text(title, 300), clean_text(explanation, 2000), now,
         rule_id, entity_type, clean_text(entity_value, 300), risk_score, first_ts, last_ts, mitre, now, _json(context or {})))


def refresh_incident_stats(alert_id):
    db = get_db()
    stats = db.one("SELECT COUNT(*) AS n, SUM(risk_score) AS score, MIN(ts_utc) AS first_ts, MAX(ts_utc) AS last_ts "
                   "FROM signals WHERE alert_id=?", (alert_id,))
    mitre = sorted({m for r in db.query("SELECT DISTINCT mitre FROM signals WHERE alert_id=?", (alert_id,))
                    for m in (r["mitre"] or "").split(",") if m})
    db.execute("UPDATE alerts SET signal_count=?, risk_score=?, first_event_ts=?, last_event_ts=?, mitre=?, updated_at=? WHERE id=?",
               (stats["n"] or 0, round(stats["score"] or 0, 1), stats["first_ts"], stats["last_ts"], ",".join(mitre), now_iso(), alert_id))


def update_incident_fields(alert_id, **fields):
    allowed = {"severity", "title", "explanation", "rule_name", "rule_id", "status", "disposition", "assignee",
               "acknowledged_at", "resolved_at", "context"}
    sets = {k: v for k, v in fields.items() if k in allowed}
    if not sets:
        return
    sets["updated_at"] = now_iso()
    get_db().execute(f"UPDATE alerts SET {', '.join(k + '=?' for k in sets)} WHERE id=?", list(sets.values()) + [alert_id])


def get_incident(alert_id):
    row = get_db().one("""SELECT a.*, e.source, e.import_id, e.source_ip, e.dest_ip FROM alerts a
                          LEFT JOIN events e ON e.id = a.event_id WHERE a.id=?""", (alert_id,))
    if row:
        row["context"] = _load(row.get("context"), {})
    return row


def list_incidents(limit=300, status="", severity="", query=""):
    sql = ("SELECT a.*, e.source, e.import_id FROM alerts a LEFT JOIN events e ON e.id = a.event_id WHERE 1=1")
    args = []
    if status == "open":
        sql += " AND a.status != 'Resolved'"
    elif status:
        sql += " AND a.status = ?"
        args.append(status)
    if severity:
        sql += " AND a.severity = ?"
        args.append(severity)
    if query:
        sql += " AND (a.title LIKE ? OR a.entity_value LIKE ? OR a.rule_name LIKE ? OR a.explanation LIKE ?)"
        args.extend([f"%{query}%"] * 4)
    sql += " ORDER BY a.id DESC LIMIT ?"
    args.append(limit)
    return get_db().query(sql, args)


def set_incident_status(alert_id, status, disposition=None):
    incident = get_incident(alert_id)
    if not incident:
        return
    fields = {"status": status}
    now = now_iso()
    if status in ("Investigating", "Resolved") and not incident.get("acknowledged_at"):
        fields["acknowledged_at"] = now
    if status == "Resolved":
        fields["resolved_at"] = incident.get("resolved_at") or now
        fields["disposition"] = disposition or incident.get("disposition") or "Undetermined"
    else:
        fields["resolved_at"] = None
        if disposition is not None:
            fields["disposition"] = disposition
    update_incident_fields(alert_id, **fields)


def delete_incident(alert_id):
    db = get_db()
    db.execute("UPDATE signals SET alert_id=NULL WHERE alert_id=?", (alert_id,))
    for table in ("incident_tasks", "incident_notes", "playbook_runs"):
        db.execute(f"DELETE FROM {table} WHERE alert_id=?", (alert_id,))
    db.execute("DELETE FROM alerts WHERE id=?", (alert_id,))


def add_note(alert_id, author, text):
    get_db().insert("INSERT INTO incident_notes(alert_id, author, text, created_at) VALUES(?,?,?,?)",
                    (alert_id, author, clean_text(text, 4000), now_iso()))


def list_notes(alert_id):
    return get_db().query("SELECT * FROM incident_notes WHERE alert_id=? ORDER BY id", (alert_id,))


def add_task(alert_id, text):
    db = get_db()
    if db.one("SELECT id FROM incident_tasks WHERE alert_id=? AND text=?", (alert_id, text)):
        return
    db.insert("INSERT INTO incident_tasks(alert_id, text, done, created_at) VALUES(?,?,0,?)", (alert_id, clean_text(text, 500), now_iso()))


def list_tasks(alert_id):
    return get_db().query("SELECT * FROM incident_tasks WHERE alert_id=? ORDER BY id", (alert_id,))


def toggle_task(task_id, done):
    get_db().execute("UPDATE incident_tasks SET done=? WHERE id=?", (1 if done else 0, task_id))


# ---------------------------------------------------------------- rules state & stats

def rule_states():
    return {r["rule_id"]: bool(r["enabled"]) for r in get_db().query("SELECT rule_id, enabled FROM rule_state")}


def set_rule_enabled(rule_id, enabled, user=None):
    get_db().execute("INSERT INTO rule_state(rule_id, enabled, updated_at, updated_by) VALUES(?,?,?,?) "
                     "ON CONFLICT(rule_id) DO UPDATE SET enabled=excluded.enabled, updated_at=excluded.updated_at, "
                     "updated_by=excluded.updated_by", (rule_id, 1 if enabled else 0, now_iso(), user))


def rule_signal_stats(since_utc):
    rows = get_db().query("SELECT rule_id, COUNT(*) AS n, MAX(ts_utc) AS last_ts FROM signals WHERE created_at >= ? "
                          "GROUP BY rule_id", (since_utc,))
    return {r["rule_id"]: r for r in rows}


def rule_disposition_stats():
    rows = get_db().query("""SELECT s.rule_id, a.disposition, COUNT(DISTINCT a.id) AS n FROM signals s
                             JOIN alerts a ON a.id = s.alert_id WHERE a.status='Resolved' GROUP BY s.rule_id, a.disposition""")
    out = {}
    for r in rows:
        out.setdefault(r["rule_id"], {})[r["disposition"] or "Undetermined"] = r["n"]
    return out


# ---------------------------------------------------------------- assets & identities

def list_assets():
    return get_db().query("SELECT * FROM assets ORDER BY criticality DESC, COALESCE(name, ip, hostname)")


def asset_lookup():
    lookup = {}
    for a in list_assets():
        for key in (a.get("ip"), (a.get("hostname") or "").lower()):
            if key:
                lookup[key] = a
    return lookup


def upsert_asset(ip=None, hostname=None, name=None, criticality=3, owner=None, tags=None, auto=False, asset_id=None):
    db = get_db()
    criticality = max(1, min(5, int(criticality or 3)))
    if asset_id:
        db.execute("UPDATE assets SET ip=?, hostname=?, name=?, criticality=?, owner=?, tags=?, auto=0, updated_at=? WHERE id=?",
                   (ip or None, hostname or None, name or None, criticality, owner or None, tags or None, now_iso(), asset_id))
        return asset_id
    existing = None
    if ip:
        existing = db.one("SELECT * FROM assets WHERE ip=?", (ip,))
    if not existing and hostname:
        existing = db.one("SELECT * FROM assets WHERE LOWER(hostname)=?", (hostname.lower(),))
    if existing:
        if auto:
            return existing["id"]
        db.execute("UPDATE assets SET ip=COALESCE(?, ip), hostname=COALESCE(?, hostname), name=COALESCE(?, name), "
                   "criticality=?, owner=COALESCE(?, owner), tags=COALESCE(?, tags), auto=0, updated_at=? WHERE id=?",
                   (ip or None, hostname or None, name or None, criticality, owner or None, tags or None, now_iso(), existing["id"]))
        return existing["id"]
    return db.insert("INSERT INTO assets(ip, hostname, name, criticality, owner, tags, auto, created_at) VALUES(?,?,?,?,?,?,?,?)",
                     (ip or None, hostname or None, name or None, criticality, owner or None, tags or None, 1 if auto else 0, now_iso()))


def delete_asset(asset_id):
    get_db().execute("DELETE FROM assets WHERE id=?", (asset_id,))


def list_identities():
    return get_db().query("SELECT * FROM identities ORDER BY privileged DESC, username")


def identity_lookup():
    return {i["username"].lower(): i for i in list_identities()}


def upsert_identity(username, display_name=None, department=None, email=None, privileged=False, auto=False):
    db = get_db()
    existing = db.one("SELECT * FROM identities WHERE LOWER(username)=?", (username.lower(),))
    if existing:
        if auto:
            return existing["id"]
        db.execute("UPDATE identities SET display_name=?, department=?, email=?, privileged=?, auto=0 WHERE id=?",
                   (display_name or None, department or None, email or None, 1 if privileged else 0, existing["id"]))
        return existing["id"]
    return db.insert("INSERT INTO identities(username, display_name, department, email, privileged, auto, created_at) "
                     "VALUES(?,?,?,?,?,?,?)", (clean_text(username, 200), display_name, department, email,
                                               1 if privileged else 0, 1 if auto else 0, now_iso()))


def delete_identity(identity_id):
    get_db().execute("DELETE FROM identities WHERE id=?", (identity_id,))


# ---------------------------------------------------------------- SOAR storage

def create_playbook_run(playbook_id, title, alert_id, status, actions):
    return get_db().insert("INSERT INTO playbook_runs(playbook_id, playbook_title, alert_id, status, actions, created_at) "
                           "VALUES(?,?,?,?,?,?)", (playbook_id, title, alert_id, status, _json(actions), now_iso()))


def update_playbook_run(run_id, status, actions, approved_by=None):
    if approved_by:
        get_db().execute("UPDATE playbook_runs SET status=?, actions=?, approved_by=?, approved_at=? WHERE id=?",
                         (status, _json(actions), approved_by, now_iso(), run_id))
    else:
        get_db().execute("UPDATE playbook_runs SET status=?, actions=?, WHERE id=?".replace(", WHERE", " WHERE"),
                         (status, _json(actions), run_id))


def get_playbook_run(run_id):
    row = get_db().one("SELECT * FROM playbook_runs WHERE id=?", (run_id,))
    if row:
        row["actions"] = _load(row.get("actions"), [])
    return row


def playbook_run_exists(playbook_id, alert_id):
    return bool(get_db().one("SELECT id FROM playbook_runs WHERE playbook_id=? AND alert_id=?", (playbook_id, alert_id)))


def list_playbook_runs(alert_id=None, status=None, limit=100):
    sql = "SELECT r.*, a.title AS alert_title, a.severity AS alert_severity FROM playbook_runs r LEFT JOIN alerts a ON a.id=r.alert_id WHERE 1=1"
    args = []
    if alert_id:
        sql += " AND r.alert_id=?"
        args.append(alert_id)
    if status:
        sql += " AND r.status=?"
        args.append(status)
    sql += " ORDER BY r.id DESC LIMIT ?"
    args.append(limit)
    rows = get_db().query(sql, args)
    for r in rows:
        r["actions"] = _load(r.get("actions"), [])
    return rows


def blocklist_add(value, kind, reason, source, alert_id=None, ttl_hours=None, user=None):
    expires = (datetime.now(timezone.utc) + timedelta(hours=int(ttl_hours))).isoformat(timespec="seconds") if ttl_hours else None
    get_db().execute(
        "INSERT INTO blocklist(value, kind, reason, source, alert_id, created_at, expires_at, active, created_by) "
        "VALUES(?,?,?,?,?,?,?,1,?) ON CONFLICT(value) DO UPDATE SET active=1, reason=excluded.reason, "
        "source=excluded.source, alert_id=excluded.alert_id, expires_at=excluded.expires_at, created_at=excluded.created_at, "
        "created_by=excluded.created_by",
        (clean_text(value, 300), kind, clean_text(reason, 300), source, alert_id, now_iso(), expires, user))


def blocklist_remove(entry_id):
    get_db().execute("UPDATE blocklist SET active=0 WHERE id=?", (entry_id,))


def list_blocklist(active_only=False):
    sql = "SELECT * FROM blocklist"
    if active_only:
        sql += " WHERE active=1 AND (expires_at IS NULL OR expires_at > ?)"
        return get_db().query(sql + " ORDER BY created_at DESC", (now_iso(),))
    return get_db().query(sql + " ORDER BY active DESC, created_at DESC")


# ---------------------------------------------------------------- users, keys, audit

def count_users():
    return get_db().scalar("SELECT COUNT(*) AS n FROM users", (), 0)


def get_user(username):
    return get_db().one("SELECT * FROM users WHERE LOWER(username)=?", (str(username or "").lower(),))


def get_user_by_id(user_id):
    return get_db().one("SELECT * FROM users WHERE id=?", (user_id,))


def list_users():
    return get_db().query("SELECT id, username, role, created_at, last_login, disabled FROM users ORDER BY username")


def create_user(username, password_hash, role):
    return get_db().insert("INSERT INTO users(username, password_hash, role, created_at) VALUES(?,?,?,?)",
                           (clean_text(username, 80), password_hash, role, now_iso()))


def update_user(user_id, role=None, disabled=None, password_hash=None):
    db = get_db()
    if role:
        db.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
    if disabled is not None:
        db.execute("UPDATE users SET disabled=? WHERE id=?", (1 if disabled else 0, user_id))
    if password_hash:
        db.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash, user_id))


def touch_login(user_id):
    get_db().execute("UPDATE users SET last_login=? WHERE id=?", (now_iso(), user_id))


def _hash_key(raw):
    return hashlib.sha256(raw.encode()).hexdigest()


def create_api_key(name, user):
    raw = "msoc_" + secrets.token_urlsafe(32)
    get_db().insert("INSERT INTO api_keys(name, prefix, key_hash, created_at, created_by) VALUES(?,?,?,?,?)",
                    (clean_text(name, 80), raw[:12], _hash_key(raw), now_iso(), user))
    return raw


def verify_api_key(raw):
    if not raw:
        return None
    row = get_db().one("SELECT * FROM api_keys WHERE key_hash=? AND revoked=0", (_hash_key(raw),))
    if row:
        get_db().execute("UPDATE api_keys SET last_used=? WHERE id=?", (now_iso(), row["id"]))
    return row


def list_api_keys():
    return get_db().query("SELECT id, name, prefix, created_at, last_used, created_by, revoked FROM api_keys ORDER BY id DESC")


def revoke_api_key(key_id):
    get_db().execute("UPDATE api_keys SET revoked=1 WHERE id=?", (key_id,))


def audit(action, detail="", username=None, ip=None):
    get_db().insert("INSERT INTO audit_log(ts, username, ip, action, detail) VALUES(?,?,?,?,?)",
                    (now_iso(), username, ip, action, clean_text(detail, 1000)))


def list_audit(limit=200):
    return get_db().query("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))


def recent_login_failures(username, ip, minutes=15):
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat(timespec="seconds")
    return get_db().scalar("SELECT COUNT(*) AS n FROM audit_log WHERE action='login_failed' AND ts >= ? AND (username=? OR ip=?)",
                           (since, username, ip), 0)


# ---------------------------------------------------------------- simulation runs

def insert_simulation_run(scenario, title, expected, fired, missing, passed, events, import_id):
    return get_db().insert("INSERT INTO simulation_runs(scenario, title, expected, fired, missing, passed, events, import_id, created_at) "
                           "VALUES(?,?,?,?,?,?,?,?,?)", (scenario, title, _json(expected), _json(fired), _json(missing),
                                                         1 if passed else 0, events, import_id, now_iso()))


def list_simulation_runs(limit=50):
    rows = get_db().query("SELECT * FROM simulation_runs ORDER BY id DESC LIMIT ?", (limit,))
    for r in rows:
        for key in ("expected", "fired", "missing"):
            r[key] = _load(r.get(key), [])
    return rows


# ---------------------------------------------------------------- collector state (Windows)

def get_collector_state(name, default=None):
    row = get_db().one("SELECT value FROM collector_state WHERE name=?", (name,))
    return row["value"] if row else default


def set_collector_state(name, value):
    get_db().execute("INSERT INTO collector_state(name, value) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value",
                     (name, str(value)))


# ---------------------------------------------------------------- dashboards & retention

def dashboard_stats():
    db = get_db()
    since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat(timespec="seconds")
    severity_rows = db.query("SELECT severity, SUM(hits) AS n FROM events GROUP BY severity")
    day_rows = db.query("SELECT SUBSTR(timestamp, 1, 10) AS day, SUM(hits) AS n FROM events GROUP BY SUBSTR(timestamp, 1, 10) "
                        "ORDER BY day DESC LIMIT 14")
    return {
        "total_events": db.scalar("SELECT SUM(hits) AS n FROM events", (), 0),
        "stored_events": db.scalar("SELECT COUNT(*) AS n FROM events", (), 0),
        "total_alerts": db.scalar("SELECT COUNT(*) AS n FROM alerts", (), 0),
        "open_alerts": db.scalar("SELECT COUNT(*) AS n FROM alerts WHERE status != 'Resolved'", (), 0),
        "critical_alerts": db.scalar("SELECT COUNT(*) AS n FROM alerts WHERE severity='Critical' AND status != 'Resolved'", (), 0),
        "signals_7d": db.scalar("SELECT COUNT(*) AS n FROM signals WHERE created_at >= ?", (since,), 0),
        "incidents_7d": db.scalar("SELECT COUNT(*) AS n FROM alerts WHERE created_at >= ?", (since,), 0),
        "total_imports": db.scalar("SELECT COUNT(*) AS n FROM imports", (), 0),
        "blocked": db.scalar("SELECT COUNT(*) AS n FROM blocklist WHERE active=1", (), 0),
        "pending_approvals": db.scalar("SELECT COUNT(*) AS n FROM playbook_runs WHERE status='pending_approval'", (), 0),
        "event_severity": {r["severity"]: int(r["n"] or 0) for r in severity_rows},
        "daily_events": list(reversed([{"day": r["day"], "count": int(r["n"] or 0)} for r in day_rows])),
    }


def scalar_pending():
    return get_db().scalar("SELECT COUNT(*) AS n FROM playbook_runs WHERE status='pending_approval'", (), 0)


def top_risk_entities(hours=24 * 7, limit=10):
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
    return get_db().query("""SELECT entity_type, entity_value, SUM(risk_score) AS score, COUNT(*) AS signals,
                             MAX(ts_utc) AS last_ts FROM signals WHERE created_at >= ?
                             GROUP BY entity_type, entity_value ORDER BY score DESC LIMIT ?""", (since, limit))


def oldest_event_ts():
    return get_db().scalar("SELECT MIN(ts_utc) AS t FROM events")


def purge_older_than(cutoff_utc):
    """Delete events/signals older than cutoff, keeping evidence of open incidents."""
    db = get_db()
    keep = "SELECT event_id FROM signals WHERE alert_id IN (SELECT id FROM alerts WHERE status != 'Resolved') AND event_id IS NOT NULL"
    n_events = db.scalar(f"SELECT COUNT(*) AS n FROM events WHERE ts_utc < ? AND id NOT IN ({keep})", (cutoff_utc,), 0)
    db.execute("DELETE FROM signals WHERE ts_utc < ? AND (alert_id IS NULL OR alert_id IN (SELECT id FROM alerts WHERE status='Resolved'))",
               (cutoff_utc,))
    db.execute(f"DELETE FROM events WHERE ts_utc < ? AND id NOT IN ({keep})", (cutoff_utc,))
    db.execute("DELETE FROM audit_log WHERE ts < ?", ((datetime.fromisoformat(cutoff_utc) - timedelta(days=275)).isoformat(),))
    db.execute("UPDATE blocklist SET active=0 WHERE expires_at IS NOT NULL AND expires_at < ?", (now_iso(),))
    return n_events
