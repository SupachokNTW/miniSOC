"""Tiny database adapter: SQLite locally, PostgreSQL (e.g. Neon via Vercel Marketplace) in the cloud.

SQL in the app is written once with `?` placeholders and portable syntax
(`ON CONFLICT ... DO NOTHING/UPDATE`, no SQLite-only functions). The adapter converts
placeholders for psycopg and returns rows as dictionaries for both engines.

Connections are request-scoped inside Flask (committed in teardown) and thread-local
outside a request (background collector, cron, scripts) — use `transaction()` there.
"""
import os
import sqlite3
import threading
from contextlib import contextmanager

import config

try:  # flask is optional for scripts/tests
    from flask import g, has_app_context
except ImportError:  # pragma: no cover
    g = None

    def has_app_context():
        return False

_local = threading.local()
_PG_CONNECT = None  # overridable by tests (see tests/pg_shim.py)


class Database:
    def __init__(self, raw, postgres):
        self.raw = raw
        self.pg = postgres

    # -- SQL translation -------------------------------------------------
    def _sql(self, sql):
        if not self.pg:
            return sql
        return sql.replace("%", "%%").replace("?", "%s")

    def execute(self, sql, args=()):
        cur = self.raw.cursor()
        cur.execute(self._sql(sql), tuple(args))
        return cur

    def query(self, sql, args=()):
        return [dict(r) for r in self.execute(sql, args).fetchall()]

    def one(self, sql, args=()):
        row = self.execute(sql, args).fetchone()
        return dict(row) if row is not None else None

    def scalar(self, sql, args=(), default=None):
        row = self.execute(sql, args).fetchone()
        if row is None:
            return default
        value = list(dict(row).values())[0]
        return default if value is None else value

    def insert(self, sql, args=()):
        """Run an INSERT and return the new row id."""
        if self.pg:
            cur = self.execute(sql.rstrip().rstrip(";") + " RETURNING id", args)
            row = cur.fetchone()
            return dict(row)["id"] if row else None
        return self.execute(sql, args).lastrowid

    def insert_many(self, table, columns, rows, chunk=400):
        """Bulk insert; returns ids in input order."""
        ids = []
        cols = ", ".join(columns)
        if not rows:
            return ids
        if self.pg:
            for start in range(0, len(rows), chunk):
                part = rows[start:start + chunk]
                placeholders = ", ".join("(" + ", ".join(["?"] * len(columns)) + ")" for _ in part)
                args = [v for row in part for v in row]
                cur = self.execute(f"INSERT INTO {table} ({cols}) VALUES {placeholders} RETURNING id", args)
                ids.extend(dict(r)["id"] for r in cur.fetchall())  # PostgreSQL returns VALUES order
        else:
            sql = f"INSERT INTO {table} ({cols}) VALUES ({', '.join(['?'] * len(columns))})"
            for row in rows:
                ids.append(self.raw.execute(sql, row).lastrowid)
        return ids

    def columns(self, table):
        if self.pg:
            rows = self.query("SELECT column_name FROM information_schema.columns WHERE table_name = ?", (table,))
            return {r["column_name"] for r in rows}
        return {r[1] for r in self.raw.execute(f"PRAGMA table_info({table})").fetchall()}

    def commit(self):
        self.raw.commit()

    def rollback(self):
        try:
            self.raw.rollback()
        except Exception:
            pass

    def close(self):
        try:
            self.raw.close()
        except Exception:
            pass


def _open():
    if config.USE_POSTGRES:
        if _PG_CONNECT is not None:
            return Database(_PG_CONNECT(config.DATABASE_URL), True)
        import psycopg
        from psycopg.rows import dict_row
        # prepare_threshold=None keeps psycopg compatible with PgBouncer/Neon pooled URLs.
        raw = psycopg.connect(config.DATABASE_URL, row_factory=dict_row, prepare_threshold=None,
                              connect_timeout=10)
        return Database(raw, True)
    os.makedirs(os.path.dirname(config.SQLITE_PATH) or ".", exist_ok=True)
    raw = sqlite3.connect(config.SQLITE_PATH, timeout=30, check_same_thread=False)
    raw.row_factory = sqlite3.Row
    raw.execute("PRAGMA foreign_keys = ON")
    return Database(raw, False)


def get_db():
    if has_app_context():
        if "minisoc_db" not in g:
            g.minisoc_db = _open()
        return g.minisoc_db
    if getattr(_local, "db", None) is None:
        _local.db = _open()
    return _local.db


def close_request_db(exc=None):
    db = g.pop("minisoc_db", None) if g is not None else None
    if db is None:
        return
    if exc is None:
        db.commit()
    else:
        db.rollback()
    db.close()


@contextmanager
def transaction():
    """For work outside a Flask request (collector thread, scripts)."""
    db = get_db()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise


def reset_thread_connection():
    db = getattr(_local, "db", None)
    if db is not None:
        db.close()
    _local.db = None


# ---------------------------------------------------------------- schema

def _schema(pg):
    pk = "BIGSERIAL PRIMARY KEY" if pg else "INTEGER PRIMARY KEY AUTOINCREMENT"
    big = "BIGINT"
    return [
        f"""CREATE TABLE IF NOT EXISTS events (
            id {pk}, timestamp TEXT NOT NULL, source TEXT NOT NULL, event_type TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'Info', host TEXT NOT NULL DEFAULT 'localhost', username TEXT,
            source_ip TEXT, details TEXT NOT NULL, event_code TEXT, created_at TEXT NOT NULL, source_record_id TEXT)""",
        "CREATE TABLE IF NOT EXISTS collector_state (name TEXT PRIMARY KEY, value TEXT NOT NULL)",
        f"""CREATE TABLE IF NOT EXISTS alerts (
            id {pk}, event_id {big}, rule_name TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL,
            explanation TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'New', created_at TEXT NOT NULL)""",
        f"""CREATE TABLE IF NOT EXISTS detection_rules (
            id {pk}, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL, severity TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1)""",
        f"""CREATE TABLE IF NOT EXISTS imports (
            id {pk}, filename TEXT NOT NULL, file_format TEXT NOT NULL, vendor TEXT, sha256 TEXT NOT NULL,
            size_bytes {big} NOT NULL DEFAULT 0, timezone TEXT, total_records INTEGER NOT NULL DEFAULT 0,
            event_count INTEGER NOT NULL DEFAULT 0, skipped INTEGER NOT NULL DEFAULT 0,
            alert_count INTEGER NOT NULL DEFAULT 0, first_seen TEXT, last_seen TEXT, meta TEXT, warnings TEXT,
            created_at TEXT NOT NULL)""",
        f"""CREATE TABLE IF NOT EXISTS signals (
            id {pk}, rule_id TEXT NOT NULL, rule_title TEXT NOT NULL, level TEXT NOT NULL, event_id {big},
            import_id {big}, ts TEXT NOT NULL, ts_utc TEXT, entity_type TEXT NOT NULL, entity_value TEXT NOT NULL,
            base_score DOUBLE PRECISION NOT NULL DEFAULT 0, risk_score DOUBLE PRECISION NOT NULL DEFAULT 0,
            mitre TEXT, message TEXT, alert_id {big}, direct_alert INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)""",
        "CREATE TABLE IF NOT EXISTS rule_state (rule_id TEXT PRIMARY KEY, enabled INTEGER NOT NULL, updated_at TEXT, updated_by TEXT)",
        f"""CREATE TABLE IF NOT EXISTS assets (
            id {pk}, ip TEXT, hostname TEXT, name TEXT, criticality INTEGER NOT NULL DEFAULT 3, owner TEXT,
            tags TEXT, auto INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT)""",
        f"""CREATE TABLE IF NOT EXISTS identities (
            id {pk}, username TEXT NOT NULL UNIQUE, display_name TEXT, department TEXT, email TEXT,
            privileged INTEGER NOT NULL DEFAULT 0, auto INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)""",
        f"""CREATE TABLE IF NOT EXISTS playbook_runs (
            id {pk}, playbook_id TEXT NOT NULL, playbook_title TEXT, alert_id {big}, status TEXT NOT NULL,
            actions TEXT, created_at TEXT NOT NULL, approved_by TEXT, approved_at TEXT)""",
        f"""CREATE TABLE IF NOT EXISTS blocklist (
            id {pk}, value TEXT NOT NULL UNIQUE, kind TEXT NOT NULL, reason TEXT, source TEXT, alert_id {big},
            created_at TEXT NOT NULL, expires_at TEXT, active INTEGER NOT NULL DEFAULT 1, created_by TEXT)""",
        f"""CREATE TABLE IF NOT EXISTS incident_tasks (
            id {pk}, alert_id {big} NOT NULL, text TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)""",
        f"""CREATE TABLE IF NOT EXISTS incident_notes (
            id {pk}, alert_id {big} NOT NULL, author TEXT, text TEXT NOT NULL, created_at TEXT NOT NULL)""",
        "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        f"""CREATE TABLE IF NOT EXISTS users (
            id {pk}, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL,
            created_at TEXT NOT NULL, last_login TEXT, disabled INTEGER NOT NULL DEFAULT 0)""",
        f"""CREATE TABLE IF NOT EXISTS api_keys (
            id {pk}, name TEXT NOT NULL, prefix TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL,
            last_used TEXT, created_by TEXT, revoked INTEGER NOT NULL DEFAULT 0)""",
        f"""CREATE TABLE IF NOT EXISTS audit_log (
            id {pk}, ts TEXT NOT NULL, username TEXT, ip TEXT, action TEXT NOT NULL, detail TEXT)""",
        f"""CREATE TABLE IF NOT EXISTS simulation_runs (
            id {pk}, scenario TEXT NOT NULL, title TEXT, expected TEXT, fired TEXT, missing TEXT,
            passed INTEGER NOT NULL DEFAULT 0, events INTEGER NOT NULL DEFAULT 0, import_id {big}, created_at TEXT NOT NULL)""",
    ]


EVENT_COLUMNS = {
    "source_record_id": "TEXT", "dest_ip": "TEXT", "dest_port": "TEXT", "action": "TEXT", "signature": "TEXT",
    "import_id": "BIGINT", "ts_utc": "TEXT", "extra": "TEXT", "dataset": "TEXT", "country": "TEXT",
    "http_status": "INTEGER", "bytes_out": "BIGINT", "http_method": "TEXT", "url_path": "TEXT",
    "hits": "INTEGER NOT NULL DEFAULT 1",
}
ALERT_COLUMNS = {
    "rule_id": "TEXT", "entity_type": "TEXT", "entity_value": "TEXT", "risk_score": "DOUBLE PRECISION",
    "signal_count": "INTEGER NOT NULL DEFAULT 0", "first_event_ts": "TEXT", "last_event_ts": "TEXT",
    "mitre": "TEXT", "disposition": "TEXT", "acknowledged_at": "TEXT", "resolved_at": "TEXT",
    "assignee": "TEXT", "updated_at": "TEXT", "context": "TEXT",
}
IMPORT_COLUMNS = {
    "raw_records": "INTEGER NOT NULL DEFAULT 0", "stored_events": "INTEGER NOT NULL DEFAULT 0",
    "summarized": "INTEGER NOT NULL DEFAULT 0", "signal_count": "INTEGER NOT NULL DEFAULT 0",
    "incident_count": "INTEGER NOT NULL DEFAULT 0", "options": "TEXT", "uploaded_by": "TEXT",
}
INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_events_import ON events(import_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_utc)",
    "CREATE INDEX IF NOT EXISTS idx_events_type_ts ON events(event_type, ts_utc)",
    "CREATE INDEX IF NOT EXISTS idx_events_user ON events(username)",
    "CREATE INDEX IF NOT EXISTS idx_events_src ON events(source_ip)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_entity ON alerts(entity_type, entity_value)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)",
    "CREATE INDEX IF NOT EXISTS idx_signals_entity ON signals(entity_type, entity_value, ts_utc)",
    "CREATE INDEX IF NOT EXISTS idx_signals_rule ON signals(rule_id, ts_utc)",
    "CREATE INDEX IF NOT EXISTS idx_signals_alert ON signals(alert_id)",
    "CREATE INDEX IF NOT EXISTS idx_signals_event ON signals(event_id)",
    "CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip)",
    "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)",
]


SCHEMA_VERSION = "1.0.0"


def init_schema(db):
    """Create/migrate tables. Skipped quickly when already at SCHEMA_VERSION (fast serverless cold starts)."""
    try:
        row = db.one("SELECT value FROM settings WHERE key='schema_version'")
        if row and row["value"] == SCHEMA_VERSION:
            return
    except Exception:  # noqa: BLE001 - settings table does not exist yet
        db.rollback()
    if not db.pg:
        try:
            db.raw.execute("PRAGMA journal_mode=WAL")
        except sqlite3.DatabaseError:
            pass
    for statement in _schema(db.pg):
        db.execute(statement)
    for table, wanted in (("events", EVENT_COLUMNS), ("alerts", ALERT_COLUMNS), ("imports", IMPORT_COLUMNS)):
        existing = db.columns(table)
        for column, col_type in wanted.items():
            if column not in existing:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
    for statement in INDEXES:
        db.execute(statement)
    db.execute("INSERT INTO settings(key, value) VALUES('schema_version', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
               (SCHEMA_VERSION,))
    db.commit()
