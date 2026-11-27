"""SQLite storage, alert de-duplication and incident correlation for MiniSOC."""
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import detection
from detection import SEV_ORDER, evaluate, is_system_account
from event_catalog import COLUMNS, level_name, to_utc_iso

APP_DIR = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'MiniSOC2'
APP_DIR.mkdir(parents=True, exist_ok=True)
DB = APP_DIR / 'minisoc.db'

CORRELATION_WINDOW_MIN = 30      # alerts sharing an actor within this window join one incident
HOST_FALLBACK_MIN = 10           # alerts with no actor join the newest incident on the host within this window
CLOSED = ('Resolved', 'Closed')


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


@contextmanager
def conn():
    c = sqlite3.connect(DB, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA journal_mode=WAL')       # UI can read while the collector writes
    c.execute('PRAGMA synchronous=NORMAL')
    c.execute('PRAGMA foreign_keys=ON')
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


def _dir(order):
    """Only ever returns ASC or DESC (safe to place in SQL)."""
    return 'ASC' if str(order).upper() == 'ASC' else 'DESC'


def _cols(c, table):
    return {r[1] for r in c.execute('PRAGMA table_info(%s)' % table)}


EVENTS_DDL = '''CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel TEXT NOT NULL DEFAULT 'Security', record_id INTEGER NOT NULL,
    event_id INTEGER, time_utc TEXT, level TEXT DEFAULT '', computer TEXT DEFAULT '',
    username TEXT DEFAULT '', subject_user TEXT DEFAULT '', source_ip TEXT DEFAULT '', logon_type TEXT DEFAULT '',
    logon_id TEXT DEFAULT '', process TEXT DEFAULT '', parent_process TEXT DEFAULT '', command_line TEXT DEFAULT '',
    process_guid TEXT DEFAULT '', parent_guid TEXT DEFAULT '', target TEXT DEFAULT '', dest_ip TEXT DEFAULT '',
    dest_port TEXT DEFAULT '', status TEXT DEFAULT '', hash TEXT DEFAULT '', tags TEXT DEFAULT '',
    data_json TEXT DEFAULT '', raw TEXT DEFAULT '', is_demo INTEGER DEFAULT 0,
    UNIQUE(channel, record_id))'''


def _migrate_v22_events(c):
    """v2.0-2.2 keyed events by record_id (Security only). Rebuild with (channel, record_id).
    Old rows keep id = old record_id so alerts.event_record_id still points at the right row."""
    cols = _cols(c, 'events')
    for name in ('level', 'logon_type'):
        if name not in cols:
            c.execute("ALTER TABLE events ADD COLUMN %s TEXT DEFAULT ''" % name)
    for r in c.execute("SELECT record_id,time_utc FROM events WHERE time_utc NOT LIKE '%+00:00'").fetchall():
        c.execute('UPDATE events SET time_utc=? WHERE record_id=?', (to_utc_iso(r['time_utc']), r['record_id']))
    for r in c.execute("SELECT record_id,event_id FROM events WHERE level IS NULL OR level=''").fetchall():
        c.execute('UPDATE events SET level=? WHERE record_id=?', (level_name(None, r['event_id']), r['record_id']))
    for idx in ('idx_events_time', 'idx_events_eid', 'idx_events_user', 'idx_events_ip'):
        c.execute('DROP INDEX IF EXISTS %s' % idx)
    c.execute('ALTER TABLE events RENAME TO events_v22')
    c.execute(EVENTS_DDL)
    c.execute('''INSERT INTO events(id,channel,record_id,event_id,time_utc,level,computer,username,source_ip,logon_type,raw,is_demo)
                 SELECT record_id,'Security',record_id,event_id,time_utc,COALESCE(level,''),COALESCE(computer,''),COALESCE(username,''),
                        COALESCE(source_ip,''),COALESCE(logon_type,''),COALESCE(raw,''),COALESCE(is_demo,0) FROM events_v22''')
    c.execute('DROP TABLE events_v22')
    old = c.execute("SELECT value FROM collector_state WHERE key='record_cursor'").fetchone() if _cols(c, 'collector_state') else None
    if old:
        c.execute("INSERT OR IGNORE INTO collector_state(key,value) VALUES('cursor:Security',?)", (old[0],))
        c.execute("DELETE FROM collector_state WHERE key='record_cursor'")


def create_schema(c):
    c.execute('CREATE TABLE IF NOT EXISTS collector_state(key TEXT PRIMARY KEY,value TEXT)')
    if _cols(c, 'events') and 'channel' not in _cols(c, 'events'):
        _migrate_v22_events(c)
    c.execute(EVENTS_DDL)
    c.executescript('''
    CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT,rule_id TEXT,severity TEXT,summary TEXT,created_utc TEXT,event_record_id INTEGER,status TEXT DEFAULT 'Open',notes TEXT DEFAULT '');
    CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT,severity TEXT,status TEXT DEFAULT 'Open',created_utc TEXT,updated_utc TEXT,description TEXT,alert_id INTEGER,owner TEXT DEFAULT '');
    CREATE TABLE IF NOT EXISTS response_requests(id INTEGER PRIMARY KEY AUTOINCREMENT,incident_id INTEGER,action TEXT,reason TEXT,status TEXT DEFAULT 'Pending Approval',created_utc TEXT,reviewed_utc TEXT,reviewed_by TEXT,review_note TEXT);
    CREATE TABLE IF NOT EXISTS activity(id INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT,action TEXT,details TEXT,created_utc TEXT);
    CREATE TABLE IF NOT EXISTS baseline(kind TEXT,key TEXT,first_seen TEXT,last_seen TEXT,count INTEGER DEFAULT 1,PRIMARY KEY(kind,key));
    CREATE TABLE IF NOT EXISTS allowlist(id INTEGER PRIMARY KEY AUTOINCREMENT,rule_id TEXT DEFAULT '*',field TEXT,pattern TEXT,note TEXT DEFAULT '',created_utc TEXT);
    ''')
    # v2.3 columns on alerts / incidents (no-ops on a fresh database)
    add = {'alerts': [('mitre', "TEXT DEFAULT ''"), ('dedupe_key', "TEXT DEFAULT ''"), ('hit_count', 'INTEGER DEFAULT 1'),
                      ('event_time_utc', "TEXT DEFAULT ''"), ('last_seen_utc', "TEXT DEFAULT ''"), ('incident_id', 'INTEGER')],
           'incidents': [('corr_keys', "TEXT DEFAULT ''"), ('alert_count', 'INTEGER DEFAULT 0'), ('mitre', "TEXT DEFAULT ''"),
                         ('last_event_utc', "TEXT DEFAULT ''")],
           # v2.4 response actions
           'response_requests': [('plan_json', "TEXT DEFAULT ''"), ('target', "TEXT DEFAULT ''"), ('alert_id', 'INTEGER'),
                                 ('mode', "TEXT DEFAULT 'manual'"), ('result', "TEXT DEFAULT ''"), ('executed_utc', "TEXT DEFAULT ''"),
                                 ('undo_json', "TEXT DEFAULT ''"), ('undone_utc', "TEXT DEFAULT ''"), ('expires_utc', "TEXT DEFAULT ''")]}
    for table, cols in add.items():
        have = _cols(c, table)
        for name, ddl in cols:
            if name not in have:
                c.execute('ALTER TABLE %s ADD COLUMN %s %s' % (table, name, ddl))
    c.execute("UPDATE alerts SET event_time_utc=created_utc WHERE event_time_utc IS NULL OR event_time_utc=''")
    c.execute("UPDATE alerts SET last_seen_utc=event_time_utc WHERE last_seen_utc IS NULL OR last_seen_utc=''")
    c.execute('UPDATE alerts SET incident_id=(SELECT i.id FROM incidents i WHERE i.alert_id=alerts.id) WHERE incident_id IS NULL')
    c.execute("UPDATE incidents SET alert_count=1 WHERE alert_count=0 AND alert_id IS NOT NULL")
    c.execute("UPDATE incidents SET last_event_utc=updated_utc WHERE last_event_utc IS NULL OR last_event_utc=''")
    for sql in ('CREATE INDEX IF NOT EXISTS idx_ev_time ON events(time_utc)',
                'CREATE INDEX IF NOT EXISTS idx_ev_kind ON events(channel,event_id,time_utc)',
                'CREATE INDEX IF NOT EXISTS idx_ev_user ON events(event_id,username,time_utc)',
                'CREATE INDEX IF NOT EXISTS idx_ev_ip ON events(event_id,source_ip,time_utc)',
                'CREATE INDEX IF NOT EXISTS idx_ev_logon ON events(logon_id,time_utc)',
                'CREATE INDEX IF NOT EXISTS idx_ev_guid ON events(process_guid,time_utc)',
                'CREATE INDEX IF NOT EXISTS idx_ev_proc_dest ON events(process,dest_ip,time_utc)',
                'CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_utc)',
                'CREATE INDEX IF NOT EXISTS idx_alerts_dedupe ON alerts(rule_id,dedupe_key,status)',
                'CREATE INDEX IF NOT EXISTS idx_inc_last ON incidents(last_event_utc)'):
        c.execute(sql)


def init():
    with conn() as c:
        create_schema(c)


def log(action, detail, actor='Local Admin'):
    with conn() as c:
        c.execute('INSERT INTO activity(actor,action,details,created_utc) VALUES(?,?,?,?)', (actor, action, detail, now()))


# ----------------------------------------------------------------------------- correlation
def _low(s):
    return (s or '').strip().lower()


def correlation_keys(c, e):
    """Identities an alert can be grouped by: logon session, user, source IP, host."""
    keys = []
    lid = _low(e.get('logon_id'))
    if not lid or lid in ('0x3e7', '0x3e4', '0x3e5', '0x0'):
        lid = ''
        guid = e.get('process_guid') or ''
        if guid and e.get('channel') == 'Sysmon':          # find the session through the process that did it
            r = c.execute("SELECT logon_id,username FROM events WHERE channel='Sysmon' AND event_id=1 AND process_guid=? LIMIT 1", (guid,)).fetchone()
            if r and _low(r[0]) not in ('', '0x3e7', '0x3e4', '0x3e5'):
                lid = _low(r[0])
    if lid:
        keys.append('logon:%s:%s' % (_low(e.get('computer')), lid))
    for u in (e.get('username'), e.get('subject_user')):
        if u and not is_system_account(u):
            k = 'user:' + _low(u)
            if k not in keys:
                keys.append(k)
    if e.get('source_ip') and e.get('channel') in ('Security', 'RDP-Auth', 'RDP-Session'):
        keys.append('ip:' + e['source_ip'])
    keys.append('host:' + _low(e.get('computer')))
    return keys


def _bump(sev, steps=1):
    i = SEV_ORDER.index(sev) if sev in SEV_ORDER else 2
    return SEV_ORDER[min(len(SEV_ORDER) - 1, i + steps)]


def _max_sev(a, b):
    return a if SEV_ORDER.index(a if a in SEV_ORDER else 'Info') >= SEV_ORDER.index(b if b in SEV_ORDER else 'Info') else b


def _actor(keys):
    for prefix in ('user:', 'ip:', 'logon:', 'host:'):
        for k in keys:
            if k.startswith(prefix):
                return k[len(prefix):]
    return 'unknown'


def _find_incident(c, keys, when, severity):
    since = (detection.dt(when) - timedelta(minutes=CORRELATION_WINDOW_MIN)).isoformat()
    rows = c.execute("SELECT id,corr_keys,last_event_utc FROM incidents WHERE status NOT IN (?,?) AND last_event_utc>=? "
                     "ORDER BY last_event_utc DESC LIMIT 100", CLOSED + (since,)).fetchall()
    strong = [k for k in keys if not k.startswith('host:')]
    for r in rows:
        if any('|%s|' % k in (r['corr_keys'] or '') for k in strong):
            return r['id']
    if SEV_ORDER.index(severity) >= SEV_ORDER.index('Medium'):
        host = next(k for k in keys if k.startswith('host:'))
        near = (detection.dt(when) - timedelta(minutes=HOST_FALLBACK_MIN)).isoformat()
        for r in rows:
            if r['last_event_utc'] >= near and '|%s|' % host in (r['corr_keys'] or ''):
                return r['id']
    return None


def _attach(c, iid, alert_id, d, keys, when):
    inc = c.execute('SELECT * FROM incidents WHERE id=?', (iid,)).fetchone()
    merged = [k for k in (inc['corr_keys'] or '').strip('|').split('|') if k]
    merged += [k for k in keys if k not in merged]
    mitre = sorted({m for m in (inc['mitre'] or '').split(', ') if m} | {d['mitre']} - {''})
    count = (inc['alert_count'] or 0) + 1
    prior = c.execute('SELECT rule_id,severity FROM alerts WHERE incident_id=?', (iid,)).fetchall()
    rules = {r[0] for r in prior} | {d['rule_id']}
    sev = d['severity']
    for r in prior:
        sev = _max_sev(sev, r[1])
    if len(rules) >= 3:                      # several different techniques by one actor -> one level up
        sev = _bump(sev)
    sev = _max_sev(sev, inc['severity'])
    title = inc['title'] if count < 2 else 'Multi-stage activity: %s (%d alerts, %d techniques)' % (_actor(merged), count, len(mitre))
    desc = (inc['description'] or '') + '\n[%s] %s  %s  %s' % (when[:19].replace('T', ' '), d['severity'], d['rule_id'], d['summary'])
    c.execute('UPDATE incidents SET corr_keys=?,mitre=?,alert_count=?,severity=?,title=?,description=?,updated_utc=?,last_event_utc=MAX(last_event_utc,?) WHERE id=?',
              ('|' + '|'.join(merged) + '|', ', '.join(mitre), count, sev, title, desc, now(), when, iid))
    c.execute('UPDATE alerts SET incident_id=? WHERE id=?', (iid, alert_id))


def _emit(c, e, d, event_row, sink=None):
    """Store one detection. Returns 1 for a new alert, 0 if it was folded into an existing one.
    sink (list) receives the id of every new or ESCALATED alert (input for auto-response)."""
    when = e.get('time_utc') or now()
    since = (detection.dt(when) - timedelta(minutes=d.get('window', 60))).isoformat()
    dup = c.execute("SELECT id,incident_id,severity FROM alerts WHERE rule_id=? AND dedupe_key=? AND status='Open' AND last_seen_utc>=? "
                    "ORDER BY id DESC LIMIT 1", (d['rule_id'], d['key'], since)).fetchone()
    if dup:
        c.execute('UPDATE alerts SET hit_count=hit_count+1,last_seen_utc=MAX(last_seen_utc,?) WHERE id=?', (when, dup['id']))
        if SEV_ORDER.index(d['severity']) > SEV_ORDER.index(dup['severity'] if dup['severity'] in SEV_ORDER else 'Info'):
            # same activity got worse (e.g. 100 -> 300 files encrypted): escalate the existing alert
            c.execute('UPDATE alerts SET severity=?,summary=?,event_record_id=COALESCE(?,event_record_id) WHERE id=?',
                      (d['severity'], d['summary'], event_row, dup['id']))
            if dup['incident_id']:
                inc = c.execute('SELECT severity FROM incidents WHERE id=?', (dup['incident_id'],)).fetchone()
                c.execute('UPDATE incidents SET severity=? WHERE id=?', (_max_sev(inc['severity'], d['severity']), dup['incident_id']))
            if sink is not None:
                sink.append(dup['id'])
        if dup['incident_id']:
            c.execute('UPDATE incidents SET last_event_utc=MAX(last_event_utc,?) WHERE id=?', (when, dup['incident_id']))
        return 0
    cur = c.execute('INSERT INTO alerts(rule_id,severity,mitre,summary,created_utc,event_time_utc,last_seen_utc,hit_count,dedupe_key,event_record_id) '
                    'VALUES(?,?,?,?,?,?,?,1,?,?)', (d['rule_id'], d['severity'], d['mitre'], d['summary'], now(), when, when, d['key'], event_row))
    aid = cur.lastrowid
    keys = correlation_keys(c, e)
    iid = _find_incident(c, keys, when, d['severity'])
    if iid:
        _attach(c, iid, aid, d, keys, when)
    elif d['severity'] != 'Low' and d['severity'] != 'Info':
        cur = c.execute('INSERT INTO incidents(title,severity,status,created_utc,updated_utc,last_event_utc,description,alert_id,corr_keys,alert_count,mitre) '
                        'VALUES(?,?,?,?,?,?,?,?,?,1,?)',
                        (d['summary'][:200], d['severity'], 'Open', now(), now(), when,
                         '[%s] %s  %s  %s' % (when[:19].replace('T', ' '), d['severity'], d['rule_id'], d['summary']), aid,
                         '|' + '|'.join(keys) + '|', d['mitre']))
        c.execute('UPDATE alerts SET incident_id=? WHERE id=?', (cur.lastrowid, aid))
    if sink is not None:
        sink.append(aid)
    return 1


# ----------------------------------------------------------------------------- ingest
def _ingest_one(c, e, sink=None):
    e = dict(e)
    e.setdefault('channel', 'Security')
    e['time_utc'] = to_utc_iso(e.get('time_utc') or now())
    e['level'] = e.get('level') or level_name(None, e['event_id'])
    for k in COLUMNS + ('computer', 'raw', 'data_json'):
        e[k] = str(e.get(k) or '')
    e['tags'] = detection.tags(e)
    cur = c.execute(
        'INSERT OR IGNORE INTO events(channel,record_id,event_id,time_utc,level,computer,%s,tags,data_json,raw,is_demo) '
        'VALUES(?,?,?,?,?,?,%s,?,?,?,?)' % (','.join(COLUMNS), ','.join('?' * len(COLUMNS))),
        (e['channel'], int(e['record_id']), int(e['event_id']), e['time_utc'], e['level'], e['computer'])
        + tuple(e[k] for k in COLUMNS) + (e['tags'], e['data_json'], e['raw'], int(e.get('is_demo', 0))))
    if cur.rowcount == 0:
        return 0
    row_id = cur.lastrowid
    new = sum(_emit(c, e, d, row_id, sink) for d in evaluate(c, e))
    if new:
        c.execute('INSERT INTO activity(actor,action,details,created_utc) VALUES(?,?,?,?)',
                  ('Detection', 'Alert generated', '%d alert(s) from %s event %s #%s' % (new, e['channel'], e['event_id'], e['record_id']), now()))
    return new


def ingest(e, sink=None):
    with conn() as c:
        return _ingest_one(c, e, sink)


def ingest_many(events, sink=None):
    """Insert a whole batch in ONE connection / ONE transaction."""
    n = 0
    with conn() as c:
        for e in events:
            n += _ingest_one(c, e, sink)
    return n


def system_alert(rule_id, severity, mitre, summary, key, computer=''):
    """Alert raised by the collector itself (sensor lost, log silent...)."""
    with conn() as c:
        e = {'channel': 'MiniSOC', 'event_id': 0, 'time_utc': now(), 'computer': computer}
        return _emit(c, e, dict(rule_id=rule_id, severity=severity, mitre=mitre, summary=summary, key=key, window=240), None)


def rows(sql, args=()):
    with conn() as c:
        return c.execute(sql, args).fetchall()


# ----------------------------------------------------------------------------- queries
SEARCH_COLS = ('CAST(event_id AS TEXT)', 'channel', 'username', 'source_ip', 'computer', 'process', 'parent_process',
               'command_line', 'target', 'dest_ip', 'hash', 'logon_id')


def events(search='', order='DESC', level='', source='', limit=1000, channel=''):
    d = _dir(order)
    where, args = [], []
    if search:
        q = '%' + search + '%'
        where.append('(' + ' OR '.join('%s LIKE ?' % col for col in SEARCH_COLS) + ')')
        args += [q] * len(SEARCH_COLS)
    if level:
        where.append('level=?')
        args.append(level)
    if channel:
        where.append('channel=?')
        args.append(channel)
    if source == 'Live':
        where.append('is_demo=0')
    elif source == 'Demo':
        where.append('is_demo=1')
    clause = (' WHERE ' + ' AND '.join(where)) if where else ''
    total = rows('SELECT COUNT(*) FROM events' + clause, args)[0][0]
    data = rows('SELECT * FROM (SELECT * FROM events%s ORDER BY time_utc DESC,id DESC LIMIT ?) ORDER BY time_utc %s,id %s' % (clause, d, d),
                args + [int(limit)])
    return data, total


def event(row_id):
    r = rows('SELECT * FROM events WHERE id=?', (row_id,))
    return r[0] if r else None


def alerts(order='DESC', limit=500):
    d = _dir(order)
    return rows('SELECT * FROM (SELECT a.*,e.username,e.source_ip,e.event_id,e.channel,e.process,e.command_line,e.target AS ev_target '
                'FROM alerts a LEFT JOIN events e ON e.id=a.event_record_id '
                'ORDER BY a.created_utc DESC,a.id DESC LIMIT %d) ORDER BY created_utc %s,id %s' % (int(limit), d, d))


def incidents(order='DESC'):
    d = _dir(order)
    return rows('SELECT * FROM (SELECT i.*,a.rule_id FROM incidents i LEFT JOIN alerts a ON a.id=i.alert_id '
                'ORDER BY i.created_utc DESC,i.id DESC LIMIT 1000) ORDER BY created_utc %s,id %s' % (d, d))


def incident_alerts(iid):
    return rows('SELECT a.*,e.channel,e.event_id,e.username,e.process,e.command_line,e.target AS ev_target,e.source_ip '
                'FROM alerts a LEFT JOIN events e ON e.id=a.event_record_id WHERE a.incident_id=? ORDER BY a.event_time_utc,a.id', (iid,))


def incident(iid):
    r = rows('SELECT * FROM incidents WHERE id=?', (iid,))
    return r[0] if r else None


def response_requests(order='DESC'):
    d = _dir(order)
    return rows('SELECT r.*,i.title AS incident_title FROM response_requests r LEFT JOIN incidents i ON i.id=r.incident_id ORDER BY r.created_utc %s,r.id %s' % (d, d))


def activities(order='DESC'):
    d = _dir(order)
    return rows('SELECT * FROM (SELECT * FROM activity ORDER BY created_utc DESC,id DESC LIMIT 500) ORDER BY created_utc %s,id %s' % (d, d))


def stats():
    with conn() as c:
        one = lambda sql: c.execute(sql).fetchone()[0]
        return {
            'events': one('SELECT COUNT(*) FROM events'),
            'alerts': one('SELECT COUNT(*) FROM alerts'),
            'incidents': one('SELECT COUNT(*) FROM incidents'),
            'open_alerts': one("SELECT COUNT(*) FROM alerts WHERE status='Open'"),
            'crit_high': one("SELECT COUNT(*) FROM alerts WHERE status='Open' AND severity IN ('Critical','High')"),
            'open_incidents': one("SELECT COUNT(*) FROM incidents WHERE status NOT IN ('Resolved','Closed')"),
            'pending': one("SELECT COUNT(*) FROM response_requests WHERE status='Pending Approval'"),
        }


def coverage():
    """Per (channel, event ID): how much has actually been recorded (live events only)."""
    per_id = {(r['channel'], r['event_id']): r for r in
              rows('SELECT channel,event_id,COUNT(*) n,MIN(time_utc) first,MAX(time_utc) last FROM events WHERE is_demo=0 GROUP BY channel,event_id')}
    levels = {r['level'] or 'Unknown': r['n'] for r in rows('SELECT level,COUNT(*) n FROM events WHERE is_demo=0 GROUP BY level')}
    span = rows('SELECT COUNT(*) n,MIN(time_utc) first,MAX(time_utc) last FROM events WHERE is_demo=0')[0]
    demo = rows('SELECT COUNT(*) FROM events WHERE is_demo=1')[0][0]
    return per_id, levels, span, demo


def last_event_time(channel):
    r = rows('SELECT MAX(time_utc) FROM events WHERE channel=? AND is_demo=0', (channel,))
    return r[0][0] if r else None


# ----------------------------------------------------------------------------- actions
def close_alert(aid):
    with conn() as c:
        c.execute("UPDATE alerts SET status='Closed' WHERE id=?", (aid,))
    log('Alert closed', 'Alert #%s' % aid)


def create_incident(title, severity, desc='', owner=''):
    with conn() as c:
        cur = c.execute('INSERT INTO incidents(title,severity,status,created_utc,updated_utc,last_event_utc,description,owner) VALUES(?,?,?,?,?,?,?,?)',
                        (title, severity, 'Open', now(), now(), now(), desc, owner))
        iid = cur.lastrowid
    log('Incident created', '#%s %s' % (iid, title))
    return iid


def update_incident(iid, status, owner):
    with conn() as c:
        c.execute('UPDATE incidents SET status=?,owner=?,updated_utc=? WHERE id=?', (status, owner, now(), iid))
        if status in CLOSED:
            c.execute("UPDATE alerts SET status='Closed' WHERE incident_id=? AND status='Open'", (iid,))
    log('Incident updated', '#%s status=%s, owner=%s' % (iid, status, owner))


def request_response(iid, action, reason):
    with conn() as c:
        cur = c.execute('INSERT INTO response_requests(incident_id,action,reason,created_utc) VALUES(?,?,?,?)', (iid, action, reason, now()))
        rid = cur.lastrowid
    log('Response requested', '#%s incident #%s action=%s' % (rid, iid, action))
    return rid


def review_response(rid, approve, reviewer, note):
    """Record the reviewer's decision. Approved requests are then executed by response.run_request()."""
    status = 'Approved' if approve else 'Rejected'
    with conn() as c:
        c.execute('UPDATE response_requests SET status=?,reviewed_utc=?,reviewed_by=?,review_note=? WHERE id=?', (status, now(), reviewer, note, rid))
    log('Response reviewed', 'Request #%s: %s by %s' % (rid, status, reviewer))


# ----------------------------------------------------------------------------- response actions (v2.4)
def add_response(iid, plan, reason, mode='manual'):
    """Store a planned action. Manual -> 'Pending Approval'; auto -> 'Running' until finish_response()."""
    status = 'Running' if mode == 'auto' else 'Pending Approval'
    with conn() as c:
        cur = c.execute('INSERT INTO response_requests(incident_id,action,reason,status,created_utc,plan_json,target,alert_id,mode,reviewed_by) '
                        'VALUES(?,?,?,?,?,?,?,?,?,?)',
                        (iid, plan['label'], reason, status, now(), json.dumps(plan), plan.get('target', ''), plan.get('alert_id'), mode,
                         'MiniSOC (auto)' if mode == 'auto' else None))
        rid = cur.lastrowid
    log('Response requested', '#%s %s: %s -> %s' % (rid, mode, plan['label'], plan.get('target', '')), 'MiniSOC' if mode == 'auto' else 'Local Admin')
    return rid


def finish_response(rid, status, result, undo_params, expires):
    with conn() as c:
        c.execute('UPDATE response_requests SET status=?,result=?,executed_utc=?,undo_json=?,expires_utc=? WHERE id=?',
                  (status, result, now(), json.dumps(undo_params) if undo_params else '', expires or '', rid))
    log('Response ' + status.lower(), '#%s %s' % (rid, result[:300]), 'Response')


def mark_undone(rid, status, text):
    with conn() as c:
        if status in ('Undone', 'Expired'):
            c.execute("UPDATE response_requests SET status=?,undone_utc=?,result=result||? WHERE id=?",
                      (status, now(), '\n' + status + ': ' + text, rid))
        else:
            # clear expires_utc so a failing expiry is not retried (and logged) every minute forever
            c.execute("UPDATE response_requests SET result=result||?,expires_utc='' WHERE id=?", ('\nUndo failed: ' + text, rid))
    log('Response undo', '#%s %s: %s' % (rid, status, text[:300]), 'Response')


def response_request(rid):
    r = rows('SELECT * FROM response_requests WHERE id=?', (rid,))
    return r[0] if r else None


def alert(aid):
    r = rows('SELECT * FROM alerts WHERE id=?', (aid,))
    return r[0] if r else None


def isolation_active():
    for r in rows("SELECT id,plan_json FROM response_requests WHERE status='Executed' AND plan_json LIKE '%isolate_host%' ORDER BY id DESC"):
        if json.loads(r['plan_json'] or '{}').get('action') == 'isolate_host':
            return r['id']
    return None


def expired_blocks():
    return rows("SELECT * FROM response_requests WHERE status='Executed' AND expires_utc!='' AND expires_utc<=?", (now(),))


# ----------------------------------------------------------------------------- tuning
def allowlist():
    return rows('SELECT * FROM allowlist ORDER BY id DESC')


def add_allow(rule_id, field, pattern, note=''):
    if field not in detection.ALLOW_FIELDS or not pattern.strip():
        raise ValueError('Choose a field and a non-empty value')
    with conn() as c:
        c.execute('INSERT INTO allowlist(rule_id,field,pattern,note,created_utc) VALUES(?,?,?,?,?)',
                  (rule_id or '*', field, pattern.strip(), note, now()))
    log('Allowlist added', '%s: %s contains "%s"' % (rule_id or '*', field, pattern.strip()))


def delete_allow(aid):
    with conn() as c:
        c.execute('DELETE FROM allowlist WHERE id=?', (aid,))
    log('Allowlist removed', 'entry #%s' % aid)


def setting(key, default=None):
    r = rows('SELECT value FROM collector_state WHERE key=?', (key,))
    return r[0][0] if r else default


def set_setting(key, value):
    with conn() as c:
        c.execute('INSERT INTO collector_state(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, str(value)))


def baseline_status():
    with conn() as c:
        start = detection._state(c, 'baseline_start')
        until = detection.learning_until(c) if start else None
        counts = {r[0]: r[1] for r in c.execute('SELECT kind,COUNT(*) FROM baseline GROUP BY kind')}
    return start, until, counts


def reset_baseline():
    with conn() as c:
        c.execute('DELETE FROM baseline')
        c.execute("DELETE FROM collector_state WHERE key='baseline_start'")
    log('Baseline reset', 'Learning restarts with the next live event')


def prune(days):
    """Delete events older than N days that no alert points at."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=int(days))).isoformat()
    with conn() as c:
        n = c.execute('DELETE FROM events WHERE time_utc<? AND id NOT IN (SELECT event_record_id FROM alerts WHERE event_record_id IS NOT NULL)',
                      (cutoff,)).rowcount
    if n:
        log('Retention', 'Deleted %d events older than %s days' % (n, days), 'System')
    return n


# ----------------------------------------------------------------------------- collector cursors
def cursors():
    """{channel: last record id}; channels never read are absent (=> first run)."""
    return {r['key'][7:]: int(r['value']) for r in rows("SELECT key,value FROM collector_state WHERE key LIKE 'cursor:%'")}


def save_cursors(cur):
    with conn() as c:
        for ch, n in cur.items():
            if n is not None:
                c.execute('INSERT INTO collector_state(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                          ('cursor:' + ch, str(int(n))))


# v2.2 API (single Security cursor) - kept so old scripts keep working
def cursor():
    return cursors().get('Security', 0)


def save_cursor(n):
    save_cursors({'Security': n})


# ----------------------------------------------------------------------------- demo
def add_demo(sink=None):
    """A realistic attack chain (all rows flagged DEMO) that exercises correlation."""
    base = int(datetime.now().timestamp() * 1000) * 100
    t0 = datetime.now(timezone.utc) - timedelta(minutes=4)
    u, ip, lid, host = 'DEMO-PC\\demo-user', '198.51.100.24', '0xde301', 'DEMO-PC'
    guid = lambda n: '{DEMO%04d-0000-0000-0000-%012d}' % (n, base % 10 ** 12)
    proc = lambda i, img, cmd, parent='C:\\Windows\\System32\\cmd.exe': dict(
        channel='Sysmon', event_id=1, process=img, command_line=cmd, parent_process=parent, logon_id=lid, username=u,
        process_guid=guid(i), level='Information',
        data_json=json.dumps({'ProcessId': str(4000 + 16 * i), 'ParentProcessId': str(3000 + i)}))
    steps = [dict(channel='Security', event_id=4625, username=u, source_ip=ip, logon_type='10 - RemoteInteractive (RDP)',
                  status='0xc000006a (wrong password)', level='Audit Failure') for _ in range(6)]
    steps += [
        dict(channel='Security', event_id=4624, username=u, source_ip=ip, logon_type='10 - RemoteInteractive (RDP)', logon_id=lid, level='Audit Success'),
        dict(channel='Security', event_id=4672, username=u, logon_id=lid, level='Audit Success'),
        proc(1, 'C:\\Windows\\System32\\whoami.exe', 'whoami /all'),
        proc(2, 'C:\\Windows\\System32\\net.exe', 'net user'),
        proc(3, 'C:\\Windows\\System32\\net.exe', 'net localgroup administrators'),
        proc(4, 'C:\\Windows\\System32\\ipconfig.exe', 'ipconfig /all'),
        proc(5, 'C:\\Windows\\System32\\systeminfo.exe', 'systeminfo'),
        proc(6, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
             'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA'),
        proc(7, 'C:\\Users\\Public\\svc.exe', 'C:\\Users\\Public\\svc.exe', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'),
        dict(channel='Sysmon', event_id=10, process='C:\\Users\\Public\\svc.exe', process_guid=guid(7), target='C:\\Windows\\system32\\lsass.exe',
             status='0x1410', level='Information', data_json=json.dumps({'SourceProcessId': str(4000 + 16 * 7)})),
        dict(channel='System', event_id=7045, target='UpdaterSvc', command_line='C:\\Users\\Public\\svc.exe', username='LocalSystem', level='Information'),
        proc(8, 'C:\\Windows\\System32\\vssadmin.exe', 'vssadmin.exe delete shadows /all /quiet'),
    ]
    n = 0
    with conn() as c:
        for i, s in enumerate(steps):
            s.update(record_id=base + i, time_utc=(t0 + timedelta(seconds=10 * i)).isoformat(), computer=host, is_demo=1,
                     raw='DEMO ONLY - synthetic attack chain')
            n += _ingest_one(c, s, sink)
    log('Demo inserted', 'Synthetic attack chain (%d events, %d alerts) inserted with DEMO flag' % (len(steps), n))
    return n
