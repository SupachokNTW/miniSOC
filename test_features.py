"""Parser, storage, migration, correlation and collector tests (no Windows needed)."""
import json
import os
import sqlite3
import tempfile
import unittest

os.environ['LOCALAPPDATA'] = tempfile.mkdtemp()   # isolate the test database
import database as db
import event_catalog as cat
import windows_collector as wc

def fresh_db():
    db.DB = db.Path(tempfile.mkdtemp()) / 'minisoc.db'
    db.init()


NS = 'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'


def xml(channel, eid, data='', user_data='', level=0, keywords=None, rec=100):
    if keywords is None:
        keywords = '0x8020000000000000' if channel == 'Security' else '0x8000000000000000'
    return ('<Event %s><System><Provider Name="P"/><EventID>%d</EventID><Level>%d</Level><Keywords>%s</Keywords>'
            '<TimeCreated SystemTime="2026-11-24T07:31:05.1234567Z"/><EventRecordID>%d</EventRecordID>'
            '<Channel>%s</Channel><Computer>PC1.corp.local</Computer></System>%s%s</Event>'
            % (NS, eid, level, keywords, rec, channel, ('<EventData>%s</EventData>' % data) if data else '',
               ('<UserData>%s</UserData>' % user_data) if user_data else ''))


def d(**kw):
    return ''.join('<Data Name="%s">%s</Data>' % (k, v) for k, v in kw.items())


class XmlParsing(unittest.TestCase):
    def test_4624_named_fields(self):
        e = cat.event_from_xml(xml('Security', 4624, d(SubjectUserName='PC1$', TargetUserName='alice', TargetDomainName='CORP',
                                                         TargetLogonId='0x3a1f2', LogonType='10', IpAddress='203.0.113.7',
                                                         ProcessName='C:\\Windows\\System32\\svchost.exe')))
        self.assertEqual((e['channel'], e['event_id'], e['record_id']), ('Security', 4624, 100))
        self.assertEqual((e['username'], e['source_ip'], e['logon_id']), ('CORP\\alice', '203.0.113.7', '0x3a1f2'))
        self.assertEqual(e['logon_type'], '10 - RemoteInteractive (RDP)')
        self.assertEqual(e['level'], 'Audit Success')
        self.assertEqual(e['time_utc'], '2026-11-24T07:31:05+00:00')          # 7-digit UTC SystemTime handled
        self.assertEqual(json.loads(e['data_json'])['TargetUserName'], 'alice')

    def test_4625_failure_reason(self):
        e = cat.event_from_xml(xml('Security', 4625, d(TargetUserName='ghost', TargetDomainName='PC1', Status='0xc000006d',
                                                         SubStatus='0xC0000064', IpAddress='::ffff:198.51.100.9', LogonType='3'),
                                   keywords='0x8010000000000000'))
        self.assertEqual(e['status'], '0xc0000064 (user does not exist)')
        self.assertEqual(e['source_ip'], '198.51.100.9')
        self.assertEqual(e['level'], 'Audit Failure')

    def test_sysmon_process(self):
        e = cat.event_from_xml(xml('Microsoft-Windows-Sysmon/Operational', 1, d(
            ProcessGuid='{A}', Image='C:\\Windows\\System32\\cmd.exe', CommandLine='cmd /c whoami', User='PC1\\alice',
            LogonId='0x3a1f2', ParentImage='C:\\Windows\\explorer.exe', ParentProcessGuid='{B}', Hashes='SHA256=AB'), level=4))
        self.assertEqual(e['channel'], 'Sysmon')
        self.assertEqual((e['process'], e['parent_process'], e['command_line']), ('C:\\Windows\\System32\\cmd.exe', 'C:\\Windows\\explorer.exe', 'cmd /c whoami'))
        self.assertEqual((e['process_guid'], e['parent_guid'], e['hash'], e['level']), ('{A}', '{B}', 'SHA256=AB', 'Information'))

    def test_sysmon_network(self):
        e = cat.event_from_xml(xml('Microsoft-Windows-Sysmon/Operational', 3, d(Image='C:\\x.exe', Initiated='true',
                                                                               DestinationIp='203.0.113.9', DestinationPort='443')))
        self.assertEqual((e['dest_ip'], e['dest_port'], e['status']), ('203.0.113.9', '443', 'outbound'))

    def test_userdata_log_cleared(self):
        ud = '<LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog"><SubjectUserName>bob</SubjectUserName>' \
             '<SubjectDomainName>PC1</SubjectDomainName></LogFileCleared>'
        self.assertEqual(cat.event_from_xml(xml('Security', 1102, user_data=ud))['username'], 'PC1\\bob')

    def test_userdata_rdp_1149(self):
        ud = '<EventXML xmlns="Event_NS"><Param1>alice</Param1><Param2>CORP</Param2><Param3>203.0.113.20</Param3></EventXML>'
        e = cat.event_from_xml(xml('Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational', 1149, user_data=ud))
        self.assertEqual((e['channel'], e['username'], e['source_ip']), ('RDP-Auth', 'CORP\\alice', '203.0.113.20'))

    def test_scheduled_task_command(self):
        task = '&lt;Task&gt;&lt;Exec&gt;&lt;Command&gt;powershell.exe&lt;/Command&gt;&lt;Arguments&gt;-w hidden -c x&lt;/Arguments&gt;&lt;/Exec&gt;&lt;/Task&gt;'
        e = cat.event_from_xml(xml('Security', 4698, d(TaskName='\\Updater', TaskContent=task)))
        self.assertEqual((e['target'], e['command_line']), ('\\Updater', 'powershell.exe -w hidden -c x'))

    def test_powershell_long_script_truncated(self):
        e = cat.event_from_xml(xml('Microsoft-Windows-PowerShell/Operational', 4104, d(ScriptBlockText='A' * 20000), level=3))
        self.assertLess(len(e['command_line']), 8100)
        self.assertEqual(e['level'], 'Warning')

    def test_bad_xml_is_ignored(self):
        self.assertIsNone(cat.event_from_xml('<not-xml'))


class LegacyParser(unittest.TestCase):
    def test_parse_4624_inserts(self):
        v = ['-'] * 22
        v[5], v[6], v[8], v[18] = 'alice', 'CORP', '10', '203.0.113.7'
        self.assertEqual(cat.parse_event(4624, v), {'username': 'CORP\\alice', 'source_ip': '203.0.113.7', 'logon_type': '10 - RemoteInteractive (RDP)'})

    def test_time_normalised_to_utc_text(self):
        self.assertEqual(cat.to_utc_iso('2026-01-01T10:00:00.123+07:00'), '2026-01-01T03:00:00+00:00')
        self.assertEqual(cat.level_from_system(4, '0x8010000000000000'), 'Audit Failure')
        self.assertEqual(cat.level_from_system(2, '0x8000000000000000'), 'Error')


class SortTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fresh_db()
        for rec, t in [(1, '2026-01-01T10:00:00+00:00'), (2, '2026-01-01T12:00:00+00:00'), (3, '2026-01-01T11:00:00+07:00')]:
            db.ingest({'channel': 'System', 'record_id': rec, 'event_id': 6005, 'time_utc': t, 'level': 'Information'})

    def rec(self, **kw):
        return [r['record_id'] for r in db.events(channel='System', **kw)[0]]

    def test_new_to_old(self):
        self.assertEqual(self.rec(order='DESC'), [2, 1, 3])

    def test_old_to_new(self):
        self.assertEqual(self.rec(order='ASC'), [3, 1, 2])

    def test_bad_order_is_safe(self):
        self.assertEqual(db._dir('x; DROP TABLE events'), 'DESC')

    def test_same_record_id_in_two_channels(self):
        db.ingest({'channel': 'Sysmon', 'record_id': 1, 'event_id': 22, 'target': 'example.org'})
        self.assertEqual(db.events(search='example.org')[1], 1)
        self.assertEqual(len(self.rec()), 3)


class Migration(unittest.TestCase):
    def test_v22_database_upgrades_in_place(self):
        c = sqlite3.connect(':memory:')
        c.row_factory = sqlite3.Row
        c.executescript('''
        CREATE TABLE events(record_id INTEGER PRIMARY KEY,event_id INTEGER,time_utc TEXT,username TEXT,source_ip TEXT,computer TEXT,raw TEXT,is_demo INTEGER DEFAULT 0,level TEXT,logon_type TEXT);
        CREATE TABLE alerts(id INTEGER PRIMARY KEY AUTOINCREMENT,rule_id TEXT,severity TEXT,summary TEXT,created_utc TEXT,event_record_id INTEGER,status TEXT DEFAULT 'Open',notes TEXT DEFAULT '');
        CREATE TABLE incidents(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT,severity TEXT,status TEXT DEFAULT 'Open',created_utc TEXT,updated_utc TEXT,description TEXT,alert_id INTEGER,owner TEXT DEFAULT '');
        CREATE TABLE collector_state(key TEXT PRIMARY KEY,value TEXT);
        INSERT INTO events VALUES(98765,1102,'2026-01-01T00:00:00+00:00','PC\\bob','','PC','a | b',0,'Audit Success','');
        INSERT INTO alerts(rule_id,severity,summary,created_utc,event_record_id) VALUES('SECURITY_LOG_CLEARED','Critical','x','2026-01-01T00:00:01+00:00',98765);
        INSERT INTO incidents(title,severity,created_utc,updated_utc,alert_id) VALUES('x','Critical','2026-01-01','2026-01-01',1);
        INSERT INTO collector_state VALUES('record_cursor','98765');
        ''')
        db.create_schema(c)
        ev = c.execute('SELECT * FROM events').fetchone()
        self.assertEqual((ev['id'], ev['channel'], ev['record_id'], ev['raw']), (98765, 'Security', 98765, 'a | b'))
        a = c.execute('SELECT a.*,e.username FROM alerts a JOIN events e ON e.id=a.event_record_id').fetchone()
        self.assertEqual((a['username'], a['incident_id'], a['hit_count']), ('PC\\bob', 1, 1))
        self.assertEqual(c.execute("SELECT value FROM collector_state WHERE key='cursor:Security'").fetchone()[0], '98765')
        db.create_schema(c)                       # running twice is harmless
        self.assertEqual(c.execute('SELECT COUNT(*) FROM events').fetchone()[0], 1)


class AlertPipeline(unittest.TestCase):
    def setUp(self):
        fresh_db()

    def test_duplicates_fold_into_one_alert(self):
        for i in range(3):
            db.ingest({'channel': 'Sysmon', 'event_id': 1, 'record_id': i + 1, 'process': 'C:\\Windows\\System32\\vssadmin.exe',
                       'command_line': 'vssadmin delete shadows /all /quiet', 'time_utc': '2026-11-24T07:00:0%d+00:00' % i})
        rows = [r for r in db.alerts() if r['rule_id'] == 'SHADOW_COPY_DELETION']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['hit_count'], 3)

    def test_demo_chain_correlates_into_one_critical_incident(self):
        db.add_demo()
        inc = db.incidents()
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]['severity'], 'Critical')
        self.assertGreaterEqual(inc[0]['alert_count'], 8)
        self.assertIn('T1003.001', inc[0]['mitre'])
        self.assertEqual(len(db.incident_alerts(inc[0]['id'])), inc[0]['alert_count'])

    def test_unrelated_low_alert_creates_no_incident(self):
        db.ingest({'channel': 'Sysmon', 'event_id': 1, 'record_id': 50, 'process': 'C:\\Users\\Public\\tool.exe',
                   'parent_process': 'C:\\Windows\\explorer.exe', 'username': 'PC\\carol'})
        self.assertEqual([r['rule_id'] for r in db.alerts()], ['EXEC_FROM_SUSPICIOUS_PATH'])
        self.assertEqual(db.incidents(), [])

    def test_allowlist_round_trip(self):
        db.add_allow('*', 'process', 'tool.exe', 'IT tool')
        db.ingest({'channel': 'Sysmon', 'event_id': 1, 'record_id': 51, 'process': 'C:\\Users\\Public\\tool.exe'})
        self.assertEqual(db.alerts(), [])
        with self.assertRaises(ValueError):
            db.add_allow('*', 'not_a_field', 'x')

    def test_cursors_round_trip(self):
        db.save_cursors({'Security': 10, 'Sysmon': 5, 'Defender': None})
        self.assertEqual(db.cursors(), {'Security': 10, 'Sysmon': 5})
        self.assertEqual(db.cursor(), 10)

    def test_prune_keeps_alert_evidence(self):
        db.ingest({'channel': 'System', 'event_id': 6005, 'record_id': 1, 'time_utc': '2020-01-01T00:00:00+00:00'})
        db.ingest({'channel': 'System', 'event_id': 104, 'record_id': 2, 'time_utc': '2020-01-01T00:00:00+00:00', 'target': 'System'})
        self.assertEqual(db.prune(30), 1)
        self.assertEqual([r['event_id'] for r in db.events()[0]], [104])


class FakeApi:
    pass


class CollectorLogic(unittest.TestCase):
    """read_channel's cursor maths, with the Windows API replaced by a fake log."""

    def setUp(self):
        self.log = [(i, 4624 if i % 2 else 4625) for i in range(1, 51)]      # 50 Security events
        self.orig = (wc._api, wc._iter_query, wc.latest_record)
        wc._api = lambda: FakeApi()
        wc.latest_record = lambda short='Security': self.log[-1][0]

        def fake_iter(api, path, xpath, reverse=False, batch_size=200):
            import re
            ids = {int(x) for x in re.findall(r'EventID=(\d+)', xpath)}
            lo, hi = map(int, re.search(r'EventRecordID>(\d+) and EventRecordID<=(\d+)', xpath).groups())
            for rec, eid in self.log:
                if eid in ids and lo < rec <= hi:
                    yield xml('Security', eid, d(TargetUserName='u'), rec=rec)
        wc._iter_query = fake_iter

    def tearDown(self):
        wc._api, wc._iter_query, wc.latest_record = self.orig

    def test_first_run_starts_at_newest(self):
        self.assertEqual(wc.read_channel('Security', None), ([], 50))

    def test_reads_everything_after_cursor(self):
        ev, cur = wc.read_channel('Security', 40)
        self.assertEqual([e['record_id'] for e in ev], list(range(41, 51)))
        self.assertEqual(cur, 50)

    def test_cap_never_skips_events(self):
        seen, cur = [], 0
        for _ in range(20):
            ev, cur = wc.read_channel('Security', cur, max_records=7)
            seen += [e['record_id'] for e in ev]
            if cur == 50:
                break
        self.assertEqual(seen, list(range(1, 51)))

    def test_cleared_log_restarts(self):
        self.log = [(i, 4624) for i in range(1, 4)]
        ev, cur = wc.read_channel('Security', 40)
        self.assertEqual(([e['record_id'] for e in ev], cur), ([1, 2, 3], 3))

    def test_xpath_shape(self):
        q = wc._xpath([4624, 4625], 10, 20, 3600000)
        self.assertEqual(q, '*[System[(EventID=4624 or EventID=4625) and EventRecordID>10 and EventRecordID<=20 '
                            'and TimeCreated[timediff(@SystemTime) <= 3600000]]]')

    def test_missing_channel_is_not_fatal(self):
        class Err(Exception):
            winerror = 15007

        def boom(short, *a, **k):
            if short == 'Sysmon':
                raise Err('not found')
            return [], 1
        orig = wc.read_channel
        wc.read_channel = boom
        try:
            _, cursors, status = wc.read_new({})
        finally:
            wc.read_channel = orig
        self.assertEqual(status['Sysmon'], 'missing')
        self.assertEqual(status['Security'], 'ok')
        self.assertNotIn('Sysmon', cursors)


if __name__ == '__main__':
    unittest.main()
