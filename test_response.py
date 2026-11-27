"""Response engine tests. The Windows commands are recorded, never run."""
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

os.environ['LOCALAPPDATA'] = tempfile.mkdtemp()
os.environ['COMPUTERNAME'] = 'PC1'
os.environ['USERNAME'] = 'me'
import database as db
import response as r


def fresh_db():
    db.DB = db.Path(tempfile.mkdtemp()) / 'minisoc.db'
    db.init()


class Guards(unittest.TestCase):
    """Targets come from event logs = attacker-controlled. Every guard must hold."""

    def setUp(self):
        r._local_cache.update(t=r.now(), ips={'192.168.1.10', '192.168.1.1', '8.8.8.8'})

    def test_ip(self):
        self.assertEqual(r.check_ip(' 45.33.32.156 '), '45.33.32.156')
        for bad in ('45.33.32.156 & calc', '45.33.32.156 dir=out', '127.0.0.1', '::1', '0.0.0.0', '224.0.0.1',
                    '169.254.1.1', '192.168.1.1', '8.8.8.8', ''):
            with self.assertRaises(r.Refused, msg=bad):
                r.check_ip(bad)

    def test_account(self):
        self.assertEqual(r.check_account('PC1\\backdoor'), 'backdoor')
        self.assertEqual(r.check_account('backdoor'), 'backdoor')
        for bad in ('a /add', '/delete', 'x&calc', 'NT AUTHORITY\\SYSTEM', 'CORP\\bob', 'Administrator', 'PC1\\me',
                    'PC1$', 'averyveryverylongname123', 'S-1-5-21-1-2-3'):
            with self.assertRaises(r.Refused, msg=bad):
                r.check_account(bad)

    def test_pid(self):
        self.assertEqual(r.check_pid('4112', 'C:\\Users\\Public\\svc.exe'), (4112, 'C:\\Users\\Public\\svc.exe'))
        for pid, image in ((None, 'C:\\x.exe'), ('abc', 'C:\\x.exe'), (4, 'System'), (700, 'C:\\Windows\\System32\\lsass.exe'),
                           (900, 'C:\\Windows\\explorer.exe'), (os.getpid(), 'C:\\python.exe'), (1234, '')):
            with self.assertRaises(r.Refused, msg=str(pid)):
                r.check_pid(pid, image)

    def test_path(self):
        self.assertEqual(r.check_path('"C:\\Users\\Public\\svc.exe"'), 'C:\\Users\\Public\\svc.exe')
        for bad in ('C:\\Windows\\System32\\drivers\\etc\\hosts', 'c:\\windows\\x.exe', 'svc.exe', '\\\\server\\share\\x.exe',
                    'C:\\Users\\..\\Windows\\x.exe', str(r.QUARANTINE) + '\\a.quarantine'):
            with self.assertRaises(r.Refused, msg=bad):
                r.check_path(bad)

    def test_service_and_task(self):
        self.assertEqual(r.check_service('UpdaterSvc'), 'UpdaterSvc')
        for bad in ('WinDefend', 'Sysmon64', 'EventLog', 'x" & calc', 'a/b', ''):
            with self.assertRaises(r.Refused, msg=bad):
                r.check_service(bad)
        self.assertEqual(r.check_task('\\Updater'), '\\Updater')
        for bad in ('\\Microsoft\\Windows\\Defrag\\ScheduledDefrag', '\\x" /f', '\\..\\x'):
            with self.assertRaises(r.Refused, msg=bad):
                r.check_task(bad)

    def test_run_key(self):
        self.assertEqual(r.check_run_key('HKU\\S-1-5-21-9\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd'),
                         ('HKU', 'S-1-5-21-9\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'upd'))
        self.assertEqual(r.check_run_key('HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\x')[2], 'x')
        for bad in ('HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell', 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\x',
                    'HKCR\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'):
            with self.assertRaises(r.Refused, msg=bad):
                r.check_run_key(bad)


class Planning(unittest.TestCase):
    def setUp(self):
        r._local_cache.update(t=r.now(), ips=set())

    def test_sysmon_kill_and_parent(self):
        ev = dict(channel='Sysmon', event_id=1, process='C:\\Users\\a\\enc.exe', parent_process='C:\\Users\\a\\loader.exe',
                  data_json=json.dumps({'ProcessId': '5000', 'ParentProcessId': '4000'}))
        self.assertEqual(r.plan_for('kill_process', ev)['params'], {'pid': 5000, 'image': 'C:\\Users\\a\\enc.exe'})
        self.assertEqual(r.plan_for('kill_parent', ev)['params'], {'pid': 4000, 'image': 'C:\\Users\\a\\loader.exe'})

    def test_4688_hex_pids(self):
        ev = dict(channel='Security', event_id=4688, process='C:\\x\\a.exe', parent_process='C:\\x\\p.exe',
                  data_json=json.dumps({'NewProcessId': '0x1a2c', 'ProcessId': '0x10'}))
        self.assertEqual(r.plan_for('kill_process', ev)['params']['pid'], 0x1a2c)
        self.assertEqual(r.plan_for('kill_parent', ev)['params']['pid'], 0x10)

    def test_protected_parent_is_blocked(self):
        ev = dict(channel='Sysmon', event_id=1, process='C:\\Windows\\System32\\vssadmin.exe', parent_process='C:\\Windows\\explorer.exe',
                  data_json=json.dumps({'ParentProcessId': '900'}))
        self.assertIn('protected', r.plan_for('kill_parent', ev)['blocked'])

    def test_service_binary_quarantine(self):
        ev = dict(channel='System', event_id=7045, target='upd', command_line='"C:\\Users\\Public\\svc.exe" -k run')
        self.assertEqual(r.plan_for('quarantine_file', ev)['params']['path'], 'C:\\Users\\Public\\svc.exe')

    def test_network_block_uses_destination(self):
        ev = dict(channel='Sysmon', event_id=3, dest_ip='45.33.32.156', source_ip='192.168.1.10')
        self.assertEqual(r.plan_for('block_ip', ev)['params']['ip'], '45.33.32.156')

    def test_sid_member_not_disabled(self):
        self.assertIsNone(r.plan_for('disable_account', dict(channel='Security', event_id=4732, username='S-1-5-21-1-2-3-1001')))


class FakeSystem(unittest.TestCase):
    """execute()/undo() with the Windows layer replaced by recorders."""

    def setUp(self):
        self.cmds = []
        self.saved = (r.WINDOWS, r._run, r._ps, r.is_admin, r.image_of)
        r.WINDOWS = True
        r._run = lambda args: self.cmds.append(list(args)) or 'OK'
        r._ps = lambda script: json.dumps([{'Name': 'Domain', 'Enabled': True}, {'Name': 'Public', 'Enabled': False}])
        r.is_admin = lambda: True
        r.image_of = lambda pid: 'C:\\Users\\Public\\svc.exe' if pid == 4112 else None
        r._local_cache.update(t=r.now(), ips=set())

    def tearDown(self):
        r.WINDOWS, r._run, r._ps, r.is_admin, r.image_of = self.saved

    def plan(self, action, **params):
        return dict(action=action, params=params, label=r.ACTIONS[action][0], target='', demo=False)

    def test_kill_runs_taskkill_as_argument_list(self):
        st, text, undo, _ = r.execute(self.plan('kill_process', pid=4112, image='C:\\Users\\Public\\svc.exe'))
        self.assertEqual(st, 'Executed')
        self.assertEqual(self.cmds, [['taskkill', '/PID', '4112', '/T', '/F']])

    def test_kill_refuses_reused_pid(self):
        r.image_of = lambda pid: 'C:\\Program Files\\Editor\\editor.exe'
        st, text, _, _ = r.execute(self.plan('kill_process', pid=4112, image='C:\\Users\\Public\\svc.exe'))
        self.assertEqual(st, 'Refused')
        self.assertIn('reused', text)
        self.assertEqual(self.cmds, [])

    def test_kill_spares_protected_children(self):
        r._ps = lambda script: json.dumps([{'ProcessId': 4200, 'ParentProcessId': 4112, 'Name': 'cmd.exe'},
                                           {'ProcessId': 4300, 'ParentProcessId': 4200, 'Name': 'lsass.exe'}])
        st, text, _, _ = r.execute(self.plan('kill_process', pid=4112, image='C:\\Users\\Public\\svc.exe'))
        self.assertEqual(st, 'Executed')
        self.assertEqual(self.cmds, [['taskkill', '/PID', '4112', '/F']])      # no /T
        self.assertIn('lsass.exe', text)

    def test_half_block_is_rolled_back(self):
        def run(args):
            self.cmds.append(list(args))
            if 'dir=out' in args:
                raise RuntimeError('netsh failed')
            return 'OK'
        r._run = run
        st, _, undo, _ = r.execute(self.plan('block_ip', ip='45.33.32.156'))
        self.assertEqual(st, 'Failed')
        self.assertEqual(self.cmds[-1], ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=MiniSOC-Block-45.33.32.156'])

    def test_block_and_expiry(self):
        st, text, undo, expires = r.execute(self.plan('block_ip', ip='45.33.32.156'), ttl_hours=1)
        self.assertEqual(st, 'Executed')
        self.assertIn(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=MiniSOC-Block-45.33.32.156', 'dir=in',
                       'action=block', 'remoteip=45.33.32.156'], self.cmds)
        self.assertEqual(len(self.cmds), 2)
        self.assertTrue(expires)
        self.assertEqual(r.undo('block_ip', undo)[0], 'Undone')
        self.assertEqual(self.cmds[-1], ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=MiniSOC-Block-45.33.32.156'])

    def test_isolate_and_release_restores_profiles(self):
        st, text, undo, _ = r.execute(self.plan('isolate_host'))
        self.assertEqual(st, 'Executed')
        self.assertIn(['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'on'], self.cmds)
        self.cmds.clear()
        self.assertEqual(r.undo('isolate_host', undo)[0], 'Undone')
        self.assertIn(['netsh', 'advfirewall', 'set', 'publicprofile', 'state', 'off'], self.cmds)       # was off before
        self.assertNotIn(['netsh', 'advfirewall', 'set', 'domainprofile', 'state', 'off'], self.cmds)   # was on before

    def test_account_disable_and_enable(self):
        st, _, undo, _ = r.execute(self.plan('disable_account', user='PC1\\backdoor'))
        self.assertEqual((st, self.cmds[-1]), ('Executed', ['net', 'user', 'backdoor', '/active:no']))
        r.undo('disable_account', undo)
        self.assertEqual(self.cmds[-1], ['net', 'user', 'backdoor', '/active:yes'])

    def test_injection_never_reaches_a_command(self):
        for p in (self.plan('block_ip', ip='1.2.3.4 & calc'), self.plan('disable_account', user='x /add'),
                  self.plan('disable_service', name='a" & calc'), self.plan('disable_task', name='\\x" /f'),
                  self.plan('kill_process', pid='12 & calc', image='C:\\x.exe')):
            self.assertEqual(r.execute(p)[0], 'Refused')
        self.assertEqual(self.cmds, [])

    def test_modes(self):
        p = self.plan('block_ip', ip='45.33.32.156')
        self.assertEqual(r.execute(p, mode='dry-run')[0], 'Dry-run')
        self.assertEqual(r.execute(dict(p, demo=True))[0], 'Simulated')
        r.is_admin = lambda: False
        self.assertEqual(r.execute(p)[0], 'Failed')
        self.assertEqual(self.cmds, [])


class AutoResponse(unittest.TestCase):
    def setUp(self):
        fresh_db()
        db.set_setting('auto_response', 'on')          # these tests exercise live mode; the default is dry-run
        self.saved = (r.WINDOWS, r._run, r._ps, r.is_admin, r.image_of)
        self.cmds = []
        r.WINDOWS = True
        r._run = lambda args: self.cmds.append(list(args)) or 'OK'
        r._ps = lambda script: '[]'
        r.is_admin = lambda: True
        r.image_of = lambda pid: 'C:\\Users\\a\\enc.exe'
        r._local_cache.update(t=r.now(), ips=set())

    def tearDown(self):
        r.WINDOWS, r._run, r._ps, r.is_admin, r.image_of = self.saved

    def files(self, n, start=0):
        sink = []
        t0 = datetime(2026, 11, 24, 7, 0, tzinfo=timezone.utc)
        db.ingest_many([dict(channel='Sysmon', event_id=11, record_id=start + i, time_utc=(t0 + timedelta(milliseconds=100 * (start + i))).isoformat(),
                             process='C:\\Users\\a\\enc.exe', process_guid='{G}', target='C:\\Users\\a\\Documents\\f%d.locked' % (start + i),
                             data_json=json.dumps({'ProcessId': '5000'})) for i in range(n)], sink)
        return sink

    def test_high_alert_waits_for_human(self):
        sink = self.files(100)
        self.assertEqual(db.alert(sink[0])['severity'], 'High')
        self.assertEqual(r.auto_respond(sink), [])

    def test_escalation_to_critical_triggers_kill_and_isolate(self):
        first = self.files(100)
        sink = self.files(200, start=100)            # same process keeps going: 300 files in < 1 min
        self.assertIn(first[0], sink)                 # the existing alert was escalated
        self.assertEqual(db.alert(first[0])['severity'], 'Critical')
        done = r.auto_respond(sink)
        self.assertEqual([d[1] for d in done], ['Executed', 'Executed'])
        self.assertIn(['taskkill', '/PID', '5000', '/T', '/F'], self.cmds)
        self.assertTrue(db.isolation_active())
        again = r.auto_respond(sink)
        self.assertNotIn('isolate', ' '.join(d[2].lower() for d in again))           # never isolates twice

    def test_default_is_dry_run(self):
        self.files(100)
        sink = self.files(200, start=100)
        with db.conn() as c:
            c.execute("DELETE FROM collector_state WHERE key='auto_response'")   # never chosen by the user
        self.assertEqual({d[1] for d in r.auto_respond(sink)}, {'Dry-run'})
        self.assertEqual(self.cmds, [])

    def test_off_and_dry_run(self):
        self.files(100)
        sink = self.files(200, start=100)
        db.set_setting('auto_response', 'off')
        self.assertEqual(r.auto_respond(sink), [])
        db.set_setting('auto_response', 'dry-run')
        self.assertEqual({d[1] for d in r.auto_respond(sink)}, {'Dry-run'})
        self.assertEqual(self.cmds, [])

    def test_manual_request_flow_and_undo(self):
        plan = r.plan_for('block_ip', dict(channel='Security', event_id=4625, source_ip='45.33.32.156'))
        rid = db.add_response(None, plan, 'test')
        self.assertEqual(db.response_request(rid)['status'], 'Pending Approval')
        db.review_response(rid, True, 'me', '')
        self.assertEqual(r.run_request(rid), 'Executed')
        self.assertEqual(r.undo_request(rid)[0], 'Undone')
        self.assertEqual(db.response_request(rid)['status'], 'Undone')

    def test_block_expiry(self):
        plan = r.plan_for('block_ip', dict(channel='Security', event_id=4625, source_ip='45.33.32.156'))
        rid = db.add_response(None, plan, 'test')
        db.finish_response(rid, 'Executed', 'ok', {'rule': 'MiniSOC-Block-45.33.32.156'}, '2020-01-01T00:00:00+00:00')
        self.assertEqual(r.expire_blocks(), 1)
        self.assertEqual(db.response_request(rid)['status'], 'Expired')

    def test_failed_expiry_is_not_retried_forever(self):
        plan = r.plan_for('block_ip', dict(channel='Security', event_id=4625, source_ip='45.33.32.156'))
        rid = db.add_response(None, plan, 'test')
        db.finish_response(rid, 'Executed', 'ok', {'rule': 'MiniSOC-Block-45.33.32.156'}, '2020-01-01T00:00:00+00:00')

        def gone(args):
            raise RuntimeError('No rules match the specified criteria.')   # rule already deleted by hand
        r._run = gone
        self.assertEqual(r.expire_blocks(), 0)
        self.assertEqual(db.expired_blocks(), [])                            # not picked up again next minute
        row = db.response_request(rid)
        self.assertEqual(row['status'], 'Executed')
        self.assertIn('remove the firewall rule MiniSOC-Block-45.33.32.156 manually', row['result'])

    def test_isolation_found_by_parsed_plan(self):
        rid = db.add_response(None, dict(r.plan_for('isolate_host', {}), demo=False), 'test')
        with db.conn() as c:                                                 # compact JSON, no spaces
            c.execute("UPDATE response_requests SET status='Executed',plan_json=? WHERE id=?",
                      (json.dumps({'action': 'isolate_host', 'params': {}}, separators=(',', ':')), rid))
        self.assertEqual(db.isolation_active(), rid)
        db.mark_undone(rid, 'Undone', 'released')
        self.assertIsNone(db.isolation_active())

    def test_demo_chain_is_only_simulated(self):
        sink = []
        db.add_demo(sink)
        done = r.auto_respond(sink)
        self.assertTrue(done)
        self.assertEqual({d[1] for d in done}, {'Simulated'})
        self.assertEqual(self.cmds, [])


if __name__ == '__main__':
    unittest.main()
