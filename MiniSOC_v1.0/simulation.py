"""Attack simulation (purple team): replay realistic synthetic attacks through the real pipeline
and check that the expected detections fire. All data is synthetic and labelled 'Simulation';
nothing is sent to any real system. IPs use documentation ranges (RFC 5737).
"""
import random
from datetime import datetime, timedelta, timezone

import database
import pipeline


def _now():
    return datetime.now(timezone(timedelta(hours=7)))  # scenarios use Thai local time (UTC+07:00)


def _ev(t, **kw):
    base = {"timestamp": t.isoformat(timespec="seconds"), "severity": "Info", "host": "shop-web",
            "username": "", "source_ip": "", "dest_ip": "", "details": "", "extra": {}, "hits": 1}
    base.update(kw)
    if not base["details"]:
        base["details"] = f"{base.get('event_type')} {base.get('username') or ''} {base.get('source_ip') or ''}".strip()
    return base


def credential_stuffing(now):
    ip = "203.0.113.45"
    events = []
    t = now - timedelta(minutes=8)
    for i in range(30):
        events.append(_ev(t + timedelta(seconds=i * 8), event_type="FailedLogin", severity="Medium", dataset="auth",
                          username=f"customer{random.randint(1000, 9999)}@example.com", source_ip=ip, country="NL",
                          http_status=401, http_method="POST", url_path="/api/v1/auth/login",
                          details="POST /api/v1/auth/login -> 401 invalid credentials"))
    events.append(_ev(t + timedelta(seconds=250), event_type="LoginSuccess", dataset="auth", username="customer4521@example.com",
                      source_ip=ip, country="NL", http_status=200, url_path="/api/v1/auth/login",
                      details="POST /api/v1/auth/login -> 200"))
    return events


def distributed_bruteforce(now):
    t = now - timedelta(minutes=12)
    return [_ev(t + timedelta(seconds=i * 40), event_type="FailedLogin", severity="Medium", dataset="auth",
                username="finance.manager", source_ip=f"198.51.100.{20 + i}", country=random.choice(["VN", "BR", "US", "ID"]),
                http_status=401, url_path="/login") for i in range(12)]


def account_takeover(now):
    events = []
    for d in range(7, 0, -1):  # 7-day baseline: alice logs in from Thailand every morning
        t = (now - timedelta(days=d)).replace(hour=9, minute=5)
        events.append(_ev(t, event_type="LoginSuccess", dataset="auth", username="alice", source_ip="192.0.2.10",
                          country="TH", http_status=200, url_path="/login"))
    t = now - timedelta(minutes=20)
    for i in range(5):
        events.append(_ev(t + timedelta(seconds=i * 30), event_type="FailedLogin", severity="Medium", dataset="auth",
                          username="alice", source_ip="198.51.100.66", country="RU", http_status=401, url_path="/login"))
    events.append(_ev(t + timedelta(minutes=3), event_type="LoginSuccess", dataset="auth", username="alice",
                      source_ip="198.51.100.66", country="RU", http_status=200, url_path="/login"))
    events.append(_ev(t + timedelta(minutes=5), event_type="MFADisabled", severity="Medium", dataset="auth", username="alice",
                      source_ip="198.51.100.66", country="RU", details="User disabled MFA from account settings"))
    return events


def api_exfiltration(now):
    events = []
    for h in range(30, 2, -1):  # baseline ~5 MB/h for a reporting token
        events.append(_ev(now - timedelta(hours=h), event_type="ApiRequest", dataset="api", username="svc-report",
                          source_ip="192.0.2.30", http_status=200, http_method="GET", url_path="/api/v1/orders/export",
                          bytes_out=random.randint(4_000_000, 6_000_000), extra={"_token": "tok_report_01"}))
    t = now - timedelta(minutes=50)
    for i in range(40):
        events.append(_ev(t + timedelta(seconds=i * 60), event_type="ApiRequest", dataset="api", username="svc-report",
                          source_ip="203.0.113.80", country="SG", http_status=200, http_method="GET",
                          url_path=f"/api/v1/customers?page={i}", bytes_out=25_000_000, extra={"_token": "tok_report_01"}))
    return events


def web_scanning(now):
    ip = "203.0.113.99"
    events = []
    t = now - timedelta(minutes=6)
    paths = ["/admin", "/.env", "/wp-login.php", "/phpmyadmin/", "/.git/config", "/backup.zip", "/server-status", "/api/v1/debug"]
    for i in range(90):
        p = paths[i % len(paths)] + ("" if i < len(paths) else f"?v={i}")
        events.append(_ev(t + timedelta(seconds=i * 2), event_type="WebRequest", dataset="web", source_ip=ip, country="US",
                          http_status=random.choice([404, 404, 403, 400]), http_method="GET", url_path=p,
                          extra={"_user_agent": "Mozilla/5.0 (compatible; Nuclei)"}))
    events.append(_ev(t + timedelta(seconds=200), event_type="WebAttack", severity="Medium", dataset="web", source_ip=ip,
                      http_status=403, url_path="/products?id=1' UNION SELECT username,password FROM users--",
                      signature="sqli", extra={"_attack_pattern": "sqli", "_user_agent": "sqlmap/1.8"}))
    for i in range(70):  # the scan also triggers a burst of 5xx on the app
        events.append(_ev(t + timedelta(seconds=210 + i), event_type="WebRequest", dataset="web", source_ip=ip,
                          http_status=500, url_path=f"/api/v1/search?q={'%27' * (i % 3)}", host="shop-web"))
    return events


def privilege_abuse(now):
    night = (now - timedelta(days=1)).replace(hour=2, minute=37, second=0)
    return [
        _ev(night, event_type="PrivilegeChange", severity="Medium", dataset="iam", username="it-admin", source_ip="192.0.2.15",
            details="Role 'Billing Admin' granted to user contractor7 by it-admin"),
        _ev(night + timedelta(minutes=2), event_type="AccountCreated", severity="Low", dataset="iam", username="backup-svc2",
            source_ip="192.0.2.15", details="New account backup-svc2 created by it-admin"),
        _ev(night + timedelta(minutes=3), event_type="GroupMemberAdded", severity="High", dataset="iam", username="backup-svc2",
            source_ip="192.0.2.15", details="backup-svc2 added to Domain Admins by it-admin"),
    ]


def ssh_bruteforce_c2(now):
    t = now - timedelta(hours=3)
    events = []
    for i, ip in enumerate(["203.0.113.11", "203.0.113.12", "198.51.100.13", "198.51.100.14"]):
        events.append(_ev(t + timedelta(minutes=i * 7), event_type="BruteForce", severity="High", dataset="network",
                          source_ip=ip, dest_ip="10.20.30.15", dest_port="22", action="Allow", host="10.20.30.15",
                          signature="SSH Server brute-force attack", country="VN",
                          extra={"_direction": "inbound", "_attempts": 60 + i * 9}))
    events.append(_ev(t + timedelta(minutes=95), event_type="MalwareTraffic", severity="High", dataset="network",
                      source_ip="10.20.30.15", dest_ip="192.0.2.200", dest_port="3333", action="Allow", host="10.20.30.15",
                      signature="MALWARE-CNC Miner BotNet For Mining.subscribe Request Traffic",
                      extra={"_direction": "outbound", "_decoded": ['{"id":1,"method":"mining.subscribe","params":[]}']}))
    return events


def windows_cleanup(now):
    t = now - timedelta(hours=1)
    return [
        _ev(t, event_type="ProcessStart", dataset="host", host="WS-ACCT-07", username="administrator",
            details="powershell.exe -nop -w hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"),
        _ev(t + timedelta(minutes=1), event_type="ScheduledTaskCreated", severity="High", dataset="host", host="WS-ACCT-07",
            username="administrator", details="Scheduled task \\Microsoft\\Windows\\UpdateCheck created"),
        _ev(t + timedelta(minutes=4), event_type="LogCleared", severity="High", dataset="host", host="WS-ACCT-07",
            username="administrator", event_code="1102", details="Security audit log was cleared"),
    ]


SCENARIOS = {
    "credential_stuffing": ("Credential stuffing on the login API", credential_stuffing,
                            ["auth-credential-stuffing", "auth-failed-login-burst", "auth-success-after-failures"],
                            "One IP tries 30 different customer accounts in 4 minutes, then one login succeeds."),
    "distributed_bruteforce": ("Distributed brute force on one account", distributed_bruteforce,
                               ["auth-distributed-bruteforce"], "12 IPs from several countries guess one account's password."),
    "account_takeover": ("Account takeover from a new country", account_takeover,
                         ["auth-account-takeover", "mfa-disabled"],
                         "alice always logs in from TH; after failed logins she logs in from RU and MFA is disabled."),
    "api_exfiltration": ("Data exfiltration through the API", api_exfiltration, ["api-data-exfiltration"],
                         "A reporting token that normally pulls ~5 MB/h downloads ~1 GB in under an hour."),
    "web_scanning": ("Scanning and exploit attempts", web_scanning,
                     ["web-scanning-error-burst", "web-attack-signature", "web-http-error-spike"],
                     "A scanner requests sensitive paths, tries SQL injection and causes a burst of 500 errors."),
    "privilege_abuse": ("Privilege abuse outside business hours", privilege_abuse,
                        ["priv-change-off-hours", "priv-group-change", "account-created"],
                        "At 02:37 an admin grants a role, creates an account and adds it to Domain Admins."),
    "ssh_bruteforce_c2": ("SSH brute force followed by miner C2", ssh_bruteforce_c2,
                          ["net-brute-force", "net-malware-c2"],
                          "Firewall reports SSH brute force on a DMZ server, which later talks to a miner pool."),
    "windows_cleanup": ("Encoded PowerShell, persistence and log clearing", windows_cleanup,
                        ["suspicious-command", "persistence-task-service", "log-cleared"],
                        "Classic post-exploitation on a Windows workstation."),
}


def run_scenario(key, user=None):
    title, builder, expected, _desc = SCENARIOS[key]
    events = builder(_now())
    import_id = database.create_import(f"simulation: {title}", "simulation", "Simulation", f"sim-{key}-{random.random()}",
                                       0, "+07:00", len(events), 0, {"scenario": key}, [], {}, user)
    stats = pipeline.process_batch(events, f"Simulation · {title}", import_id=import_id, user=user,
                                   options={"isolated": True, "aggregate_web": "1"})
    database.finish_import(import_id, stats["stored"], stats["summarized_records"], stats["signals"], stats["incidents_created"])
    fired = stats["rules_fired"]
    missing = [r for r in expected if r not in fired]
    run_id = database.insert_simulation_run(key, title, expected, fired, missing, not missing, len(events), import_id)
    return {"run_id": run_id, "import_id": import_id, "title": title, "expected": expected, "fired": fired,
            "missing": missing, "passed": not missing, "stats": stats}


def run_all(user=None):
    return [run_scenario(k, user) for k in SCENARIOS]
