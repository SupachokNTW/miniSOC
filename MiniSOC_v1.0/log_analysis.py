"""Analysis of one imported log file: statistics, correlations, findings and IOCs.

Findings are explainable heuristics meant to speed up triage. They are not proof of
compromise and they cannot see anything that is missing from the imported file.
"""
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from database import get_import, list_import_alerts, list_import_events, signals_for_import
from log_parser import SEVERITIES, SEVERITY_RANK, is_internal

ATTACK_TYPES = {"WebAttack", "ExploitAttempt", "IntrusionEvent", "DoS", "BruteForce", "Scan", "MalwareTraffic", "EmailThreat"}
WEB_TYPES = {"WebAttack", "ExploitAttempt", "IntrusionEvent"}
WATCH_TERMS = ("mimikatz", "sekurlsa", "-encodedcommand", " -enc ", "frombase64string", "downloadstring",
               "invoke-expression", "iex(", "certutil -urlcache", "bitsadmin", "rundll32", "regsvr32 /s /n /u /i:",
               "wget http", "curl http", "chmod 777", "/dev/tcp/", "nc -e", "base64 -d")
OFFENSIVE_TOOLS = {"sqlmap", "nikto", "nmap", "masscan", "nuclei", "zgrab", "gobuster", "dirbuster", "wpscan", "burp",
                   "acunetix", "netsparker", "openvas"}
PORT_NAMES = {"21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP", "53": "DNS", "80": "HTTP", "110": "POP3",
              "135": "MS-RPC", "139": "NetBIOS", "143": "IMAP", "443": "HTTPS", "445": "SMB", "1433": "MSSQL",
              "3306": "MySQL", "3389": "RDP", "5432": "PostgreSQL", "5900": "VNC", "6379": "Redis",
              "8080": "HTTP-alt", "8443": "HTTPS-alt", "9200": "Elasticsearch"}


def _dt(value):
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def _start(event):
    """When the activity began: the device's 'Attack started' value if present, else the event time."""
    return _dt(event["extra"].get("_attack_started")) or _dt(event["timestamp"])


def _show(value):
    """Display a stored ISO timestamp in the log's own clock time."""
    return str(value or "")[:19].replace("T", " ")


def _duration(seconds):
    seconds = int(max(0, seconds))
    if seconds < 90:
        return f"{seconds} s"
    if seconds < 5400:
        return f"{seconds // 60} min"
    if seconds < 172800:
        return f"{seconds / 3600:.1f} h"
    return f"{seconds / 86400:.1f} days"


def _max_sev(values):
    best = "Info"
    for v in values:
        if SEVERITY_RANK.get(v, -1) > SEVERITY_RANK.get(best, -1):
            best = v
    return best


def _port_label(port):
    port = str(port or "")
    return f"{port}/{PORT_NAMES[port]}" if port in PORT_NAMES else port


def _top(counter, n=5):
    return ", ".join(f"{k} ({v})" for k, v in counter.most_common(n) if k)


def _finding(severity, title, summary, evidence=None, recommendations=None, category="General", ips=None):
    return {"severity": severity, "title": title, "summary": summary, "evidence": evidence or [],
            "recommendations": recommendations or [], "category": category, "ips": sorted(set(ips or []))}


# ---------------------------------------------------------------- statistics

def _timeline(events):
    times = [(e, _dt(e["timestamp"])) for e in events]
    times = [(e, t) for e, t in times if t]
    if not times:
        return {"labels": [], "series": {}, "bucket": ""}
    first = min(t for _, t in times)
    last = max(t for _, t in times)
    span = (last - first).total_seconds()
    if span <= 6 * 3600:
        step, label = timedelta(minutes=15), "15 minutes"
    elif span <= 3 * 86400:
        step, label = timedelta(hours=1), "1 hour"
    else:
        step, label = timedelta(days=1), "1 day"
    # Bucket on the log's own clock (the offset stored with each event).
    def floor(t):
        naive = t.replace(tzinfo=None)
        if step >= timedelta(days=1):
            return naive.replace(hour=0, minute=0, second=0, microsecond=0)
        if step >= timedelta(hours=1):
            return naive.replace(minute=0, second=0, microsecond=0)
        return naive.replace(minute=naive.minute - naive.minute % 15, second=0, microsecond=0)
    start = floor(first)
    end = floor(last)
    if (end - start) / step > 400:  # mixed offsets / very long spans: fall back to daily
        step, label = timedelta(days=1), "1 day"
        start, end = start.replace(hour=0, minute=0), end.replace(hour=0, minute=0)
    buckets = []
    cur = start
    while cur <= end and len(buckets) < 500:
        buckets.append(cur)
        cur += step
    index = {b: i for i, b in enumerate(buckets)}
    series = {sev: [0] * len(buckets) for sev in SEVERITIES}
    for e, t in times:
        key = floor(t)
        if step == timedelta(days=1):
            key = key.replace(hour=0, minute=0)
        i = index.get(key)
        if i is not None:
            series.setdefault(e["severity"], [0] * len(buckets))[i] += 1
    fmt = "%Y-%m-%d" if step >= timedelta(days=1) else "%m-%d %H:%M"
    return {"labels": [b.strftime(fmt) for b in buckets],
            "series": {k: v for k, v in series.items() if any(v)}, "bucket": label}


def _source_table(events, limit=15):
    groups = defaultdict(list)
    for e in events:
        if e.get("source_ip"):
            groups[e["source_ip"]].append(e)
    rows = []
    for ip, items in groups.items():
        sigs = Counter(e.get("signature") or e["event_type"] for e in items)
        rows.append({
            "ip": ip,
            "internal": is_internal(ip),
            "location": Counter(e["extra"].get("_src_location", "") for e in items).most_common(1)[0][0],
            "events": len(items),
            "max_severity": _max_sev(e["severity"] for e in items),
            "signatures": len(sigs),
            "top_signature": sigs.most_common(1)[0][0],
            "targets": sorted({e.get("dest_ip") or e.get("host") for e in items if e.get("dest_ip") or e.get("host")}),
            "types": sorted({e["event_type"] for e in items}),
            "first": _show(items[0]["timestamp"]),
            "last": _show(items[-1]["timestamp"]),
            "scanner": next((e["extra"].get("_scanner") for e in items if e["extra"].get("_scanner")), ""),
            "allowed": sum(1 for e in items if e.get("action") == "Allow"),
        })
    rows.sort(key=lambda r: (-r["events"], -SEVERITY_RANK.get(r["max_severity"], 0)))
    return rows[:limit]


def _target_table(events, limit=15):
    groups = defaultdict(list)
    for e in events:
        direction = e["extra"].get("_direction")
        key = e.get("dest_ip") if direction in ("inbound", "internal") else (e.get("host") if not e.get("dest_ip") else None)
        if key:
            groups[key].append(e)
    rows = []
    for target, items in groups.items():
        rows.append({
            "target": target,
            "events": len(items),
            "ports": sorted({_port_label(e.get("dest_port")) for e in items if e.get("dest_port")}),
            "attackers": len({e.get("source_ip") for e in items if e.get("source_ip")}),
            "max_severity": _max_sev(e["severity"] for e in items),
            "signatures": len({e.get("signature") for e in items if e.get("signature")}),
            "names": sorted({e["extra"].get("Host") or "" for e in items} - {""})[:3],
            "hostnames": sorted({(e["extra"].get("_url") or "").split("/")[0] for e in items
                                 if e["extra"].get("_url") and not (e["extra"].get("_url") or "")[0:1].isdigit()} - {""})[:4],
        })
    rows.sort(key=lambda r: (-r["events"], -SEVERITY_RANK.get(r["max_severity"], 0)))
    return rows[:limit]


def _signature_table(events, limit=20):
    groups = defaultdict(list)
    for e in events:
        if e.get("signature"):
            groups[e["signature"]].append(e)
    rows = []
    for sig, items in groups.items():
        cves = sorted({c for e in items for c in e["extra"].get("_cves", [])})
        rows.append({
            "signature": sig,
            "events": len(items),
            "type": Counter(e["event_type"] for e in items).most_common(1)[0][0],
            "max_severity": _max_sev(e["severity"] for e in items),
            "cves": cves,
            "attackers": len({e.get("source_ip") for e in items if e.get("source_ip")}),
            "targets": len({e.get("dest_ip") or e.get("host") for e in items}),
            "statuses": dict(Counter(e["extra"].get("_http_status") for e in items if e["extra"].get("_http_status"))),
        })
    rows.sort(key=lambda r: (-SEVERITY_RANK.get(r["max_severity"], 0), -r["events"]))
    return rows[:limit]


def _ioc_table(events):
    iocs = {}
    for e in events:
        scanner = bool(e["extra"].get("_scanner"))
        for item in e["extra"].get("_iocs", []):
            key = (item["type"], item["value"].lower())
            row = iocs.setdefault(key, {"type": item["type"], "value": item["value"], "host": item["host"],
                                        "count": 0, "first_seen": e["timestamp"], "last_seen": e["timestamp"],
                                        "context": Counter(), "scanner_only": True, "sources": set()})
            row["count"] += 1
            row["last_seen"] = e["timestamp"]
            row["context"][e.get("signature") or e["event_type"]] += 1
            row["scanner_only"] = row["scanner_only"] and scanner
            if e.get("source_ip"):
                row["sources"].add(e["source_ip"])
        if e["event_type"] == "MalwareTraffic" and e["extra"].get("_direction") == "outbound" and e.get("dest_ip"):
            key = ("c2", e["dest_ip"])
            row = iocs.setdefault(key, {"type": "c2", "value": e["dest_ip"], "host": e["dest_ip"], "count": 0,
                                        "first_seen": e["timestamp"], "last_seen": e["timestamp"],
                                        "context": Counter(), "scanner_only": False, "sources": set()})
            row["count"] += 1
            row["last_seen"] = e["timestamp"]
            row["context"][e.get("signature") or "Malware traffic"] += 1
            row["sources"].add(e.get("source_ip") or e.get("host"))
    rows = []
    for row in iocs.values():
        rows.append({
            "type": row["type"], "value": row["value"], "host": row["host"], "count": row["count"],
            "first_seen": _show(row["first_seen"]), "last_seen": _show(row["last_seen"]),
            "context": _top(row["context"], 2), "scanner_only": row["scanner_only"],
            "sources": sorted(s for s in row["sources"] if s),
            "verdict": "Scanner callback (verify)" if row["scanner_only"] else
                       ("C2 destination" if row["type"] == "c2" else "Malware staging / download"),
        })
    order = {"c2": 0, "ip": 1, "url": 2, "domain": 3}
    rows.sort(key=lambda r: (r["scanner_only"], order.get(r["type"], 9), -r["count"]))
    return rows


# ---------------------------------------------------------------- findings

def _network_findings(events, meta, iocs):
    findings = []
    attack_events = [e for e in events if e["event_type"] in ATTACK_TYPES]
    if not attack_events:
        return findings

    # 1. Internal hosts that generate malware / C2 traffic (+ correlation with earlier attacks on them)
    compromised = defaultdict(list)
    for e in events:
        if e["event_type"] == "MalwareTraffic" and e["extra"].get("_direction") in ("outbound", "internal"):
            compromised[e.get("source_ip") or e["host"]].append(e)
    for host, items in compromised.items():
        first_c2 = _dt(items[0]["timestamp"])
        destinations = Counter(f"{e.get('dest_ip')}:{e.get('dest_port')}" for e in items)
        # Device-aggregated reports (e.g. Sangfor brute force) are written after the attack;
        # "Attack started" is the better time for ordering.
        prior = [e for e in events if e.get("dest_ip") == host and e["extra"].get("_direction") == "inbound"
                 and _start(e) and first_c2 and _start(e) <= first_c2]
        prior_bf = [e for e in prior if e["event_type"] == "BruteForce"]
        evidence = [
            f"{len(items)} malware/C2 event(s) from {host} between {_show(items[0]['timestamp'])} and {_show(items[-1]['timestamp'])}.",
            f"Destinations: {_top(destinations, 6)}.",
            f"Signatures: {_top(Counter(e.get('signature') for e in items), 3)}.",
        ]
        decoded = next((d for e in items for d in e["extra"].get("_decoded", [])), "")
        if decoded:
            evidence.append(f"Decoded payload: {decoded[:220]}")
        if prior:
            started = min((e["extra"].get("_attack_started") or e["timestamp"]) for e in prior)
            evidence.append(
                f"Before the first C2 event this host received {len(prior)} inbound attack event(s) from "
                f"{len({e.get('source_ip') for e in prior})} source(s), earliest activity {_show(started)} "
                f"({_top(Counter(e['event_type'] for e in prior), 4)}).")
        if prior_bf:
            attempts = sum(e["extra"].get("_attempts", 0) for e in prior_bf)
            ports = sorted({_port_label(e.get('dest_port')) for e in prior_bf})
            evidence.append(f"Brute-force on {', '.join(ports)} from {len({e.get('source_ip') for e in prior_bf})} IP(s)"
                            f"{f', {attempts} attempts reported' if attempts else ''} — a likely initial-access path.")
        allowed = sum(1 for e in items if e.get("action") == "Allow")
        if allowed:
            evidence.append(f"{allowed} of {len(items)} C2 event(s) were allowed by the firewall.")
        summary = (f"{host} is an internal host that sent traffic matching malware command-and-control signatures"
                   + (" after being attacked from the internet" if prior else "") + ". Treat it as possibly compromised.")
        findings.append(_finding(
            "Critical", f"Possible compromised internal host {host}", summary, evidence,
            ["Isolate the host from the network (or restrict it to an investigation VLAN) before cleaning it.",
             "Look for coin-miner / bot processes, high CPU, new cron jobs, systemd services, authorized_keys changes and files in /tmp.",
             f"Review {host}'s SSH / authentication logs for successful logins from the attacking IPs.",
             "Reset credentials used on the host, then rebuild it from a known-good image if compromise is confirmed.",
             f"Block the C2 destinations: {', '.join(sorted({e.get('dest_ip') for e in items if e.get('dest_ip')}))}."],
            "Compromise", [host] + [e.get("dest_ip") for e in items]))

    # 2. Brute force against exposed services
    brute = defaultdict(list)
    for e in events:
        if e["event_type"] == "BruteForce":
            brute[(e.get("dest_ip") or e["host"], e.get("dest_port") or "")].append(e)
    for (target, port), items in sorted(brute.items(), key=lambda kv: -len(kv[1])):
        attackers = Counter(e.get("source_ip") for e in items if e.get("source_ip"))
        attempts = sum(e["extra"].get("_attempts", 0) for e in items)
        countries = Counter(e["extra"].get("_src_location") for e in items if e["extra"].get("_src_location"))
        allowed = sum(1 for e in items if e.get("action") == "Allow")
        severity = "Critical" if target in compromised else "High"
        evidence = [f"{len(attackers)} attacking IP(s), {len(items)} report(s)" + (f", {attempts} attempts in total." if attempts else "."),
                    f"Top attackers: {_top(attackers, 6)}."]
        if countries:
            evidence.append(f"Source countries: {_top(countries, 6)}.")
        window_start = min((e["extra"].get("_attack_started") or e["timestamp"]) for e in items)
        evidence.append(f"Activity: {_show(window_start)} → {_show(items[-1]['timestamp'])}; {allowed} of {len(items)} allowed by the firewall.")
        if target in compromised:
            evidence.append(f"{target} later produced malware/C2 traffic (see the compromise finding).")
        findings.append(_finding(
            severity, f"Brute-force attack on {target}:{_port_label(port)}",
            f"{target} on port {_port_label(port)} is reachable from the internet and is being password-guessed by multiple sources.",
            evidence,
            [f"Do not expose {_port_label(port)} directly to the internet; allow it only from VPN / admin IP allow-lists.",
             "Disable password authentication (use keys/MFA) and enforce lockout or fail2ban-style throttling.",
             "Block the attacking IPs and check the server's auth logs for any successful login from them."],
            "Brute force", [target] + list(attackers)))

    # 3. Attacks that were allowed
    high_attacks = [e for e in attack_events if e["severity"] in ("High", "Critical")]
    allowed = [e for e in high_attacks if e.get("action") == "Allow"]
    if allowed:
        policies = Counter(e["extra"].get("_policy") for e in allowed if e["extra"].get("_policy"))
        filtered_allow = "allow" in str(meta.get("Action", "")).lower() and "deny" not in str(meta.get("Action", "")).lower()
        evidence = [f"{len(allowed)} of {len(high_attacks)} High/Critical attack event(s) have Action = Allow."]
        if policies:
            evidence.append(f"Matched policies: {_top(policies, 4)}.")
        if filtered_allow:
            evidence.append("Note: this export was filtered to Action = Allow, so blocked events are not in the file; "
                            "the ratio above describes only what was exported.")
        findings.append(_finding(
            "High", "High/Critical attacks were allowed, not blocked",
            "The firewall/IPS detected these attacks but let the traffic through (monitor/log-only behaviour).",
            evidence,
            ["Change the IPS/WAF action for High and Critical signatures in the matched policies from Allow/Monitor to Block/Deny.",
             "Confirm the protected servers are patched for the CVEs listed in the signature table.",
             "Re-export the same period including blocked events to see the full picture."],
            "Policy"))

    # 4. Critical exploit attempts and responses that look successful
    critical = [e for e in attack_events if e["severity"] == "Critical"]
    if critical:
        sig = Counter(e.get("signature") for e in critical)
        statuses = Counter(e["extra"].get("_http_status") or "no response captured" for e in critical)
        findings.append(_finding(
            "High", f"{len(critical)} Critical-severity exploit attempt(s)",
            "Critical signatures usually mean remote code execution or memory corruption attempts.",
            [f"Signatures: {_top(sig, 5)}.",
             f"Targets: {_top(Counter(e.get('dest_ip') for e in critical), 5)}.",
             f"Attackers: {_top(Counter(e.get('source_ip') for e in critical), 5)}.",
             f"HTTP responses: {_top(statuses, 5)}."],
            ["Check whether the targeted applications/versions are actually deployed and patched.",
             "Review the web/application logs on the targets at the listed times for errors or unexpected processes."],
            "Exploit", [e.get("source_ip") for e in critical] + [e.get("dest_ip") for e in critical]))
    web = [e for e in attack_events if e["event_type"] in WEB_TYPES]
    success = [e for e in web if str(e["extra"].get("_http_status", "")).startswith("2")]
    if success:
        findings.append(_finding(
            "High", f"{len(success)} exploit request(s) answered with HTTP 2xx",
            "A 2xx response does not prove exploitation, but it means the request reached the application and was processed.",
            [f"{_show(e['timestamp'])} {e.get('source_ip')} → {e.get('dest_ip')}:{e.get('dest_port')} "
             f"{e.get('signature')} (HTTP {e['extra'].get('_http_status')})" for e in success[:8]],
            ["Inspect the application logs and file system of these targets around the listed times."],
            "Exploit", [e.get("dest_ip") for e in success]))
    elif web:
        statuses = Counter(e["extra"].get("_http_status") for e in web if e["extra"].get("_http_status"))
        if statuses:
            findings.append(_finding(
                "Info", "No exploit request received a 2xx response",
                "Captured responses were redirects or errors, which lowers (but does not remove) the chance that these web attacks succeeded.",
                [f"Response codes: {_top(statuses, 6)}; {len(web) - sum(statuses.values())} event(s) had no response captured."],
                [], "Exploit"))

    # 5. Scanners / high-volume sources
    by_src = defaultdict(list)
    for e in attack_events:
        if e.get("source_ip") and e["extra"].get("_direction") in ("inbound", "external"):
            by_src[e["source_ip"]].append(e)
    scanner_groups = defaultdict(list)
    for ip, items in by_src.items():
        marker = next((e["extra"].get("_scanner") for e in items if e["extra"].get("_scanner")), "")
        if marker:
            scanner_groups[marker].append((ip, items))
    for marker, group in scanner_groups.items():
        total = sum(len(items) for _, items in group)
        sigs = {e.get("signature") for _, items in group for e in items}
        tool = marker.lower() in OFFENSIVE_TOOLS
        findings.append(_finding(
            "Medium", f"{'Attack tool' if tool else 'Vulnerability scanner'} identified: {marker}",
            ("The requests were sent with a well-known offensive / open-source scanning tool. Unless this is your own "
             "penetration test, treat the source as hostile.") if tool else
            ("These requests carry a scanner identifier. Commercial attack-surface scanners are often authorised by the organisation, "
             "but the findings still show which exploits your servers are exposed to."),
            [f"{total} event(s), {len(sigs)} different signature(s) from {', '.join(ip for ip, _ in group)}.",
             f"Targets: {_top(Counter(e.get('dest_ip') for _, items in group for e in items), 5)}."],
            ["Confirm with your security team / vendor that this scan is authorised; if not, block the source IPs.",
             "Use the signature list as a to-do list for patch verification."],
            "Scanning", [ip for ip, _ in group]))
    for ip, items in by_src.items():
        if any(e["extra"].get("_scanner") for e in items):
            continue
        sigs = {e.get("signature") for e in items}
        if len(items) >= 10 or len(sigs) >= 5:
            findings.append(_finding(
                "Medium", f"High-volume attack source {ip}",
                f"{ip} produced {len(items)} attack event(s) using {len(sigs)} signature(s) — automated exploitation or scanning.",
                [f"Location: {items[0]['extra'].get('_src_location') or 'unknown'}; targets: {_top(Counter(e.get('dest_ip') for e in items), 5)}.",
                 f"Top signatures: {_top(Counter(e.get('signature') for e in items), 4)}."],
                [f"Block {ip} at the perimeter and add it to your threat-intel watchlist."],
                "Scanning", [ip]))

    # 6. IOCs in payloads
    malicious = [i for i in iocs if not i["scanner_only"] and i["type"] in ("ip", "domain", "url")]
    if malicious:
        hosts = sorted({i["host"] for i in malicious})
        findings.append(_finding(
            "High", "Malware download hosts found in attack payloads",
            "Exploit payloads tried to make the victim download and run scripts from these hosts (bot/miner droppers).",
            [f"{i['value']} — seen {i['count']}x in {i['context']}" for i in malicious if i["type"] == "url"][:10]
            or [f"{i['value']} ({i['count']}x)" for i in malicious[:10]],
            [f"Block these hosts on the firewall, proxy and DNS: {', '.join(hosts[:15])}.",
             "Search firewall/proxy logs for any outbound connection to them — a hit means a payload probably executed."],
            "IOC", hosts))

    # 7. Exposed services
    inbound = [e for e in attack_events if e["extra"].get("_direction") == "inbound" and e.get("dest_port")]
    if inbound:
        ports = defaultdict(lambda: {"events": 0, "attackers": set(), "targets": set()})
        for e in inbound:
            row = ports[e["dest_port"]]
            row["events"] += 1
            row["attackers"].add(e.get("source_ip"))
            row["targets"].add(e.get("dest_ip"))
        evidence = [f"Port {_port_label(p)}: {r['events']} event(s), {len(r['attackers'])} attacker(s), targets {', '.join(sorted(t for t in r['targets'] if t))}"
                    for p, r in sorted(ports.items(), key=lambda kv: -kv[1]["events"])[:8]]
        findings.append(_finding(
            "Medium", "Internet-exposed services under attack",
            "These internal servers/ports are reachable from the internet and are actively attacked.",
            evidence,
            ["Review the NAT/publishing rules: expose only services that must be public.",
             "Keep internet-facing applications patched and placed behind a WAF in blocking mode."],
            "Exposure"))
    return findings


def _sliding_max(times, window):
    best, j = 0, 0
    for i in range(len(times)):
        while times[i] - times[j] > window:
            j += 1
        best = max(best, i - j + 1)
    return best


def _host_findings(events):
    findings = []
    failed = [e for e in events if e["event_type"] == "FailedLogin"]
    success = [e for e in events if e["event_type"] == "LoginSuccess"]
    groups = defaultdict(list)
    for e in failed:
        key = e.get("source_ip") or f"{e.get('username') or '?'}@{e.get('host')}"
        groups[key].append(e)
    for key, items in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        if len(items) < 5:
            continue
        times = sorted(t for t in (_dt(e["timestamp"]) for e in items) if t)
        peak = _sliding_max(times, timedelta(minutes=5)) if times else 0
        users = Counter(e.get("username") for e in items if e.get("username"))
        later_success = [s for s in success
                         if ((s.get("source_ip") and s.get("source_ip") == items[0].get("source_ip"))
                             or (not items[0].get("source_ip") and s.get("username") in users))
                         and _dt(s["timestamp"]) and times and _dt(s["timestamp"]) >= times[0]]
        evidence = [f"{len(items)} failed logins, peak {peak} within 5 minutes, {_show(items[0]['timestamp'])} → {_show(items[-1]['timestamp'])}.",
                    f"Accounts tried: {_top(users, 8) or 'unknown'}."]
        severity = "High" if len(items) >= 20 or peak >= 10 else "Medium"
        title = f"Password guessing from {key}"
        if len(users) >= 5:
            title = f"Password spraying from {key} ({len(users)} accounts)"
            severity = "High"
        if later_success:
            s = later_success[0]
            severity = "Critical"
            title = f"Successful login after repeated failures from {key}"
            evidence.append(f"Successful login as '{s.get('username')}' at {_show(s['timestamp'])} on {s.get('host')}.")
        findings.append(_finding(
            severity, title,
            "Repeated authentication failures from one source indicate brute-force or password guessing.",
            evidence,
            ["Block or rate-limit the source and confirm the targeted accounts have strong passwords / MFA."]
            + (["Treat the successful session as suspicious: review what the account did afterwards and reset its password."] if later_success else []),
            "Brute force", [items[0].get("source_ip")] if items[0].get("source_ip") else []))

    simple = [
        ({"LogCleared"}, "High", "Security / event log cleared",
         "Clearing logs is a common anti-forensics step.", ["Confirm who cleared the log and why; collect logs from other sources for that period."]),
        ({"ServiceInstalled", "ScheduledTaskCreated", "Persistence"}, "High", "Persistence mechanisms created",
         "New services and scheduled tasks are common ways for malware to survive a reboot.",
         ["Verify each service/task against change records; inspect the executable path and signer."]),
        ({"AccountCreated", "GroupMemberAdded", "PasswordReset"}, "Medium", "Account and group changes",
         "New accounts or group membership changes can indicate privilege escalation or persistence.",
         ["Confirm each change was approved; remove unexpected accounts or memberships."]),
        ({"AccountLockout"}, "Medium", "Account lockouts", "Lockouts often follow password guessing.",
         ["Identify the source of the failed attempts for each locked account."]),
    ]
    for types, severity, title, summary, recs in simple:
        items = [e for e in events if e["event_type"] in types]
        if not items:
            continue
        if any(e["event_type"] == "GroupMemberAdded" and e["severity"] in ("High", "Critical") for e in items):
            severity, title = "High", "Privileged group membership changed"
        findings.append(_finding(
            severity, f"{title} ({len(items)})", summary,
            [f"{_show(e['timestamp'])} {e.get('host')}: {e.get('details')[:200]}" for e in items[:8]], recs, "Host"))

    suspicious = [e for e in events
                  if any(t in (str(e.get("details", "")) + " " + str(e["extra"].get("_command", ""))).lower() for t in WATCH_TERMS)
                  and e["event_type"] not in ATTACK_TYPES]
    if suspicious:
        findings.append(_finding(
            "High", f"Suspicious commands ({len(suspicious)})",
            "Commands matched a watch-list of techniques used for credential theft, download-and-execute or obfuscation.",
            [f"{_show(e['timestamp'])} {e.get('host')} {e.get('username') or ''}: {e.get('details')[:200]}" for e in suspicious[:8]],
            ["Review the parent process and the user session; collect the script/binary for analysis."], "Host"))

    night = [e for e in success if _dt(e["timestamp"]) and (_dt(e["timestamp"]).hour >= 22 or _dt(e["timestamp"]).hour < 6)]
    if night:
        findings.append(_finding(
            "Low", f"Successful logins outside business hours ({len(night)})",
            "Logins between 22:00 and 06:00 (log clock time) are worth a quick review.",
            [f"{_show(e['timestamp'])} {e.get('username')} from {e.get('source_ip') or 'local'} on {e.get('host')}" for e in night[:8]],
            ["Confirm these sessions with the account owners."], "Host"))
    return findings


# ---------------------------------------------------------------- entry point

def analyze_import(import_id):
    imp = get_import(import_id)
    if not imp:
        return None
    events = list_import_events(import_id)
    alerts = list_import_alerts(import_id)
    meta = imp.get("meta") or {}

    first = events[0]["timestamp"] if events else None
    last = events[-1]["timestamp"] if events else None
    span = (_dt(last) - _dt(first)).total_seconds() if first and last and _dt(first) and _dt(last) else 0
    severity_counts, action_counts, type_counts = Counter(), Counter(), Counter()
    for e in events:  # summary rows stand for many original records (pipeline data reduction)
        hits = int(e.get("hits") or 1)
        severity_counts[e["severity"]] += hits
        action_counts[e.get("action") or "Not recorded"] += hits
        type_counts[e["event_type"]] += hits
    raw_total = sum(int(e.get("hits") or 1) for e in events)
    signals = signals_for_import(import_id)
    detections = {}
    for sig in signals:
        d = detections.setdefault(sig["rule_id"], {"rule_id": sig["rule_id"], "title": sig["rule_title"], "level": sig["level"],
                                                   "signals": 0, "risk": 0.0, "entities": set(), "mitre": sig.get("mitre") or "",
                                                   "example": sig.get("message")})
        d["signals"] += 1
        d["risk"] += float(sig.get("risk_score") or 0)
        d["entities"].add(f"{sig['entity_type']}:{sig['entity_value']}")
    detections = sorted(({**d, "entities": sorted(d["entities"])[:6], "entity_count": len(d["entities"]), "risk": round(d["risk"])}
                         for d in detections.values()), key=lambda d: (-SEVERITY_RANK.get(d["level"], 0), -d["signals"]))
    src_ips = {e.get("source_ip") for e in events if e.get("source_ip")}
    external_sources = {ip for ip in src_ips if not is_internal(ip)}
    internal_targets = {e.get("dest_ip") for e in events if e.get("dest_ip") and is_internal(e.get("dest_ip"))}
    countries = Counter(e["extra"].get("_src_location") for e in events
                        if e["extra"].get("_src_location") and e["extra"].get("_direction") == "inbound")
    ports = Counter(_port_label(e.get("dest_port")) for e in events
                    if e.get("dest_port") and e["extra"].get("_direction") == "inbound")
    users = Counter(e.get("username") for e in events if e.get("username"))

    iocs = _ioc_table(events)
    findings = _network_findings(events, meta, iocs) + _host_findings(events)
    findings.sort(key=lambda f: -SEVERITY_RANK.get(f["severity"], 0))
    if not findings:
        findings.append(_finding(
            "Info", "No notable findings",
            "None of the analysis heuristics matched. This does not prove the systems are clean — "
            "it only means nothing in this file matched MiniSOC's starter logic.", [], [], "General"))
    overall = _max_sev(f["severity"] for f in findings) if findings else "Info"

    recommendations, seen = [], set()
    for f in findings:
        for rec in f["recommendations"][:2]:
            if rec not in seen:
                seen.add(rec)
                recommendations.append({"severity": f["severity"], "text": rec, "finding": f["title"]})

    return {
        "import": imp,
        "meta": meta,
        "overall": overall,
        "detections": detections,
        "pipeline": {"raw": imp.get("raw_records") or raw_total, "stored": len(events),
                     "summarized": imp.get("summarized") or 0, "signals": len(signals),
                     "incidents": len({a["id"] for a in alerts}),
                     "reduction": round(100 * (1 - len(events) / raw_total)) if raw_total else 0},
        "summary": {
            "events": raw_total,
            "first": _show(first), "last": _show(last), "span": _duration(span),
            "unique_sources": len(src_ips), "external_sources": len(external_sources),
            "internal_targets": len(internal_targets),
            "hosts": len({e.get("host") for e in events if e.get("host")}),
            "users": len(users),
            "alerts": len(alerts),
            "high_or_critical": severity_counts.get("High", 0) + severity_counts.get("Critical", 0),
            "allowed": action_counts.get("Allow", 0),
            "blocked": action_counts.get("Block", 0),
            "iocs": len([i for i in iocs if not i["scanner_only"]]),
        },
        "severity": [{"name": s, "count": severity_counts.get(s, 0)} for s in SEVERITIES],
        "actions": action_counts.most_common(),
        "event_types": type_counts.most_common(),
        "countries": countries.most_common(10),
        "ports": ports.most_common(10),
        "users": users.most_common(10),
        "timeline": _timeline(events),
        "top_sources": _source_table(events),
        "top_targets": _target_table(events),
        "signatures": _signature_table(events),
        "iocs": iocs,
        "findings": findings,
        "recommendations": recommendations[:12],
        "alerts": alerts,
        "alert_rules": Counter(a["rule_name"] for a in alerts).most_common(),
        "sample_events": events[:40],
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
