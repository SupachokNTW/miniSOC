"""Ingestion pipeline shared by file imports, the HTTP ingest API, simulations and the Windows collector.

    parse -> normalise -> enrich (assets, identities, business hours) -> detect (rules)
          -> reduce (summarise normal traffic, keep evidence) -> store -> risk-based alerting -> SOAR

Detection always runs on the *full* batch before reduction, so summarising normal requests
saves storage (SIEM cost) without hiding anything from the rules.
"""
import ipaddress
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

import config
import database
import risk
import soar
from detection_engine import DBHistory, Engine, get_rules, to_dt

AGGREGATABLE = {"WebRequest", "ApiRequest", "LogEntry", "Syslog", "FirewallEvent", "CloudApiCall", "Logout", "Logoff"}
DATASET_BY_TYPE = {
    "FailedLogin": "auth", "LoginSuccess": "auth", "InvalidUser": "auth", "MFADisabled": "auth", "PasswordChange": "auth",
    "PrivilegeChange": "iam", "GroupMemberAdded": "iam", "AccountCreated": "iam", "AdminAction": "iam",
    "WebRequest": "web", "WebAttack": "web", "ApiRequest": "api", "BruteForce": "network", "MalwareTraffic": "network",
    "ExploitAttempt": "network", "IntrusionEvent": "network", "ProcessStart": "host", "ServiceInstalled": "host",
    "ScheduledTaskCreated": "host", "LogCleared": "host", "SudoCommand": "linux", "Syslog": "linux",
}
PRIVILEGED_NAMES = re.compile(r"^(admin|administrator|root|sa|sysadmin|superuser|domain admins?|it-admin|.*-admin|admin-.*)$", re.I)


def _is_internal(value):
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return any(ip in n for n in (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
                                 ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("100.64.0.0/10"),
                                 ipaddress.ip_network("127.0.0.0/8")) if ip.version == n.version)


def _business(settings):
    try:
        start, end = settings.get("business_hours", "08:00-19:00").split("-")
        sh, sm = (int(x) for x in start.split(":"))
        eh, em = (int(x) for x in end.split(":"))
    except ValueError:
        sh, sm, eh, em = 8, 0, 19, 0
    days = set()
    for part in str(settings.get("business_days", "1-5")).split(","):
        if "-" in part:
            a, b = part.split("-")
            days.update(range(int(a), int(b) + 1))
        elif part.strip().isdigit():
            days.add(int(part))
    return (sh * 60 + sm, eh * 60 + em, days or {1, 2, 3, 4, 5})


def off_hours(timestamp, business):
    try:
        local = datetime.fromisoformat(str(timestamp))
    except ValueError:
        return False
    minutes = local.hour * 60 + local.minute
    start, end, days = business
    return local.isoweekday() not in days or not (start <= minutes < end)


def enrich(events, settings, assets, identities):
    business = _business(settings)
    for e in events:
        e.setdefault("extra", {})
        e.setdefault("hits", 1)
        e["_t"] = e.get("_t") or to_dt(e.get("timestamp"))
        if not e.get("dataset"):
            e["dataset"] = DATASET_BY_TYPE.get(e.get("event_type"), "app")
        e["extra"]["_off_hours"] = off_hours(e.get("timestamp"), business)
        for field in ("host", "dest_ip", "source_ip"):
            value = e.get(field)
            asset = assets.get(value) or assets.get(str(value or "").lower())
            if asset:
                e["extra"].setdefault("_asset", {"name": asset.get("name") or asset.get("hostname") or asset.get("ip"),
                                                 "criticality": asset.get("criticality"), "owner": asset.get("owner"),
                                                 "field": field})
                e["extra"]["_asset_criticality"] = asset.get("criticality")
                break
        user = (e.get("username") or "").lower()
        if user and user in identities:
            ident = identities[user]
            e["extra"]["_privileged"] = bool(ident.get("privileged"))
            if ident.get("department"):
                e["extra"]["_department"] = ident["department"]
        elif user and PRIVILEGED_NAMES.match(user):
            e["extra"]["_privileged"] = True
    return events


def _status_class(status):
    return f"{int(status) // 100}xx" if status else "-"


def reduce_events(events, signals, settings, options):
    """Return (stored_events, stats). Events used as evidence by a signal are always kept."""
    evidence = {id(s["event"]) for s in signals}
    aggregate = str(options.get("aggregate_web", settings.get("pipeline_aggregate_web", "1"))) in ("1", "true", "True", "on")
    min_sev = options.get("min_severity") or settings.get("pipeline_store_min_severity", "Info")
    min_rank = config.SEVERITY_RANK.get(min_sev, 0)
    kept, dropped = [], 0
    buckets = defaultdict(list)
    for e in events:
        if id(e) in evidence:
            kept.append(e)
            continue
        low_value = (e.get("event_type") in AGGREGATABLE and e.get("severity") == "Info"
                     and not (e.get("extra") or {}).get("_attack_pattern") and (e.get("http_status") or 0) < 500)
        if aggregate and low_value and e.get("_t"):
            t = e["_t"]
            bucket = t.replace(minute=t.minute - t.minute % 5, second=0, microsecond=0)
            key = (bucket, e.get("dataset"), e.get("event_type"), e.get("source_ip") or "", e.get("username") or "",
                   e.get("host") or "", _status_class(e.get("http_status")))
            buckets[key].append(e)
            continue
        if config.SEVERITY_RANK.get(e.get("severity"), 0) < min_rank:
            dropped += 1
            continue
        kept.append(e)
    summaries = []
    for key, items in buckets.items():
        if len(items) == 1:
            kept.append(items[0])
            continue
        _, dataset, etype, src, user, host, sclass = key
        items.sort(key=lambda x: x["_t"])
        first = items[0]
        hits = sum(int(i.get("hits") or 1) for i in items)
        total_bytes = sum(int(i.get("bytes_out") or 0) for i in items)
        statuses = Counter(str(i.get("http_status") or "-") for i in items)
        paths = Counter(i.get("url_path") for i in items if i.get("url_path"))
        status = statuses.most_common(1)[0][0]
        summary = {
            "timestamp": first["timestamp"], "_t": first["_t"], "event_type": etype, "severity": "Info",
            "host": host or first.get("host"), "username": user, "source_ip": src, "dest_ip": first.get("dest_ip"),
            "dest_port": first.get("dest_port"), "action": first.get("action"), "signature": first.get("signature"),
            "event_code": first.get("event_code"), "dataset": dataset, "country": first.get("country"),
            "http_status": int(status) if status.isdigit() else None, "bytes_out": total_bytes or None,
            "http_method": first.get("http_method"), "url_path": paths.most_common(1)[0][0] if paths else first.get("url_path"),
            "hits": hits, "source": first.get("source"),
            "details": (f"Summary of {hits} {etype} events ({sclass}) from {src or user or host or 'unknown'} in 5 min"
                        + (f" | {total_bytes:,} B" if total_bytes else "")
                        + (f" | top paths: {', '.join(p for p, _ in paths.most_common(3))}" if paths else "")),
            "extra": {"_summary": True, "_status_counts": dict(statuses), "_top_paths": dict(paths.most_common(5)),
                      "_last": items[-1]["timestamp"], "_off_hours": first["extra"].get("_off_hours")},
        }
        summaries.append(summary)
    stored = sorted(kept + summaries, key=lambda x: x.get("_t") or datetime.min.replace(tzinfo=timezone.utc))
    return stored, {"summarized_records": sum(len(v) for v in buckets.values() if len(v) > 1),
                    "summary_rows": len(summaries), "dropped": dropped}


def _register_context(events):
    """Auto-discover internal assets and identities so analysts can set criticality/owners later."""
    assets = database.asset_lookup()
    identities = database.identity_lookup()
    new_assets, new_users = set(), set()
    for e in events:
        for field in ("dest_ip", "host"):
            value = e.get(field)
            if value and _is_internal(value) and value not in assets:
                new_assets.add(value)
        if e.get("event_type") in ("MalwareTraffic",) and e.get("source_ip") and _is_internal(e["source_ip"]):
            if e["source_ip"] not in assets:
                new_assets.add(e["source_ip"])
        user = (e.get("username") or "").strip()
        if user and e.get("dataset") in ("auth", "iam", "api", "cloud") and user.lower() not in identities and len(new_users) < 500:
            new_users.add(user)
    for ip in list(new_assets)[:500]:
        database.upsert_asset(ip=ip, criticality=3, auto=True)
    for user in new_users:
        database.upsert_identity(user, privileged=bool(PRIVILEGED_NAMES.match(user)), auto=True)


def enabled_rules():
    rules, errors = get_rules()
    states = database.rule_states()
    return rules, {r.id: states.get(r.id, r.enabled_default) for r in rules}


def process_batch(events, source_label, import_id=None, options=None, user=None):
    """Run the full pipeline for a batch of parsed events. Caller commits the transaction."""
    options = options or {}
    settings = database.get_settings()
    if not events:
        return {"received": 0, "stored": 0, "signals": 0, "incidents_created": 0, "incidents_updated": 0}
    for e in events:
        e["source"] = e.get("source") or source_label
    enrich(events, settings, database.asset_lookup(), database.identity_lookup())
    events = [e for e in events if e.get("_t")]

    rules, enabled = enabled_rules()
    history = DBHistory()
    if options.get("isolated"):  # simulations: re-runnable, so previous runs must not dedup new signals
        history.last_signal = lambda *a, **k: None
    engine = Engine(rules, history, enabled)
    signals = engine.run(events)

    stored, stats = reduce_events(events, signals, settings, options)
    for e in stored:
        e["source"] = e.get("source") or source_label
    ids = database.insert_events_bulk(stored, import_id)
    id_by_obj = {id(e): new_id for e, new_id in zip(stored, ids)}

    risk.apply_multipliers(signals)
    for s in signals:
        s["event_id"] = id_by_obj.get(id(s["event"]))
        s["import_id"] = import_id
    signal_ids = database.insert_signals(signals)
    for s, sid in zip(signals, signal_ids):
        s["id"] = sid
    incidents = risk.correlate(signals, settings)
    soar.run_for_incidents(incidents, settings, user=user)
    _register_context(events)
    return {
        "received": sum(int(e.get("hits") or 1) for e in events),
        "stored": len(stored),
        "summarized_records": stats["summarized_records"],
        "summary_rows": stats["summary_rows"],
        "dropped": stats["dropped"],
        "signals": len(signals),
        "rules_fired": sorted({s["rule_id"] for s in signals}),
        "incidents_created": sum(1 for i in incidents if i["action"] == "created"),
        "incidents_updated": sum(1 for i in incidents if i["action"] == "updated"),
        "incident_ids": sorted({i["alert_id"] for i in incidents}),
    }
