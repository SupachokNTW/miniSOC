"""Export events in Elastic Common Schema (ECS) style NDJSON, so data can move to Wazuh / Elastic /
Sentinel / a data lake (S3 + Athena) without re-parsing. Personal data can be masked (PDPA)."""
import json

CATEGORY = {
    "FailedLogin": ("authentication", "start", "failure"), "LoginSuccess": ("authentication", "start", "success"),
    "MFADisabled": ("iam", "change", "success"), "PasswordChange": ("iam", "change", "success"),
    "PrivilegeChange": ("iam", "change", "success"), "GroupMemberAdded": ("iam", "group", "success"),
    "AccountCreated": ("iam", "creation", "success"), "WebRequest": ("web", "access", None),
    "ApiRequest": ("web", "access", None), "WebAttack": ("intrusion_detection", "denied", None),
    "ExploitAttempt": ("intrusion_detection", "info", None), "BruteForce": ("intrusion_detection", "info", None),
    "MalwareTraffic": ("malware", "connection", None), "ProcessStart": ("process", "start", None),
    "ServiceInstalled": ("configuration", "creation", None), "ScheduledTaskCreated": ("configuration", "creation", None),
    "LogCleared": ("configuration", "deletion", None),
}


def to_ecs(e, mask=None):
    m = mask or (lambda v, kind=None: v)
    category, etype, outcome = CATEGORY.get(e.get("event_type"), ("host", "info", None))
    doc = {
        "@timestamp": e.get("ts_utc") or e.get("timestamp"),
        "event": {"kind": "event", "category": [category], "type": [etype], "action": e.get("event_type"),
                  "severity_name": e.get("severity"), "dataset": f"minisoc.{e.get('dataset') or 'other'}",
                  "code": e.get("event_code") or None, "original_count": e.get("hits", 1)},
        "message": m(e.get("details"), "text"),
        "host": {"name": e.get("host")},
        "observer": {"product": e.get("source")},
        "labels": {"minisoc_event_id": e.get("id"), "minisoc_import_id": e.get("import_id")},
    }
    if outcome:
        doc["event"]["outcome"] = outcome
    if e.get("source_ip"):
        doc["source"] = {"ip": m(e["source_ip"], "ip")}
        if e.get("country"):
            doc["source"]["geo"] = {"country_iso_code": e["country"]}
    if e.get("dest_ip") or e.get("dest_port"):
        doc["destination"] = {"ip": e.get("dest_ip") or None, "port": int(e["dest_port"]) if str(e.get("dest_port") or "").isdigit() else None}
    if e.get("username"):
        doc["user"] = {"name": m(e["username"], "user")}
    if e.get("http_status") or e.get("http_method"):
        doc["http"] = {"request": {"method": e.get("http_method") or None},
                       "response": {"status_code": e.get("http_status"), "bytes": e.get("bytes_out")}}
    if e.get("url_path"):
        doc["url"] = {"path": e["url_path"]}
    if e.get("action"):
        doc["event"]["outcome"] = "success" if e["action"] == "Allow" else "failure"
    if e.get("signature"):
        doc["rule"] = {"name": e["signature"]}
    return doc


def ndjson(events, mask=None):
    for e in events:
        yield json.dumps(to_ecs(e, mask), ensure_ascii=False, default=str) + "\n"
