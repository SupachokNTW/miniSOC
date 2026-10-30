"""SOAR: playbooks (playbooks/*.yml) that respond to incidents automatically or after approval.

Actions
- blocklist_add   add the attacking IP (and payload IOCs) to the blocklist feed (/feeds/blocklist.txt)
                  that a WAF / firewall can pull; internal and allow-listed addresses are never blocked
- notify          post a message to Slack / Microsoft Teams / Discord / generic webhook
- webhook         post the incident to an integration URL from Settings (WAF, EDR, identity, ticketing)
- disable_user    ask the identity provider webhook to disable/suspend the account (or create a task)
- isolate_host    ask the EDR webhook to isolate the host (or create a task)
- create_ticket   send the incident to the ticketing webhook
- set_status      move the incident to Investigating and assign it
- create_task     add checklist items to the incident
"""
import glob
import ipaddress
import json
import os
import urllib.error
import urllib.request

import yaml

import config
import database

ACTION_TYPES = {"blocklist_add", "notify", "webhook", "disable_user", "isolate_host", "create_ticket", "set_status", "create_task"}
_CACHE = {"stamp": None, "playbooks": [], "errors": []}


def load_playbooks():
    files = sorted(glob.glob(os.path.join(config.PLAYBOOKS_DIR, "*.y*ml")))
    stamp = tuple((f, os.path.getmtime(f)) for f in files)
    if _CACHE["stamp"] == stamp:
        return _CACHE["playbooks"], _CACHE["errors"]
    playbooks, errors = [], []
    for path in files:
        try:
            with open(path, encoding="utf-8") as fh:
                source = fh.read()
            data = yaml.safe_load(source) or {}
            if not data.get("id"):
                raise ValueError("missing id")
            for action in data.get("actions") or []:
                if action.get("type") not in ACTION_TYPES:
                    raise ValueError(f"unknown action type '{action.get('type')}'")
            data["mode"] = data.get("mode", "auto")
            if data["mode"] not in ("auto", "approval"):
                raise ValueError("mode must be auto or approval")
            data["trigger"] = data.get("trigger") or {}
            data["_source"] = source
            data["_file"] = os.path.basename(path)
            playbooks.append(data)
        except Exception as exc:  # noqa: BLE001
            errors.append({"file": os.path.basename(path), "error": str(exc)})
    _CACHE.update(stamp=stamp, playbooks=playbooks, errors=errors)
    return playbooks, errors


def _allowlisted(value, settings):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return True
    for part in str(settings.get("allowlist", "")).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if ip in ipaddress.ip_network(part, strict=False):
                return True
        except ValueError:
            continue
    return False


def _is_ip(value):
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def matches_trigger(playbook, incident, rule_ids, settings, action):
    trig = playbook["trigger"]
    on = trig.get("on", ["created"])
    on = on if isinstance(on, list) else [on]
    if action not in on and not (action == "updated" and "escalated" in on and incident.get("_escalated")):
        return False
    if config.SEVERITY_RANK.get(incident["severity"], 0) < config.SEVERITY_RANK.get(trig.get("min_severity", "Low"), 0):
        return False
    etypes = trig.get("entity_types")
    if etypes and incident.get("entity_type") not in etypes:
        return False
    scope = trig.get("entity_scope")
    if scope and incident.get("entity_type") == "ip":
        internal = _allowlisted(incident["entity_value"], settings)
        if (scope == "external" and internal) or (scope == "internal" and not internal):
            return False
    rules = trig.get("rules")
    if rules and not (set(rules) & set(rule_ids)):
        return False
    return True


def run_for_incidents(results, settings, user=None):
    if str(settings.get("soar_enabled", "1")) not in ("1", "true", "on"):
        return
    playbooks, _ = load_playbooks()
    for result in results:
        incident = database.get_incident(result["alert_id"])
        if not incident:
            continue
        incident["_escalated"] = result.get("escalated")
        rule_ids = {s["rule_id"] for s in database.signals_for_alert(incident["id"])}
        for pb in playbooks:
            if database.playbook_run_exists(pb["id"], incident["id"]):
                continue
            if not matches_trigger(pb, incident, rule_ids, settings, result["action"]):
                continue
            if pb["mode"] == "approval":
                planned = [{"type": a["type"], "status": "planned", "detail": describe(a, incident)} for a in pb.get("actions", [])]
                database.create_playbook_run(pb["id"], pb.get("title"), incident["id"], "pending_approval", planned)
            else:
                run_id = database.create_playbook_run(pb["id"], pb.get("title"), incident["id"], "running", [])
                outcome = execute(pb, incident, settings, user or "soar")
                database.update_playbook_run(run_id, _overall(outcome), outcome)


def _overall(outcome):
    if any(o["status"] == "failed" for o in outcome):
        return "partial" if any(o["status"] == "done" for o in outcome) else "failed"
    return "done"


def describe(action, incident):
    t = action["type"]
    entity = f"{incident.get('entity_type')} {incident.get('entity_value')}"
    return {
        "blocklist_add": f"Add {entity} (and payload IOCs) to the blocklist for {action.get('ttl_hours', 72)} h",
        "notify": "Send a chat notification",
        "webhook": f"POST the incident to the '{action.get('target', '?')}' integration",
        "disable_user": f"Disable / suspend account {incident.get('entity_value')} at the identity provider",
        "isolate_host": f"Isolate host {incident.get('entity_value')} via EDR",
        "create_ticket": "Open a ticket in the ticketing system",
        "set_status": f"Set status to {action.get('status', 'Investigating')}",
        "create_task": f"Add {len(action.get('tasks', []))} checklist task(s)",
    }.get(t, t)


def post_json(url, payload, timeout=6):
    if not url or not url.startswith(("https://", "http://")):
        raise ValueError("integration URL not configured")
    body = json.dumps(payload, ensure_ascii=False, default=str).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json",
                                                          "User-Agent": "MiniSOC-SOAR/1.0"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - URL comes from admin settings
        return resp.status


def _incident_payload(incident, settings, extra=None):
    base = (settings.get("base_url") or "").rstrip("/")
    payload = {
        "source": "MiniSOC", "incident_id": incident["id"], "title": incident["title"],
        "severity": incident["severity"], "status": incident["status"], "entity_type": incident.get("entity_type"),
        "entity": incident.get("entity_value"), "risk_score": incident.get("risk_score"),
        "mitre": incident.get("mitre"), "explanation": incident.get("explanation"),
        "url": f"{base}/incidents/{incident['id']}" if base else None,
    }
    payload.update(extra or {})
    return payload


def _iocs_for_incident(incident):
    values = set()
    for s in database.signals_for_alert(incident["id"]):
        if not s.get("event_id"):
            continue
        for e in database.get_events_by_ids([s["event_id"]]):
            for ioc in (e.get("extra") or {}).get("_iocs", []):
                if ioc.get("type") in ("ip", "domain"):
                    values.add((ioc["host"], "domain" if ioc["type"] == "domain" else "ip"))
            if e.get("event_type") == "MalwareTraffic" and e.get("dest_ip"):
                values.add((e["dest_ip"], "ip"))
    return values


def execute(playbook, incident, settings, actor):
    results = []
    for action in playbook.get("actions", []):
        t = action["type"]
        try:
            if t == "blocklist_add":
                targets = set()
                if incident.get("entity_type") == "ip":
                    targets.add((incident["entity_value"], "ip"))
                if action.get("include_iocs", True):
                    targets |= _iocs_for_incident(incident)
                added, skipped = [], []
                for value, kind in sorted(targets):
                    if kind == "ip" and (not _is_ip(value) or _allowlisted(value, settings)):
                        skipped.append(value)
                        continue
                    database.blocklist_add(value, kind, f"Incident #{incident['id']}: {incident['title'][:120]}",
                                           f"playbook:{playbook['id']}", incident["id"], action.get("ttl_hours", 72), actor)
                    added.append(value)
                detail = f"Blocked {', '.join(added) or 'nothing'}"
                if skipped:
                    detail += f"; skipped internal/allow-listed {', '.join(skipped)}"
                if added and settings.get("webhook_waf_url"):
                    try:
                        post_json(settings["webhook_waf_url"], _incident_payload(incident, settings, {"action": "block", "indicators": added}))
                        detail += "; pushed to WAF webhook"
                    except Exception as exc:  # noqa: BLE001
                        detail += f"; WAF webhook failed: {exc}"
                results.append({"type": t, "status": "done" if added else "skipped", "detail": detail})
            elif t == "notify":
                url = settings.get("notify_webhook_url")
                min_sev = action.get("min_severity") or settings.get("notify_min_severity", "High")
                if not url:
                    results.append({"type": t, "status": "skipped", "detail": "No notification webhook configured (Settings)"})
                elif config.SEVERITY_RANK.get(incident["severity"], 0) < config.SEVERITY_RANK.get(min_sev, 0):
                    results.append({"type": t, "status": "skipped", "detail": f"Severity below {min_sev}"})
                else:
                    text = (f"[MiniSOC] {incident['severity']} incident #{incident['id']}: {incident['title']}\n"
                            f"Risk {incident.get('risk_score')} · {incident.get('explanation', '')[:300]}")
                    payload = _incident_payload(incident, settings, {"text": text, "content": text[:1900]})
                    code = post_json(url, payload)
                    results.append({"type": t, "status": "done", "detail": f"Notification sent (HTTP {code})"})
            elif t in ("webhook", "create_ticket", "disable_user", "isolate_host"):
                target = {"create_ticket": "ticket", "disable_user": "identity", "isolate_host": "edr"}.get(t, action.get("target", ""))
                url = settings.get(f"webhook_{target}_url")
                verb = {"disable_user": "disable_user", "isolate_host": "isolate_host", "create_ticket": "create_ticket"}.get(t, action.get("verb", "incident"))
                if url:
                    code = post_json(url, _incident_payload(incident, settings, {"action": verb}))
                    results.append({"type": t, "status": "done", "detail": f"{verb} sent to {target} webhook (HTTP {code})"})
                elif t in ("disable_user", "isolate_host"):
                    task = (f"Disable / suspend account '{incident.get('entity_value')}' and revoke its sessions and tokens"
                            if t == "disable_user" else f"Isolate host {incident.get('entity_value')} from the network (EDR / switch port / VLAN)")
                    database.add_task(incident["id"], task)
                    results.append({"type": t, "status": "done", "detail": f"No {target} webhook configured - created manual task"})
                else:
                    results.append({"type": t, "status": "skipped", "detail": f"No {target} webhook configured (Settings)"})
            elif t == "set_status":
                status = action.get("status", "Investigating")
                if incident["status"] == "New":
                    database.set_incident_status(incident["id"], status)
                    database.update_incident_fields(incident["id"], assignee=action.get("assignee", "SOAR"))
                results.append({"type": t, "status": "done", "detail": f"Status {status}"})
            elif t == "create_task":
                for task in action.get("tasks", []):
                    database.add_task(incident["id"], str(task).replace("{entity}", str(incident.get("entity_value"))))
                results.append({"type": t, "status": "done", "detail": f"{len(action.get('tasks', []))} task(s) added"})
        except Exception as exc:  # noqa: BLE001 - one failed action must not stop the playbook
            results.append({"type": t, "status": "failed", "detail": str(exc)[:300]})
    return results


def approve_run(run_id, settings, actor, approve=True):
    run = database.get_playbook_run(run_id)
    if not run or run["status"] != "pending_approval":
        return None
    if not approve:
        database.update_playbook_run(run_id, "rejected", run["actions"], approved_by=actor)
        return "rejected"
    playbooks, _ = load_playbooks()
    pb = next((p for p in playbooks if p["id"] == run["playbook_id"]), None)
    incident = database.get_incident(run["alert_id"])
    if not pb or not incident:
        database.update_playbook_run(run_id, "failed", [{"type": "-", "status": "failed", "detail": "Playbook or incident missing"}], actor)
        return "failed"
    outcome = execute(pb, incident, settings, actor)
    status = _overall(outcome)
    database.update_playbook_run(run_id, status, outcome, approved_by=actor)
    return status


def run_manual(playbook_id, alert_id, settings, actor):
    playbooks, _ = load_playbooks()
    pb = next((p for p in playbooks if p["id"] == playbook_id), None)
    incident = database.get_incident(alert_id)
    if not pb or not incident:
        return None
    run_id = database.create_playbook_run(pb["id"], pb.get("title"), alert_id, "running", [])
    outcome = execute(pb, incident, settings, actor)
    database.update_playbook_run(run_id, _overall(outcome), outcome, approved_by=actor)
    return outcome
