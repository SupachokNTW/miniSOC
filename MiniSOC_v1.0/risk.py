"""Risk-Based Alerting (RBA).

Every rule match is a *signal* that adds risk points to an entity (IP, user or host).
An incident is opened only when an entity's risk inside the window (default 24 h) crosses
the threshold (default 100), or when a rule marked `alert: true` fires. Later signals for the
same entity are attached to the open incident instead of creating new alerts — this is how
MiniSOC fights alert fatigue.
"""
from collections import Counter, defaultdict
from datetime import timedelta

import config
import database
from detection_engine import iso, to_dt

CRITICALITY_MULTIPLIER = {1: 0.6, 2: 0.8, 3: 1.0, 4: 1.5, 5: 2.0}
PRIVILEGED_MULTIPLIER = 1.5
LABELS = {"ip": "IP", "user": "user", "host": "host"}


def apply_multipliers(signals):
    """Context matters: risk on a critical asset or a privileged account counts more."""
    assets = database.asset_lookup()
    identities = database.identity_lookup()
    for s in signals:
        multiplier = 1.0
        if s["entity_type"] in ("ip", "host"):
            asset = assets.get(s["entity_value"]) or assets.get(s["entity_value"].lower())
            if asset:
                multiplier = CRITICALITY_MULTIPLIER.get(int(asset.get("criticality") or 3), 1.0)
        elif s["entity_type"] == "user":
            ident = identities.get(s["entity_value"].lower())
            privileged = (ident and ident.get("privileged")) or (s["event"].get("extra") or {}).get("_privileged")
            if privileged:
                multiplier = PRIVILEGED_MULTIPLIER
        s["multiplier"] = multiplier
        s["risk_score"] = round(float(s["base_score"]) * multiplier, 1)


def score_severity(score):
    if score >= 300:
        return "Critical"
    if score >= 180:
        return "High"
    if score >= 100:
        return "Medium"
    return "Low"


def _max_sev(*values):
    return max((v for v in values if v), key=lambda v: config.SEVERITY_RANK.get(v, 0), default="Low")


def entity_label(entity_type, value):
    return f"{LABELS.get(entity_type, entity_type)} {value}"


def correlate(signals, settings):
    threshold = float(settings.get("rba_threshold", 100) or 100)
    window = timedelta(hours=float(settings.get("rba_window_hours", 24) or 24))
    by_entity = defaultdict(list)
    for s in signals:
        if s.get("id"):
            by_entity[(s["entity_type"], s["entity_value"])].append(s)
    results = []
    for (etype, evalue), items in by_entity.items():
        latest = max(s["_t"] for s in items)
        earliest = min(s["_t"] for s in items)
        open_incident = database.open_incident_for_entity(etype, evalue, iso(earliest - window), iso(latest + window))
        if open_incident:
            database.attach_signals([s["id"] for s in items], open_incident["id"])
            database.refresh_incident_stats(open_incident["id"])
            fresh = database.get_incident(open_incident["id"])
            direct = [s["level"] for s in items if s.get("direct_alert")]
            new_sev = _max_sev(open_incident["severity"], score_severity(fresh["risk_score"] or 0), *direct)
            if new_sev != open_incident["severity"]:
                database.update_incident_fields(open_incident["id"], severity=new_sev)
            results.append({"alert_id": open_incident["id"], "action": "updated", "severity": new_sev,
                            "escalated": new_sev != open_incident["severity"]})
            continue
        pool = database.entity_signals(etype, evalue, iso(latest - window), iso(latest), unattached_only=True)
        score = sum(float(p["risk_score"] or 0) for p in pool)
        direct = [p for p in pool if p.get("direct_alert")]
        if score < threshold and not direct:
            continue
        rules = Counter(p["rule_title"] for p in pool)
        top = max(pool, key=lambda p: (p.get("direct_alert") or 0, float(p["risk_score"] or 0)))
        severity = _max_sev(score_severity(score), *[d["level"] for d in direct])
        label = entity_label(etype, evalue)
        if direct:
            title = f"{top['rule_title']} — {label}"
            reason = "a high-confidence rule fired"
        else:
            title = f"Risk threshold exceeded — {label}"
            reason = f"risk {score:.0f} ≥ threshold {threshold:.0f} within {int(window.total_seconds() // 3600)} h"
        explanation = (f"Opened because {reason}. {len(pool)} detection(s) from {len(rules)} rule(s): "
                       + ", ".join(f"{name} ×{n}" for name, n in rules.most_common(5))
                       + f". Strongest signal: {top['message']}")
        alert_id = database.create_incident(
            event_id=top.get("event_id"), rule_id=top["rule_id"], rule_name=top["rule_title"], severity=severity,
            title=title, explanation=explanation, entity_type=etype, entity_value=evalue, risk_score=round(score, 1),
            first_ts=pool[0]["ts_utc"], last_ts=pool[-1]["ts_utc"], mitre=top.get("mitre"),
            context={"threshold": threshold, "window_hours": window.total_seconds() / 3600})
        database.attach_signals([p["id"] for p in pool], alert_id)
        database.refresh_incident_stats(alert_id)
        results.append({"alert_id": alert_id, "action": "created", "severity": severity, "escalated": False})
    return results


def entity_risk(entity_type, entity_value, hours=24):
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    rows = database.entity_signals(entity_type, entity_value, iso(now - timedelta(hours=hours)), iso(now))
    return sum(float(r["risk_score"] or 0) for r in rows)


__all__ = ["apply_multipliers", "correlate", "score_severity", "entity_label", "to_dt"]
