"""SOC performance metrics: MTTD, MTTA, MTTR, false-positive rates, alert and data reduction."""
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from db import get_db
from detection_engine import to_dt


def _avg(values):
    values = [v for v in values if v is not None and v >= 0]
    return sum(values) / len(values) if values else None


def human(seconds):
    if seconds is None:
        return "—"
    seconds = int(seconds)
    if seconds < 120:
        return f"{seconds} s"
    if seconds < 7200:
        return f"{seconds // 60} min"
    if seconds < 172800:
        return f"{seconds / 3600:.1f} h"
    return f"{seconds / 86400:.1f} d"


def compute(days=30):
    db = get_db()
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    incidents = db.query("SELECT * FROM alerts WHERE created_at >= ?", (since,))
    mttd, mtta, mttr = [], [], []
    for inc in incidents:
        created = to_dt(inc["created_at"])
        first = to_dt(inc.get("first_event_ts"))
        if created and first:
            mttd.append((created - first).total_seconds())
        if created and inc.get("acknowledged_at"):
            mtta.append((to_dt(inc["acknowledged_at"]) - created).total_seconds())
        if created and inc.get("resolved_at"):
            mttr.append((to_dt(inc["resolved_at"]) - created).total_seconds())
    resolved = [i for i in incidents if i["status"] == "Resolved"]
    dispositions = Counter(i.get("disposition") or "Undetermined" for i in resolved)
    fp = dispositions.get("False positive", 0)
    signals = db.scalar("SELECT COUNT(*) AS n FROM signals WHERE created_at >= ?", (since,), 0)
    events = db.scalar("SELECT SUM(hits) AS n FROM events WHERE created_at >= ?", (since,), 0) or 0
    stored = db.scalar("SELECT COUNT(*) AS n FROM events WHERE created_at >= ?", (since,), 0)

    # per-rule quality: signals, incidents, false-positive rate -> tuning suggestions
    per_rule = defaultdict(lambda: {"signals": 0, "incidents": set(), "fp": 0, "tp": 0, "resolved": 0})
    for row in db.query("""SELECT s.rule_id, s.rule_title, s.alert_id, a.status, a.disposition FROM signals s
                           LEFT JOIN alerts a ON a.id = s.alert_id WHERE s.created_at >= ?""", (since,)):
        r = per_rule[(row["rule_id"], row["rule_title"])]
        r["signals"] += 1
        if row["alert_id"] and row["alert_id"] not in r["incidents"]:
            r["incidents"].add(row["alert_id"])
            if row["status"] == "Resolved":
                r["resolved"] += 1
                if row["disposition"] == "False positive":
                    r["fp"] += 1
                elif row["disposition"] == "True positive":
                    r["tp"] += 1
    rules = []
    for (rule_id, title), r in per_rule.items():
        fp_rate = r["fp"] / r["resolved"] if r["resolved"] else None
        if r["resolved"] >= 3 and fp_rate is not None and fp_rate >= 0.5:
            advice = "Noisy: tune the threshold/selection or disable"
        elif r["signals"] >= 200 and not r["incidents"]:
            advice = "High volume, never escalates: consider lowering its risk score"
        else:
            advice = ""
        rules.append({"rule_id": rule_id, "title": title, "signals": r["signals"], "incidents": len(r["incidents"]),
                      "resolved": r["resolved"], "fp": r["fp"], "tp": r["tp"],
                      "fp_rate": round(fp_rate * 100) if fp_rate is not None else None, "advice": advice})
    rules.sort(key=lambda x: -x["signals"])

    daily = defaultdict(lambda: {"events": 0, "signals": 0, "incidents": 0})
    for row in db.query("SELECT SUBSTR(created_at,1,10) AS d, SUM(hits) AS n FROM events WHERE created_at >= ? GROUP BY SUBSTR(created_at,1,10)", (since,)):
        daily[row["d"]]["events"] = int(row["n"] or 0)
    for row in db.query("SELECT SUBSTR(created_at,1,10) AS d, COUNT(*) AS n FROM signals WHERE created_at >= ? GROUP BY SUBSTR(created_at,1,10)", (since,)):
        daily[row["d"]]["signals"] = int(row["n"] or 0)
    for row in db.query("SELECT SUBSTR(created_at,1,10) AS d, COUNT(*) AS n FROM alerts WHERE created_at >= ? GROUP BY SUBSTR(created_at,1,10)", (since,)):
        daily[row["d"]]["incidents"] = int(row["n"] or 0)
    datasets = db.query("SELECT COALESCE(dataset,'other') AS dataset, SUM(hits) AS n, COUNT(*) AS rows_ FROM events "
                        "WHERE created_at >= ? GROUP BY COALESCE(dataset,'other') ORDER BY n DESC", (since,))
    imports = db.query("SELECT SUM(raw_records) AS raw, SUM(stored_events) AS stored, SUM(summarized) AS summarized "
                       "FROM imports WHERE created_at >= ?", (since,))[0]
    sim = db.query("SELECT scenario, title, passed, created_at FROM simulation_runs ORDER BY id DESC LIMIT 50")
    latest_sim = {}
    for row in sim:
        latest_sim.setdefault(row["scenario"], row)
    return {
        "days": days,
        "incidents": len(incidents),
        "open": sum(1 for i in incidents if i["status"] != "Resolved"),
        "mttd": human(_avg(mttd)), "mtta": human(_avg(mtta)), "mttr": human(_avg(mttr)),
        "mttd_n": len(mttd), "mtta_n": len(mtta), "mttr_n": len(mttr),
        "resolved": len(resolved), "dispositions": dict(dispositions),
        "fp_rate": round(100 * fp / len(resolved)) if resolved else None,
        "signals": signals, "events": int(events), "stored": stored,
        "alert_reduction": round(100 * (1 - len(incidents) / signals)) if signals else None,
        "storage_reduction": round(100 * (1 - stored / events)) if events else None,
        "rules": rules,
        "daily": [{"day": d, **v} for d, v in sorted(daily.items())],
        "datasets": [{"dataset": r["dataset"], "events": int(r["n"] or 0), "rows": int(r["rows_"] or 0)} for r in datasets],
        "imports": {k: int(v or 0) for k, v in imports.items()},
        "simulations": list(latest_sim.values()),
        "sim_passed": sum(1 for r in latest_sim.values() if r["passed"]),
    }
