"""MiniSOC v1.0 — runs locally (python app.py / run.bat) and on Vercel (Flask zero-config: `app` in app.py)."""
import csv
import io
import json
import os
import secrets
from datetime import datetime, timedelta, timezone

from flask import (Flask, Response, abort, flash, g, jsonify, redirect, render_template, request, session,
                   stream_with_context, url_for)

import auth
import config
import database
import ecs
import metrics
import mitre
import simulation
import soar
from auth import has_role, role_required
from db import close_request_db, transaction
from detection_engine import get_rules, run_rule_tests
from log_analysis import analyze_import
from log_import import DuplicateImport, import_log_file, ingest_records
from log_parser import FORMAT_LABELS, ParseError, _json_records

app = Flask(__name__, static_folder=os.path.join(config.BASE_DIR, "public", "static"), static_url_path="/static")


def _secret_key():
    if config.SECRET_KEY:
        return config.SECRET_KEY
    if config.IS_VERCEL:
        return None
    path = os.path.join(config.BASE_DIR, "data", "secret_key")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w") as fh:
            fh.write(secrets.token_hex(32))
    with open(path) as fh:
        return fh.read().strip()


app.secret_key = _secret_key() or secrets.token_hex(32)
app.config.update(
    MAX_CONTENT_LENGTH=config.MAX_REQUEST_BYTES + 512 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=config.IS_VERCEL,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)
if config.IS_VERCEL:  # trust Vercel's proxy headers for client IP and https URLs
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.teardown_appcontext(close_request_db)
app.jinja_env.globals.update(csrf_token=auth.csrf_token, has_role=has_role)
CONFIG_PROBLEMS = []
if config.IS_VERCEL and not config.SECRET_KEY:
    CONFIG_PROBLEMS.append("MINISOC_SECRET is not set — sessions reset on every cold start. Add it in Vercel → Settings → Environment Variables.")
if config.EPHEMERAL_STORAGE:
    CONFIG_PROBLEMS.append("No DATABASE_URL — data is kept in /tmp and lost when the function restarts. Connect a Postgres database (e.g. Neon from the Vercel Marketplace).")
if config.IS_VERCEL and not config.ADMIN_PASSWORD:
    CONFIG_PROBLEMS.append("MINISOC_ADMIN_PASSWORD is not set — no administrator can sign in.")

with app.app_context():
    database.init_db()
    auth.bootstrap_admin()

PUBLIC_ENDPOINTS = {"login_page", "setup_page", "static", "healthz", "blocklist_feed", "api_ingest", "cron_daily"}
TIMEZONE_OPTIONS = [("local", "This server's time zone"), ("UTC", "UTC")] + [
    (f"{'+' if h >= 0 else '-'}{abs(h):02d}:00", f"UTC{'+' if h >= 0 else '-'}{abs(h):02d}:00") for h in range(-12, 15) if h != 0]


@app.before_request
def before():
    auth.load_user()
    if request.endpoint in PUBLIC_ENDPOINTS or request.endpoint is None:
        if request.method == "POST" and request.endpoint in ("login_page", "setup_page"):
            auth.check_csrf()
        return None
    if not g.user:
        if database.count_users() == 0 and auth.setup_allowed():
            return redirect(url_for("setup_page"))
        return redirect(url_for("login_page", next=request.full_path if request.method == "GET" else None))
    if request.method == "POST":
        auth.check_csrf()
    return None


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    resp.headers.setdefault("Content-Security-Policy",
                            "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
                            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
    if config.IS_VERCEL:
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return resp


@app.context_processor
def inject():
    return {
        "csrf_token": auth.csrf_token, "has_role": has_role, "current_user": g.get("user"),
        "config_problems": CONFIG_PROBLEMS, "is_vercel": config.IS_VERCEL, "using_postgres": config.USE_POSTGRES,
        "masking": auth.masking_active() if g.get("user") else False,
        "pending_count": database.scalar_pending() if g.get("user") else 0,
    }


@app.template_filter("pii")
def pii_filter(value, kind=None):
    return auth.pii(value, kind)


@app.template_filter("ts")
def ts_filter(value):
    return str(value or "")[:19].replace("T", " ")


@app.template_filter("num")
def num_filter(value):
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return value


def actor():
    return g.user["username"] if g.get("user") else "system"


def audit(action, detail=""):
    database.audit(action, detail, actor(), auth.client_ip())


# ---------------------------------------------------------------- auth pages

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if database.count_users() == 0 and auth.setup_allowed():
        return redirect(url_for("setup_page"))
    if request.method == "POST":
        user, error = auth.login(request.form.get("username", "").strip(), request.form.get("password", ""))
        if user:
            target = request.args.get("next") or ""
            return redirect(target if target.startswith("/") and not target.startswith("//") else url_for("overview"))
        flash(error, "error")
    return render_template("login.html", no_users=database.count_users() == 0)


@app.route("/setup", methods=["GET", "POST"])
def setup_page():
    if not auth.setup_allowed():
        return redirect(url_for("login_page"))
    if request.method == "POST":
        username = request.form.get("username", "").strip() or "admin"
        password = request.form.get("password", "")
        problem = auth.validate_password(password)
        if problem:
            flash(problem, "error")
        elif password != request.form.get("confirm", ""):
            flash("Passwords do not match.", "error")
        else:
            database.create_user(username, auth.hash_password(password), "admin")
            database.audit("user_created", f"first admin '{username}' via local setup", username, auth.client_ip())
            flash("Administrator created. Please sign in.", "success")
            return redirect(url_for("login_page"))
    return render_template("setup.html")


@app.post("/logout")
def logout():
    auth.logout()
    return redirect(url_for("login_page"))


@app.route("/healthz")
def healthz():
    return jsonify({"ok": True, "database": "postgres" if config.USE_POSTGRES else "sqlite", "vercel": config.IS_VERCEL})


# ---------------------------------------------------------------- overview

@app.route("/")
def overview():
    stats = database.dashboard_stats()
    return render_template("overview.html", stats=stats, entities=database.top_risk_entities(),
                           incidents=database.list_incidents(limit=8, status="open"),
                           threshold=database.get_setting("rba_threshold", "100"))


@app.post("/demo")
@role_required("analyst")
def demo():
    results = simulation.run_all(actor())
    audit("simulation_all", f"{len(results)} scenarios")
    flash(f"Loaded demo data: {len(results)} attack scenarios replayed through the pipeline.", "success")
    return redirect(url_for("overview"))


# ---------------------------------------------------------------- events

@app.route("/events")
def events_page():
    args = {k: request.args.get(k, "").strip() for k in ("severity", "q", "dataset", "type")}
    import_id = request.args.get("import", type=int)
    events = database.list_events(limit=300, severity=args["severity"], query=args["q"], import_id=import_id,
                                  dataset=args["dataset"], event_type=args["type"])
    return render_template("events.html", events=events, args=args, import_id=import_id,
                           current_import=database.get_import(import_id) if import_id else None,
                           datasets=["auth", "iam", "web", "api", "network", "host", "windows", "linux", "cloud", "app"])


@app.route("/events/export.ndjson")
def events_export():
    import_id = request.args.get("import", type=int)
    events = database.list_events(limit=50000, import_id=import_id, query=request.args.get("q", ""),
                                  dataset=request.args.get("dataset", ""))
    mask = auth.mask_value if auth.masking_active() else None
    audit("export_events", f"{len(events)} events (ECS NDJSON){' masked' if mask else ''}")
    return Response(stream_with_context(ecs.ndjson(events, mask)), mimetype="application/x-ndjson",
                    headers={"Content-Disposition": "attachment; filename=minisoc-events-ecs.ndjson"})


# ---------------------------------------------------------------- incidents

@app.route("/incidents")
def incidents_page():
    status = request.args.get("status", "open")
    severity = request.args.get("severity", "")
    query = request.args.get("q", "").strip()
    return render_template("incidents.html", incidents=database.list_incidents(status=status if status != "all" else "",
                                                                              severity=severity, query=query),
                           status=status, severity=severity, query=query)


@app.route("/alerts")
def alerts_legacy():
    return redirect(url_for("incidents_page"))


@app.route("/incidents/<int:alert_id>")
def incident_page(alert_id):
    incident = database.get_incident(alert_id)
    if not incident:
        abort(404)
    signals = database.signals_for_alert(alert_id)
    event_ids = sorted({s["event_id"] for s in signals if s.get("event_id")} | ({incident["event_id"]} if incident.get("event_id") else set()))
    events = database.get_events_by_ids(event_ids)
    context = {}
    if incident.get("entity_type") in ("ip", "host"):
        context["asset"] = database.asset_lookup().get(incident["entity_value"]) or database.asset_lookup().get(str(incident["entity_value"]).lower())
    if incident.get("entity_type") == "user":
        context["identity"] = database.identity_lookup().get(str(incident["entity_value"]).lower())
    countries = sorted({e.get("country") for e in events if e.get("country")})
    rules = {r.id: r for r in get_rules()[0]}
    techniques = [(t, mitre.technique_name(t)) for t in (incident.get("mitre") or "").split(",") if t]
    playbooks, _ = soar.load_playbooks()
    blocked = {b["value"] for b in database.list_blocklist(active_only=True)}
    return render_template("incident.html", i=incident, signals=signals, events=events, context=context,
                           countries=countries, rules=rules, techniques=techniques,
                           runs=database.list_playbook_runs(alert_id=alert_id), playbooks=playbooks,
                           notes=database.list_notes(alert_id), tasks=database.list_tasks(alert_id),
                           blocked=blocked)


@app.post("/incidents/<int:alert_id>/status")
@role_required("analyst")
def incident_status(alert_id):
    status = request.form.get("status", "New")
    if status not in ("New", "Investigating", "Resolved"):
        abort(400)
    disposition = request.form.get("disposition") or None
    if disposition and disposition not in ("True positive", "False positive", "Benign", "Undetermined"):
        abort(400)
    if status == "Resolved" and not disposition:
        flash("Choose a disposition (true positive, false positive, benign) when resolving — it drives rule tuning.", "error")
        return redirect(request.referrer or url_for("incident_page", alert_id=alert_id))
    database.set_incident_status(alert_id, status, disposition)
    if request.form.get("assignee") is not None:
        database.update_incident_fields(alert_id, assignee=request.form.get("assignee", "").strip()[:80] or None)
    audit("incident_status", f"#{alert_id} -> {status} {disposition or ''}")
    flash(f"Incident #{alert_id} updated.", "success")
    return redirect(request.referrer or url_for("incident_page", alert_id=alert_id))


@app.post("/incidents/<int:alert_id>/note")
@role_required("analyst")
def incident_note(alert_id):
    text = request.form.get("text", "").strip()
    if text:
        database.add_note(alert_id, actor(), text)
    return redirect(url_for("incident_page", alert_id=alert_id) + "#notes")


@app.post("/incidents/<int:alert_id>/task/<int:task_id>")
@role_required("analyst")
def incident_task(alert_id, task_id):
    database.toggle_task(task_id, request.form.get("done") == "1")
    return redirect(url_for("incident_page", alert_id=alert_id) + "#tasks")


@app.post("/incidents/<int:alert_id>/playbook")
@role_required("analyst")
def incident_playbook(alert_id):
    outcome = soar.run_manual(request.form.get("playbook", ""), alert_id, database.get_settings(), actor())
    if outcome is None:
        abort(404)
    audit("playbook_manual", f"{request.form.get('playbook')} on #{alert_id}")
    flash("Playbook executed: " + "; ".join(f"{o['type']}: {o['status']}" for o in outcome), "success")
    return redirect(url_for("incident_page", alert_id=alert_id) + "#response")


@app.post("/response/runs/<int:run_id>/<decision>")
@role_required("analyst")
def playbook_decision(run_id, decision):
    if decision not in ("approve", "reject"):
        abort(400)
    result = soar.approve_run(run_id, database.get_settings(), actor(), approve=decision == "approve")
    audit(f"playbook_{decision}", f"run #{run_id} -> {result}")
    flash(f"Playbook run #{run_id}: {result or 'not pending'}.", "success" if result in ("done", "rejected") else "error")
    return redirect(request.referrer or url_for("response_page"))


# ---------------------------------------------------------------- imports

@app.route("/imports")
def imports_page():
    return render_template("imports.html", imports=database.list_imports(), formats=FORMAT_LABELS,
                           timezones=TIMEZONE_OPTIONS, max_mb=config.MAX_REQUEST_BYTES // (1024 * 1024),
                           settings=database.get_settings())


@app.post("/imports/upload")
@role_required("analyst")
def upload_import():
    upload = request.files.get("logfile")
    if not upload or not upload.filename:
        flash("Choose a log file to import.", "error")
        return redirect(url_for("imports_page"))
    fmt = request.form.get("format", "auto")
    fmt = fmt if fmt in FORMAT_LABELS else "auto"
    tz_option = request.form.get("timezone", "local")
    if tz_option not in {v for v, _ in TIMEZONE_OPTIONS}:
        tz_option = "local"
    options = {"aggregate_web": "1" if request.form.get("aggregate_web") == "1" else "0",
               "min_severity": request.form.get("min_severity") if request.form.get("min_severity") in config.SEVERITY_RANK else "Info"}
    filename = upload.filename[:-3] if upload.filename.lower().endswith(".gz") and request.form.get("client_gzip") == "1" else upload.filename
    try:
        import_id, stats = import_log_file(filename, upload.read(), fmt=fmt, tz_option=tz_option,
                                           keep_unmatched=request.form.get("keep_unmatched") == "1",
                                           allow_duplicate=request.form.get("allow_duplicate") == "1",
                                           options=options, user=actor())
    except DuplicateImport as dup:
        flash(f"{dup} Delete it first or tick 'Import again even if identical'.", "error")
        return redirect(url_for("import_report", import_id=dup.existing["id"]))
    except ParseError as exc:
        flash(f"Import failed: {exc}", "error")
        return redirect(url_for("imports_page"))
    audit("import", f"#{import_id} {filename}: {stats['received']} records")
    flash(f"Imported {stats['received']:,} record(s) → stored {stats['stored']:,} · {stats['signals']} detection(s) · "
          f"{stats['incidents_created']} new / {stats['incidents_updated']} updated incident(s).", "success")
    return redirect(url_for("import_report", import_id=import_id))


@app.route("/imports/<int:import_id>")
def import_report(import_id):
    report = analyze_import(import_id)
    if not report:
        abort(404)
    return render_template("import_report.html", r=report, formats=FORMAT_LABELS)


@app.route("/imports/<int:import_id>/report.json")
def import_report_json(import_id):
    report = analyze_import(import_id)
    if not report:
        abort(404)
    report.pop("sample_events", None)
    body = json.dumps(report, ensure_ascii=False, indent=2, default=str)
    if auth.masking_active():
        body = auth.mask_value(body)
    audit("export_report", f"import #{import_id}")
    return Response(body, mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=minisoc-import-{import_id}-report.json"})


@app.route("/imports/<int:import_id>/iocs.csv")
def import_iocs_csv(import_id):
    report = analyze_import(import_id)
    if not report:
        abort(404)
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["type", "value", "host", "verdict", "count", "first_seen", "last_seen", "context", "related_sources"])
    for ioc in report["iocs"]:
        writer.writerow([ioc["type"], ioc["value"], ioc["host"], ioc["verdict"], ioc["count"], ioc["first_seen"],
                         ioc["last_seen"], ioc["context"], " ".join(auth.pii(s, "ip") for s in ioc["sources"])])
    return Response("﻿" + out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=minisoc-import-{import_id}-iocs.csv"})


@app.post("/imports/<int:import_id>/delete")
@role_required("analyst")
def delete_import_route(import_id):
    imp = database.get_import(import_id)
    if imp:
        database.delete_import(import_id)
        audit("import_delete", f"#{import_id} {imp['filename']}")
        flash(f"Deleted Import #{import_id} ({imp['filename']}) with its events, detections and empty incidents.", "success")
    return redirect(url_for("imports_page"))


@app.post("/collect/windows")
@role_required("analyst")
def collect_windows():
    if config.IS_VERCEL:
        flash("Windows Event Log collection only works in the local Windows build.", "error")
        return redirect(url_for("events_page"))
    try:
        from collector import collect_recent_windows_events
        count = collect_recent_windows_events()
        flash(f"Imported {count} recent Windows events.", "success")
    except Exception as exc:  # noqa: BLE001
        flash(f"Windows collection failed: {exc}", "error")
    return redirect(url_for("events_page"))


# ---------------------------------------------------------------- detection-as-code

@app.route("/detection")
def detection_page():
    rules, errors = get_rules()
    states = database.rule_states()
    since = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(timespec="seconds")
    stats = database.rule_signal_stats(since)
    dispositions = database.rule_disposition_stats()
    tests = {r.id: run_rule_tests(r) for r in rules}
    sims = database.list_simulation_runs()
    tested = set()
    for run in sims:
        if run["passed"]:
            for rid in run["fired"]:
                for r in rules:
                    if r.id == rid:
                        tested.update(r.mitre)
    rows = []
    for r in rules:
        d = dispositions.get(r.id, {})
        resolved = sum(d.values())
        rows.append({"rule": r, "enabled": states.get(r.id, r.enabled_default),
                     "signals": (stats.get(r.id) or {}).get("n", 0), "last": (stats.get(r.id) or {}).get("last_ts"),
                     "tests": tests[r.id], "tests_passed": all(t["passed"] for t in tests[r.id]) if tests[r.id] else None,
                     "fp_rate": round(100 * d.get("False positive", 0) / resolved) if resolved else None, "resolved": resolved})
    return render_template("detection.html", rows=rows, errors=errors, coverage=mitre.coverage(rules, tested),
                           tab=request.args.get("tab", "rules"))


@app.route("/detection/<rule_id>")
def rule_page(rule_id):
    rules, _ = get_rules()
    rule = next((r for r in rules if r.id == rule_id), None)
    if not rule:
        abort(404)
    since = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(timespec="seconds")
    recent = database.get_db().query("SELECT * FROM signals WHERE rule_id=? ORDER BY id DESC LIMIT 50", (rule_id,))
    return render_template("rule.html", rule=rule, tests=run_rule_tests(rule), recent=recent,
                           enabled=database.rule_states().get(rule.id, rule.enabled_default),
                           stats=database.rule_signal_stats(since).get(rule.id, {}),
                           techniques=[(t, mitre.technique_name(t)) for t in rule.mitre])


@app.post("/detection/<rule_id>/toggle")
@role_required("admin")
def toggle_rule(rule_id):
    enabled = request.form.get("enabled") == "1"
    database.set_rule_enabled(rule_id, enabled, actor())
    audit("rule_toggle", f"{rule_id} -> {'enabled' if enabled else 'disabled'}")
    flash(f"Rule {rule_id} {'enabled' if enabled else 'disabled'}.", "success")
    return redirect(request.referrer or url_for("detection_page"))


@app.route("/rules")
def rules_legacy():
    return redirect(url_for("detection_page"))


# ---------------------------------------------------------------- response (SOAR)

@app.route("/response")
def response_page():
    playbooks, errors = soar.load_playbooks()
    return render_template("response.html", playbooks=playbooks, errors=errors,
                           pending=database.list_playbook_runs(status="pending_approval"),
                           runs=database.list_playbook_runs(limit=60), blocklist=database.list_blocklist(),
                           settings=database.get_settings())


@app.post("/response/blocklist")
@role_required("analyst")
def blocklist_add_route():
    value = request.form.get("value", "").strip()
    if not value:
        abort(400)
    kind = "ip" if soar._is_ip(value) else "domain"
    if kind == "ip" and soar._allowlisted(value, database.get_settings()):
        flash(f"{value} is internal or allow-listed and was not blocked.", "error")
        return redirect(url_for("response_page"))
    database.blocklist_add(value, kind, request.form.get("reason", "Manual entry")[:200], "manual", None,
                           request.form.get("ttl_hours", type=int) or None, actor())
    audit("blocklist_add", value)
    flash(f"{value} added to the blocklist.", "success")
    return redirect(url_for("response_page"))


@app.post("/response/blocklist/<int:entry_id>/remove")
@role_required("analyst")
def blocklist_remove_route(entry_id):
    database.blocklist_remove(entry_id)
    audit("blocklist_remove", f"entry {entry_id}")
    return redirect(url_for("response_page"))


@app.route("/feeds/blocklist.txt")
def blocklist_feed():
    token = request.args.get("token") or request.headers.get("Authorization", "").replace("Bearer ", "")
    expected = database.get_setting("feed_token", "")
    if not expected or not secrets.compare_digest(token or "", expected):
        abort(403)
    kind = request.args.get("kind", "ip")
    lines = [b["value"] for b in database.list_blocklist(active_only=True) if kind == "all" or b["kind"] == kind]
    return Response("\n".join(lines) + ("\n" if lines else ""), mimetype="text/plain",
                    headers={"Cache-Control": "no-store"})


# ---------------------------------------------------------------- context: assets & identities

@app.route("/assets")
def assets_page():
    return render_template("assets.html", assets=database.list_assets(), identities=database.list_identities())


@app.post("/assets/save")
@role_required("analyst")
def asset_save():
    f = request.form
    database.upsert_asset(ip=f.get("ip", "").strip(), hostname=f.get("hostname", "").strip(), name=f.get("name", "").strip(),
                          criticality=f.get("criticality", 3, type=int), owner=f.get("owner", "").strip(),
                          tags=f.get("tags", "").strip(), asset_id=f.get("id", type=int))
    audit("asset_save", f.get("ip") or f.get("hostname") or "")
    flash("Asset saved. Risk on this asset is weighted by its criticality.", "success")
    return redirect(url_for("assets_page"))


@app.post("/assets/<int:asset_id>/delete")
@role_required("analyst")
def asset_delete(asset_id):
    database.delete_asset(asset_id)
    return redirect(url_for("assets_page"))


@app.post("/assets/import")
@role_required("analyst")
def asset_import():
    upload = request.files.get("csvfile")
    if not upload:
        abort(400)
    text = upload.read().decode("utf-8-sig", "replace")
    count = 0
    for row in csv.DictReader(io.StringIO(text)):
        row = {str(k).strip().lower(): (v or "").strip() for k, v in row.items() if k}
        if row.get("ip") or row.get("hostname"):
            database.upsert_asset(ip=row.get("ip"), hostname=row.get("hostname"), name=row.get("name"),
                                  criticality=int(row.get("criticality") or 3), owner=row.get("owner"), tags=row.get("tags"))
            count += 1
    audit("asset_import", f"{count} assets")
    flash(f"Imported {count} asset(s).", "success")
    return redirect(url_for("assets_page"))


@app.post("/identities/save")
@role_required("analyst")
def identity_save():
    f = request.form
    username = f.get("username", "").strip()
    if username:
        database.upsert_identity(username, f.get("display_name", "").strip(), f.get("department", "").strip(),
                                 f.get("email", "").strip(), f.get("privileged") == "1")
        audit("identity_save", username)
    return redirect(url_for("assets_page") + "#identities")


@app.post("/identities/<int:identity_id>/delete")
@role_required("analyst")
def identity_delete(identity_id):
    database.delete_identity(identity_id)
    return redirect(url_for("assets_page") + "#identities")


# ---------------------------------------------------------------- metrics & simulation

@app.route("/metrics")
def metrics_page():
    days = request.args.get("days", 30, type=int)
    return render_template("metrics.html", m=metrics.compute(max(1, min(days, 365))))


@app.route("/simulation")
def simulation_page():
    return render_template("simulation.html", scenarios=simulation.SCENARIOS, runs=database.list_simulation_runs())


@app.post("/simulation/run")
@role_required("analyst")
def simulation_run():
    key = request.form.get("scenario", "")
    if key == "all":
        results = simulation.run_all(actor())
        passed = sum(1 for r in results if r["passed"])
        flash(f"{passed}/{len(results)} scenarios detected as expected.", "success" if passed == len(results) else "error")
    elif key in simulation.SCENARIOS:
        r = simulation.run_scenario(key, actor())
        flash(f"{r['title']}: {'detected' if r['passed'] else 'MISSED ' + ', '.join(r['missing'])} "
              f"({len(r['fired'])} rule(s) fired, {r['stats']['incidents_created']} incident(s)).",
              "success" if r["passed"] else "error")
    else:
        abort(400)
    audit("simulation", key)
    return redirect(url_for("simulation_page"))


# ---------------------------------------------------------------- settings (admin)

SETTING_FIELDS = ["retention_days", "rba_threshold", "rba_window_hours", "business_hours", "business_days", "mask_pii",
                  "soar_enabled", "notify_webhook_url", "notify_min_severity", "webhook_waf_url", "webhook_identity_url",
                  "webhook_edr_url", "webhook_ticket_url", "allowlist", "base_url", "pipeline_aggregate_web",
                  "pipeline_store_min_severity"]


@app.route("/settings")
@role_required("admin")
def settings_page():
    settings = database.get_settings()
    oldest = database.oldest_event_ts()
    return render_template("settings.html", s=settings, users=database.list_users(), keys=database.list_api_keys(),
                           audit_log=database.list_audit(80), oldest=oldest, new_key=session.pop("new_key", None),
                           feed_url=url_for("blocklist_feed", token=settings.get("feed_token"), _external=True),
                           ingest_url=url_for("api_ingest", _external=True))


@app.post("/settings")
@role_required("admin")
def settings_save():
    values = {}
    for key in SETTING_FIELDS:
        if key in ("soar_enabled", "pipeline_aggregate_web"):
            values[key] = "1" if request.form.get(key) == "1" else "0"
        elif key in request.form:
            values[key] = request.form.get(key, "").strip()
    try:
        days = int(values.get("retention_days", 90))
    except ValueError:
        days = 90
    if days < 90:
        flash("Retention below 90 days is not allowed: the Thai Computer Crime Act requires service providers to keep "
              "computer traffic data for at least 90 days. Set to 90.", "error")
        days = 90
    values["retention_days"] = str(min(days, 3650))
    for key in ("rba_threshold", "rba_window_hours"):
        try:
            values[key] = str(max(1, float(values.get(key, 0))))
        except ValueError:
            values.pop(key, None)
    if values.get("mask_pii") not in ("off", "viewer", "non_admin"):
        values["mask_pii"] = "viewer"
    database.set_settings(values)
    audit("settings_save", ", ".join(sorted(values)))
    flash("Settings saved.", "success")
    return redirect(url_for("settings_page"))


@app.post("/settings/feed-token")
@role_required("admin")
def rotate_feed_token():
    database.set_settings({"feed_token": secrets.token_urlsafe(24)})
    audit("feed_token_rotate")
    flash("Blocklist feed token rotated — update the URL on your WAF/firewall.", "success")
    return redirect(url_for("settings_page"))


@app.post("/settings/test-webhook")
@role_required("admin")
def test_webhook():
    url = database.get_setting("notify_webhook_url")
    try:
        code = soar.post_json(url, {"text": "MiniSOC test notification ✅", "content": "MiniSOC test notification ✅"})
        flash(f"Webhook answered HTTP {code}.", "success")
    except Exception as exc:  # noqa: BLE001
        flash(f"Webhook test failed: {exc}", "error")
    return redirect(url_for("settings_page"))


@app.post("/settings/users")
@role_required("admin")
def user_create():
    username = request.form.get("username", "").strip()
    role = request.form.get("role", "viewer")
    password = request.form.get("password", "")
    problem = auth.validate_password(password)
    if not username or role not in config.ROLES:
        flash("Username and a valid role are required.", "error")
    elif database.get_user(username):
        flash("That username already exists.", "error")
    elif problem:
        flash(problem, "error")
    else:
        database.create_user(username, auth.hash_password(password), role)
        audit("user_created", f"{username} ({role})")
        flash(f"User {username} created.", "success")
    return redirect(url_for("settings_page") + "#users")


@app.post("/settings/users/<int:user_id>")
@role_required("admin")
def user_update(user_id):
    target = database.get_user_by_id(user_id)
    if not target:
        abort(404)
    if target["id"] == g.user["id"] and (request.form.get("role") not in (None, "admin") or request.form.get("disabled") == "1"):
        flash("You cannot demote or disable your own account.", "error")
        return redirect(url_for("settings_page") + "#users")
    password = request.form.get("password", "")
    if password:
        problem = auth.validate_password(password)
        if problem:
            flash(problem, "error")
            return redirect(url_for("settings_page") + "#users")
    database.update_user(user_id, role=request.form.get("role") if request.form.get("role") in config.ROLES else None,
                         disabled=request.form.get("disabled") == "1" if "disabled" in request.form else None,
                         password_hash=auth.hash_password(password) if password else None)
    audit("user_updated", target["username"])
    flash(f"User {target['username']} updated.", "success")
    return redirect(url_for("settings_page") + "#users")


@app.post("/settings/api-keys")
@role_required("admin")
def api_key_create():
    name = request.form.get("name", "").strip() or "ingest"
    session["new_key"] = database.create_api_key(name, actor())
    audit("api_key_created", name)
    return redirect(url_for("settings_page") + "#api")


@app.post("/settings/api-keys/<int:key_id>/revoke")
@role_required("admin")
def api_key_revoke(key_id):
    database.revoke_api_key(key_id)
    audit("api_key_revoked", str(key_id))
    return redirect(url_for("settings_page") + "#api")


@app.post("/settings/retention")
@role_required("admin")
def retention_now():
    removed = run_retention()
    audit("retention_run", f"{removed} events removed")
    flash(f"Retention applied: {removed} event(s) older than {database.get_setting('retention_days')} days removed.", "success")
    return redirect(url_for("settings_page"))


def run_retention():
    days = max(90, int(database.get_setting("retention_days", "90") or 90))
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    return database.purge_older_than(cutoff)


# ---------------------------------------------------------------- machine endpoints

@app.post("/api/ingest")
def api_ingest():
    """Push structured logs: Authorization: Bearer <API key>; body = JSON object, array or NDJSON (gzip allowed)."""
    key = database.verify_api_key(request.headers.get("Authorization", "").replace("Bearer ", "").strip())
    if not key:
        return jsonify({"error": "invalid or missing API key"}), 401
    raw = request.get_data(cache=False)
    if request.headers.get("Content-Encoding") == "gzip" or raw[:2] == b"\x1f\x8b":
        import zlib
        raw = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(raw, config.MAX_DECOMPRESSED_BYTES)
    try:
        records = _json_records(raw.decode("utf-8", "replace"))
    except ParseError as exc:
        return jsonify({"error": str(exc)}), 400
    if not records:
        return jsonify({"error": "no records"}), 400
    if len(records) > 20000:
        return jsonify({"error": "too many records in one request (max 20000)"}), 413
    try:
        stats = ingest_records(records, key["name"], tz_option=request.args.get("tz", "UTC"), user=f"api:{key['name']}")
    except ParseError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"accepted": len(records), **{k: v for k, v in stats.items() if k != "incident_ids"},
                    "incident_ids": stats.get("incident_ids", [])})


@app.route("/api/cron/daily")
def cron_daily():
    """Vercel Cron (vercel.json) — retention purge and blocklist expiry."""
    if not config.CRON_SECRET or request.headers.get("Authorization") != f"Bearer {config.CRON_SECRET}":
        abort(401)
    removed = run_retention()
    database.audit("retention_cron", f"{removed} events removed", "cron")
    return jsonify({"ok": True, "removed": removed})


@app.errorhandler(413)
def too_large(_error):
    flash(f"Request larger than {config.MAX_REQUEST_BYTES // (1024 * 1024)} MB. Compress (gzip) or split the file.", "error")
    return redirect(url_for("imports_page"))


@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", code=400, message=getattr(error, "description", "Bad request")), 400


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="Page not found."), 404


def _local_background():
    """Local build only: Windows Security log polling and a daily retention job."""
    import threading
    import time
    from collector import start_background_collector
    start_background_collector(interval_seconds=int(os.environ.get("MINISOC_POLL_SECONDS", "30")))

    def retention_loop():
        while True:
            try:
                with app.app_context():
                    run_retention()
            except Exception as exc:  # noqa: BLE001
                print(f"[MiniSOC] retention failed: {exc}")
            time.sleep(24 * 3600)
    threading.Thread(target=retention_loop, name="minisoc-retention", daemon=True).start()


if __name__ == "__main__":
    _local_background()
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5055")), debug=False)
