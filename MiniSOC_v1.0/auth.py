"""Authentication, roles, CSRF protection and PDPA masking helpers."""
import functools
import hmac
import ipaddress
import re
import secrets

from flask import abort, flash, g, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import config
import database

ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}
MAX_FAILURES = 8


def hash_password(password):
    return generate_password_hash(password)


def validate_password(password):
    if len(password or "") < 10:
        return "Password must be at least 10 characters."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "Password must contain letters and digits."
    return None


def client_ip():
    # Vercel sets x-forwarded-for; locally it is the socket address.
    return request.remote_addr or ""  # ProxyFix applies x-forwarded-for on Vercel


def bootstrap_admin():
    """Create the first admin from MINISOC_ADMIN_PASSWORD (required on Vercel)."""
    if database.count_users() == 0 and config.ADMIN_PASSWORD:
        database.create_user(config.ADMIN_USER, hash_password(config.ADMIN_PASSWORD), "admin")
        database.audit("user_bootstrap", f"admin '{config.ADMIN_USER}' created from environment")


def setup_allowed():
    """The browser setup page is only offered locally, when no user exists yet."""
    if config.IS_VERCEL or database.count_users() > 0:
        return False
    try:
        return ipaddress.ip_address(request.remote_addr or "").is_loopback
    except ValueError:
        return False


def load_user():
    g.user = None
    user_id = session.get("uid")
    if user_id:
        user = database.get_user_by_id(user_id)
        if user and not user["disabled"] and session.get("pw") == user["password_hash"][-16:]:
            g.user = user


def login(username, password):
    ip = client_ip()
    if database.recent_login_failures(username, ip) >= MAX_FAILURES:
        database.audit("login_blocked", f"too many failures for '{username}'", username, ip)
        return None, "Too many failed attempts. Wait 15 minutes and try again."
    user = database.get_user(username)
    if not user or user["disabled"] or not check_password_hash(user["password_hash"], password or ""):
        database.audit("login_failed", f"failed login for '{username}'", username, ip)
        _self_monitor("FailedLogin", username, ip)
        return None, "Invalid username or password."
    session.clear()
    session["uid"] = user["id"]
    session["pw"] = user["password_hash"][-16:]  # invalidates sessions after a password change
    session["csrf"] = secrets.token_urlsafe(24)
    session.permanent = True
    database.touch_login(user["id"])
    database.audit("login", "successful login", user["username"], ip)
    _self_monitor("LoginSuccess", user["username"], ip)
    return user, None


def _self_monitor(event_type, username, ip):
    """MiniSOC watches its own console: logins become events, so brute force against it is detected."""
    from db import get_db
    db = get_db()
    try:
        import pipeline
        from datetime import datetime, timezone
        db.execute("SAVEPOINT selfmon")
        pipeline.process_batch([{
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"), "event_type": event_type,
            "severity": "Medium" if event_type == "FailedLogin" else "Info", "host": "minisoc-console",
            "username": username, "source_ip": ip, "dataset": "auth",
            "details": f"MiniSOC console {'failed login' if event_type == 'FailedLogin' else 'login'} for {username}",
            "extra": {},
        }], "MiniSOC console")
        db.execute("RELEASE SAVEPOINT selfmon")
    except Exception:  # noqa: BLE001 - monitoring must never block a login
        try:
            db.execute("ROLLBACK TO SAVEPOINT selfmon")
        except Exception:  # noqa: BLE001
            pass


def logout():
    if g.get("user"):
        database.audit("logout", "", g.user["username"], client_ip())
    session.clear()


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


def check_csrf():
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
    if not sent or not hmac.compare_digest(sent, session.get("csrf", "")):
        abort(400, description="Invalid or missing CSRF token. Reload the page and try again.")


def role_required(role="viewer"):
    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            if not g.get("user"):
                return redirect(url_for("login_page", next=request.full_path if request.method == "GET" else None))
            if ROLE_RANK.get(g.user["role"], 0) < ROLE_RANK[role]:
                flash(f"This action needs the {role} role.", "error")
                return redirect(request.referrer or url_for("overview"))
            return view(*args, **kwargs)
        return wrapped
    return decorator


def has_role(role):
    return bool(g.get("user")) and ROLE_RANK.get(g.user["role"], 0) >= ROLE_RANK[role]


# ---------------------------------------------------------------- PDPA masking

def masking_active():
    mode = database.get_setting("mask_pii", "viewer")
    user = g.get("user")
    if not user or mode == "off":
        return mode != "off" and not user
    if mode == "viewer":
        return user["role"] == "viewer"
    if mode == "non_admin":
        return user["role"] != "admin"
    return False


IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
EMAIL = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")


def mask_value(value, kind=None):
    if value in (None, ""):
        return value
    text = str(value)
    if kind == "user" and "@" not in text:
        return text[0] + "***" if len(text) > 1 else "*"
    text = IPV4.sub(lambda m: f"{m.group(1)}.{m.group(2)}.x.x", text)
    text = EMAIL.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", text)
    if kind == "ip" and ":" in text and text.count(":") >= 2:
        text = ":".join(text.split(":")[:3]) + ":…"
    return text


def pii(value, kind=None):
    return mask_value(value, kind) if masking_active() else value
