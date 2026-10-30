"""Runtime configuration shared by the local (Windows) build and the Vercel build."""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IS_VERCEL = bool(os.environ.get("VERCEL"))
DATABASE_URL = (os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")
                or os.environ.get("POSTGRES_PRISMA_URL") or "")
USE_POSTGRES = DATABASE_URL.startswith(("postgres://", "postgresql://"))

# SQLite lives next to the app locally; on Vercel only /tmp is writable (and it is not persistent).
SQLITE_PATH = os.environ.get("MINISOC_SQLITE_PATH") or (
    "/tmp/minisoc.db" if IS_VERCEL else os.path.join(BASE_DIR, "data", "minisoc.db"))
EPHEMERAL_STORAGE = IS_VERCEL and not USE_POSTGRES

SECRET_KEY = os.environ.get("MINISOC_SECRET") or os.environ.get("SECRET_KEY") or ""
ADMIN_USER = os.environ.get("MINISOC_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("MINISOC_ADMIN_PASSWORD", "")
CRON_SECRET = os.environ.get("CRON_SECRET", "")

# Vercel rejects request bodies over 4.5 MB; the browser gzips large text logs before upload.
MAX_REQUEST_BYTES = int(os.environ.get("MINISOC_MAX_REQUEST_MB", "4" if IS_VERCEL else "60")) * 1024 * 1024
MAX_DECOMPRESSED_BYTES = 80 * 1024 * 1024
MAX_EVENTS_PER_IMPORT = int(os.environ.get("MINISOC_MAX_EVENTS", "30000" if IS_VERCEL else "50000"))

RULES_DIR = os.path.join(BASE_DIR, "rules")
PLAYBOOKS_DIR = os.path.join(BASE_DIR, "playbooks")

DEFAULT_SETTINGS = {
    "retention_days": "90",              # Thai Computer Crime Act: keep traffic data >= 90 days
    "rba_threshold": "100",              # risk points per entity before an incident is opened
    "rba_window_hours": "24",
    "business_hours": "08:00-19:00",
    "business_days": "1-5",              # ISO weekdays, Mon=1
    "mask_pii": "viewer",                # off | viewer | non_admin  (PDPA)
    "soar_enabled": "1",
    "notify_webhook_url": "",
    "notify_min_severity": "High",
    "webhook_waf_url": "",
    "webhook_identity_url": "",
    "webhook_edr_url": "",
    "webhook_ticket_url": "",
    "allowlist": "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,100.64.0.0/10",
    "feed_token": "",
    "base_url": "",
    "pipeline_aggregate_web": "1",       # summarise normal web/API requests instead of storing each one
    "pipeline_store_min_severity": "Info",
}

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_RANK = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
ROLES = ("admin", "analyst", "viewer")
