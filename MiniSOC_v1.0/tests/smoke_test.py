"""End-to-end smoke test through the HTTP routes.

Usage (from the project folder, with a throw-away database!):
    MINISOC_SQLITE_PATH=/tmp/minisoc-test.db python tests/smoke_test.py
Pass `pg` as argument to use tests/pg_shim.py against a local PostgreSQL test database."""
import io, json, re, sys, time
sys.path.insert(0, ".")
if len(sys.argv) > 1 and sys.argv[1] == "pg":
    sys.path.insert(0, "tests")
    import pg_shim
    pg_shim.install(__import__("os").environ.get("MINISOC_TEST_PG", "postgresql://postgres@/minisoc?host=/tmp&port=55432"))
import app as appmod
app = appmod.app
c = app.test_client()
SANGFOR = "samples/sangfor_af_report.xlsx"  # optional: put a real Sangfor export here

def token(html):
    m = re.search(r'name="csrf_token" value="([^"]+)"', html); return m.group(1) if m else ""
def flashes(html): return re.findall(r'class="flash (\w+)">([^<]{0,160})', html)

# first-run setup (local) or env bootstrap
r = c.get("/login", follow_redirects=True)
html = r.get_data(as_text=True)
if "Create the administrator" in html:
    r = c.post("/setup", data={"csrf_token": token(html), "username": "admin", "password": "Sup3rSecret!", "confirm": "Sup3rSecret!"}, follow_redirects=True)
    html = r.get_data(as_text=True)
# wrong password then correct
c.post("/login", data={"csrf_token": token(html), "username": "admin", "password": "nope"})
html = c.get("/login").get_data(as_text=True)
r = c.post("/login", data={"csrf_token": token(html), "username": "admin", "password": "Sup3rSecret!"}, follow_redirects=True)
html = r.get_data(as_text=True); tok = token(html)
print("login:", r.status_code, "Overview" in html)
# CSRF enforced
print("csrf missing ->", c.post("/demo").status_code)
t = time.time()
r = c.post("/demo", data={"csrf_token": tok}, follow_redirects=True); print("demo:", r.status_code, flashes(r.get_data(as_text=True)), round(time.time()-t, 1), "s")
for path, name, tz in [(SANGFOR, "sangfor-AF-report.xlsx", "+07:00"), ("samples/nginx_access_sample.log", "nginx_access_sample.log", "+07:00"),
                       ("samples/app_auth_events.jsonl", "app_auth_events.jsonl", "UTC"), ("samples/cloudtrail_sample.json", "cloudtrail_sample.json", "UTC"),
                       ("samples/linux_auth_sample.log", "linux_auth_sample.log", "+07:00"), ("samples/windows_security_sample.xml", "windows_security_sample.xml", "local"),
                       ("samples/sangfor_af_sample.csv", "sangfor_af_sample.csv", "+07:00")]:
    try:
        data = open(path, "rb").read()
    except FileNotFoundError:
        print("missing sample", path); continue
    t = time.time()
    r = c.post("/imports/upload", data={"csrf_token": tok, "logfile": (io.BytesIO(data), name), "timezone": tz, "keep_unmatched": "1", "aggregate_web": "1", "min_severity": "Info"},
               content_type="multipart/form-data", follow_redirects=True)
    print(f"import {name}: {r.status_code} {round(time.time()-t,1)}s", flashes(r.get_data(as_text=True))[:2])
pages = ["/", "/incidents", "/incidents?status=all", "/events", "/events?dataset=web", "/imports", "/imports/1", "/imports/9", "/detection", "/detection?tab=coverage",
         "/detection/auth-credential-stuffing", "/response", "/assets", "/metrics", "/simulation", "/settings", "/events/export.ndjson?import=1", "/imports/9/iocs.csv", "/imports/9/report.json"]
for p in pages:
    r = c.get(p); print(p, r.status_code, len(r.data))
    if r.status_code >= 500: print(r.get_data(as_text=True)[-2000:])
inc_html = c.get("/incidents?status=all").get_data(as_text=True)
ids = re.findall(r'href="/incidents/(\d+)"', inc_html)
print("incidents:", len(set(ids)))
for i in sorted(set(ids), key=int)[:40]:
    r = c.get(f"/incidents/{i}")
    if r.status_code != 200: print("incident", i, r.status_code); print(r.get_data(as_text=True)[-1500:])
# triage: resolve one as FP, approve a pending run
first = sorted(set(ids), key=int)[0]
r = c.post(f"/incidents/{first}/status", data={"csrf_token": tok, "status": "Investigating", "disposition": ""}, follow_redirects=True)
r = c.post(f"/incidents/{first}/status", data={"csrf_token": tok, "status": "Resolved", "disposition": "False positive"}, follow_redirects=True)
print("resolve:", flashes(r.get_data(as_text=True)))
resp = c.get("/response").get_data(as_text=True)
runs = re.findall(r'/response/runs/(\d+)/approve', resp)
if runs:
    r = c.post(f"/response/runs/{runs[0]}/approve", data={"csrf_token": tok}, follow_redirects=True); print("approve:", flashes(r.get_data(as_text=True)))
# blocklist feed + api ingest
sett = c.get("/settings").get_data(as_text=True)
feed = re.search(r'(http://localhost/feeds/blocklist\.txt\?token=[^<\s]+)', sett).group(1).replace("&amp;", "&")
print("feed:", c.get(feed.replace("http://localhost", "")).get_data(as_text=True).split())
print("feed bad token:", c.get("/feeds/blocklist.txt?token=x").status_code)
r = c.post("/settings/api-keys", data={"csrf_token": tok, "name": "shop-api"}, follow_redirects=True)
key = re.search(r"(msoc_[\w-]+)", r.get_data(as_text=True)).group(1)
recs = [{"@timestamp": f"2026-10-30T03:{i:02d}:10Z", "event.action": "login_failure", "user.name": f"user{i}", "source.ip": "203.0.113.200", "source.geo.country_iso_code": "BR"} for i in range(12)]
r = c.post("/api/ingest", data=json.dumps(recs), headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
print("ingest:", r.status_code, r.get_json())
print("ingest no key:", c.post("/api/ingest", data="[]").status_code)
# viewer role & masking
c.post("/settings/users", data={"csrf_token": tok, "username": "viewer1", "password": "Viewer12345", "role": "viewer"})
v = app.test_client()
h = v.get("/login").get_data(as_text=True)
v.post("/login", data={"csrf_token": token(h), "username": "viewer1", "password": "Viewer12345"})
ev = v.get("/events").get_data(as_text=True)
print("viewer masked:", "PDPA MASK" in ev, bool(re.search(r"\b\d+\.\d+\.x\.x\b", ev)), "unmasked IPv4 in table:", len(re.findall(r'<small class="cell-sub">(\d+\.\d+\.\d+\.\d+)', ev)))
print("viewer forbidden post:", v.post("/demo", data={"csrf_token": token(ev)}).status_code)
print("viewer settings:", v.get("/settings").status_code)
# cron
print("cron no secret:", c.get("/api/cron/daily").status_code)
r = c.post("/settings", data={"csrf_token": tok, "retention_days": "30", "mask_pii": "viewer", "rba_threshold": "100", "rba_window_hours": "24", "business_hours": "08:00-19:00", "business_days": "1-5", "allowlist": "10.0.0.0/8"}, follow_redirects=True)
print("retention<90:", flashes(r.get_data(as_text=True))[:1])
print("delete import:", flashes(c.post("/imports/2/delete", data={"csrf_token": tok}, follow_redirects=True).get_data(as_text=True)))
print("metrics ok:", c.get("/metrics").status_code)
