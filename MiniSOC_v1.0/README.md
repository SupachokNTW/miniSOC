# MiniSOC 1.0 — Web-service SOC (local Windows + Vercel)

MiniSOC is a small, explainable SIEM/SOC platform built with Python + Flask. Version 1.0 redesigns
v0.5 around the problems in *“ปัญหาของ SIEM และแนวทางแก้ไขสำหรับ Web Services”*.
The **same code** runs on a Windows PC (SQLite, `run.bat`) and on **Vercel**
(serverless Flask + PostgreSQL/Neon).

> Educational prototype. Detections are triage signals, not proof of compromise.

## How each SIEM problem is addressed

| Problem (doc) | What MiniSOC 1.0 does |
|---|---|
| Alert fatigue | **Risk-based alerting**: every rule match is a *detection* that adds risk points to an IP / user / host (×asset criticality, ×1.5 privileged). An **incident** opens only when risk ≥ threshold (default 100 / 24 h) or a high-confidence rule fires; later detections attach to the open incident. Dispositions (true/false positive) give a **false-positive rate per rule** with tuning advice. |
| High cost (GB/day) | **Pipeline data reduction**: rules run on every record first, then normal web/API traffic is summarised into 5-minute rows and low-severity noise can be dropped. Evidence is always kept. Browser-side gzip for uploads. **ECS NDJSON export** for cheap cold storage (S3 + Athena) or another SIEM. |
| Hard to install & maintain | **Detection-as-Code**: rules are Sigma-style YAML files in `rules/` with tests, MITRE ATT&CK mapping and CI (`.github/workflows/detection-tests.yml`). Invalid rules are reported, not crashing the app. One-click deploy on Vercel. |
| Staff shortage | Plain-language explanations, evidence timeline, MITRE names, checklists and playbooks that do the routine steps. |
| Blind to application threats | Web/API use cases: credential stuffing, distributed brute force, success-after-failures, **account takeover (new country after failures, UEBA baseline)**, **API data exfiltration (volume vs 7-day baseline)**, 4xx scanning bursts, 5xx spikes, privilege change outside business hours, MFA disabled. |
| Non-standard logs | Parsers for Sangfor AF, CSV/Excel, JSON/JSONL/ECS, Nginx/Apache, AWS CloudTrail, Windows XML, Linux auth, plain text → one normalised schema (datasets auth/iam/web/api/network/host/cloud) → ECS export. |
| Missing context | **Assets & Users** inventory (criticality, owner, tags, privileged flag), auto-discovery from logs, enrichment on every incident. |
| Slow response | **SOAR playbooks** (`playbooks/*.yml`): blocklist feed for WAF/firewall, Slack/Teams/Discord notification, ticket/IdP/EDR webhooks, tasks; disruptive actions require approval. |
| Measure & test (doc §9) | **Metrics**: MTTD, MTTA, MTTR, FP rate, alert and storage reduction. **Attack simulation (purple team)**: 8 scenarios replayed through the real pipeline, pass/fail per expected rule, shown on the ATT&CK coverage matrix. |
| Thai law (doc §10) | Retention minimum **90 days** (พ.ร.บ.คอมพิวเตอร์) enforced, daily purge (Vercel Cron); **PDPA** role-based access, IP/e-mail masking for viewers, masked exports, audit log. |

## Run locally (Windows)
1. Install Python 3.10+ (`py` launcher). Extract the folder.
2. Double-click `run.bat` → opens http://127.0.0.1:5055.
3. First visit from this PC shows **Create the administrator**.
4. Overview → **Load demo attacks**, or Log Import → upload a file from `samples/`.

Existing v0.4/v0.5 databases (`data/minisoc.db`) are migrated automatically; copy the file into the new
folder's `data/` while the app is stopped. Windows Security log polling still works locally.

## Deploy on Vercel
1. Push this folder to a GitHub repository (do **not** commit `data/`).
2. Vercel → **Add New → Project** → import the repo. Framework preset: **Flask** (auto-detected from `app.py`).
3. Vercel → project → **Storage → Create/Connect Database → Neon (Postgres)**. This adds `DATABASE_URL`.
4. Project → **Settings → Environment Variables** (see `.env.example`):
   - `MINISOC_SECRET` — 64 random hex chars (e.g. `python -c "import secrets;print(secrets.token_hex(32))"`)
   - `MINISOC_ADMIN_USER`, `MINISOC_ADMIN_PASSWORD` — the first admin (created on first start)
   - `CRON_SECRET` — random string protecting `/api/cron/daily`
5. Deploy. Sign in, open **Settings**: set the public base URL, webhooks, and create other users.

Notes for Vercel
- Without `DATABASE_URL` the app falls back to SQLite in `/tmp` (data lost on restart) and shows a warning.
- Requests are limited to 4.5 MB: text logs are gzip-compressed in the browser (often 10-20× smaller);
  `.xlsx` must be < 4 MB; split bigger exports. Max 30,000 records per import (`MINISOC_MAX_EVENTS`).
- `vercel.json` sets `maxDuration` 120 s and a daily cron (19:15 UTC = 02:15 Thailand) for retention.
- The Windows collector is disabled on Vercel; push logs with the **Ingest API** instead.

## Ingest API (push logs from your web service)
Create a key in Settings → Ingest API keys, then:
```bash
curl -X POST https://<your-app>.vercel.app/api/ingest \
  -H "Authorization: Bearer msoc_..." -H "Content-Type: application/json" \
  -d '[{"@timestamp":"2026-10-30T10:00:00Z","event.action":"login_failure","user.name":"alice","source.ip":"203.0.113.9","source.geo.country_iso_code":"RU"}]'
```
Body: JSON object, array or NDJSON (gzip allowed, `Content-Encoding: gzip`). Recognised actions include
`login_success`, `login_failure`, `mfa_disabled`, `password_changed`, `role_granted`, `user_created`,
`api_request` (with `http.response.bytes`). Query `?tz=+07:00` if timestamps have no zone.

## Blocklist feed for WAF / firewall
`/feeds/blocklist.txt?token=…` (URL in Settings) returns one active IP per line (`&kind=all` adds domains).
Use it as an external/dynamic IP list (e.g. FortiGate threat feed, Palo Alto EDL, scripts for NGINX/Cloudflare).
Internal and allow-listed ranges are never added; entries expire (72 h by default).

## Detection-as-Code
- Rules: `rules/*.yml` · Playbooks: `playbooks/*.yml` · Engine: `detection_engine.py`
- Validate & test: `python tests/run_rule_tests.py` (also runs in GitHub Actions)
- Rule fields: `detection` (selections + `condition`, optional `aggregate` count/distinct_count/sum over a
  sliding window), `risk` (entity + score), `alert`, `dedup`, `mitre`, `falsepositives`, `tests`.
- Built-in analytics (`type: builtin`): `account_takeover`, `new_country_login`, `success_after_failures`,
  `api_exfiltration`, `http_error_spike`.

## Roles
viewer = read-only (PII masked by default) · analyst = triage, imports, approvals, assets · admin = rules, settings, users, keys.

## Project layout
`app.py` routes · `config.py` env · `db.py` SQLite/Postgres adapter · `database.py` data access ·
`log_parser.py` parsers · `pipeline.py` enrich/detect/reduce/store · `risk.py` RBA · `soar.py` playbooks ·
`metrics.py` · `simulation.py` · `log_analysis.py` import report · `ecs.py` export · `auth.py` login/CSRF/PDPA ·
`collector.py` Windows (local) · `templates/` · `public/static/` · `samples/` · `tests/`.

## Testing
- `python tests/run_rule_tests.py` — 20 rules, 35 tests.
- `MINISOC_SQLITE_PATH=/tmp/t.db python tests/smoke_test.py` — end-to-end through every page/route.
- `python tests/smoke_test.py pg` — same against PostgreSQL (uses `tests/pg_shim.py` and a local server).

---

## คู่มือภาษาไทย (สรุป)

**MiniSOC 1.0** ปรับปรุงจากเอกสาร “ปัญหาของ SIEM และแนวทางแก้ไขสำหรับ Web Services” ทั้ง 8 ปัญหา และ 10 แนวทาง:

- **Alert fatigue** → ใช้ *Risk-Based Alerting*: กฎแต่ละครั้งที่ตรงเป็น “detection” สะสมคะแนนความเสี่ยงให้ IP/ผู้ใช้/เครื่อง
  เปิด incident เมื่อเกินเกณฑ์ (ค่าเริ่มต้น 100 คะแนนใน 24 ชม.) และรวม alert ซ้ำของ entity เดียวกันเป็น incident เดียว
- **ค่าใช้จ่ายสูง** → pipeline ตรวจจับกับข้อมูลทั้งหมดก่อน แล้วสรุป traffic ปกติเป็นแถวสรุปทุก 5 นาที เก็บเฉพาะหลักฐาน และ export ECS ไปเก็บราคาถูก
- **ดูแลยาก** → Detection-as-Code: กฎเป็นไฟล์ YAML (แนว Sigma) มี test, MITRE ATT&CK และ CI
- **มองไม่เห็นภัยระดับแอป** → กฎสำหรับ credential stuffing, account takeover (login จากประเทศใหม่หลังล้มเหลว), API exfiltration, scanning (4xx/5xx), เปลี่ยนสิทธิ์นอกเวลาทำงาน
- **Log ไม่เป็นมาตรฐาน / ขาดบริบท** → normalize ทุกแหล่งเป็น schema เดียว, มีทะเบียน Assets & Users (ความสำคัญ, เจ้าของ, บัญชีสิทธิ์สูง)
- **ตอบสนองช้า** → SOAR playbook: เพิ่ม IP เข้า blocklist feed ให้ WAF/Firewall ดึง, แจ้ง Slack/Teams, เปิด ticket, งานที่กระทบผู้ใช้ต้องอนุมัติก่อน
- **วัดผล** → หน้า Metrics (MTTD/MTTA/MTTR/อัตรา false positive) และหน้า Simulation ทดสอบการโจมตีจำลอง 8 แบบ
- **กฎหมายไทย** → เก็บ log ขั้นต่ำ 90 วันตาม พ.ร.บ.คอมพิวเตอร์ และ PDPA: กำหนดสิทธิ์ผู้ใช้ ปิดบัง IP/อีเมลสำหรับ viewer และบันทึก audit log

**ติดตั้งบน Vercel:** push โค้ดขึ้น GitHub → Import project ใน Vercel → เชื่อม Neon Postgres จาก Storage →
ตั้งค่า `MINISOC_SECRET`, `MINISOC_ADMIN_USER`, `MINISOC_ADMIN_PASSWORD`, `CRON_SECRET` → Deploy

**ใช้งานบน Windows:** ดับเบิลคลิก `run.bat` แล้วสร้างบัญชีผู้ดูแลในหน้าแรก
