"""Detection-as-Code engine.

Rules live in rules/*.yml (Sigma-inspired) and are reviewed/tested like code:

    id: auth-credential-stuffing
    title: Credential stuffing
    level: high                      # informational | low | medium | high | critical
    mitre: [T1110.004]
    detection:
      selection:
        event_type: FailedLogin
        source_ip|exists: true
      condition: selection           # and / or / not / ( ) / "1 of sel_*" / "all of sel_*"
      aggregate:                     # optional: threshold over a sliding time window
        function: distinct_count     # count | distinct_count | sum
        field: username
        group_by: [source_ip]
        timeframe: 10m
        threshold: 8
    risk:                            # risk-based alerting: who accumulates risk
      - {entity: source_ip, score: 60}
    alert: false                     # true = open an incident immediately (bypass the risk threshold)
    message: "{value} accounts tried from {source_ip} in {timeframe}"
    tests:
      - {name: ..., expect: match, events: [...]}

Field modifiers: contains, startswith, endswith, re, gt, gte, lt, lte, cidr, exists, all.
Rules of `type: builtin` call a Python analytic (UEBA baselines, spikes) with YAML parameters.
"""
import glob
import ipaddress
import math
import os
import re
import string
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone

import yaml

import config

LEVELS = {"informational": "Info", "info": "Info", "low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}
ENTITY_TYPES = {"source_ip": "ip", "dest_ip": "ip", "host": "host", "username": "user", "email": "user"}
FIELD_ALIASES = {"direction": "_direction", "off_hours": "_off_hours", "attempts": "_attempts", "scanner": "_scanner",
                 "command": "_command", "privileged": "_privileged", "asset_criticality": "_asset_criticality",
                 "attack_pattern": "_attack_pattern", "iocs": "_iocs", "user_agent": "_user_agent", "token": "_token",
                 "group": "_group", "cves": "_cves"}
TEST_BASE = datetime(2026, 1, 5, 10, 0, 0, tzinfo=timezone(timedelta(hours=7)))  # a Monday, business hours


# ---------------------------------------------------------------- helpers

def parse_duration(text, default=300):
    if text in (None, ""):
        return default
    if isinstance(text, (int, float)):
        return int(text)
    m = re.fullmatch(r"\s*(\d+)\s*([smhd]?)\s*", str(text))
    if not m:
        raise ValueError(f"invalid duration '{text}' (use e.g. 30s, 5m, 1h, 7d)")
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def human_duration(seconds):
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size and seconds % size == 0:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


def to_dt(value):
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def get_field(event, name):
    if name in event:
        return event[name]
    extra = event.get("extra") or {}
    if name.startswith("extra."):
        return extra.get(name[6:])
    key = FIELD_ALIASES.get(name, name)
    if key in extra:
        return extra[key]
    return extra.get("_" + name)


def _as_text(value):
    if isinstance(value, (list, tuple, set)):
        return " ".join(_as_text(v) for v in value)
    if isinstance(value, dict):
        return " ".join(f"{k}={_as_text(v)}" for k, v in value.items())
    return "" if value is None else str(value)


def _num(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def match_value(actual, expected, mods):
    if "exists" in mods:
        present = actual not in (None, "", [], {})
        return present == bool(expected)
    if expected is None:
        return actual in (None, "")
    if actual in (None, "") and not isinstance(expected, bool):
        return False
    for op in ("gte", "gt", "lte", "lt"):
        if op in mods:
            a, b = _num(actual), _num(expected)
            if a is None or b is None:
                return False
            return {"gte": a >= b, "gt": a > b, "lte": a <= b, "lt": a < b}[op]
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            return False
    if isinstance(expected, bool):
        return bool(actual) == expected and actual not in ("", "0", "false", "False")
    a, b = _as_text(actual).lower(), str(expected).lower()
    if "re" in mods:
        return re.search(str(expected), _as_text(actual), re.I) is not None
    if "contains" in mods:
        return b in a
    if "startswith" in mods:
        return a.startswith(b)
    if "endswith" in mods:
        return a.endswith(b)
    if isinstance(expected, (int, float)) and _num(actual) is not None:
        return _num(actual) == float(expected)
    return a == b


def match_selection(event, selection):
    if isinstance(selection, list):  # keyword list: any keyword in the free text
        haystack = " ".join(_as_text(get_field(event, f)) for f in ("details", "signature", "command", "url_path", "raw")).lower()
        return any(str(k).lower() in haystack for k in selection)
    for key, expected in selection.items():
        field, *mods = key.split("|")
        values = expected if isinstance(expected, list) else [expected]
        actual = get_field(event, field)
        if "all" in mods:
            ok = all(match_value(actual, v, mods) for v in values)
        else:
            ok = any(match_value(actual, v, mods) for v in values)
        if not ok:
            return False
    return True


class Condition:
    TOKEN = re.compile(r"\s*(\(|\)|\b(?:and|or|not)\b|(?:1|all) of [\w*]+|[\w*]+)\s*", re.I)

    def __init__(self, text, names):
        self.text = text
        self.names = names
        self.tokens = [t for t in self.TOKEN.findall(text or "") if t.strip()]
        if not self.tokens:
            raise ValueError("empty condition")
        self.pos = 0
        self.tree = self._expr()
        if self.pos != len(self.tokens):
            raise ValueError(f"unexpected token '{self.tokens[self.pos]}' in condition")

    def _peek(self):
        return self.tokens[self.pos].lower() if self.pos < len(self.tokens) else None

    def _take(self):
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def _expr(self):
        node = self._term()
        while self._peek() == "or":
            self._take()
            node = ("or", node, self._term())
        return node

    def _term(self):
        node = self._factor()
        while self._peek() == "and":
            self._take()
            node = ("and", node, self._factor())
        return node

    def _factor(self):
        token = self._peek()
        if token is None:
            raise ValueError("condition ended unexpectedly")
        if token == "not":
            self._take()
            return ("not", self._factor())
        if token == "(":
            self._take()
            node = self._expr()
            if self._peek() != ")":
                raise ValueError("missing ')' in condition")
            self._take()
            return node
        raw = self._take()
        m = re.fullmatch(r"(1|all) of ([\w*]+)", raw, re.I)
        if m:
            pattern = re.compile("^" + re.escape(m.group(2)).replace(r"\*", ".*") + "$")
            matched = [n for n in self.names if pattern.match(n)]
            if not matched:
                raise ValueError(f"'{raw}' matches no selection")
            return ("any" if m.group(1) == "1" else "all", matched)
        if raw not in self.names:
            raise ValueError(f"unknown selection '{raw}'")
        return ("name", raw)

    def evaluate(self, results, node=None):
        node = node or self.tree
        kind = node[0]
        if kind == "name":
            return results[node[1]]
        if kind == "not":
            return not self.evaluate(results, node[1])
        if kind == "and":
            return self.evaluate(results, node[1]) and self.evaluate(results, node[2])
        if kind == "or":
            return self.evaluate(results, node[1]) or self.evaluate(results, node[2])
        if kind == "any":
            return any(results[n] for n in node[1])
        return all(results[n] for n in node[1])


class _SafeDict(dict):
    def __missing__(self, key):
        return "?"


def render_message(template, values):
    try:
        return string.Formatter().vformat(template or "", (), _SafeDict(values))
    except (ValueError, IndexError):
        return template or ""


# ---------------------------------------------------------------- rules

class Rule:
    def __init__(self, data, path="", source=""):
        self.data = data
        self.path = path
        self.source = source
        self.id = str(data.get("id") or "").strip()
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,80}", self.id):
            raise ValueError("id must be lowercase letters, digits, '-', '_' or '.'")
        self.title = str(data.get("title") or self.id)
        self.description = str(data.get("description") or "").strip()
        self.level_raw = str(data.get("level") or "medium").lower()
        if self.level_raw not in LEVELS:
            raise ValueError(f"unknown level '{self.level_raw}'")
        self.level = LEVELS[self.level_raw]
        self.status = str(data.get("status") or "stable")
        self.author = str(data.get("author") or "")
        self.category = str((data.get("logsource") or {}).get("category") or data.get("category") or "general")
        self.mitre = [str(m).upper() for m in (data.get("mitre") or [])]
        self.enabled_default = bool(data.get("enabled", True))
        self.alert = bool(data.get("alert", False))
        self.message = data.get("message") or self.title
        self.false_positives = data.get("falsepositives") or data.get("false_positives") or []
        self.response = data.get("response") or []
        self.tests = data.get("tests") or []
        self.type = str(data.get("type") or ("aggregate" if (data.get("detection") or {}).get("aggregate") else "match"))
        self.params = data.get("params") or {}
        self.handler = data.get("handler")
        det = data.get("detection") or {}
        self.selections = {k: v for k, v in det.items() if k not in ("condition", "aggregate")}
        if self.type != "builtin":
            if not self.selections:
                raise ValueError("detection needs at least one selection")
            for name, sel in self.selections.items():
                if not isinstance(sel, (dict, list)):
                    raise ValueError(f"selection '{name}' must be a mapping or a keyword list")
            self.condition = Condition(det.get("condition") or " and ".join(self.selections), list(self.selections))
        else:
            if self.handler not in BUILTINS:
                raise ValueError(f"unknown builtin handler '{self.handler}'")
            self.condition = None
        agg = det.get("aggregate")
        self.aggregate = None
        if agg:
            fn = str(agg.get("function", "count"))
            if fn not in ("count", "distinct_count", "sum"):
                raise ValueError("aggregate.function must be count, distinct_count or sum")
            if fn != "count" and not agg.get("field"):
                raise ValueError(f"aggregate.function {fn} needs a field")
            self.aggregate = {
                "function": fn, "field": agg.get("field"),
                "group_by": agg.get("group_by") or [],
                "timeframe": parse_duration(agg.get("timeframe", "5m")),
                "threshold": float(agg.get("threshold", 5)),
            }
        self.dedup = parse_duration(data.get("dedup"), self.aggregate["timeframe"] if self.aggregate else 0)
        self.lookback = max(self.aggregate["timeframe"] if self.aggregate else 0,
                            parse_duration(self.params.get("lookback"), 0) if self.params else 0)
        risk = data.get("risk") or [{"entity": "source_ip", "score": 10}]
        self.risk = []
        for item in risk:
            entity = item.get("entity")
            if entity not in ENTITY_TYPES:
                raise ValueError(f"risk entity must be one of {', '.join(ENTITY_TYPES)}")
            self.risk.append({"entity": entity, "score": float(item.get("score", 10))})

    def matches(self, event):
        if self.condition is None:
            return False
        results = {name: match_selection(event, sel) for name, sel in self.selections.items()}
        return self.condition.evaluate(results)

    @property
    def max_score(self):
        return max(r["score"] for r in self.risk)


def load_rules(directory=None):
    """Return (rules, errors). Errors are shown on the Detection page instead of crashing the app."""
    directory = directory or config.RULES_DIR
    rules, errors, seen = [], [], set()
    for path in sorted(glob.glob(os.path.join(directory, "*.yml")) + glob.glob(os.path.join(directory, "*.yaml"))):
        try:
            with open(path, encoding="utf-8") as fh:
                source = fh.read()
            data = yaml.safe_load(source) or {}
            rule = Rule(data, path, source)
            if rule.id in seen:
                raise ValueError(f"duplicate rule id '{rule.id}'")
            seen.add(rule.id)
            rules.append(rule)
        except Exception as exc:  # noqa: BLE001 - report any rule problem
            errors.append({"file": os.path.basename(path), "error": str(exc)})
    return rules, errors


_CACHE = {"mtime": None, "rules": [], "errors": []}


def get_rules():
    files = glob.glob(os.path.join(config.RULES_DIR, "*.y*ml"))
    stamp = tuple(sorted((f, os.path.getmtime(f)) for f in files))
    if _CACHE["mtime"] != stamp:
        _CACHE["rules"], _CACHE["errors"] = load_rules()
        _CACHE["mtime"] = stamp
    return _CACHE["rules"], _CACHE["errors"]


# ---------------------------------------------------------------- history providers

class NullHistory:
    def window(self, start, end):
        return []

    def last_signal(self, rule_id, entity_type, entity_value, start, end):
        return None

    def login_history(self, username, before):
        return []

    def bytes_history(self, field, value, start, end):
        return []

    def error_history(self, start, end):
        return []


class ListHistory(NullHistory):
    """History made of prepared events (used by rule tests and simulations)."""

    def __init__(self, events):
        self.events = events

    def window(self, start, end):
        return [e for e in self.events if e.get("_t") and start <= e["_t"] <= end]

    def login_history(self, username, before):
        return [{"country": e.get("country"), "source_ip": e.get("source_ip"), "ts_utc": iso(e["_t"])}
                for e in self.events if e.get("event_type") == "LoginSuccess" and e.get("username") == username and e["_t"] < before]

    def bytes_history(self, field, value, start, end):
        return [{"ts_utc": iso(e["_t"]), "bytes_out": e.get("bytes_out"), "hits": e.get("hits", 1)}
                for e in self.events if e.get(field) == value and e.get("bytes_out") and start <= e["_t"] < end]

    def error_history(self, start, end):
        return [{"ts_utc": iso(e["_t"]), "hits": e.get("hits", 1), "http_status": e.get("http_status")}
                for e in self.events if (e.get("http_status") or 0) >= 500 and start <= e["_t"] < end]


class DBHistory(NullHistory):
    def __init__(self):
        import database
        self.db = database
        self._window = None

    def window(self, start, end):
        if self._window is None or self._window[0] > start or self._window[1] < end:
            events = self.db.events_in_window(iso(start), iso(end))
            for e in events:
                e["_t"] = to_dt(e.get("ts_utc") or e.get("timestamp"))
            self._window = (start, end, events)
        return [e for e in self._window[2] if e["_t"] and start <= e["_t"] <= end]

    def last_signal(self, rule_id, entity_type, entity_value, start, end):
        value = self.db.last_signal_time(rule_id, entity_type, entity_value, iso(start), iso(end))
        return to_dt(value) if value else None

    def login_history(self, username, before):
        return self.db.user_login_history(username, iso(before))

    def bytes_history(self, field, value, start, end):
        return self.db.entity_bytes_history(field, value, iso(start), iso(end))

    def error_history(self, start, end):
        return self.db.error_history(iso(start), iso(end))


# ---------------------------------------------------------------- engine

class Engine:
    def __init__(self, rules, history=None, enabled=None):
        self.rules = [r for r in rules if (enabled or {}).get(r.id, r.enabled_default)]
        self.history = history or NullHistory()

    def _signal(self, rule, event, values, entity_source=None):
        signals = []
        merged = dict(event)
        for k, v in (event.get("extra") or {}).items():
            merged[k] = v
            if k.startswith("_") and k[1:] not in merged:
                merged[k[1:]] = v  # e.g. {attempts} for extra._attempts
        merged.update(values)
        message = render_message(rule.message, merged)
        for index, item in enumerate(rule.risk):
            value = (entity_source or {}).get(item["entity"]) or get_field(event, item["entity"])
            if value in (None, "", "-"):
                continue
            etype = ENTITY_TYPES[item["entity"]]
            if etype == "host" and _is_ip(value):
                etype = "ip"
            signals.append({
                "rule_id": rule.id, "rule_title": rule.title, "level": rule.level, "event": event,
                "ts": event.get("timestamp"), "_t": event["_t"], "entity_type": etype, "entity_value": str(value),
                "entity_field": item["entity"], "base_score": item["score"], "mitre": ",".join(rule.mitre),
                "message": message, "direct_alert": rule.alert and index == 0,  # secondary entities only accumulate risk
            })
        return signals

    def _deduped(self, rule, key, t, memory):
        if not rule.dedup:
            return False
        last = memory.get((rule.id, key))
        if last and t - last < timedelta(seconds=rule.dedup):
            return True
        return False

    def _db_deduped(self, rule, signals):
        if not rule.dedup or not signals:
            return False
        s = signals[0]
        start = s["_t"] - timedelta(seconds=rule.dedup)
        last = self.history.last_signal(rule.id, s["entity_type"], s["entity_value"], start, s["_t"])
        return last is not None

    def run(self, events):
        batch = [e for e in events if e.get("_t") or to_dt(e.get("timestamp"))]
        for e in batch:
            e.setdefault("_t", to_dt(e.get("timestamp")))
            e["_batch"] = True
        if not batch:
            return []
        batch.sort(key=lambda e: e["_t"])
        t_min, t_max = batch[0]["_t"], batch[-1]["_t"]
        lookback = max([r.lookback for r in self.rules] + [0])
        history = []
        if lookback:
            history = [e for e in self.history.window(t_min - timedelta(seconds=lookback), t_max) if not e.get("_batch")]
        context = {"batch": batch, "history": history, "history_provider": self.history}
        signals, memory = [], {}
        for rule in self.rules:
            if rule.type == "builtin":
                for event, values, entities in BUILTINS[rule.handler](rule, context):
                    new = self._signal(rule, event, values, entities)
                    key = tuple((s["entity_type"], s["entity_value"]) for s in new)
                    if new and not self._deduped(rule, key, event["_t"], memory) and not self._db_deduped(rule, new):
                        memory[(rule.id, key)] = event["_t"]
                        signals.extend(new)
            elif rule.aggregate:
                signals.extend(self._run_aggregate(rule, batch, history, memory))
            else:
                for event in batch:
                    if rule.matches(event):
                        new = self._signal(rule, event, {})
                        key = tuple((s["entity_type"], s["entity_value"]) for s in new)
                        if not new or self._deduped(rule, key, event["_t"], memory) or self._db_deduped(rule, new):
                            continue
                        memory[(rule.id, key)] = event["_t"]
                        signals.extend(new)
        return signals

    def _run_aggregate(self, rule, batch, history, memory):
        agg = rule.aggregate
        tf = timedelta(seconds=agg["timeframe"])
        candidates = sorted((e for e in history + batch if rule.matches(e)), key=lambda e: e["_t"])
        groups = defaultdict(list)
        for e in candidates:
            key = tuple(str(get_field(e, f) or "") for f in agg["group_by"])
            if agg["group_by"] and not all(key):
                continue
            groups[key].append(e)
        out = []
        for key, items in groups.items():
            window = deque()
            running = 0.0
            values = Counter()
            for e in items:
                window.append(e)
                hits = int(e.get("hits") or 1)
                if agg["function"] == "count":
                    running += hits
                elif agg["function"] == "sum":
                    running += (_num(get_field(e, agg["field"])) or 0)
                else:
                    v = get_field(e, agg["field"])
                    if v not in (None, ""):
                        values[str(v).lower()] += 1
                while window and window[0]["_t"] <= e["_t"] - tf:
                    old = window.popleft()
                    if agg["function"] == "count":
                        running -= int(old.get("hits") or 1)
                    elif agg["function"] == "sum":
                        running -= (_num(get_field(old, agg["field"])) or 0)
                    else:
                        v = get_field(old, agg["field"])
                        if v not in (None, ""):
                            values[str(v).lower()] -= 1
                            if values[str(v).lower()] <= 0:
                                del values[str(v).lower()]
                value = len(values) if agg["function"] == "distinct_count" else running
                if not e.get("_batch") or value < agg["threshold"]:
                    continue
                if self._deduped(rule, key, e["_t"], memory):
                    continue
                entity_source = dict(zip(agg["group_by"], key))
                sample = sorted(values)[:6] if agg["function"] == "distinct_count" else []
                new = self._signal(rule, e, {
                    "value": int(value) if float(value).is_integer() else round(value, 1),
                    "threshold": int(agg["threshold"]), "timeframe": human_duration(agg["timeframe"]),
                    "group": ", ".join(key), "sample": ", ".join(sample), "first_seen": window[0].get("timestamp"),
                }, entity_source)
                if not new or self._db_deduped(rule, new):
                    memory[(rule.id, key)] = e["_t"]
                    continue
                memory[(rule.id, key)] = e["_t"]
                out.extend(new)
        return out


def _is_ip(value):
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------- builtin analytics (UEBA / anomaly)

def _events(context, types=None, include_history=True):
    pool = (context["history"] if include_history else []) + context["batch"]
    return [e for e in pool if types is None or e.get("event_type") in types]


def builtin_new_country_login(rule, context, require_failures=False):
    p = rule.params
    min_failures = int(p.get("min_failures", 3))
    fail_window = timedelta(seconds=parse_duration(p.get("failures_window", "60m")))
    successes = sorted(_events(context, {"LoginSuccess"}), key=lambda e: e["_t"])
    failures = _events(context, {"FailedLogin"})
    seen = {}
    for e in successes:
        user, country = e.get("username"), (e.get("country") or "").strip()
        if not user or not country:
            continue
        if user not in seen:
            seen[user] = {(h.get("country") or "").strip().lower()
                          for h in context["history_provider"].login_history(user, e["_t"]) if h.get("country")}
            seen[user] |= {(h.get("country") or "").strip().lower() for h in context["history"]
                           if h.get("event_type") == "LoginSuccess" and h.get("username") == user and h.get("country")
                           and h["_t"] < e["_t"]}
        known = seen[user]
        if e.get("_batch") and known and country.lower() not in known:
            recent_fail = [f for f in failures if f.get("username") == user and e["_t"] - fail_window <= f["_t"] < e["_t"]]
            fail_count = sum(int(f.get("hits") or 1) for f in recent_fail)
            if (not require_failures) or fail_count >= min_failures:
                yield e, {"known_countries": ", ".join(sorted(k.upper() for k in known)), "failures": fail_count,
                          "fail_window": human_duration(int(fail_window.total_seconds()))}, None
        known.add(country.lower())


def builtin_account_takeover(rule, context):
    yield from builtin_new_country_login(rule, context, require_failures=True)


def builtin_success_after_failures(rule, context):
    p = rule.params
    min_failures = int(p.get("min_failures", 5))
    window = timedelta(seconds=parse_duration(p.get("window", "30m")))
    failures = _events(context, {"FailedLogin"})
    by_ip = defaultdict(list)
    for f in failures:
        if f.get("source_ip"):
            by_ip[f["source_ip"]].append(f)
    for e in context["batch"]:
        if e.get("event_type") != "LoginSuccess" or not e.get("source_ip"):
            continue
        prior = [f for f in by_ip.get(e["source_ip"], []) if e["_t"] - window <= f["_t"] < e["_t"]]
        count = sum(int(f.get("hits") or 1) for f in prior)
        if count >= min_failures:
            users = sorted({f.get("username") for f in prior if f.get("username")})
            yield e, {"failures": count, "window": human_duration(int(window.total_seconds())),
                      "tried_users": ", ".join(users[:6])}, None


def _fmt_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024


def builtin_api_exfiltration(rule, context):
    p = rule.params
    field = p.get("entity_field", "username")
    min_bytes = float(p.get("min_bytes", 100 * 1024 * 1024))
    factor = float(p.get("factor", 5))
    baseline_days = int(p.get("baseline_days", 7))
    buckets = defaultdict(lambda: {"bytes": 0.0, "last": None})
    for e in context["batch"]:
        value, size = e.get(field), _num(e.get("bytes_out"))
        if not value or not size:
            continue
        hour = e["_t"].replace(minute=0, second=0, microsecond=0)
        b = buckets[(value, hour)]
        b["bytes"] += size
        if b["last"] is None or e["_t"] >= b["last"]["_t"]:
            b["last"] = e
    for (value, hour), b in sorted(buckets.items(), key=lambda kv: kv[0][1]):
        if b["bytes"] < min_bytes:
            continue
        start = hour - timedelta(days=baseline_days)
        hourly = defaultdict(float)
        for row in context["history_provider"].bytes_history(field, value, start, hour):
            t = to_dt(row["ts_utc"])
            if t:
                hourly[t.replace(minute=0, second=0, microsecond=0)] += float(row.get("bytes_out") or 0)
        for (v2, h2), b2 in buckets.items():
            if v2 == value and h2 < hour:
                hourly[h2] += b2["bytes"]
        baseline = (sum(hourly.values()) / len(hourly)) if len(hourly) >= 3 else None
        if baseline:
            if b["bytes"] < factor * baseline:
                continue
            ratio = f"x{b['bytes'] / baseline:.0f} of baseline {_fmt_bytes(baseline)}/h"
        else:
            if b["bytes"] < min_bytes * 5:
                continue
            ratio = "no baseline yet"
        yield b["last"], {"volume": _fmt_bytes(b["bytes"]), "baseline": ratio, "entity": value,
                          "hour": hour.isoformat(timespec="minutes")}, {field: value}


def builtin_http_error_spike(rule, context):
    p = rule.params
    bucket = timedelta(seconds=parse_duration(p.get("bucket", "5m")))
    min_errors = float(p.get("min_errors", 50))
    sigma = float(p.get("sigma", 4))
    status_min = int(p.get("status_min", 500))
    baseline_span = timedelta(seconds=parse_duration(p.get("baseline", "24h")))

    def floor(t):
        seconds = int(t.timestamp()) // int(bucket.total_seconds()) * int(bucket.total_seconds())
        return datetime.fromtimestamp(seconds, tz=timezone.utc)

    current = defaultdict(lambda: {"n": 0, "last": None, "hosts": Counter()})
    for e in context["batch"]:
        if (e.get("http_status") or 0) >= status_min:
            b = current[floor(e["_t"])]
            b["n"] += int(e.get("hits") or 1)
            b["hosts"][e.get("host") or "web"] += 1
            if b["last"] is None or e["_t"] >= b["last"]["_t"]:
                b["last"] = e
    if not current:
        return
    t_min = min(current)
    counts = defaultdict(float)
    for row in context["history_provider"].error_history(t_min - baseline_span, t_min):
        t = to_dt(row["ts_utc"])
        if t and (row.get("http_status") or 0) >= status_min:
            counts[floor(t)] += int(row.get("hits") or 1)
    for k, b in current.items():
        counts[k] += b["n"]
    span_start = t_min - baseline_span
    n_buckets = max(1, int((max(current) - span_start) / bucket) + 1)
    for key, b in sorted(current.items()):
        others = [v for k, v in counts.items() if k != key]
        mean = sum(others) / n_buckets
        var = sum((v - mean) ** 2 for v in others) + (n_buckets - len(others)) * mean ** 2
        std = math.sqrt(var / n_buckets)
        limit = max(min_errors, mean + sigma * std)
        if b["n"] >= limit:
            host = b["hosts"].most_common(1)[0][0]
            yield b["last"], {"errors": b["n"], "bucket": human_duration(int(bucket.total_seconds())),
                              "baseline_mean": round(mean, 1), "status_min": status_min, "service": host}, {"host": host}


BUILTINS = {
    "new_country_login": builtin_new_country_login,
    "account_takeover": builtin_account_takeover,
    "success_after_failures": builtin_success_after_failures,
    "api_exfiltration": builtin_api_exfiltration,
    "http_error_spike": builtin_http_error_spike,
}


# ---------------------------------------------------------------- rule tests

def _expand_test_events(specs):
    events = []
    for spec in specs or []:
        repeat = int(spec.get("repeat", 1))
        step = parse_duration(spec.get("step", "10s"))
        at = str(spec.get("at", "0s")).strip()
        sign = -1 if at.startswith("-") else 1
        offset = sign * sum(parse_duration(part) for part in re.findall(r"\d+[smhd]?", at.lstrip("+-")) or ["0"])
        for i in range(repeat):
            event = {}
            for k, v in spec.items():
                if k in ("repeat", "step", "at"):
                    continue
                event[k] = v.replace("{i}", str(i)) if isinstance(v, str) else v
            if "timestamp" not in event:
                event["timestamp"] = (TEST_BASE + timedelta(seconds=offset + i * step)).isoformat()
            event.setdefault("extra", {})
            event.setdefault("hits", 1)
            event["_t"] = to_dt(event["timestamp"])
            events.append(event)
    return events


def run_rule_tests(rule):
    """Execute the YAML tests of one rule. Returns a list of {name, passed, detail}."""
    results = []
    for i, test in enumerate(rule.tests):
        name = test.get("name") or f"test {i + 1}"
        try:
            history = _expand_test_events(test.get("history"))
            events = _expand_test_events(test.get("events"))
            engine = Engine([rule], ListHistory(history), enabled={rule.id: True})
            signals = engine.run(events)
            matched = bool(signals)
            expect = str(test.get("expect", "match")).lower()
            passed = matched if expect == "match" else not matched
            detail = f"{len(signals)} signal(s)" + (f": {signals[0]['message']}" if signals else "")
            if "count" in test and expect == "match":
                n = len({(s['ts'], s['entity_value']) for s in signals if s['entity_field'] == rule.risk[0]['entity']})
                passed = passed and n == int(test["count"])
                detail += f" (expected {test['count']}, got {n})"
            results.append({"name": name, "passed": passed, "expect": expect, "detail": detail})
        except Exception as exc:  # noqa: BLE001
            results.append({"name": name, "passed": False, "expect": test.get("expect"), "detail": f"error: {exc}"})
    return results
