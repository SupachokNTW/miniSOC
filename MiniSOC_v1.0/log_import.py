"""Upload -> parse -> pipeline for imported log files and the HTTP ingest API."""
import hashlib

import database
import pipeline
from log_parser import ParseError, parse_file, _json_records  # noqa: F401  (re-exported for app.py)

MAX_UPLOAD_BYTES = 60 * 1024 * 1024


class DuplicateImport(Exception):
    def __init__(self, existing):
        super().__init__(f"This file was already imported as Import #{existing['id']}.")
        self.existing = existing


def import_log_file(filename, data, fmt="auto", tz_option="local", keep_unmatched=True, allow_duplicate=False,
                    options=None, user=None):
    """Import one uploaded file and return (import_id, pipeline_stats)."""
    if len(data) > MAX_UPLOAD_BYTES:
        raise ParseError(f"File is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB. Split or filter the export first.")
    digest = hashlib.sha256(data).hexdigest()
    existing = database.find_import_by_hash(digest)
    if existing and not allow_duplicate:
        raise DuplicateImport(existing)
    result = parse_file(filename, data, fmt=fmt, tz_option=tz_option, keep_unmatched=keep_unmatched)
    options = dict(options or {})
    import_id = database.create_import(
        (filename or "uploaded-log")[:200], result["format"], result["vendor"], digest, len(data), result["timezone"],
        result["total_records"], result["skipped"], result["meta"], result["warnings"], options, user)
    label = f"Import #{import_id}" + (f" · {result['vendor']}" if result["vendor"] else "")
    stats = pipeline.process_batch(result["events"], label, import_id=import_id, options=options, user=user)
    database.finish_import(import_id, stats["stored"], stats["summarized_records"], stats["signals"],
                           stats["incidents_created"])
    return import_id, stats


def ingest_records(records, source_name, tz_option="UTC", user=None):
    """Ingest already-structured JSON records (HTTP API). Returns pipeline stats."""
    import json
    payload = json.dumps(records, ensure_ascii=False).encode()
    result = parse_file("api.json", payload, fmt="json", tz_option=tz_option, keep_unmatched=True)
    return pipeline.process_batch(result["events"], f"API · {source_name}", import_id=None, user=user)
