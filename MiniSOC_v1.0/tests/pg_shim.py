"""Test-only stand-in for psycopg that sends SQL through the `psql` CLI.

It lets the PostgreSQL code path be exercised where the psycopg wheel is not
available. Parameters are inlined as SQL literals and row-returning statements are
wrapped with row_to_json so values keep their types. Never use this in production.
"""
import json
import re
import subprocess


def _literal(value):
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (int, float)):
        return repr(value)
    text = str(value)
    if "\x00" in text:
        raise ValueError("PostgreSQL text cannot contain NUL (0x00) characters")
    return "'" + text.replace("'", "''") + "'"


def _inline(sql, params):
    params = list(params or ())
    out, i = [], 0
    for token in re.split(r"(%%|%s)", sql):
        if token == "%%":
            out.append("%")
        elif token == "%s":
            out.append(_literal(params[i]))
            i += 1
        else:
            out.append(token)
    if i != len(params):
        raise ValueError(f"placeholder mismatch: used {i}, given {len(params)}")
    return "".join(out)


class _Cursor:
    def __init__(self, conn):
        self.conn = conn
        self.rows = []

    def execute(self, sql, params=()):
        text = _inline(sql, params).strip().rstrip(";")
        head = text.lstrip("( \n").upper()
        returns = head.startswith(("SELECT", "WITH")) or re.search(r"\bRETURNING\b", text, re.I)
        if returns:
            text = f"WITH _q AS ({text}) SELECT row_to_json(_q)::text FROM _q"
        result = subprocess.run(
            ["psql", self.conn.dsn, "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1", "-f", "-"],
            input=text + ";\n", capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"psql error: {result.stderr.strip()}\nSQL: {text[:600]}")
        self.conn.statements += 1
        self.rows = [json.loads(line) for line in result.stdout.splitlines() if line.strip()] if returns else []
        return self

    def fetchone(self):
        return self.rows.pop(0) if self.rows else None

    def fetchall(self):
        rows, self.rows = self.rows, []
        return rows


class ShimConnection:
    def __init__(self, dsn):
        self.dsn = dsn
        self.statements = 0

    def cursor(self):
        return _Cursor(self)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


def install(dsn):
    import config
    import db
    config.DATABASE_URL = dsn
    config.USE_POSTGRES = True
    db._PG_CONNECT = ShimConnection
