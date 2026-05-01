"""
Xalgorix tool-invocation testbench.

Intentionally vulnerable Flask application with 5 login endpoints (each
exercising a different sqlmap invocation shape) + 5 static pages.

Runs on :8000 inside Docker, exposed on 127.0.0.1:8088 on the host.

IMPORTANT: This app is deliberately vulnerable. NEVER deploy outside of a
local Docker network.
"""

import json
import os
import re
import secrets
import sqlite3
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import Flask, Response, g, jsonify, make_response, request, session

APP_SECRET = secrets.token_hex(16)
DB_PATH = "/app/data/app.db"
LOG_PATH = Path("/app/logs/requests.log")
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = APP_SECRET


# ---------------------------------------------------------------------------
# DB bootstrap
# ---------------------------------------------------------------------------

def _init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user'
        );
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT NOT NULL,
            value TEXT NOT NULL
        );
        """
    )
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
            [
                ("admin", "S3cret!Admin2026", "admin@testbench.local", "admin"),
                ("alice", "alice-password-1", "alice@testbench.local", "user"),
                ("bob", "bob-password-2", "bob@testbench.local", "user"),
                ("carol", "carol-password-3", "carol@testbench.local", "user"),
                ("svc_ci", "svc-ci-s3cret", "ci@testbench.local", "service"),
            ],
        )
        cur.executemany(
            "INSERT INTO secrets (label, value) VALUES (?, ?)",
            [
                ("flag_login1", "FLAG{login1-error-based-mysql-style}"),
                ("flag_login2", "FLAG{login2-json-boolean-blind}"),
                ("flag_login3", "FLAG{login3-csrf-protected-form}"),
                ("flag_login4", "FLAG{login4-cookie-time-based}"),
                ("flag_login5", "FLAG{login5-get-param-easy}"),
            ],
        )
    conn.commit()
    conn.close()


def _db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def _close_db(_exc: Any) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------------------------------------------------------------------------
# Request logger
# ---------------------------------------------------------------------------

def _log_request(extra: dict[str, Any] | None = None) -> None:
    entry = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "req_id": getattr(g, "req_id", None),
        "method": request.method,
        "path": request.path,
        "query": request.query_string.decode("latin-1", errors="replace"),
        "remote": request.remote_addr,
        "ua": request.headers.get("User-Agent", ""),
        "content_type": request.headers.get("Content-Type", ""),
        "cookies": dict(request.cookies),
        "headers": {k: v for k, v in request.headers.items() if k.lower() not in {"cookie"}},
        "body": _safe_body(),
    }
    if extra:
        entry.update(extra)
    try:
        with LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as exc:
        app.logger.warning("failed to log request: %s", exc)


def _safe_body() -> str:
    raw = getattr(g, "raw_body", None)
    if raw is None:
        try:
            raw = request.get_data(cache=True, as_text=True)
        except Exception:
            return "<unreadable>"
    if len(raw) > 8192:
        return raw[:8192] + "...[TRUNCATED]"
    return raw


@app.before_request
def _before() -> None:
    g.req_id = uuid.uuid4().hex[:12]
    g.t0 = time.monotonic()
    try:
        g.raw_body = request.get_data(cache=True, as_text=True)
    except Exception:
        g.raw_body = ""


@app.after_request
def _after(response: Response) -> Response:
    _log_request(
        {
            "status": response.status_code,
            "latency_ms": round((time.monotonic() - g.t0) * 1000, 1),
        }
    )
    response.headers["X-Req-Id"] = g.req_id
    return response


# ---------------------------------------------------------------------------
# Vulnerable SQL helper. Uses SQLite (real SQL engine) with string
# concatenation — this is what gives sqlmap something real to detect.
# We translate SLEEP(n) and pg_sleep(n) into wall-clock delays so the
# time-based variant is detectable too.
# ---------------------------------------------------------------------------

_SLEEP_RE = re.compile(r"(?:SLEEP|pg_sleep|WAITFOR\s+DELAY)[^)]*?(\d+)", re.IGNORECASE)


def _emulate_sleep(payload: str) -> None:
    m = _SLEEP_RE.search(payload)
    if not m:
        return
    try:
        secs = float(m.group(1))
    except ValueError:
        return
    time.sleep(min(secs, 15.0))


def vulnerable_query(query: str, dialect: str = "mysql") -> tuple[list[dict[str, Any]] | None, str | None]:
    """
    Run `query` against SQLite. Returns (rows, error_message).
    `dialect` controls how errors are formatted — we emit messages that
    look like the requested DBMS so sqlmap fingerprints it correctly.
    """
    _emulate_sleep(query)
    conn = _db()
    try:
        cur = conn.execute(query)
        rows = [dict(r) for r in cur.fetchall()]
        return rows, None
    except sqlite3.Error as exc:
        msg = str(exc)
        if dialect == "mysql":
            msg = (
                "You have an error in your SQL syntax; check the manual that "
                "corresponds to your MySQL server version for the right syntax "
                "to use near '" + msg + "' at line 1"
            )
        elif dialect == "postgres":
            msg = (
                "ERROR:  syntax error at or near \"'\"\nLINE 1: " + msg +
                "\nHINT:  PostgreSQL 14.2 - consult documentation."
            )
        elif dialect == "mssql":
            msg = (
                "Msg 102, Level 15, State 1, Line 1\nIncorrect syntax near '" +
                msg + "'."
            )
        return None, msg


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

INDEX_HTML = """
<!doctype html>
<html><head><title>xalgorix testbench</title></head>
<body style="font-family:sans-serif;max-width:720px;margin:2rem auto">
<h1>Xalgorix Tool-Invocation Testbench</h1>
<p>Five deliberately-vulnerable login endpoints and five inert pages.</p>
<h2>Login forms</h2>
<ul>
<li><a href="/login1">/login1</a> — POST form-urlencoded, MySQL error-based</li>
<li><a href="/login2">/login2</a> — POST JSON, MySQL boolean-blind</li>
<li><a href="/login3">/login3</a> — POST form-urlencoded with CSRF token</li>
<li><a href="/login4">/login4</a> — SQLi in <code>session_hint</code> cookie, PostgreSQL time-based</li>
<li><a href="/login5?user=admin&amp;pass=x">/login5</a> — GET params, easy case</li>
</ul>
<h2>Inert pages</h2>
<ul>
<li><a href="/about">/about</a></li>
<li><a href="/contact">/contact</a></li>
<li><a href="/faq">/faq</a></li>
<li><a href="/legal">/legal</a></li>
<li><a href="/pricing">/pricing</a></li>
</ul>
</body></html>
"""


@app.route("/")
def index() -> Response:
    return Response(INDEX_HTML, mimetype="text/html")


# --- login1: form-urlencoded, MySQL-style errors, error-based SQLi ---------

LOGIN1_HTML = """
<!doctype html><html><body style="font-family:sans-serif">
<h2>Login 1 (form-urlencoded)</h2>
<form method="POST" action="/login1">
  <label>Username <input name="username"></label><br>
  <label>Password <input name="password" type="password"></label><br>
  <button type="submit">Sign in</button>
</form>
</body></html>
"""


@app.route("/login1", methods=["GET", "POST"])
def login1() -> Response:
    if request.method == "GET":
        return Response(LOGIN1_HTML, mimetype="text/html")
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    query = (
        f"SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    rows, err = vulnerable_query(query, dialect="mysql")
    if err:
        return Response(f"<pre>{err}</pre>", status=500, mimetype="text/html")
    if rows:
        return Response(
            f"<h2>Welcome, {rows[0]['username']}</h2>", mimetype="text/html"
        )
    return Response("Invalid credentials", status=401, mimetype="text/html")


# --- login2: POST JSON, MySQL, boolean-blind --------------------------------

@app.route("/login2", methods=["GET", "POST"])
def login2() -> Response:
    if request.method == "GET":
        doc = {
            "endpoint": "/login2",
            "method": "POST",
            "content_type": "application/json",
            "body_example": {"username": "admin", "password": "..."},
        }
        return jsonify(doc)
    try:
        payload = request.get_json(force=True, silent=False) or {}
    except Exception:
        return jsonify({"ok": False, "error": "invalid_json"}), 400
    username = str(payload.get("username", ""))
    password = str(payload.get("password", ""))
    query = (
        f"SELECT id, username FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    rows, err = vulnerable_query(query, dialect="mysql")
    if err:
        # Boolean-blind: return generic error without details.
        return jsonify({"ok": False}), 200
    return jsonify({"ok": bool(rows)}), 200


# --- login3: CSRF-protected POST form ---------------------------------------

LOGIN3_HTML = """
<!doctype html><html><body style="font-family:sans-serif">
<h2>Login 3 (CSRF-protected)</h2>
<form method="POST" action="/login3">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <label>Username <input name="username"></label><br>
  <label>Password <input name="password" type="password"></label><br>
  <button type="submit">Sign in</button>
</form>
<p>CSRF token: <code>{csrf}</code></p>
</body></html>
"""


@app.route("/login3", methods=["GET", "POST"])
def login3() -> Response:
    if request.method == "GET":
        token = secrets.token_hex(16)
        session["csrf_token"] = token
        return Response(
            LOGIN3_HTML.format(csrf=token), mimetype="text/html"
        )
    submitted = request.form.get("csrf_token", "")
    expected = session.get("csrf_token")
    if not expected or submitted != expected:
        return Response("csrf_invalid", status=403, mimetype="text/plain")
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    query = (
        f"SELECT id, username FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    rows, err = vulnerable_query(query, dialect="mysql")
    if err:
        return Response(f"<pre>{err}</pre>", status=500, mimetype="text/html")
    if rows:
        return Response("ok", mimetype="text/plain")
    return Response("bad", status=401, mimetype="text/plain")


# --- login4: SQLi in cookie, PostgreSQL time-based --------------------------

LOGIN4_HTML = """
<!doctype html><html><body style="font-family:sans-serif">
<h2>Login 4 (cookie-based)</h2>
<p>This form seeds a <code>session_hint</code> cookie on GET. The backend
uses that cookie as part of a pre-login lookup query. SQLi lives in the
cookie, not in the body.</p>
<form method="POST" action="/login4">
  <label>Username <input name="username"></label><br>
  <label>Password <input name="password" type="password"></label><br>
  <button type="submit">Sign in</button>
</form>
</body></html>
"""


@app.route("/login4", methods=["GET", "POST"])
def login4() -> Response:
    if request.method == "GET":
        resp = make_response(Response(LOGIN4_HTML, mimetype="text/html"))
        if "session_hint" not in request.cookies:
            resp.set_cookie("session_hint", "guest", httponly=False)
        return resp
    hint = request.cookies.get("session_hint", "guest")
    query = f"SELECT role FROM users WHERE username = '{hint}'"
    _, err = vulnerable_query(query, dialect="postgres")
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    auth_query = (
        f"SELECT id FROM users WHERE username = '{username}' "
        f"AND password = '{password}'"
    )
    rows, auth_err = vulnerable_query(auth_query, dialect="postgres")
    if err:
        return Response(f"<pre>{err}</pre>", status=500, mimetype="text/html")
    if auth_err:
        return Response(f"<pre>{auth_err}</pre>", status=500, mimetype="text/html")
    if rows:
        return Response("ok", mimetype="text/plain")
    return Response("bad", status=401, mimetype="text/plain")


# --- login5: GET params, MySQL error-based (easy sanity-check) --------------

@app.route("/login5", methods=["GET"])
def login5() -> Response:
    username = request.args.get("user", "")
    password = request.args.get("pass", "")
    query = (
        f"SELECT id, username FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    rows, err = vulnerable_query(query, dialect="mysql")
    if err:
        return Response(f"<pre>{err}</pre>", status=500, mimetype="text/html")
    if rows:
        return jsonify({"ok": True, "user": rows[0]["username"]})
    return jsonify({"ok": False}), 401


# --- 5 inert static pages ---------------------------------------------------

INERT_BODY = """
<!doctype html><html><body style="font-family:sans-serif;max-width:640px;margin:2rem auto">
<h2>{title}</h2>
<p>{body}</p>
<p>This page has no parameters, no forms, no SQL. It exists only to measure
whether the agent wastes sqlmap/ffuf runs on obviously-inert content.</p>
<p><a href="/">Home</a></p>
</body></html>
"""

INERT_PAGES = {
    "about": ("About", "Xalgorix testbench — internal fixture, v1."),
    "contact": ("Contact", "Email us at contact@testbench.local."),
    "faq": ("FAQ", "Q: Is this safe? A: Only inside Docker. Never expose."),
    "legal": ("Legal", "All rights reserved. Do not redistribute."),
    "pricing": ("Pricing", "This fixture is free and worth every penny."),
}


@app.route("/<page>")
def inert(page: str) -> Response:
    if page not in INERT_PAGES:
        return Response("not found", status=404)
    title, body = INERT_PAGES[page]
    return Response(INERT_BODY.format(title=title, body=body), mimetype="text/html")


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

with app.app_context():
    _init_db()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, threaded=True)
