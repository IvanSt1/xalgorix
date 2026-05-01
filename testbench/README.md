# Tool-invocation testbench

A small, deliberately vulnerable Flask app used to measure how reliably an
external scanner / agent drives pentesting tools (sqlmap, ffuf, nuclei) at
login forms.

The testbench is fully self-contained: it runs in Docker and does not depend
on `make` or any parent project.

## Layout

- `app/` — Flask application with 5 vulnerable login endpoints + 5 inert pages.
- `docker-compose.yml` — one container, listens on `127.0.0.1:8088` by default.
- `logs/` — request log written by the app (mounted from the container).
- `analyze/extract_commands.py` — optional helper that parses scanner output
  (e.g. `~/xalgorix-data/<target>/.../scan.json`) into `REPORT.md`.
- `REPORT_TEMPLATE.md` — stub report used when no scans have been recorded yet.

## Endpoints

| Path       | Method | Shape                  | Vulnerability                |
|------------|--------|------------------------|------------------------------|
| `/login1`  | POST   | form-urlencoded        | MySQL, error-based           |
| `/login2`  | POST   | JSON                   | MySQL, boolean-blind         |
| `/login3`  | POST   | form-urlencoded + CSRF | MySQL (needs `--csrf-token`) |
| `/login4`  | POST   | cookie `session_hint`  | PostgreSQL, time-based       |
| `/login5`  | GET    | query string           | MySQL, error-based (easy)    |
| `/about`, `/contact`, `/faq`, `/legal`, `/pricing` | GET | static | — (negative control) |

The first four endpoints require different sqlmap invocations. The agent
must correctly pick `-r request.txt`, `--data`, `--cookie="...=*"`, or
`--csrf-token`/`--csrf-url` — this is the core thing the testbench
measures.

## Quick start

Requires only Docker (with the Compose plugin). Run from this directory:

```bash
# build & start in background
docker compose up -d --build

# tail the request log written by the app
tail -f logs/requests.log

# stop (preserves logs and DB volume)
docker compose down

# stop and wipe the database volume
docker compose down -v
```

The app will be available at <http://127.0.0.1:8088>. To change the host or
port, set environment variables before running compose:

```bash
TESTBENCH_HOST=0.0.0.0 TESTBENCH_PORT=9000 docker compose up -d --build
```

> Reminder: this app is intentionally vulnerable. Keep the bind address on
> `127.0.0.1` unless you fully trust the network.

## Running a scan against it

Point any scanner / agent at `http://127.0.0.1:8088`, e.g.:

```bash
sqlmap -u 'http://127.0.0.1:8088/login5?user=a&pass=a' --batch
```

After scans, optionally classify what commands were issued:

```bash
python3 analyze/extract_commands.py /path/to/scan-output-dir > REPORT.md
```

## Safety

The app uses string-concatenated SQL against a local SQLite database and
returns fake MySQL/PostgreSQL/MSSQL error messages so sqlmap fingerprints
it correctly. Never expose to anything other than `127.0.0.1`.
