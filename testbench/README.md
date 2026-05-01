# Xalgorix tool-invocation testbench

A small, deliberately vulnerable Flask app used to measure how reliably
`xalgorix` drives external pentesting tools (sqlmap, ffuf, nuclei) at
login forms.

## Layout

- `app/` — Flask application with 5 vulnerable login endpoints + 5 inert pages.
- `docker-compose.yml` — one container, listens on `127.0.0.1:8088`.
- `logs/` — request log written by the app (mounted from the container).
- `analyze/extract_commands.py` — parses `~/xalgorix-data/<target>/.../scan.json`
  and produces a classification report at `REPORT.md`.
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

## Usage

```bash
# From the xalgorix/ directory:
make bench-up         # docker compose up -d --build
make bench-logs       # tail the request log
make bench-down       # docker compose down (preserves logs)
make bench-clean      # wipe logs

# Run a scan:
xalgorix --target http://127.0.0.1:8088

# After scans, classify what sqlmap/ffuf/nuclei commands were issued:
make bench-report     # writes testbench/REPORT.md
```

## Fixes applied on top of the baseline

The testbench was built to measure four specific reliability problems in
xalgorix's tool invocation. Each fix is independent and ships behind the
same binary — no feature flags required.

1. **sqlmap recipe card** added to Phase 6C of the agent system prompt
   (`internal/agent/agent.go`) — four concrete copy-paste commands for
   form-urlencoded / JSON / CSRF / cookie logins, plus an explicit
   invented-flag blacklist (`--json`, `--auto`, `--full`, ...).
2. **`sqlmap_scan` structured tool** (`internal/tools/sqlmaptool/`) —
   one of five recipes (`get|form|json|csrf|cookie`) is selected via
   parameters; the tool builds the sqlmap command itself, always sets
   `--batch --random-agent --flush-session --output-dir=...` and fails
   fast on invalid arguments. Failures are now counted per-tool instead
   of against the shared `terminal_execute` circuit breaker.
3. **Package map sync** (`internal/tools/terminal/terminal.go`) — added
   `wpscan`, `joomscan`, `nikto`, `whatweb`, `wafw00f`, `testssl`,
   `sslyze`, `dirsearch`, `arjun`, `theharvester`, `hydra`, `hashid`,
   `hashcat` so they auto-install instead of returning exit 127 and
   tripping the circuit breaker.
4. **Point-MCP adapter** (`internal/tools/mcp/`) — opt-in via
   `XALGORIX_MCP_SERVERS="name=cmd args;..."`. Each configured MCP
   stdio server contributes its tools as `mcp_<server>_<tool>` without
   rewriting the existing `tools.Registry`. Nothing happens unless the
   env variable is set.

## Verifying the structured tool end-to-end

Once xalgorix is rebuilt (` + "`" + `make build` + "`" + `), a scan that calls
` + "`" + `sqlmap_scan` + "`" + ` on the testbench should show canonical, reproducible
commands in ` + "`" + `logs/requests.log` + "`" + `:

- ` + "`" + `POST /login1` + "`" + ` with ` + "`" + `Content-Type: application/x-www-form-urlencoded` + "`" + `
  and sqlmap-generated payloads in both ` + "`" + `username` + "`" + ` and ` + "`" + `password` + "`" + `.
- ` + "`" + `POST /login2` + "`" + ` with ` + "`" + `Content-Type: application/json` + "`" + ` and payloads
  inside JSON strings.
- ` + "`" + `GET /login3 → POST /login3` + "`" + ` pairs where sqlmap scrapes a fresh
  ` + "`" + `csrf_token` + "`" + ` on every probe.
- ` + "`" + `POST /login4` + "`" + ` where the ` + "`" + `session_hint` + "`" + ` cookie value cycles
  through sqlmap probes and the server sleeps on ` + "`" + `pg_sleep` + "`" + `.
- ` + "`" + `GET /login5?user=...&pass=...` + "`" + ` — easy sanity check.

` + "`" + `testbench/analyze/extract_commands.py` + "`" + ` turns all of that into a
classification table.

## Safety

The app uses string-concatenated SQL against a local SQLite database and
returns fake MySQL/PostgreSQL/MSSQL error messages so sqlmap fingerprints
it correctly. Never expose to anything other than `127.0.0.1`.
