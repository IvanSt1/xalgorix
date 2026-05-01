# Testbench — tool invocation report (stub)

No scans have been recorded yet. Generate real data with:

```bash
docker compose up -d --build
# point your scanner / agent at http://127.0.0.1:8088
python3 analyze/extract_commands.py /path/to/scan-output-dir > REPORT.md
```

The generated `REPORT.md` will replace this file with a table classifying
every tool call the agent issued, grouped by login endpoint and failure
reason (invented flags, missing `--batch`, missing `--data`/`-r`, missing
cookie/CSRF, tool-not-installed, circuit-breaker blocks, etc.).
