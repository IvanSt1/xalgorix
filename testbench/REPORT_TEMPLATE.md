# Xalgorix testbench — tool invocation report (stub)

No scans have been recorded yet. Generate real data with:

```bash
make bench-up
xalgorix --target http://127.0.0.1:8088 \
         --instruction "Test each /loginN endpoint for SQL injection"
make bench-report
```

The generated `REPORT.md` will replace this file with a table classifying
every `terminal_execute` call the agent issued, grouped by login endpoint
and failure reason (invented flags, missing `--batch`, missing
`--data`/`-r`, missing cookie/CSRF, tool-not-installed, circuit-breaker
blocks, etc.).
