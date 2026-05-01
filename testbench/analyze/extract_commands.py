#!/usr/bin/env python3
"""
Classify terminal_execute commands recorded by xalgorix against the
testbench, and write a human-readable REPORT.md.

Usage:
    python3 extract_commands.py [SCAN_DIR]

SCAN_DIR defaults to ~/xalgorix-data. The script walks the directory
looking for scan.json files, pulls every terminal_execute call issued by
the agent, classifies sqlmap/ffuf/nuclei invocations, and emits a
markdown table keyed by login endpoint.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


LOGIN_ENDPOINTS = ["/login1", "/login2", "/login3", "/login4", "/login5"]
INERT_ENDPOINTS = ["/about", "/contact", "/faq", "/legal", "/pricing"]

KNOWN_SQLMAP_FLAGS = {
    "-u", "--url", "-r", "-p", "-d", "--data", "--method", "--cookie",
    "--cookies", "--headers", "--header", "-H", "--user-agent", "-A",
    "--random-agent", "--batch", "--flush-session", "--purge",
    "--purge-output", "--level", "--risk", "--technique", "--dbms", "--os",
    "--threads", "--forms", "--crawl", "--csrf-token", "--csrf-url",
    "--csrf-method", "--csrf-data", "--proxy", "--proxy-cred",
    "--auth-type", "--auth-cred", "--auth-file", "--ignore-code",
    "--safe-url", "--safe-post", "--safe-req", "--output-dir", "--dbs",
    "--tables", "--columns", "--dump", "--dump-all", "--schema", "--count",
    "--search", "--current-user", "--current-db", "--hostname", "--users",
    "--passwords", "--privileges", "--roles", "-v", "--verbose",
    "--timeout", "--retries", "--delay", "--time-sec", "--union-cols",
    "--union-char", "--union-from", "--second-url", "--second-req",
    "--os-shell", "--os-cmd", "--sql-query", "--sql-shell", "--file-read",
    "--file-write", "--file-dest", "--tamper", "--eval", "--parse-errors",
    "--keep-alive", "--null-connection", "--skip", "--skip-static",
    "--mobile", "-s", "-l", "-t", "--string", "--not-string",
    "--code", "--text-only", "--titles", "--smart", "--test-filter",
    "--test-skip", "--start", "--stop", "--prefix", "--suffix",
    "--identify-waf", "--skip-waf", "--hex", "--force-ssl", "--data-string",
}


def iter_scan_files(root: Path) -> Iterable[Path]:
    if not root.exists():
        return
    for p in root.rglob("scan.json"):
        if p.is_file():
            yield p


def load_scan(path: Path) -> list[dict[str, Any]]:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    # scan.json may be either a list or a JSON-lines event stream — handle both.
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            if "events" in data and isinstance(data["events"], list):
                return data["events"]
            return [data]
    except json.JSONDecodeError:
        pass
    events = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def extract_terminal_calls(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    xalgorix persists events as WSEvent objects (see internal/web/server.go).
    Tool calls and results are separate events sharing the same tool_name;
    in the result event the stdout/stderr are flattened to top-level `output`
    and `error` fields.
    """
    calls: list[dict[str, Any]] = []
    pending: dict[str, Any] | None = None
    for evt in events:
        if not isinstance(evt, dict):
            continue
        etype = evt.get("type") or evt.get("Type")
        tool = evt.get("tool_name") or evt.get("ToolName") or evt.get("tool")
        if etype == "tool_call" and tool == "terminal_execute":
            args = evt.get("tool_args") or evt.get("ToolArgs") or {}
            pending = {
                "command": args.get("command", ""),
                "ts": evt.get("timestamp") or evt.get("Timestamp"),
                "result": None,
            }
            calls.append(pending)
        elif etype == "tool_result" and tool == "terminal_execute" and pending is not None:
            output = evt.get("output") or evt.get("Output") or ""
            error = evt.get("error") or evt.get("Error") or ""
            pending["result"] = {
                "output": output[:4096] if isinstance(output, str) else "",
                "error": error if isinstance(error, str) else "",
            }
            pending = None
    return calls


def which_tool(cmd: str) -> str | None:
    stripped = cmd.lstrip()
    for tool in ("sqlmap", "ffuf", "nuclei", "gobuster", "dalfox", "nmap", "curl"):
        if stripped.startswith(tool + " ") or stripped == tool:
            return tool
        if (
            f"\n{tool} " in stripped
            or f"; {tool} " in stripped
            or f"&& {tool} " in stripped
            or f"| {tool} " in stripped
        ):
            return tool
    return None


def which_endpoint(cmd: str) -> str | None:
    for ep in LOGIN_ENDPOINTS + INERT_ENDPOINTS:
        if ep in cmd:
            return ep
    return None


def classify_sqlmap(cmd: str, result: dict[str, Any] | None) -> list[str]:
    tags: list[str] = []
    tokens = re.findall(r"-{1,2}[a-zA-Z][a-zA-Z0-9-]*", cmd)
    for tok in tokens:
        if tok not in KNOWN_SQLMAP_FLAGS:
            tags.append(f"invented_flag:{tok}")
    if "sqlmap" in cmd and "--batch" not in cmd:
        tags.append("missing_--batch")
    uses_url = "-u " in cmd or "--url " in cmd or "--url=" in cmd
    uses_req = "-r " in cmd or "--request-file" in cmd
    uses_data = "--data" in cmd
    method_is_post = "--method=POST" in cmd or "--method POST" in cmd
    if "/login1" in cmd and not (uses_req or (uses_url and (uses_data or method_is_post))):
        tags.append("login1_missing_post_body")
    if "/login2" in cmd and not uses_data:
        tags.append("login2_missing_json_data")
    if "/login3" in cmd and "--csrf-token" not in cmd:
        tags.append("login3_missing_csrf")
    if "/login4" in cmd and "--cookie" not in cmd:
        tags.append("login4_missing_cookie")
    if result:
        out = (result.get("output") or "").lower()
        if "command not found" in out or "not found in" in out:
            tags.append("tool_not_installed")
        if "[timeout]" in out:
            tags.append("timeout")
        if "circuit breaker open" in out:
            tags.append("circuit_breaker_blocked")
        if "you need to specify the target" in out or "critical" in out and "sqlmap" in out:
            tags.append("sqlmap_usage_error")
    return tags


def aggregate(scan_dir: Path) -> dict[str, Any]:
    all_calls: list[dict[str, Any]] = []
    for scan_path in iter_scan_files(scan_dir):
        events = load_scan(scan_path)
        calls = extract_terminal_calls(events)
        for c in calls:
            c["scan"] = str(scan_path)
        all_calls.extend(calls)

    by_endpoint: dict[str, list[dict[str, Any]]] = defaultdict(list)
    per_tool_counts: Counter[str] = Counter()
    sqlmap_tag_counts: Counter[str] = Counter()
    for call in all_calls:
        cmd = call["command"]
        tool = which_tool(cmd)
        if tool:
            per_tool_counts[tool] += 1
        ep = which_endpoint(cmd)
        if ep:
            by_endpoint[ep].append(call)
        if tool == "sqlmap":
            tags = classify_sqlmap(cmd, call.get("result"))
            call["tags"] = tags
            for t in tags:
                sqlmap_tag_counts[t] += 1

    return {
        "total_calls": len(all_calls),
        "per_tool": dict(per_tool_counts),
        "by_endpoint": by_endpoint,
        "sqlmap_tags": dict(sqlmap_tag_counts),
    }


def render_report(data: dict[str, Any]) -> str:
    out: list[str] = []
    out.append("# Xalgorix testbench — tool invocation report\n")
    out.append(f"Scans analysed: {data['total_calls']} terminal_execute calls.\n")
    out.append("## Tool usage\n")
    out.append("| Tool | Calls |")
    out.append("|------|------:|")
    for tool, n in sorted(data["per_tool"].items(), key=lambda kv: -kv[1]):
        out.append(f"| `{tool}` | {n} |")
    out.append("")
    out.append("## Login endpoint coverage\n")
    out.append("| Endpoint | sqlmap calls | ffuf calls | nuclei calls | curl calls | other |")
    out.append("|----------|-------------:|-----------:|-------------:|-----------:|------:|")
    for ep in LOGIN_ENDPOINTS:
        calls = data["by_endpoint"].get(ep, [])
        per = Counter(which_tool(c["command"]) for c in calls)
        out.append(
            f"| `{ep}` | {per.get('sqlmap', 0)} | {per.get('ffuf', 0)} "
            f"| {per.get('nuclei', 0)} | {per.get('curl', 0)} "
            f"| {sum(v for k, v in per.items() if k not in {'sqlmap','ffuf','nuclei','curl'})} |"
        )
    out.append("")
    out.append("## Inert-page waste\n")
    out.append("| Endpoint | Any tool calls (should be 0) |")
    out.append("|----------|-----------------------------:|")
    for ep in INERT_ENDPOINTS:
        calls = data["by_endpoint"].get(ep, [])
        out.append(f"| `{ep}` | {len(calls)} |")
    out.append("")
    out.append("## sqlmap failure tags\n")
    if not data["sqlmap_tags"]:
        out.append("_No sqlmap invocations recorded yet._")
    else:
        out.append("| Tag | Count |")
        out.append("|-----|------:|")
        for tag, n in sorted(data["sqlmap_tags"].items(), key=lambda kv: -kv[1]):
            out.append(f"| `{tag}` | {n} |")
    out.append("")
    out.append("## Decision rule (Stage 2 → Stage 3)\n")
    out.append(
        "After applying the Stage 2 prompt fix, rerun `make bench-report`. "
        "If sqlmap is invoked correctly on ≥ 4 of 5 login endpoints and the "
        "`invented_flag:*` / `missing_--batch` / `*_missing_*` tag counts drop "
        "to near zero, stop here. Otherwise proceed to Stage 3 and enable the "
        "structured `sqlmap_scan` tool."
    )
    return "\n".join(out) + "\n"


def main(argv: list[str]) -> int:
    scan_dir = Path(argv[1]) if len(argv) > 1 else Path.home() / "xalgorix-data"
    data = aggregate(scan_dir)
    sys.stdout.write(render_report(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
