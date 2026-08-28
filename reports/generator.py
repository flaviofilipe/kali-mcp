"""
Report content generation: turns a list of finding rows into Markdown or
JSON report text. Pure formatting logic, no I/O and no MCP/Docker
dependencies — kept separate from tools/governance.py so it's trivially
unit-testable and reusable (e.g. by a future export tool).
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any


def rows_to_findings(rows: list[tuple]) -> list[dict[str, Any]]:
    """Converts core.db.query_findings_full() rows into the dict shape used below."""
    return [
        {
            "tool": r[0], "target": r[1], "timestamp": r[2],
            "exit_code": r[3], "success": bool(r[4]), "output": r[5], "error": r[6],
        }
        for r in rows
    ]


def safe_filename(target: str) -> str:
    return target.replace("/", "_").replace(":", "_").replace(".", "_")


def build_json_report(target: str, findings: list[dict[str, Any]], generated_at: datetime) -> str:
    return json.dumps(
        {"target": target, "generated": generated_at.isoformat(), "findings": findings},
        indent=2, ensure_ascii=False,
    )


def build_markdown_report(target: str, findings: list[dict[str, Any]], generated_at: datetime) -> str:
    tools_used = sorted({f["tool"] for f in findings})
    total      = len(findings)
    success    = sum(1 for f in findings if f["success"])

    lines = [
        f"# Security Report — {target} — {generated_at.strftime('%Y-%m-%d %H:%M')}",
        "",
        "## Scope Tested",
        f"- **Target:** `{target}`",
        f"- **Tools executed:** {', '.join(tools_used)}",
        f"- **Total scans:** {total}  |  **Successful:** {success}  |  **Failed:** {total - success}",
        f"- **Generated at:** {generated_at.isoformat()}",
        "",
        "---",
        "",
        "## Findings by Tool",
        "",
    ]
    for f in findings:
        status = "OK" if f["success"] else "FAILED"
        lines += [
            f"### [{status}] {f['tool'].upper()} — {f['timestamp']}",
            f"**Target:** `{f['target']}`  |  **Exit code:** `{f['exit_code']}`",
            "",
        ]
        if f["error"]:
            lines += [f"> **Error:** {f['error']}", ""]
        if f["output"]:
            preview   = f["output"][:5000]
            truncated = " *(truncated — see the full file)*" if len(f["output"]) > 5000 else ""
            lines += [f"```\n{preview}\n```{truncated}", ""]
        lines += ["---", ""]

    lines += [
        "## Execution Summary",
        "| Tool | Status | Timestamp |",
        "|---|---|---|",
    ]
    for f in findings:
        lines.append(f"| {f['tool']} | {'✓' if f['success'] else '✗'} | {f['timestamp']} |")

    return "\n".join(lines)


def build_report(target: str, rows: list[tuple], output_format: str = "markdown") -> tuple[str, str]:
    """
    Builds report content from raw finding rows.

    Returns (content, file_extension) — extension is "json" or "md".
    """
    findings     = rows_to_findings(rows)
    generated_at = datetime.now()

    if output_format == "json":
        return build_json_report(target, findings, generated_at), "json"
    return build_markdown_report(target, findings, generated_at), "md"
