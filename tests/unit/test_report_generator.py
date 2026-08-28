"""Unit tests for reports.generator — pure formatting logic, no I/O."""

from __future__ import annotations

import json

from reports.generator import build_report, rows_to_findings, safe_filename

_ROWS = [
    ("nmap", "10.0.0.5", "2026-01-01T00:00:00", 0, 1, "22/tcp open ssh", None),
    ("nikto", "10.0.0.5", "2026-01-01T00:01:00", 1, 0, "", "connection refused"),
]


def test_rows_to_findings_shape():
    findings = rows_to_findings(_ROWS)
    assert len(findings) == 2
    assert findings[0]["tool"] == "nmap"
    assert findings[0]["success"] is True
    assert findings[1]["success"] is False
    assert findings[1]["error"] == "connection refused"


def test_safe_filename_strips_special_chars():
    assert safe_filename("http://10.0.0.5:8080/") == "http___10_0_0_5_8080_"


def test_build_report_markdown_contains_expected_sections():
    content, ext = build_report("10.0.0.5", _ROWS, "markdown")
    assert ext == "md"
    assert "# Security Report" in content
    assert "## Scope Tested" in content
    assert "## Findings by Tool" in content
    assert "## Execution Summary" in content
    assert "NMAP" in content
    assert "connection refused" in content


def test_build_report_json_round_trips():
    content, ext = build_report("10.0.0.5", _ROWS, "json")
    assert ext == "json"
    parsed = json.loads(content)
    assert parsed["target"] == "10.0.0.5"
    assert len(parsed["findings"]) == 2


def test_build_report_defaults_to_markdown_for_unknown_format():
    content, ext = build_report("10.0.0.5", _ROWS, "yaml")
    assert ext == "md"


def test_build_report_truncates_long_output():
    long_output = "A" * 6000
    rows = [("nmap", "10.0.0.5", "2026-01-01T00:00:00", 0, 1, long_output, None)]
    content, _ = build_report("10.0.0.5", rows, "markdown")
    assert "truncated" in content
    assert len(content) < len(long_output) + 2000
