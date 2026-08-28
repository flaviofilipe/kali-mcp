"""
Governance and orchestration tools: allowlist management, target liveness,
session resumption, finding queries, report generation, and the autonomous
full-pentest pipeline.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from core.config import STEALTH_UA, WORKSPACE_DIR, mcp
from core.db import allowlist_add, allowlist_list, allowlist_remove, query_findings, query_findings_full, target_output_dir
from core.docker_exec import exec_in_kali
from core.security import issue_confirmation_token
from tools.web import scan_xmlrpc_wordpress

# ── Allowlist ────────────────────────────────────────────────────────────────


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
    from core.audit import audit

    if action == "add":
        if not entry:
            return {"success": False, "error": "entry is required for action='add'"}
        allowlist_add(entry, note)
        audit.info("ALLOWLIST ADD | entry=%s note=%s", entry, note)
        return {"success": True, "action": "add", "entry": entry}

    if action == "remove":
        if not entry:
            return {"success": False, "error": "entry is required for action='remove'"}
        allowlist_remove(entry)
        audit.info("ALLOWLIST REMOVE | entry=%s", entry)
        return {"success": True, "action": "remove", "entry": entry}

    if action == "list":
        rows = allowlist_list()
        return {
            "success": True,
            "allowlist": [{"entry": r[0], "added": r[1], "note": r[2]} for r in rows],
            "total": len(rows),
        }

    return {"success": False, "error": f"invalid action: '{action}'. Use 'add', 'remove', or 'list'"}


@mcp.tool()
def request_high_risk_action(action: str, target: str, justification: str) -> dict[str, Any]:
    """
    Issues a short-lived (10 minute), single-use confirmation token required
    before running a high-risk action: credential dumping (impacket_secretsdump),
    lateral movement (impacket_psexec), Mimikatz, netexec in a write/exec mode,
    or opening a pivot tunnel (start_chisel_tunnel, start_ligolo_tunnel).

    The token is bound to the exact (action, target) pair passed here — it
    cannot be reused for a different action or target, and it is consumed on
    first use. The justification is written to the audit log.

    Args:
        action:        Name of the gated tool/action you're about to run.
                       E.g.: "impacket_secretsdump", "run_mimikatz"
        target:        Target the action will run against.
        justification: Why this is authorized. E.g.: "Domain Admin creds needed
                       to validate lateral movement per engagement scope §3.2"
    """
    from core.audit import audit

    if not action or not target or not justification:
        return {"success": False, "error": "action, target, and justification are all required."}

    token_info = issue_confirmation_token(action, target, justification)
    audit.info(
        "HIGH_RISK_CONFIRMATION_ISSUED | action=%s target=%s justification=%s expires_at=%s",
        action, target, justification, token_info["expires_at"],
    )
    return {
        "success": True,
        **token_info,
        "note": "Pass this token as confirmation_token= to the gated tool within 10 minutes. Single use.",
    }


@mcp.tool()
def check_target_online(target: str) -> dict[str, Any]:
    """
    Checks whether the target responds to ping before starting any scan.
    Use this as the first check to avoid unnecessary scans.

    Args:
        target: IP or hostname. E.g.: "192.168.1.10", "app.example.com"
    """
    cmd = ["ping", "-c", "3", "-W", "2", target]
    return exec_in_kali(cmd, tool_name="ping", target=target).model_dump()


@mcp.tool()
def resume_session(target: str) -> dict[str, Any]:
    """
    Lists all scans saved to disk for a target, allowing you to resume an
    interrupted pentest without losing previous progress.

    Outputs are automatically saved to ~/mcps/outputs/kali-mcp/<target>/ on every scan.

    Args:
        target: Domain or IP of the target. E.g.: "example.com", "192.168.1.10"
    """
    out_dir = target_output_dir(target)
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
    rows = query_findings(target, limit)
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
    rows = query_findings_full(target)

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


# ── Orchestration ────────────────────────────────────────────────────────────


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
    _gb_ua       = ["-a", STEALTH_UA] if evasion else []
    _nmap_delay  = ["--scan-delay", "1s", "-T2"] if evasion else []
    _nuclei_rate = "10" if evasion else "20"
    _katana_rate = ["-rate-limit", "5"] if evasion else []

    # ── 1. Ping ──
    ping = exec_in_kali(["ping", "-c", "3", "-W", "2", target], "ping", target)
    results["phases"]["ping"] = ping.model_dump()
    if not ping.success:
        results["warnings"].append("Target did not respond to ping — it may be offline or blocking ICMP. Continuing anyway.")

    # ── 2. Nmap ──
    nmap = exec_in_kali(
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
        sub = exec_in_kali(["subfinder", "-d", target, "-silent"], "subfinder", target)
        results["phases"]["subfinder"] = sub.model_dump()

    # ── Web phases (only if a URL is available) ──
    if target_url:
        is_https = target_url.startswith("https")

        # ── 4. Gobuster ──
        gobuster = exec_in_kali(
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
        exposed = exec_in_kali(
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
        nikto = exec_in_kali(
            ["nikto", "-h", target_url, "-nointeractive", "-maxtime", "120s"],
            "nikto", target_url,
        )
        results["phases"]["nikto"] = nikto.model_dump()

        # ── 7. Security headers ──
        headers_cmd = ["curl", "-s", "-I", "-L", "--max-time", "10", target_url]
        headers_raw = exec_in_kali(headers_cmd, "curl", target_url)
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
            "-H", f"User-Agent: {STEALTH_UA}",
        ]
        if is_wordpress:
            nuclei_cmd += ["-tags", "wordpress"]
        nuclei = exec_in_kali(nuclei_cmd, "nuclei", target_url)
        results["phases"]["nuclei"] = nuclei.model_dump()

        # ── 9. WPScan (only if WordPress detected) ──
        if is_wordpress:
            wpscan = exec_in_kali(
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
            xmlrpc_check = exec_in_kali(
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
            testssl = exec_in_kali(
                ["testssl.sh", "--quiet", "--color", "0", "--fast", host_port],
                "testssl", target,
            )
            results["phases"]["testssl"] = testssl.model_dump()

        # ── 12. Katana (crawling with XHR) ──
        katana = exec_in_kali(
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

            dalfox = exec_in_kali(
                ["dalfox", "url", test_url, "--no-color", "--silence", "--timeout", "30", "--worker", "10"],
                "dalfox", test_url,
            )
            results["phases"]["dalfox"] = dalfox.model_dump()

            sqlmap = exec_in_kali(
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
            hydra_ssh = exec_in_kali(
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
            hydra_ftp = exec_in_kali(
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
