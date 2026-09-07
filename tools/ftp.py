"""
FTP enumeration: anonymous (or credentialed) login check plus a listing of
the server's root directory — one of the most common early recon steps
against beginner-tier lab targets.
"""

from __future__ import annotations

from typing import Any

from core.config import mcp
from core.docker_exec import exec_in_kali


@mcp.tool()
def enumerate_ftp(
    target: str,
    port: int = 21,
    username: str = "anonymous",
    password: str = "anonymous",
) -> dict[str, Any]:
    """
    Connects to FTP, reports whether login succeeded, and lists the root
    directory. Use when Nmap identifies an exposed port 21 — anonymous FTP
    access (the default credentials here) is one of the most common early
    findings on beginner-tier lab targets.

    Non-interactive (a single request/response), unlike connect_telnet() or
    evil_winrm_connect() — nothing to drive afterward with session_exec().

    Args:
        target:   IP or hostname of the FTP server. Must be in the allowlist.
        port:     FTP port. Default: 21
        username: Username. Default: "anonymous"
        password: Password. Default: "anonymous"
    """
    url = f"ftp://{target}:{port}/"
    cmd = [
        "curl", "-s",
        "--connect-timeout", "10",
        "--user", f"{username}:{password}",
        url,
    ]
    result = exec_in_kali(cmd, tool_name="ftp", target=target)
    out = result.model_dump()
    out["logged_in"] = result.success
    out["username"]  = username
    out["summary"] = (
        f"Logged in as {username}@{target}:{port}. 'output' holds the root directory listing."
        if result.success else
        f"Login failed for {username}@{target}:{port} (or connection error) — see 'error'/'output'."
    )
    return out
