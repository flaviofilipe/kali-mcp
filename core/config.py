"""
Shared configuration: paths, environment variables, constants, and the
single FastMCP app instance every tool module registers against.

Every module under tools/ does `from core.config import mcp` and decorates
its functions with `@mcp.tool()`. server.py owns process startup
(`mcp.run(...)`) but never defines the app itself, which avoids a circular
import between server.py and tools/*.py.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastmcp import FastMCP

# ── Auth (AWS Cognito) ───────────────────────────────────────────────────────
# Only required in remote HTTP mode — local stdio use (Claude Code on this
# machine) stays login-free, since the OS itself already controls who can
# spawn the process.

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
        "Connects to a Kali Linux container and runs tools covering the full offensive security "
        "lifecycle: recon → enumeration → web analysis → exploitation → credential access → "
        "post-exploitation → report. "
        "REQUIRED: add the target to the allowlist before any scan. "
        "High-risk actions (credential dumping, lateral movement, pivoting) require a short-lived "
        "confirmation token from request_high_risk_action() first. "
        "Always follow this order: check_target_online → scan_ports_nmap → web tools → "
        "exploitation → generate_report."
    ),
    auth=_auth,
)

# ── Paths ─────────────────────────────────────────────────────────────────────

CONTAINER_NAME = "kali-mcp-box"
BASE_DIR       = Path.home() / ".kali-mcp"
WORKSPACE_DIR  = BASE_DIR / "workspaces"
DB_PATH        = BASE_DIR / "findings.db"
LOG_PATH       = BASE_DIR / "audit.log"
OUTPUTS_DIR    = Path.home() / "mcps/outputs/kali-mcp"
SECRET_KEY_PATH = BASE_DIR / "secret.key"

BASE_DIR.mkdir(parents=True, exist_ok=True)
WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

# ── Evasion headers ───────────────────────────────────────────────────────────
# Real browser User-Agent for WAF/IDS evasion.

STEALTH_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
STEALTH_HEADERS = [
    "-H", f"User-Agent: {STEALTH_UA}",
    "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "-H", "Accept-Language: en-US,en;q=0.9",
    "-H", "Accept-Encoding: gzip, deflate",
]

# ── Post-exploitation payload delivery ───────────────────────────────────────
# LinPEAS/WinPEAS (and, if staged, Mimikatz) are served to a compromised
# session over plain HTTP from this directory inside the container, started
# on demand by tools.post_exploitation. Kept as one shared directory so a
# single http.server process can serve all of them.
HTTP_SERVE_DIR  = "/opt/mcp-payloads"
HTTP_SERVE_PORT = 8421

# Mirrors the Dockerfile's --build-arg INCLUDE_OFFENSIVE_BINARIES=true. When
# the image was built without it, Mimikatz is not staged inside the
# container and run_mimikatz() must refuse to run.
MIMIKATZ_PATH = f"{HTTP_SERVE_DIR}/mimikatz.exe"

# ── High-risk confirmation gate ──────────────────────────────────────────────
CONFIRMATION_TTL_SECONDS = 10 * 60  # 10 minutes
