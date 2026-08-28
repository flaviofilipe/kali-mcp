"""
Kali Security Bridge — MCP Server

Exposes offensive security tools executed inside the kali-mcp-box container
via Docker exec. All commands are passed as a list of strings: Docker uses
execve() directly, without /bin/sh, so shell metacharacters (;, &&, |, $(...))
are harmless on the host.

This file is a thin entrypoint: it owns nothing but process startup. The
FastMCP app itself lives in core.config (`mcp`), the security/persistence
primitives live in core/, and every tool is defined in tools/*.py — importing
those modules below is what registers them against the app via `@mcp.tool()`.

See core/config.py for the full module map and CONTRIBUTING.md for where to
add a new tool.

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

import logging
import os

from core.config import mcp

# ── Tool registration ────────────────────────────────────────────────────────
# Each import below has the side effect of registering its @mcp.tool()
# functions against the shared `mcp` app defined in core.config. Order
# doesn't matter for registration, but tools.governance imports from
# tools.web (run_full_pentest calls scan_xmlrpc_wordpress), so web is
# imported first for clarity.

import tools.credentials    # noqa: F401,E402
import tools.recon          # noqa: F401,E402
import tools.web            # noqa: F401,E402
import tools.exploitation   # noqa: F401,E402
import tools.sessions       # noqa: F401,E402
import tools.governance     # noqa: F401,E402

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
