"""
Session management: reverse shells, and any other interactive shell opened
against an authorized target (SSH, evil-winrm, msf), kept alive inside the
Kali container as a detached tmux session so a session survives across
multiple MCP tool calls.

Every function here re-validates the target against the allowlist on every
call — not just when the session was opened — per the hardening spec's
extended security model (a session or a pivot must not become a standing
bypass of the allowlist).
"""

from __future__ import annotations

import uuid
from typing import Any

from core.audit import audit
from core.config import mcp
from core.db import create_session, get_session, list_sessions as db_list_sessions, update_session_status
from core.docker_exec import exec_in_kali, get_container
from core.security import is_allowed

_VALID_SHELL_TYPES = {"bash", "sh", "powershell", "cmd"}


def _tmux_name(session_id: str) -> str:
    return f"mcp_{session_id}"


def open_tmux_session(session_type: str, target: str, host: str, port: int | None, command: list[str]) -> dict[str, Any]:
    """
    Shared helper: starts `command` detached inside a new tmux session and
    records it in core.db.sessions. Used by start_reverse_shell_listener()
    here and by evil_winrm_connect() in tools/active_directory.py.

    Revalidates the allowlist itself — callers must not skip that check.
    """
    if not is_allowed(target):
        return {
            "success": False,
            "error": f"Target '{target}' is not in the allowlist. Use manage_allowlist() first.",
        }

    session_id = uuid.uuid4().hex[:12]
    tmux_name  = _tmux_name(session_id)

    try:
        container = get_container()
    except RuntimeError as exc:
        return {"success": False, "error": str(exc)}

    exit_code, raw = container.exec_run(["tmux", "new-session", "-d", "-s", tmux_name] + command)
    if exit_code != 0:
        output = raw.decode("utf-8", errors="replace") if raw else ""
        return {"success": False, "error": f"Failed to start tmux session: {output}"}

    create_session(session_id, target, session_type, host=host, port=port, status="open")
    audit.info("SESSION_OPENED | id=%s type=%s target=%s", session_id, session_type, target)

    return {
        "success": True, "session_id": session_id, "target": target,
        "session_type": session_type, "status": "open",
    }


@mcp.tool()
def start_reverse_shell_listener(target: str, port: int, shell_type: str = "bash") -> dict[str, Any]:
    """
    Starts a netcat listener inside the Kali container to catch an incoming
    reverse shell from `target`, kept alive in a detached tmux session so
    session_exec() can drive it across multiple tool calls.

    You still need to trigger the reverse shell on the target yourself
    (e.g., via a web RCE PoC or a payload from metasploit_generate_payload)
    pointed at the container's reachable address and this port.

    Args:
        target:     The host expected to connect back. Must be in the allowlist.
        port:       Local port to listen on inside the container.
        shell_type: Cosmetic hint for the session record. "bash" | "sh" | "powershell" | "cmd"
    """
    if shell_type not in _VALID_SHELL_TYPES:
        return {"success": False, "error": f"Invalid shell_type '{shell_type}'. Valid: {sorted(_VALID_SHELL_TYPES)}"}

    return open_tmux_session(
        session_type="reverse_shell",
        target=target,
        host=target,
        port=port,
        command=["nc", "-lvnp", str(port)],
    )


@mcp.tool()
def connect_telnet(target: str, port: int = 23) -> dict[str, Any]:
    """
    Opens an interactive Telnet session, kept alive in a tmux session so
    session_exec() can drive it across multiple tool calls (login prompt,
    commands, etc.) — same pattern as evil_winrm_connect(). Use when Nmap
    identifies an exposed Telnet service (typically port 23).

    Args:
        target: IP or hostname of the Telnet service. Must be in the allowlist.
        port:   Telnet port. Default: 23
    """
    audit.info("TELNET_CONNECT | target=%s port=%d", target, port)
    return open_tmux_session(
        session_type="telnet", target=target, host=target, port=port,
        command=["telnet", target, str(port)],
    )


@mcp.tool()
def session_exec(session_id: str, command: str) -> dict[str, Any]:
    """
    Sends a command to an open session and returns the captured pane output.
    Re-validates the session's target against the allowlist before sending
    anything — a session on a target later removed from the allowlist stops
    accepting commands.

    Args:
        session_id: ID returned by start_reverse_shell_listener() or evil_winrm_connect().
        command:    Command line to send to the remote shell.
    """
    record = get_session(session_id)
    if record is None:
        return {"success": False, "error": f"No session with id '{session_id}'."}

    _, target, _session_type, _host, _port, status, _opened_at, _closed_at = record
    if status != "open":
        return {"success": False, "error": f"Session '{session_id}' is not open (status: {status})."}
    if not is_allowed(target):
        return {
            "success": False,
            "error": f"Target '{target}' for session '{session_id}' is no longer in the allowlist.",
        }

    tmux_name = _tmux_name(session_id)
    result = exec_in_kali(
        ["tmux", "send-keys", "-t", tmux_name, command, "Enter"],
        tool_name="session-exec", target=target,
    )
    if not result.success:
        return {"success": False, "error": result.error or "Failed to send command to session."}

    capture = exec_in_kali(
        ["tmux", "capture-pane", "-t", tmux_name, "-p"],
        tool_name="session-exec", target=target,
    )
    return {"success": True, "session_id": session_id, "command": command, "output": capture.output}


@mcp.tool()
def session_status(session_id: str = "") -> dict[str, Any]:
    """
    Shows the status of one session, or lists all sessions if session_id is empty.

    Args:
        session_id: Session ID to check. Empty = list every session.
    """
    if session_id:
        record = get_session(session_id)
        if record is None:
            return {"success": False, "error": f"No session with id '{session_id}'."}
        keys = ["id", "target", "session_type", "host", "port", "status", "opened_at", "closed_at"]
        return {"success": True, **dict(zip(keys, record, strict=True))}

    rows = db_list_sessions()
    keys = ["id", "target", "session_type", "host", "port", "status", "opened_at", "closed_at"]
    return {"success": True, "total": len(rows), "sessions": [dict(zip(keys, r, strict=True)) for r in rows]}


@mcp.tool()
def session_close(session_id: str) -> dict[str, Any]:
    """
    Closes an open session, killing its tmux process inside the container.

    Args:
        session_id: Session ID to close.
    """
    record = get_session(session_id)
    if record is None:
        return {"success": False, "error": f"No session with id '{session_id}'."}

    try:
        container = get_container()
        container.exec_run(["tmux", "kill-session", "-t", _tmux_name(session_id)])
    except RuntimeError as exc:
        return {"success": False, "error": str(exc)}

    update_session_status(session_id, "closed", closed=True)
    audit.info("SESSION_CLOSED | id=%s", session_id)
    return {"success": True, "session_id": session_id, "status": "closed"}


@mcp.tool()
def session_list(target: str = "") -> dict[str, Any]:
    """
    Lists sessions, optionally filtered by target.

    Args:
        target: Partial target filter. Empty = all sessions.
    """
    rows = db_list_sessions(target)
    keys = ["id", "target", "session_type", "host", "port", "status", "opened_at", "closed_at"]
    return {"success": True, "total": len(rows), "sessions": [dict(zip(keys, r, strict=True)) for r in rows]}
