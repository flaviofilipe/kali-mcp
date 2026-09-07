"""
Active Directory / Windows tools: SMB and AD enumeration, BloodHound
collection, Impacket lateral movement, and evil-winrm sessions.

Credential-dumping and lateral-movement actions (impacket_secretsdump,
impacket_psexec, and netexec's write/exec modes) are gated behind
core.security.consume_confirmation() — call
request_high_risk_action(action=<tool name>, target=..., justification=...)
first and pass the returned token as confirmation_token.
"""

from __future__ import annotations

import uuid
from typing import Any

from core.audit import audit
from core.config import mcp
from core.db import save_credential
from core.docker_exec import exec_in_kali, read_file
from core.security import consume_confirmation, is_allowed
from tools.sessions import open_tmux_session

_READ_MODE_FLAGS: dict[str, list[str]] = {
    "shares":          ["--shares"],
    "users":           ["--users"],
    "groups":          ["--groups"],
    "sessions":        ["--sessions"],
    "pass-pol":        ["--pass-pol"],
    "loggedon-users":  ["--loggedon-users"],
}
_GATED_MODE_FLAGS: dict[str, list[str]] = {
    "sam":  ["--sam"],
    "lsa":  ["--lsa"],
    "ntds": ["--ntds"],
}


@mcp.tool()
def enum_smb_shares(target: str) -> dict[str, Any]:
    """
    Enumerates SMB shares, users, groups, and OS/policy info via
    enum4linux-ng. Read-only reconnaissance, no allowlist gate beyond the
    normal one — use as the first AD/Windows recon step.

    Args:
        target: IP or hostname of the SMB/AD host.
    """
    cmd = ["enum4linux-ng", "-A", target]
    return exec_in_kali(cmd, tool_name="enum4linux-ng", target=target).model_dump()


def _smb_auth_args(username: str, password: str) -> list[str]:
    return ["-U", f"{username}%{password}"] if username else ["-N"]


@mcp.tool()
def smb_list_dir(
    target: str,
    share: str,
    path: str = "",
    username: str = "",
    password: str = "",
) -> dict[str, Any]:
    """
    Lists the contents of an SMB share (or a subdirectory within it) via
    smbclient. enum_smb_shares() (enum4linux-ng) tells you which shares
    *exist*; this lists the files *inside* one — use it to find exact
    filenames/subfolders (e.g. a "backups" directory) before smb_get_file().

    Anonymous access (guest/null session) is the default — pass a username
    only when the share requires authentication.

    Args:
        target:   IP or hostname of the SMB host. Must be in the allowlist.
        share:    Share name, e.g. "share", "public".
        path:     Subdirectory within the share to list. Empty = share root.
        username: Username for authenticated access. Empty = anonymous (-N).
        password: Password. Ignored when username is empty.
    """
    script = f'cd "{path}"; ls' if path else "ls"
    cmd = ["smbclient", f"//{target}/{share}", *_smb_auth_args(username, password), "-c", script]
    return exec_in_kali(cmd, tool_name="smbclient", target=target).model_dump()


@mcp.tool()
def smb_get_file(
    target: str,
    share: str,
    remote_path: str,
    username: str = "",
    password: str = "",
) -> dict[str, Any]:
    """
    Downloads a file from an SMB share and returns its content — the "pull
    the flag" step that enum_smb_shares() (enumeration only) doesn't cover.
    Use after enum_smb_shares() or smb_list_dir() has shown which share/path
    to fetch (e.g. "flag.txt", "backups/usuarios.txt").

    Anonymous access (guest/null session) is the default — pass a username
    only when the share requires authentication.

    Args:
        target:      IP or hostname of the SMB host. Must be in the allowlist.
        share:       Share name, e.g. "share", "public".
        remote_path: Path of the file within the share, e.g. "flag.txt" or
                     "backups/usuarios.txt".
        username:    Username for authenticated access. Empty = anonymous (-N).
        password:    Password. Ignored when username is empty.
    """
    if not remote_path:
        return {"success": False, "error": "remote_path is required."}

    local_path = f"/tmp/smb_dl_{uuid.uuid4().hex[:8]}"
    cmd = [
        "smbclient", f"//{target}/{share}", *_smb_auth_args(username, password),
        "-c", f'get "{remote_path}" {local_path}',
    ]

    result = exec_in_kali(cmd, tool_name="smbclient", target=target)
    out = result.model_dump()
    if not result.success:
        out["summary"] = f"smbclient failed against //{target}/{share} — see 'output'/'error'."
        return out

    content, read_error = read_file(local_path)
    if read_error:
        out["success"] = False
        out["error"]   = f"smbclient ran, but '{remote_path}' was not retrieved: {read_error}"
        out["summary"] = out["error"]
        return out

    out["file_content"] = content
    out["remote_path"]  = remote_path
    out["summary"] = f"Downloaded '{remote_path}' from //{target}/{share} ({len(content)} chars) — see 'file_content'."
    return out


@mcp.tool()
def enum_ad_netexec(
    target: str,
    mode: str = "shares",
    username: str = "",
    password: str = "",
    command: str = "",
    confirmation_token: str = "",
) -> dict[str, Any]:
    """
    Enumerates (or, in gated modes, acts against) a Windows/AD host via
    netexec (nxc), the successor to CrackMapExec.

    Read-only modes run directly, no confirmation needed:
      "shares" (default), "users", "groups", "sessions", "pass-pol", "loggedon-users"

    Modes that dump credential material or execute code require a
    confirmation_token from
    request_high_risk_action(action="enum_ad_netexec", target=target, justification=...):
      "sam", "lsa", "ntds", "exec" (uses `command`)

    Args:
        target:             IP or hostname of the Windows/AD host.
        mode:                See above. Default: "shares"
        username:           Optional credential for authenticated enumeration.
        password:           Optional credential for authenticated enumeration.
        command:            Shell command to run — only used with mode="exec".
        confirmation_token: Required for sam/lsa/ntds/exec modes.
    """
    is_gated = mode in _GATED_MODE_FLAGS or mode == "exec"
    if not is_gated and mode not in _READ_MODE_FLAGS:
        valid = sorted(_READ_MODE_FLAGS) + sorted(_GATED_MODE_FLAGS) + ["exec"]
        return {"success": False, "error": f"Invalid mode '{mode}'. Valid: {valid}"}

    if is_gated:
        ok, error = consume_confirmation(confirmation_token, "enum_ad_netexec", target)
        if not ok:
            return {"success": False, "error": error}

    cmd = ["nxc", "smb", target]
    if username:
        cmd += ["-u", username, "-p", password]
    if mode == "exec":
        if not command:
            return {"success": False, "error": "command is required for mode='exec'."}
        cmd += ["-x", command]
    else:
        cmd += (_GATED_MODE_FLAGS | _READ_MODE_FLAGS)[mode]

    audit.info("NETEXEC_RUN | target=%s mode=%s username=%s", target, mode, username or "(anonymous)")
    return exec_in_kali(cmd, tool_name="netexec", target=target).model_dump()


@mcp.tool()
def bloodhound_collect(domain: str, target: str, username: str, password: str) -> dict[str, Any]:
    """
    Collects Active Directory attack-path data (users, groups, ACLs,
    sessions, trusts) using bloodhound-python, producing a zip ready to
    import into BloodHound's UI for analysis.

    Args:
        domain:   AD domain name. E.g.: "corp.local"
        target:   Domain controller IP or hostname (also used as the DNS server).
        username: Domain credential.
        password: Domain credential.
    """
    if not is_allowed(target):
        return {"success": False, "error": f"Target '{target}' is not in the allowlist. Use manage_allowlist() first."}

    cmd = [
        "bloodhound-python",
        "-u", username, "-p", password, "-d", domain,
        "-ns", target, "-c", "All", "--zip",
    ]
    audit.info("BLOODHOUND_COLLECT | domain=%s target=%s username=%s", domain, target, username)
    return exec_in_kali(cmd, tool_name="bloodhound-python", target=target).model_dump()


@mcp.tool()
def impacket_secretsdump(target: str, username: str, password: str, confirmation_token: str) -> dict[str, Any]:
    """
    Dumps SAM/LSA secrets and (if run against a DC) NTDS.dit hashes via
    secretsdump.py (Impacket).

    HIGH RISK — extracts credential material from the target. Requires a
    confirmation_token from
    request_high_risk_action(action="impacket_secretsdump", target=target, justification=...).

    Extracted hashes are parsed out of the output and stored encrypted via
    core.db.save_credential() — never written to the audit log in the clear.

    Args:
        target:             IP or hostname of the Windows host.
        username:           Domain/local admin credential.
        password:           Domain/local admin credential.
        confirmation_token: Token from request_high_risk_action().
    """
    ok, error = consume_confirmation(confirmation_token, "impacket_secretsdump", target)
    if not ok:
        return {"success": False, "error": error}
    if not is_allowed(target):
        return {"success": False, "error": f"Target '{target}' is not in the allowlist. Use manage_allowlist() first."}

    cmd = ["secretsdump.py", f"{username}:{password}@{target}"]
    result = exec_in_kali(cmd, tool_name="secretsdump", target=target)
    out = result.model_dump()

    saved = 0
    for line in result.output.splitlines():
        # secretsdump NTLM lines look like: "user:RID:LMHASH:NTHASH:::"
        parts = line.split(":")
        if len(parts) >= 4 and parts[1].isdigit():
            save_credential(
                target=target, service="secretsdump", username=parts[0],
                hash_type="ntlm", hash_value=":".join(parts[2:4]),
            )
            saved += 1
    out["credentials_saved"] = saved
    audit.info("SECRETSDUMP_RUN | target=%s username=%s credentials_saved=%s", target, username, saved)
    return out


@mcp.tool()
def impacket_psexec(target: str, username: str, password: str, command: str, confirmation_token: str) -> dict[str, Any]:
    """
    Executes a command on a Windows host via psexec.py (Impacket) — deploys
    a service binary over the SMB admin share (ADMIN$). Classic lateral
    movement technique.

    HIGH RISK. Requires a confirmation_token from
    request_high_risk_action(action="impacket_psexec", target=target, justification=...).

    Args:
        target:             IP or hostname of the Windows host.
        username:           Local admin or domain credential.
        password:           Local admin or domain credential.
        command:            Command to run on the target. E.g.: "whoami /all"
        confirmation_token: Token from request_high_risk_action().
    """
    ok, error = consume_confirmation(confirmation_token, "impacket_psexec", target)
    if not ok:
        return {"success": False, "error": error}
    if not is_allowed(target):
        return {"success": False, "error": f"Target '{target}' is not in the allowlist. Use manage_allowlist() first."}

    cmd = ["psexec.py", f"{username}:{password}@{target}", command]
    audit.info("PSEXEC_RUN | target=%s username=%s", target, username)
    return exec_in_kali(cmd, tool_name="psexec", target=target).model_dump()


@mcp.tool()
def evil_winrm_connect(target: str, username: str, password: str) -> dict[str, Any]:
    """
    Opens an interactive Windows session over WinRM using evil-winrm, kept
    alive in a tmux session so session_exec() can drive it across multiple
    tool calls. Use when the target exposes WinRM (5985/5986) and you have
    valid credentials.

    Args:
        target:   IP or hostname of the Windows host.
        username: WinRM credential.
        password: WinRM credential.
    """
    audit.info("EVIL_WINRM_CONNECT | target=%s username=%s", target, username)
    return open_tmux_session(
        session_type="evil_winrm", target=target, host=target, port=5985,
        command=["evil-winrm", "-i", target, "-u", username, "-p", password],
    )
