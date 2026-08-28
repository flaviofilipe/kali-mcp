"""
EXPERIMENTAL — CTF-oriented binary exploitation helpers, not part of the
standard web pentest flow: angr symbolic execution and pwntools scripting,
both run by writing the supplied code to a file inside the Kali container
and executing it with python3.

These execute arbitrary Python you (or an LLM acting on your behalf)
supply, sandboxed only by the Kali container itself — no additional
sandboxing beyond what the container already provides. Review any
generated script before running it, exactly as you would before running
any other code.
"""

from __future__ import annotations

import uuid
from typing import Any

from core.config import mcp
from core.docker_exec import exec_in_kali, write_file


@mcp.tool()
def analyze_binary_angr(binary_path: str, analysis: str) -> dict[str, Any]:
    """
    EXPERIMENTAL — CTF / reverse-engineering workflow. Runs a snippet of
    angr analysis code against a binary inside the container.

    `analysis` is executed as the body of a script with
    `proj = angr.Project(binary_path, auto_load_libs=False)` already set up.
    Assign to a variable named `result` to have it printed.

    Args:
        binary_path: Path to the binary inside the container.
        analysis:    Python code using `proj` (an angr.Project). E.g.:
                     "cfg = proj.analyses.CFGFast(); result = len(cfg.graph.nodes)"
    """
    script_path = f"/tmp/angr_{uuid.uuid4().hex[:8]}.py"
    script = (
        "import angr\n"
        f"proj = angr.Project({binary_path!r}, auto_load_libs=False)\n"
        "result = None\n"
        f"{analysis}\n"
        "print(result)\n"
    )
    write_error = write_file(script_path, script)
    if write_error:
        return {"success": False, "error": write_error}

    return exec_in_kali(
        ["python3", script_path], tool_name="angr", target=binary_path, skip_allowlist=True,
    ).model_dump()


@mcp.tool()
def exploit_pwntools_helper(script: str) -> dict[str, Any]:
    """
    EXPERIMENTAL — CTF workflow. Executes a pwntools Python script inside
    the Kali container (pwntools is preinstalled) and returns its stdout.

    Args:
        script: Full pwntools Python script source. E.g.:
                "from pwn import *\\np = process('/tmp/vuln')\\np.sendline(b'A'*40)\\nprint(p.recvall())"
    """
    script_path = f"/tmp/pwn_{uuid.uuid4().hex[:8]}.py"
    write_error = write_file(script_path, script)
    if write_error:
        return {"success": False, "error": write_error}

    return exec_in_kali(
        ["python3", script_path], tool_name="pwntools", target="offline", skip_allowlist=True,
    ).model_dump()
