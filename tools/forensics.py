"""
Forensics / binary-analysis tools: memory dump analysis, disassembly, and
firmware/blob extraction.

These operate on files already inside the Kali container (copied in via
`docker cp`, pulled down through a session, etc.) rather than a live
network target, so they skip the allowlist (target is the file path, for
logging only). CTF / forensics workflow — not part of the standard web
pentest flow.
"""

from __future__ import annotations

from typing import Any

from core.config import mcp
from core.docker_exec import exec_in_kali


@mcp.tool()
def analyze_memory_volatility(dump_path: str, plugin: str) -> dict[str, Any]:
    """
    Analyzes a memory dump using Volatility3. CTF / forensics workflow.

    Args:
        dump_path: Path to the memory dump inside the container.
        plugin:    Volatility3 plugin. E.g.: "windows.pslist", "windows.hashdump",
                   "windows.cmdline", "linux.bash", "linux.pslist"
    """
    cmd = ["vol", "-f", dump_path, plugin]
    return exec_in_kali(cmd, tool_name="volatility3", target=dump_path, skip_allowlist=True).model_dump()


@mcp.tool()
def disassemble_binary_r2(binary_path: str, command: str = "aaa; afl") -> dict[str, Any]:
    """
    Analyzes/disassembles a binary using radare2 in batch mode (r2 -q -c).
    CTF / reverse-engineering workflow.

    Args:
        binary_path: Path to the binary inside the container.
        command:     radare2 command(s), semicolon-separated.
                     Default: "aaa; afl" (auto-analyze, then list functions).
                     Other examples: "aaa; pdf @ main" (disassemble main),
                     "izz" (strings).
    """
    cmd = ["r2", "-q", "-c", command, binary_path]
    return exec_in_kali(cmd, tool_name="radare2", target=binary_path, skip_allowlist=True).model_dump()


@mcp.tool()
def debug_binary_gdb(binary_path: str, commands: str = "info functions") -> dict[str, Any]:
    """
    Runs GDB in batch (non-interactive) mode against a binary. CTF /
    reverse-engineering workflow.

    Args:
        binary_path: Path to the binary inside the container.
        commands:    Semicolon-separated GDB commands, each run with -ex.
                     Default: "info functions". Other examples:
                     "break main; run; info registers", "disassemble main"
    """
    gdb_cmd = ["gdb", "-q", "-batch"]
    for part in commands.split(";"):
        part = part.strip()
        if part:
            gdb_cmd += ["-ex", part]
    gdb_cmd.append(binary_path)
    return exec_in_kali(gdb_cmd, tool_name="gdb", target=binary_path, skip_allowlist=True).model_dump()


@mcp.tool()
def extract_binwalk(file_path: str) -> dict[str, Any]:
    """
    Extracts embedded files and filesystems from a firmware image or binary
    blob using binwalk (-e). Extracted content is written under
    <file_path>.extracted/ inside the container. CTF / firmware-analysis
    workflow.

    Args:
        file_path: Path to the file inside the container.
    """
    cmd = ["binwalk", "-e", file_path]
    return exec_in_kali(cmd, tool_name="binwalk", target=file_path, skip_allowlist=True).model_dump()
