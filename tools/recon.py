"""Reconnaissance tools: port scanning and subdomain enumeration."""

from __future__ import annotations

import shlex
from typing import Any

from core.config import mcp
from core.docker_exec import exec_in_kali


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
    return exec_in_kali(cmd, tool_name="nmap", target=target).model_dump()


@mcp.tool()
def enum_subdomains_subfinder(domain: str) -> dict[str, Any]:
    """
    Enumerates subdomains via passive reconnaissance using Subfinder.
    Use when the target is a public domain, after the initial Nmap scan.

    Args:
        domain: Root domain. E.g.: "example.com", "app.local"
    """
    cmd = ["subfinder", "-d", domain, "-silent"]
    return exec_in_kali(cmd, tool_name="subfinder", target=domain).model_dump()
