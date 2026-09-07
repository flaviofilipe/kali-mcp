"""Unit tests for tools.recon."""

from __future__ import annotations

import core.db as db
from tools import recon


def test_scan_ports_nmap_default_flags(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.9")
    fake_container.when(lambda cmd: cmd[0] == "nmap", 0, "22/tcp open  ssh\n")

    result = recon.scan_ports_nmap(target="10.0.0.9")
    assert result["success"] is True
    cmd = fake_container.calls[0]
    assert cmd == ["nmap", "-sV", "-F", "10.0.0.9"]


def test_scan_ports_nmap_skip_host_discovery_adds_pn(allowlist_db, fake_container, no_rate_limit):
    """HTB-style lab targets reliably report as down without -Pn."""
    db.allowlist_add("10.0.0.9")
    fake_container.when(lambda cmd: cmd[0] == "nmap", 0, "22/tcp open  ssh\n")

    result = recon.scan_ports_nmap(target="10.0.0.9", skip_host_discovery=True)
    assert result["success"] is True
    cmd = fake_container.calls[0]
    assert "-Pn" in cmd


def test_scan_ports_nmap_skip_host_discovery_does_not_duplicate_pn(allowlist_db, fake_container, no_rate_limit):
    """A caller who already passed -Pn via flags shouldn't get it twice."""
    db.allowlist_add("10.0.0.9")
    fake_container.when(lambda cmd: cmd[0] == "nmap", 0, "22/tcp open  ssh\n")

    result = recon.scan_ports_nmap(target="10.0.0.9", flags="-sV -F -Pn", skip_host_discovery=True)
    assert result["success"] is True
    cmd = fake_container.calls[0]
    assert cmd.count("-Pn") == 1
