"""
Unit tests for tools.pivoting — including the requirement that a host
reached only via a tunnel is still blocked by the allowlist for every
ordinary scan tool (section 4 of the hardening spec).
"""

from __future__ import annotations

import core.db as db
import core.security as security
from tools import pivoting
from tools import recon


def test_chisel_tunnel_blocked_when_target_not_allowlisted(allowlist_db, fake_container, no_rate_limit):
    result = pivoting.start_chisel_tunnel(target="10.0.0.40", local_port=9001, remote_port=8080, confirmation_token="")
    assert result["success"] is False
    assert fake_container.calls == []


def test_chisel_tunnel_requires_confirmation(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.40")
    result = pivoting.start_chisel_tunnel(target="10.0.0.40", local_port=9001, remote_port=8080, confirmation_token="")
    assert result["success"] is False
    assert fake_container.calls == []


def test_chisel_tunnel_opens_with_valid_token(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.40")
    token = security.issue_confirmation_token("start_chisel_tunnel", "10.0.0.40", "authorized pivot")["token"]
    result = pivoting.start_chisel_tunnel(target="10.0.0.40", local_port=9001, remote_port=8080, confirmation_token=token)

    assert result["success"] is True
    assert result["local_port"] == 9001
    assert "client_command" in result
    cmd = fake_container.calls[0]
    assert cmd[:3] == ["tmux", "new-session", "-d"]
    assert "chisel" in cmd


def test_ligolo_tunnel_requires_confirmation(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.41")
    result = pivoting.start_ligolo_tunnel(target="10.0.0.41", confirmation_token="")
    assert result["success"] is False
    assert fake_container.calls == []


def test_ligolo_tunnel_opens_with_valid_token(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.41")
    token = security.issue_confirmation_token("start_ligolo_tunnel", "10.0.0.41", "authorized pivot")["token"]
    result = pivoting.start_ligolo_tunnel(target="10.0.0.41", confirmation_token=token)

    assert result["success"] is True
    assert "agent_command" in result


def test_host_reached_via_tunnel_still_requires_its_own_allowlist_entry(allowlist_db, fake_container, no_rate_limit):
    """
    Opening a tunnel to an allowlisted pivot host must NOT implicitly
    authorize scanning whatever is on the other side of it.
    """
    db.allowlist_add("10.0.0.40")  # the pivot host itself is authorized
    token = security.issue_confirmation_token("start_chisel_tunnel", "10.0.0.40", "authorized pivot")["token"]
    pivoting.start_chisel_tunnel(target="10.0.0.40", local_port=9001, remote_port=8080, confirmation_token=token)

    # An internal host only reachable *through* that tunnel is a different
    # target and was never added — every ordinary tool must still refuse it.
    result = recon.scan_ports_nmap(target="10.10.10.10")
    assert result["success"] is False
    assert "allowlist" in result["error"].lower()


def test_tunnel_recorded_as_session(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.40")
    token = security.issue_confirmation_token("start_chisel_tunnel", "10.0.0.40", "authorized pivot")["token"]
    result = pivoting.start_chisel_tunnel(target="10.0.0.40", local_port=9001, remote_port=8080, confirmation_token=token)

    record = db.get_session(result["tunnel_id"])
    assert record is not None
    assert record[2] == "pivot-chisel"  # session_type
