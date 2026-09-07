"""Unit tests for tools.ftp — a fake Docker container stands in for curl."""

from __future__ import annotations

import core.db as db
from tools import ftp


def test_enumerate_ftp_blocked_when_not_allowlisted(allowlist_db, fake_container, no_rate_limit):
    result = ftp.enumerate_ftp(target="10.0.0.9")
    assert result["success"] is False
    assert "allowlist" in result["error"].lower()
    assert fake_container.calls == []


def test_enumerate_ftp_reports_successful_login_and_listing(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.9")
    fake_container.when(lambda cmd: cmd[0] == "curl", 0, "drwxr-xr-x 2 ftp ftp 4096 note.txt\n")

    result = ftp.enumerate_ftp(target="10.0.0.9")
    assert result["success"] is True
    assert result["logged_in"] is True
    assert result["username"] == "anonymous"
    assert "note.txt" in result["output"]

    cmd = fake_container.calls[0]
    assert cmd[0] == "curl"
    assert "--user" in cmd
    assert "anonymous:anonymous" in cmd
    assert "ftp://10.0.0.9:21/" in cmd


def test_enumerate_ftp_reports_failed_login(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.9")
    fake_container.when(lambda cmd: cmd[0] == "curl", 67, "curl: (67) Login denied\n")

    result = ftp.enumerate_ftp(target="10.0.0.9", username="admin", password="wrong")
    assert result["logged_in"] is False
    assert "Login failed" in result["summary"]


def test_enumerate_ftp_uses_custom_credentials_and_port(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.9")
    fake_container.when(lambda cmd: cmd[0] == "curl", 0, "")

    ftp.enumerate_ftp(target="10.0.0.9", port=2121, username="admin", password="s3cret")
    cmd = fake_container.calls[0]
    assert "admin:s3cret" in cmd
    assert "ftp://10.0.0.9:2121/" in cmd
