"""
Unit tests for tools.sessions — a fake Docker container stands in for
tmux/nc, so no real Docker daemon is touched.
"""

from __future__ import annotations

import core.db as db
from tools import sessions


def test_start_reverse_shell_listener_blocked_when_not_allowlisted(allowlist_db, fake_container, no_rate_limit):
    result = sessions.start_reverse_shell_listener(target="10.0.0.9", port=4444)
    assert result["success"] is False
    assert "allowlist" in result["error"].lower()
    assert fake_container.calls == []  # never even tried to talk to the container


def test_start_reverse_shell_listener_opens_tmux_session(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.9")
    result = sessions.start_reverse_shell_listener(target="10.0.0.9", port=4444)

    assert result["success"] is True
    assert result["status"] == "open"
    session_id = result["session_id"]

    assert fake_container.calls[0][:3] == ["tmux", "new-session", "-d"]
    assert "nc" in fake_container.calls[0]
    assert "4444" in fake_container.calls[0]

    record = db.get_session(session_id)
    assert record is not None
    assert record[1] == "10.0.0.9"  # target
    assert record[5] == "open"      # status


def test_start_reverse_shell_listener_rejects_invalid_shell_type(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.9")
    result = sessions.start_reverse_shell_listener(target="10.0.0.9", port=4444, shell_type="fortran")
    assert result["success"] is False
    assert "shell_type" in result["error"]


def test_session_exec_unknown_session(allowlist_db, fake_container, no_rate_limit):
    result = sessions.session_exec(session_id="does-not-exist", command="whoami")
    assert result["success"] is False


def test_session_exec_sends_and_captures(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.9")
    opened = sessions.start_reverse_shell_listener(target="10.0.0.9", port=4444)
    session_id = opened["session_id"]

    fake_container.when(lambda cmd: "capture-pane" in cmd, 0, "root@victim:~# whoami\nroot\n")

    result = sessions.session_exec(session_id=session_id, command="whoami")
    assert result["success"] is True
    assert "root" in result["output"]


def test_session_exec_revalidates_allowlist_on_every_call(allowlist_db, fake_container, no_rate_limit):
    """A target removed from the allowlist after a session opens must stop accepting commands."""
    db.allowlist_add("10.0.0.9")
    opened = sessions.start_reverse_shell_listener(target="10.0.0.9", port=4444)
    session_id = opened["session_id"]

    db.allowlist_remove("10.0.0.9")

    result = sessions.session_exec(session_id=session_id, command="whoami")
    assert result["success"] is False
    assert "allowlist" in result["error"].lower()


def test_session_close_marks_closed(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.9")
    opened = sessions.start_reverse_shell_listener(target="10.0.0.9", port=4444)
    session_id = opened["session_id"]

    result = sessions.session_close(session_id)
    assert result["success"] is True
    assert result["status"] == "closed"

    record = db.get_session(session_id)
    assert record[5] == "closed"
    assert record[7] is not None  # closed_at set


def test_session_list_filters_by_target(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.9")
    db.allowlist_add("10.0.0.10")
    sessions.start_reverse_shell_listener(target="10.0.0.9", port=4444)
    sessions.start_reverse_shell_listener(target="10.0.0.10", port=4445)

    result = sessions.session_list(target="10.0.0.9")
    assert result["total"] == 1
    assert result["sessions"][0]["target"] == "10.0.0.9"


def test_session_status_without_id_lists_all(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.9")
    sessions.start_reverse_shell_listener(target="10.0.0.9", port=4444)

    result = sessions.session_status()
    assert result["total"] == 1
