"""Integration: session management plumbing (tmux-backed), real container."""

from __future__ import annotations

from tests.integration.conftest import requires_test_lab
from tools import sessions

pytestmark = requires_test_lab


def test_start_session_exec_and_close_round_trip(test_lab):
    target = test_lab["juice_shop"]

    opened = sessions.start_reverse_shell_listener(target=target, port=14444)
    assert opened["success"] is True
    session_id = opened["session_id"]

    try:
        status = sessions.session_status(session_id=session_id)
        assert status["success"] is True
        assert status["status"] == "open"
    finally:
        closed = sessions.session_close(session_id)
        assert closed["success"] is True
        assert closed["status"] == "closed"
