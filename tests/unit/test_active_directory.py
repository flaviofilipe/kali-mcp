"""Unit tests for tools.active_directory."""

from __future__ import annotations

import base64

import core.db as db
import core.security as security
from tools import active_directory as ad


def test_enum_smb_shares_blocked_when_not_allowlisted(allowlist_db, fake_container, no_rate_limit):
    result = ad.enum_smb_shares(target="10.0.0.20")
    assert result["success"] is False


def test_enum_smb_shares_runs_enum4linux(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.20")
    fake_container.when(lambda cmd: cmd[0] == "enum4linux-ng", 0, "shares found")
    result = ad.enum_smb_shares(target="10.0.0.20")
    assert result["success"] is True
    assert fake_container.calls[0] == ["enum4linux-ng", "-A", "10.0.0.20"]


def test_smb_list_dir_lists_share_root(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.20")
    fake_container.when(lambda cmd: cmd[0] == "smbclient", 0, "  flag.txt   N   20  ...\n  backups   D   0  ...")
    result = ad.smb_list_dir(target="10.0.0.20", share="share")
    assert result["success"] is True
    assert fake_container.calls[0][-1] == "ls"
    assert "-N" in fake_container.calls[0]


def test_smb_list_dir_cds_into_subpath(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.20")
    fake_container.when(lambda cmd: cmd[0] == "smbclient", 0, "  usuarios.txt   N   40  ...")
    result = ad.smb_list_dir(target="10.0.0.20", share="share", path="backups")
    assert result["success"] is True
    assert fake_container.calls[0][-1] == 'cd "backups"; ls'


def test_smb_list_dir_blocked_when_not_allowlisted(allowlist_db, fake_container, no_rate_limit):
    result = ad.smb_list_dir(target="10.0.0.20", share="share")
    assert result["success"] is False
    assert fake_container.calls == []


def test_smb_get_file_requires_remote_path(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.20")
    result = ad.smb_get_file(target="10.0.0.20", share="share", remote_path="")
    assert result["success"] is False
    assert fake_container.calls == []


def test_smb_get_file_blocked_when_not_allowlisted(allowlist_db, fake_container, no_rate_limit):
    result = ad.smb_get_file(target="10.0.0.20", share="share", remote_path="flag.txt")
    assert result["success"] is False


def test_smb_get_file_downloads_and_returns_content_anonymous(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.20")
    fake_container.when(lambda cmd: cmd[0] == "smbclient", 0, "getting file \\flag.txt of size 14 as ...")
    encoded = base64.b64encode(b"LAB1{deadbeef}").decode("ascii")
    fake_container.when(lambda cmd: cmd[0] == "sh" and "base64" in cmd[-1], 0, encoded + "\n")

    result = ad.smb_get_file(target="10.0.0.20", share="share", remote_path="flag.txt")

    assert result["success"] is True
    assert result["file_content"] == "LAB1{deadbeef}"
    assert result["remote_path"] == "flag.txt"
    smb_call = fake_container.calls[0]
    assert smb_call[:2] == ["smbclient", "//10.0.0.20/share"]
    assert "-N" in smb_call
    assert 'get "flag.txt"' in smb_call[-1]


def test_smb_get_file_uses_credentials_when_given(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.20")
    fake_container.when(lambda cmd: cmd[0] == "smbclient", 0, "getting file")
    fake_container.when(
        lambda cmd: cmd[0] == "sh" and "base64" in cmd[-1], 0,
        base64.b64encode(b"SQLAdmin:admin123").decode("ascii"),
    )

    result = ad.smb_get_file(
        target="10.0.0.20", share="share", remote_path="backups/usuarios.txt",
        username="SQLAdmin", password="admin123",
    )

    assert result["success"] is True
    smb_call = fake_container.calls[0]
    assert "-U" in smb_call
    assert "SQLAdmin%admin123" in smb_call


def test_smb_get_file_reports_error_when_file_was_never_downloaded(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.20")
    fake_container.when(lambda cmd: cmd[0] == "smbclient", 0, "NT_STATUS_NO_SUCH_FILE opening remote file")
    fake_container.when(
        lambda cmd: cmd[0] == "sh" and "base64" in cmd[-1], 1,
        "base64: /tmp/smb_dl_xxx: No such file or directory",
    )

    result = ad.smb_get_file(target="10.0.0.20", share="share", remote_path="nope.txt")

    assert result["success"] is False
    assert "not retrieved" in result["error"]


def test_enum_ad_netexec_read_mode_no_token_needed(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.20")
    fake_container.when(lambda cmd: cmd[0] == "nxc", 0, "shares listed")
    result = ad.enum_ad_netexec(target="10.0.0.20", mode="shares")
    assert result["success"] is True
    assert "--shares" in fake_container.calls[0]


def test_enum_ad_netexec_gated_mode_refused_without_token(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.20")
    result = ad.enum_ad_netexec(target="10.0.0.20", mode="ntds")
    assert result["success"] is False
    assert fake_container.calls == []


def test_enum_ad_netexec_gated_mode_accepted_with_valid_token(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.20")
    fake_container.when(lambda cmd: cmd[0] == "nxc", 0, "ntds dumped")
    token = security.issue_confirmation_token("enum_ad_netexec", "10.0.0.20", "authorized")["token"]
    result = ad.enum_ad_netexec(target="10.0.0.20", mode="ntds", confirmation_token=token)
    assert result["success"] is True
    assert "--ntds" in fake_container.calls[0]


def test_enum_ad_netexec_invalid_mode_rejected(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.20")
    result = ad.enum_ad_netexec(target="10.0.0.20", mode="not-a-real-mode")
    assert result["success"] is False


def test_enum_ad_netexec_exec_requires_command(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.20")
    token = security.issue_confirmation_token("enum_ad_netexec", "10.0.0.20", "authorized")["token"]
    result = ad.enum_ad_netexec(target="10.0.0.20", mode="exec", confirmation_token=token)
    assert result["success"] is False
    assert "command" in result["error"]


def test_bloodhound_collect_blocked_when_not_allowlisted(allowlist_db, fake_container, no_rate_limit):
    result = ad.bloodhound_collect(domain="corp.local", target="10.0.0.20", username="u", password="p")
    assert result["success"] is False


def test_impacket_secretsdump_requires_confirmation(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.20")
    result = ad.impacket_secretsdump(target="10.0.0.20", username="admin", password="pw", confirmation_token="")
    assert result["success"] is False
    assert fake_container.calls == []


def test_impacket_secretsdump_saves_credentials_encrypted(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.20")
    fake_container.when(
        lambda cmd: cmd[0] == "secretsdump.py", 0,
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n",
    )
    token = security.issue_confirmation_token("impacket_secretsdump", "10.0.0.20", "authorized dump")["token"]
    result = ad.impacket_secretsdump(target="10.0.0.20", username="admin", password="pw", confirmation_token=token)

    assert result["success"] is True
    assert result["credentials_saved"] == 1

    listing = db.list_credentials("10.0.0.20")
    assert len(listing) == 1
    assert listing[0]["username"] == "Administrator"
    # list_credentials() is metadata-only — it must never expose the raw hash.
    assert "hash_value" not in listing[0]

    # The credentials table's own hash_value_encrypted column (as opposed to
    # findings.output, which intentionally keeps the raw tool output as
    # evidence) must never hold the plaintext hash — see
    # tests/security/test_credential_encryption.py for the dedicated check.
    import sqlite3
    with sqlite3.connect(db.DB_PATH) as conn:
        row = conn.execute("SELECT hash_value_encrypted FROM credentials WHERE username = 'Administrator'").fetchone()
    assert b"31d6cfe0d16ae931b73c59d7e0c089c0" not in row[0]


def test_impacket_secretsdump_token_bound_to_target(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.20")
    db.allowlist_add("10.0.0.21")
    token = security.issue_confirmation_token("impacket_secretsdump", "10.0.0.20", "authorized")["token"]
    result = ad.impacket_secretsdump(target="10.0.0.21", username="admin", password="pw", confirmation_token=token)
    assert result["success"] is False


def test_impacket_psexec_requires_confirmation(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.20")
    result = ad.impacket_psexec(
        target="10.0.0.20", username="admin", password="pw", command="whoami", confirmation_token="",
    )
    assert result["success"] is False
    assert fake_container.calls == []


def test_impacket_psexec_runs_with_valid_token(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.20")
    fake_container.when(lambda cmd: cmd[0] == "psexec.py", 0, "nt authority\\system")
    token = security.issue_confirmation_token("impacket_psexec", "10.0.0.20", "authorized")["token"]
    result = ad.impacket_psexec(
        target="10.0.0.20", username="admin", password="pw", command="whoami", confirmation_token=token,
    )
    assert result["success"] is True


def test_evil_winrm_connect_opens_tmux_session(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("10.0.0.20")
    result = ad.evil_winrm_connect(target="10.0.0.20", username="admin", password="pw")
    assert result["success"] is True
    assert result["session_type"] == "evil_winrm"
    assert "evil-winrm" in fake_container.calls[0]
