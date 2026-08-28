"""
Credentials table must never store hash/plaintext values in the clear:
neither via the Python API (get_credential decrypts correctly) nor in the
raw SQLite file on disk (a direct dump of the DB file must not contain the
plaintext bytes).
"""

from __future__ import annotations

import sqlite3

import pytest

import core.db as db


@pytest.fixture
def crypto_db(tmp_path, monkeypatch):
    db_path = tmp_path / "findings.db"
    key_path = tmp_path / "secret.key"
    monkeypatch.setattr(db, "DB_PATH", db_path)
    monkeypatch.setattr(db, "SECRET_KEY_PATH", key_path)
    monkeypatch.setattr(db, "_fernet", None)  # drop any cached key from another test
    db.init_db()
    yield db_path
    monkeypatch.setattr(db, "_fernet", None)


KNOWN_PASSWORD = "Tr0ub4dor&3-hunter2-VERY-SECRET"
KNOWN_HASH = "5f4dcc3b5aa765d61d8327deb882cf99"


def test_get_credential_round_trips_decrypted_values(crypto_db):
    cred_id = db.save_credential(
        target="10.0.0.5", service="smb", username="admin",
        hash_type="ntlm", hash_value=KNOWN_HASH, cracked_plaintext=KNOWN_PASSWORD,
    )
    cred = db.get_credential(cred_id)
    assert cred["hash_value"] == KNOWN_HASH
    assert cred["cracked_plaintext"] == KNOWN_PASSWORD


def test_plaintext_and_hash_never_appear_unencrypted_on_disk(crypto_db):
    db.save_credential(
        target="10.0.0.5", service="smb", username="admin",
        hash_type="ntlm", hash_value=KNOWN_HASH, cracked_plaintext=KNOWN_PASSWORD,
    )
    raw_bytes = crypto_db.read_bytes()
    assert KNOWN_PASSWORD.encode() not in raw_bytes
    assert KNOWN_HASH.encode() not in raw_bytes


def test_credentials_encrypted_blob_differs_from_plaintext_in_db_row(crypto_db):
    db.save_credential(
        target="10.0.0.5", service="smb", username="admin",
        hash_type="ntlm", hash_value=KNOWN_HASH, cracked_plaintext=KNOWN_PASSWORD,
    )
    with sqlite3.connect(crypto_db) as conn:
        row = conn.execute(
            "SELECT hash_value_encrypted, cracked_plaintext_encrypted FROM credentials"
        ).fetchone()
    assert row[0] != KNOWN_HASH.encode()
    assert row[1] != KNOWN_PASSWORD.encode()
    assert KNOWN_HASH.encode() not in row[0]
    assert KNOWN_PASSWORD.encode() not in row[1]


def test_list_credentials_never_returns_secret_columns(crypto_db):
    db.save_credential(
        target="10.0.0.5", service="smb", username="admin",
        hash_type="ntlm", hash_value=KNOWN_HASH, cracked_plaintext=KNOWN_PASSWORD,
    )
    listing = db.list_credentials("10.0.0.5")
    assert len(listing) == 1
    assert "hash_value" not in listing[0]
    assert "cracked_plaintext" not in listing[0]
    assert listing[0]["cracked"] is True


def test_mark_credential_cracked_updates_decrypted_value(crypto_db):
    cred_id = db.save_credential(
        target="10.0.0.5", service="smb", username="admin",
        hash_type="ntlm", hash_value=KNOWN_HASH, cracked_plaintext=None,
    )
    assert db.get_credential(cred_id)["cracked_plaintext"] is None
    db.mark_credential_cracked(cred_id, KNOWN_PASSWORD)
    assert db.get_credential(cred_id)["cracked_plaintext"] == KNOWN_PASSWORD


def test_secret_key_file_has_owner_only_permissions(crypto_db):
    import stat

    db.save_credential(target="10.0.0.5", service="smb", username="admin", hash_type="ntlm", hash_value=KNOWN_HASH)
    mode = stat.S_IMODE(db.SECRET_KEY_PATH.stat().st_mode)
    assert mode == stat.S_IRUSR | stat.S_IWUSR  # 0600
