"""
Integration: credentials category — fully offline, no lab target needed,
just the real john/hashcat/rockyou.txt inside kali-mcp-box-test.
"""

from __future__ import annotations

from tests.integration.conftest import requires_test_lab
from tools import credentials

pytestmark = requires_test_lab

# md5("password") — the second entry in rockyou.txt, cracks near-instantly.
_MD5_PASSWORD = "5f4dcc3b5aa765d61d8327deb882cf99"


def test_crack_hash_john_cracks_known_weak_md5(test_lab):
    result = credentials.crack_hash_john(hash_value=_MD5_PASSWORD, hash_type="raw-md5")
    assert result["success"] is True
    assert result["cracked"] is True
    assert result["plaintext"] == "password"


def test_crack_hash_hashcat_cracks_known_weak_md5(test_lab):
    result = credentials.crack_hash_hashcat(hash_value=_MD5_PASSWORD, hash_mode=0)
    assert result["success"] is True
    assert result["cracked"] is True
    assert result["plaintext"] == "password"


def test_identify_hash_recognizes_md5(test_lab):
    result = credentials.identify_hash(hash_value=_MD5_PASSWORD)
    assert result["success"] is True
    assert "MD5" in result["output"].upper()
