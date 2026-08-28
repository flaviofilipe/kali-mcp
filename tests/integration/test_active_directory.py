"""Integration: AD/SMB enumeration, against the real samba-test lab target."""

from __future__ import annotations

from tests.integration.conftest import requires_test_lab
from tools import active_directory as ad

pytestmark = requires_test_lab


def test_enum_smb_shares_against_samba_test(test_lab):
    target = test_lab["samba"]
    result = ad.enum_smb_shares(target=target)
    assert result["success"] is True


def test_enum_ad_netexec_shares_against_samba_test(test_lab):
    target = test_lab["samba"]
    result = ad.enum_ad_netexec(target=target, mode="shares", username="testuser", password="testpass")
    assert result["success"] is True
