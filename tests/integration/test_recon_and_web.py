"""
Integration: recon + web categories, against the real juice-shop-test lab
target (a real vulnerable app) via the real kali-mcp-box-test container.
"""

from __future__ import annotations

from tests.integration.conftest import requires_test_lab
from tools import recon, web

pytestmark = requires_test_lab


def test_scan_ports_nmap_finds_juice_shop_port(test_lab):
    target = test_lab["juice_shop"]
    result = recon.scan_ports_nmap(target=target, flags="-sV -p 3000")
    assert result["success"] is True
    assert "3000" in result["output"]


def test_check_security_headers_against_juice_shop(test_lab):
    target = test_lab["juice_shop"]
    result = web.check_security_headers(target_url=f"http://{target}:3000")
    assert result["success"] is True
    assert "security_headers" in result
