"""Unit tests for pure-logic helpers in tools.credentials — no Docker involved."""

from __future__ import annotations

from tools.credentials import extract_cves


def test_extract_cves_finds_single():
    assert extract_cves("Vulnerable to CVE-2023-12345") == ["CVE-2023-12345"]


def test_extract_cves_dedupes_preserving_order():
    text = "CVE-2021-4034 found. Also CVE-2021-4034 again, then CVE-2020-0001."
    assert extract_cves(text) == ["CVE-2021-4034", "CVE-2020-0001"]


def test_extract_cves_normalizes_case():
    assert extract_cves("cve-2019-0708") == ["CVE-2019-0708"]


def test_extract_cves_empty_when_none_present():
    assert extract_cves("Nothing interesting here.") == []


def test_extract_cves_handles_empty_string():
    assert extract_cves("") == []


def test_extract_cves_handles_none():
    assert extract_cves(None) == []
