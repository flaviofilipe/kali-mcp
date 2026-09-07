"""Unit tests for tools.governance's nmap-output parsing helpers."""

from __future__ import annotations

from tools.governance import _detect_ports_from_nmap, _infer_target_url

# Real `nmap -sV -F --open` output captured against a host that has both a
# real port 80 (nginx, plain HTTP) and a real port 8443 (https-alt) open at
# the same time — the exact scenario that exposed the substring-matching bug:
# a naive `"443/tcp" in line` check also matches inside "8443/tcp", and
# `"80/tcp" in line` inside "8080/tcp", producing a corrupted port list and
# silently pointing every web phase (gobuster, nikto, nuclei, ...) at
# 443/target, which was never actually open, while 80/8080/8888 — the ports
# that *were* open — never got scanned.
REAL_NMAP_OUTPUT = """\
Starting Nmap 7.99 ( https://nmap.org ) at 2026-09-07 15:40 +0000
Nmap scan report for 192.168.0.8 (192.168.0.8)
Host is up (0.000010s latency).
Not shown: 88 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
22/tcp   open  ssh         OpenSSH 10.2p1 Ubuntu 2ubuntu3.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        nginx
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
389/tcp  open  ldap        OpenLDAP 2.2.X - 2.3.X
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
631/tcp  open  ipp         CUPS 2.4
3306/tcp open  mysql       MySQL 5.7.44
8080/tcp open  http        (PHP 8.4.22)
8081/tcp open  http        Apache httpd 2.4.57 ((Debian) PHP/8.2.17)
8443/tcp open  https-alt?
8888/tcp open  http        nginx 1.27.5
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 183.96 seconds
"""


def test_detect_ports_does_not_false_positive_on_substring_ports():
    # Before the fix: web_ports came back [80, 80, 8080, 443, 8443, 8888] —
    # a phantom 443 (from inside "8443/tcp") and a duplicated 80 (from
    # inside "8080/tcp"). Neither may appear now.
    web_ports, has_ssh, has_ftp = _detect_ports_from_nmap(REAL_NMAP_OUTPUT)

    assert web_ports == [80, 8080, 8443, 8888]
    assert 443 not in web_ports
    assert web_ports.count(80) == 1
    assert has_ssh is True
    assert has_ftp is True


def test_detect_ports_empty_output():
    web_ports, has_ssh, has_ftp = _detect_ports_from_nmap("")
    assert web_ports == []
    assert has_ssh is False
    assert has_ftp is False


def test_detect_ports_ignores_closed_and_filtered_lines():
    output = "443/tcp  closed https\n8443/tcp filtered https-alt\n"
    web_ports, _, _ = _detect_ports_from_nmap(output)
    assert web_ports == []


def test_infer_target_url_prefers_plain_http_on_port_80_even_with_8443_open():
    # The second half of the same bug: even with web_ports correctly
    # containing no phantom 443, the old code decided "https" from a global
    # "is 443/8443 open *anywhere*" flag instead of the chosen port — so a
    # host with real 80 (http) AND real 8443 (https) still got probed as
    # https://target (i.e. implied port 443, which doesn't exist).
    url = _infer_target_url("192.168.0.8", [80, 8080, 8443, 8888])
    assert url == "http://192.168.0.8"


def test_infer_target_url_https_only_port_443():
    assert _infer_target_url("10.0.0.5", [443]) == "https://10.0.0.5"


def test_infer_target_url_https_alt_port_keeps_port_suffix():
    assert _infer_target_url("10.0.0.5", [8443]) == "https://10.0.0.5:8443"


def test_infer_target_url_http_alt_port_keeps_port_suffix():
    assert _infer_target_url("10.0.0.5", [8080]) == "http://10.0.0.5:8080"


def test_infer_target_url_no_web_ports_returns_none():
    assert _infer_target_url("10.0.0.5", []) is None
