"""
Credential tools: hash identification/cracking and public-exploit lookup.

Hash cracking runs entirely offline inside the Kali container against a
value the caller already has in hand — it never touches a network target,
so these tools pass target="offline" with skip_allowlist=True to
exec_in_kali(). Cracked plaintext is always persisted encrypted (see
core.db.save_credential) and never appears in the audit log — only in the
tool's direct return value, which is the whole point of running it.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any

from core.audit import audit
from core.config import mcp
from core.db import save_credential, save_exploit
from core.docker_exec import exec_in_kali, get_container

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_MAX_AUTO_SUGGESTED_CVES = 5


@mcp.tool()
def identify_hash(hash_value: str) -> dict[str, Any]:
    """
    Identifies the likely hash algorithm(s) for a given hash string, using
    hashid. Run this before crack_hash_john/crack_hash_hashcat if you don't
    already know the hash type (john can auto-detect for its own crack
    attempt, but hashcat's -m mode must be picked manually).

    Args:
        hash_value: The hash to identify. E.g.: "5f4dcc3b5aa765d61d8327deb882cf99"
    """
    result = exec_in_kali(["hashid", hash_value], tool_name="hashid", target="offline", skip_allowlist=True)
    return result.model_dump()


def _write_temp_file(path: str, content: str) -> str | None:
    """Writes `content` verbatim to `path` inside the container. Returns an error string, or None on success."""
    try:
        container = get_container()
        container.exec_run(["sh", "-c", f"printf '%s' '{content}' > {path}"])
        return None
    except RuntimeError as exc:
        return str(exc)


@mcp.tool()
def crack_hash_john(hash_value: str, hash_type: str = "", wordlist: str = "rockyou.txt") -> dict[str, Any]:
    """
    Attempts to crack a password hash using John the Ripper with a
    dictionary attack.

    Args:
        hash_value: The hash to crack.
        hash_type:  John --format value. E.g.: "raw-md5", "sha256crypt", "nt".
                    Leave empty to let John auto-detect the format.
        wordlist:   Wordlist filename under /usr/share/wordlists/, or an
                    absolute path. Default: "rockyou.txt"
    """
    job_id    = uuid.uuid4().hex[:10]
    hash_path = f"/tmp/john_{job_id}.hash"
    wordlist_path = wordlist if wordlist.startswith("/") else f"/usr/share/wordlists/{wordlist}"

    write_error = _write_temp_file(hash_path, hash_value)
    if write_error:
        return {"success": False, "error": write_error}

    cmd = ["john"]
    if hash_type:
        cmd.append(f"--format={hash_type}")
    cmd += [f"--wordlist={wordlist_path}", hash_path]
    crack_result = exec_in_kali(cmd, tool_name="john", target="offline", skip_allowlist=True)

    show_cmd = ["john", "--show"]
    if hash_type:
        show_cmd.append(f"--format={hash_type}")
    show_cmd.append(hash_path)
    show_result = exec_in_kali(show_cmd, tool_name="john", target="offline", skip_allowlist=True)

    plaintext = None
    first_line = show_result.output.splitlines()[0] if show_result.output else ""
    parts = first_line.split(":")
    if len(parts) >= 2 and "0 password hash" not in show_result.output:
        plaintext = parts[1]
    cracked = plaintext is not None

    credential_id = save_credential(
        target="offline", service="hash-crack", username="",
        hash_type=hash_type or "auto-detect",
        hash_value=hash_value, cracked_plaintext=plaintext,
    )
    audit.info(
        "HASH_CRACK_ATTEMPT | tool=john hash_type=%s cracked=%s credential_id=%s",
        hash_type or "auto-detect", cracked, credential_id,
    )

    return {
        "tool": "john", "success": crack_result.success, "cracked": cracked,
        "credential_id": credential_id, "plaintext": plaintext,
        "raw_output": crack_result.output,
    }


@mcp.tool()
def crack_hash_hashcat(hash_value: str, hash_mode: int, wordlist: str = "rockyou.txt") -> dict[str, Any]:
    """
    Attempts to crack a password hash using Hashcat with a dictionary attack.
    Faster than John for most modes, but requires knowing the exact -m mode
    (use identify_hash first if unsure).

    Common modes: 0=MD5, 100=SHA1, 1400=SHA256, 1000=NTLM, 3200=bcrypt,
    400=phpass/WordPress.

    Args:
        hash_value: The hash to crack.
        hash_mode:  Hashcat -m mode number. E.g.: 0 (MD5), 1000 (NTLM), 400 (phpass)
        wordlist:   Wordlist filename under /usr/share/wordlists/, or an
                    absolute path. Default: "rockyou.txt"
    """
    job_id    = uuid.uuid4().hex[:10]
    hash_path = f"/tmp/hc_{job_id}.hash"
    out_path  = f"/tmp/hc_{job_id}.out"
    wordlist_path = wordlist if wordlist.startswith("/") else f"/usr/share/wordlists/{wordlist}"

    write_error = _write_temp_file(hash_path, hash_value)
    if write_error:
        return {"success": False, "error": write_error}

    cmd = [
        "hashcat", "-m", str(hash_mode), "-a", "0",
        hash_path, wordlist_path,
        "--potfile-disable", "--quiet",
        "--outfile", out_path, "--outfile-format", "2",
    ]
    crack_result = exec_in_kali(cmd, tool_name="hashcat", target="offline", skip_allowlist=True)
    cat_result = exec_in_kali(["cat", out_path], tool_name="hashcat", target="offline", skip_allowlist=True)
    plaintext = cat_result.output.strip() or None
    cracked   = plaintext is not None

    try:
        get_container().exec_run(["sh", "-c", f"rm -f {hash_path} {out_path}"])
    except RuntimeError:
        pass

    credential_id = save_credential(
        target="offline", service="hash-crack", username="",
        hash_type=f"hashcat-mode-{hash_mode}",
        hash_value=hash_value, cracked_plaintext=plaintext,
    )
    audit.info(
        "HASH_CRACK_ATTEMPT | tool=hashcat mode=%s cracked=%s credential_id=%s",
        hash_mode, cracked, credential_id,
    )

    return {
        "tool": "hashcat", "success": crack_result.success, "cracked": cracked,
        "credential_id": credential_id, "plaintext": plaintext,
        "raw_output": crack_result.output,
    }


@mcp.tool()
def search_exploit(query: str) -> dict[str, Any]:
    """
    Searches Exploit-DB for public exploits matching a product/version or
    CVE, using searchsploit. Called automatically at the end of scan_nuclei
    and scan_ports_nmap for any CVE identifiers found in their output.

    Args:
        query: Product/version or CVE. E.g.: "wordpress 6.2", "CVE-2023-1234"
    """
    result = exec_in_kali(
        ["searchsploit", "--json", query], tool_name="searchsploit", target="offline", skip_allowlist=True,
    )
    exploits: list[dict[str, Any]] = []
    if result.output:
        try:
            parsed = json.loads(result.output)
            exploits = parsed.get("RESULTS_EXPLOIT", [])
        except json.JSONDecodeError:
            exploits = []

    return {
        "tool": "searchsploit", "query": query, "success": result.success,
        "exploits_found": len(exploits), "exploits": exploits,
        "raw_output": result.output,
    }


def extract_cves(text: str) -> list[str]:
    """Unique CVE identifiers found in `text`, in first-seen order."""
    seen: list[str] = []
    for match in _CVE_RE.finditer(text or ""):
        cve = match.group(0).upper()
        if cve not in seen:
            seen.append(cve)
    return seen


def suggest_exploits_for_output(target: str, tool_source: str, output: str) -> list[dict[str, Any]]:
    """
    Extracts CVE identifiers from a scan's output and looks each one up via
    search_exploit(), persisting any hits to the exploits table. Capped at
    _MAX_AUTO_SUGGESTED_CVES to bound the extra latency this adds to the
    calling scan. Never raises — a lookup failure just yields no suggestion
    for that CVE.
    """
    suggestions: list[dict[str, Any]] = []
    for cve in extract_cves(output)[:_MAX_AUTO_SUGGESTED_CVES]:
        try:
            found = search_exploit(cve)
        except Exception:
            continue
        for exploit in found.get("exploits", []):
            exploit_db_id = str(exploit.get("EDB-ID") or exploit.get("id") or "")
            save_exploit(target=target, cve=cve, exploit_db_id=exploit_db_id, tool_source=tool_source)
        if found.get("exploits_found"):
            suggestions.append({"cve": cve, "exploits_found": found["exploits_found"], "exploits": found["exploits"]})
    return suggestions
