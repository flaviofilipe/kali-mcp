# kali-security-bridge

An [MCP](https://modelcontextprotocol.io) server that gives Claude (or any
MCP-compatible AI agent) a complete offensive security testing toolkit —
reconnaissance, enumeration, web analysis, and exploitation — running
inside an isolated Kali Linux container, with a mandatory target allowlist,
rate limiting, and a full audit log.

In short: **AI-driven penetration testing automation**, safely sandboxed in
Docker, exposed as MCP tools so Claude Code or Claude Desktop can run a full
web app / WordPress / network pentest — Nmap port scanning, Nikto and Nuclei
vulnerability scanning, Gobuster/ffuf directory brute forcing, SQLMap SQL
injection testing, Hydra credential brute forcing, WPScan WordPress
auditing, and automated Markdown/JSON reporting — all from a chat
conversation.

> ⚠️ Read [`SECURITY.md`](./SECURITY.md) before using this. This project runs
> real offensive tools (`hydra`, `sqlmap`, malicious file upload as a PoC,
> etc.) — only ever against targets you have explicit authorization to test.

## Table of contents

- [Architecture and infrastructure](#architecture-and-infrastructure)
- [Minimum requirements](#minimum-requirements)
- [Tools available in the container](#tools-available-in-the-container)
- [Starting the Docker image](#starting-the-docker-image)
- [Connecting to Claude Code (local, stdio)](#connecting-to-claude-code-local-stdio)
- [Connecting to Claude Desktop (remote, via Cloudflare Tunnel)](#connecting-to-claude-desktop-remote-via-cloudflare-tunnel)
- [MCP tools — reference and usage examples](#mcp-tools--reference-and-usage-examples)
- [Local data](#local-data-outside-the-repository)

## Architecture and infrastructure

```
Claude (Code / Desktop)
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
| **Cloudflare Tunnel** (`cloudflared`) | remote mode | Exposes the server on a real public domain with valid TLS. **Needed even for personal remote use**: Claude Desktop's OAuth registration is done by *Anthropic's backend*, which can't reach domains that only exist on private DNS/VPN (e.g. Tailscale's `.ts.net`) |

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
| `nikto` | Web vulnerability scanning |
| `testssl.sh` | SSL/TLS analysis |
| `wpscan` | WordPress security auditing |
| `sqlmap` | SQL injection testing |
| `hydra` | Credential brute forcing |
| `gobuster`, `dirb` | Directory enumeration |
| `ffuf` | Fast fuzzing |
| `mariadb-client` | Direct MySQL/MariaDB enumeration |
| `curl`, `wget`, `chromium` | HTTP requests / rendering |

Compiled from source in a separate Go builder stage (`golang:1.24-bookworm`),
with only the final binaries copied into the image (keeps the final image lean):

| Tool | Category |
|---|---|
| `subfinder` | Subdomain enumeration |
| `katana` | Web application crawling |
| `nuclei` | Template-based CVE detection (updated at build time) |
| `dalfox` | XSS detection |
| `gowitness` | Screenshot evidence capture |
| `httpx` | Batch HTTP probing |

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

Rebuilding periodically is recommended — the image doesn't update itself,
and the Nuclei templates/`apt` packages stay frozen at build time.

## Connecting to Claude Code (local, stdio)

1. Install the Python dependencies:
   ```bash
   uv sync
   ```
2. Confirm the container is running (`docker ps --filter name=kali-mcp-box`).
3. Register the server in `~/.mcp.json`:
   ```json
   {
     "mcpServers": {
       "kali-security-bridge": {
         "command": "uv",
         "args": ["run", "--project", "/absolute/path/to/kali-mcp", "/absolute/path/to/kali-mcp/server.py"]
       }
     }
   }
   ```
4. Restart Claude Code. All 25 tools should show up as available.

In this mode, **there is no authentication** — the OS itself controls who
can spawn the process, and `KALI_MCP_TRANSPORT` stays at `stdio` (the
default, nothing to set).

## Connecting to Claude Desktop (remote, via Cloudflare Tunnel)

Use this path when Claude Desktop runs on a different machine than the
server/container. Desktop's native "Connectors" flow requires the server
to: (a) be on HTTPS with a publicly resolvable domain, and (b) implement
OAuth with dynamic client registration (RFC 7591) — both come ready-made
here via FastMCP + AWS Cognito.

### 1. Create the auth infrastructure (one time)

```bash
# User Pool with self-signup disabled — only you (or anyone added
# manually) can log in
aws cognito-idp create-user-pool \
  --pool-name kali-mcp-bridge \
  --auto-verified-attributes email \
  --admin-create-user-config AllowAdminCreateUserOnly=true \
  --region us-east-1

# Hosted UI (login) domain
aws cognito-idp create-user-pool-domain \
  --domain <your-unique-prefix> \
  --user-pool-id <POOL_ID> \
  --region us-east-1

# App Client with a secret
aws cognito-idp create-user-pool-client \
  --user-pool-id <POOL_ID> \
  --client-name kali-mcp-bridge-client \
  --generate-secret \
  --allowed-o-auth-flows code \
  --allowed-o-auth-scopes openid email profile \
  --allowed-o-auth-flows-user-pool-client \
  --callback-urls "https://<your-cloudflare-domain>/auth/callback" \
  --supported-identity-providers COGNITO \
  --region us-east-1

# your user (self-signup is off, so only an admin can create one)
aws cognito-idp admin-create-user \
  --user-pool-id <POOL_ID> \
  --username your-email@example.com \
  --user-attributes Name=email,Value=your-email@example.com Name=email_verified,Value=true \
  --message-action SUPPRESS --region us-east-1

aws cognito-idp admin-set-user-password \
  --user-pool-id <POOL_ID> --username your-email@example.com \
  --password '<strong-password>' --permanent --region us-east-1
```

### 2. Start the Cloudflare tunnel

```bash
# quick test, no account/domain needed (temporary *.trycloudflare.com URL)
cloudflared tunnel --url http://127.0.0.1:8765

# for production: create a named tunnel with your own domain
# https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/
```

Note the generated URL (e.g. `https://some-random-words.trycloudflare.com`) —
it changes every time a Quick Tunnel restarts. For permanent use, use a
named tunnel with a fixed domain.

### 3. Configure and start the server in HTTP mode

Environment variables (via a local `.env`, or set directly):

```bash
KALI_MCP_TRANSPORT=http
KALI_MCP_HOST=127.0.0.1        # bind loopback only — the Cloudflare Tunnel exposes it externally
KALI_MCP_PORT=8765
KALI_MCP_PUBLIC_URL=https://<tunnel-url>
COGNITO_USER_POOL_ID=<POOL_ID>
COGNITO_REGION=us-east-1
COGNITO_CLIENT_ID=<CLIENT_ID>
COGNITO_CLIENT_SECRET=<CLIENT_SECRET>
```

```bash
uv run --project . server.py
```

To keep it running persistently on Linux, use a `systemd --user` service
with `EnvironmentFile` pointing at the `.env` and `Restart=on-failure` —
see the commented example in the repository (not checked in, specific to
each deployment).

### 4. Add the connector in Claude Desktop

In Desktop's settings, under Connectors → **Add custom connector**:

- **Name:** `kali-security-bridge`
- **URL:** `https://<tunnel-url>/mcp`
- Leave the advanced settings blank — OAuth registration is automatic
  (dynamic client registration), no manual Client ID needed

You'll be redirected to Cognito's hosted login screen. Once authenticated,
all 25 tools become available as usual.

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

### Reconnaissance

**`scan_ports_nmap`** — port scanning, always the first phase
```python
scan_ports_nmap(target="192.168.1.10", flags="-sV -F")
scan_ports_nmap(target="192.168.1.10", flags="-p 1-65535 -sV", stealth=True)
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

### Orchestration

**`run_full_pentest`** — autonomous end-to-end pipeline (16 phases)
```python
run_full_pentest(target="192.168.1.10")
run_full_pentest(target="example.com", target_url="https://example.com", include_brute_force=True, evasion=True)
```

## Local data (outside the repository)

| Path | Contents |
|---|---|
| `~/.kali-mcp/findings.db` | SQLite database with all findings per target |
| `~/.kali-mcp/audit.log` | Audit log of every execution |
| `~/.kali-mcp/workspaces/` | Reports generated by `generate_report` |
| `~/mcps/outputs/kali-mcp/<target>/` | Raw output of each scan + `session.json` (enables resuming via `resume_session`) |

## License

[MIT](./LICENSE)
