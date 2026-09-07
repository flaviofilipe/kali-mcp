# Contributing

## Module map

`server.py` is a thin entrypoint only — it builds nothing itself. It
imports `core.config.mcp` (the shared FastMCP app instance) and every
`tools/*.py` module (which register their functions against that app via
`@mcp.tool()` as a side effect of being imported), then calls `mcp.run()`.

```
kali-mcp/
├── server.py                  # entrypoint: imports core.config.mcp + tools/*, calls mcp.run()
├── core/
│   ├── config.py               # the shared `mcp` app instance, paths, env vars, constants
│   ├── docker_exec.py          # get_container(), exec_in_kali() (execve, no shell), write_file()
│   ├── security.py             # is_allowed() (allowlist), rate_limit(), confirmation gate
│   ├── audit.py                # audit logger + redact()
│   └── db.py                   # SQLite schema + access (findings, allowlist, sessions,
│                                # credentials, exploits, high_risk_confirmations)
├── tools/
│   ├── governance.py            # manage_allowlist, check_target_online, resume_session,
│   │                             # list_findings, generate_report, request_high_risk_action,
│   │                             # run_full_pentest (orchestration)
│   ├── recon.py                 # scan_ports_nmap, enum_subdomains_subfinder
│   ├── ftp.py                    # enumerate_ftp
│   ├── web.py                   # gobuster, katana, ffuf, nikto, testssl, nuclei, dalfox,
│   │                             # wpscan, xmlrpc, check_security_headers, check_exposed_files,
│   │                             # screenshot_gowitness, make_http_request
│   ├── exploitation.py          # sqlmap, hydra, test_file_upload, enumerate_mysql_database,
│   │                             # metasploit_generate_payload, metasploit_run_module
│   ├── credentials.py           # identify_hash, crack_hash_john, crack_hash_hashcat,
│   │                             # search_exploit, CVE auto-suggest helper
│   ├── sessions.py               # start_reverse_shell_listener, connect_telnet, session_exec,
│   │                             # session_status, session_close, session_list,
│   │                             # open_tmux_session() (shared)
│   ├── active_directory.py       # enum_smb_shares, enum_ad_netexec, bloodhound_collect,
│   │                             # impacket_secretsdump, impacket_psexec, evil_winrm_connect
│   ├── post_exploitation.py      # run_linpeas, run_winpeas, run_mimikatz
│   ├── pivoting.py               # start_chisel_tunnel, start_ligolo_tunnel,
│   │                             # pivot_scan_via_proxychains
│   ├── forensics.py              # analyze_memory_volatility, disassemble_binary_r2,
│   │                             # debug_binary_gdb, extract_binwalk
│   ├── crypto_binary.py          # analyze_binary_angr, exploit_pwntools_helper (EXPERIMENTAL)
│   └── secrets_js.py             # scan_secrets_trufflehog, scan_js_secretfinder, analyze_jwt,
│                                  # fingerprint_graphql_graphw00f
├── reports/
│   └── generator.py              # pure Markdown/JSON report formatting, no I/O
├── tests/
│   ├── unit/                     # mock docker.from_env()/container.exec_run() — no real Docker
│   ├── security/                 # allowlist bypass, redaction, rate limit, confirmation gate
│   └── integration/               # run against docker-compose.test.yml's ephemeral lab
├── Dockerfile
├── docker-compose.yml            # production container (kali-mcp-box)
├── docker-compose.test.yml       # ephemeral test lab (kali-mcp-box-test + vulnerable targets)
├── .github/workflows/test.yml
├── pyproject.toml
├── README.md
├── SECURITY.md
└── CONTRIBUTING.md               # this file
```

## Adding a new tool

1. **Pick the right module** in `tools/` by category (see the map above —
   create a new module only if the tool genuinely doesn't fit an existing
   category).
2. **Never duplicate allowlist/rate-limit/audit logic.** Every tool that
   touches the container goes through `core.docker_exec.exec_in_kali(cmd,
   tool_name=..., target=...)`, which already applies the allowlist check,
   rate limiting, and audit logging. If your tool doesn't target a live
   network host (offline hash cracking, analyzing a file already inside the
   container), pass `skip_allowlist=True` and use a descriptive
   `target=` value for logging (e.g. `"offline"`), not a made-up hostname.
3. **Add a rate limit entry** in `core.security.RATE_LIMITS` for your
   `tool_name`, sized to the tool's real cost (offline/CPU-bound work can be
   more permissive than anything hitting a network target).
4. **Gate high-risk actions.** If the tool dumps credentials, executes code
   on a remote host, or otherwise has a meaningfully bigger blast radius
   than a scan, add a `confirmation_token: str` parameter and call
   `core.security.consume_confirmation(confirmation_token, "<tool_name>",
   target)` before doing anything — return its error message directly if it
   fails. Document in the docstring that the caller needs
   `request_high_risk_action(action="<tool_name>", ...)` first.
5. **Never log secrets.** If you're logging tool parameters (beyond what
   `exec_in_kali` already logs — tool/target/exit_code/success), pass them
   through `core.audit.redact()` first. Store any credential material via
   `core.db.save_credential()` (encrypted at rest), never as a raw string
   in a log line or a plain DB column.
6. **Register the module** in `server.py`'s import block (only needed once
   per module, not per tool — importing the module registers every
   `@mcp.tool()` in it).
7. **Write a test.** `tests/unit/` for parsing/formatting logic and the
   allowlist/confirmation-gate branches (mock `docker.from_env()` via the
   `fake_container`/`allowlist_db`/`no_rate_limit` fixtures in
   `tests/unit/conftest.py`); add an integration test in
   `tests/integration/` if there's a real lab target it can run against
   (see `docker-compose.test.yml`).
8. **Install the underlying binary in the Dockerfile**, in whichever stage
   fits (`apt`, the Go builder, the `uv`-managed Python venv, or a
   pinned-tag git clone), and add it to the tables in `README.md`. Pin a
   specific version/tag/commit — never `@latest` or an unpinned branch, for
   reproducible builds. **Verify the package actually exists under that
   name on PyPI/the Go module proxy/npm before wiring it up** — see
   SECURITY.md's note on the `graphw00f` PyPI decoy package, found the hard
   way while building this project's own image.
9. **Update `README.md`**'s tool table and the "MCP tools — reference and
   usage examples" section with your tool's signature and an example call.

## Running the tests locally

```bash
uv sync --group dev

# fast, no Docker:
uv run ruff check .
uv run pytest tests/unit tests/security -v

# slow, needs Docker — builds the test image and brings up the lab:
docker compose -f docker-compose.test.yml up -d --build
uv run pytest tests/integration -v
docker compose -f docker-compose.test.yml down -v
```

CI (`.github/workflows/test.yml`) runs the fast suite on every PR, and the
integration suite on push to `main` or when a PR carries the
`run-integration` label.

## Adding a tutorial for a new AI client

Client setup guides live in [`docs/tutorials/`](./docs/tutorials/), one
file per client, so `README.md` stays a short index rather than growing a
new multi-paragraph section for every client that speaks MCP. To add one:

1. If the client connects over local `stdio` (client and server on the
   same machine), copy [`docs/tutorials/claude-code.md`](./docs/tutorials/claude-code.md)
   as a template.
2. If it connects remotely over HTTPS/OAuth (client on a different
   machine), copy [`docs/tutorials/claude-desktop.md`](./docs/tutorials/claude-desktop.md)
   or [`docs/tutorials/chatgpt.md`](./docs/tutorials/chatgpt.md) as a
   template — keep the shared Cognito/Cloudflare setup itself in
   [`docs/tutorials/remote-https-setup.md`](./docs/tutorials/remote-https-setup.md)
   rather than repeating it; your new file should only cover the
   client-specific "where do I paste the URL" steps and link back to it.
3. Add a row for it in [`docs/tutorials/README.md`](./docs/tutorials/README.md)'s
   index table and in the table in `README.md`'s "Tutorials" section.
4. If you tested it end-to-end yourself, say so in the guide (see how
   `claude-desktop.md` and `chatgpt.md` differ on this) — don't claim a
   flow works unless you've actually walked through it.
