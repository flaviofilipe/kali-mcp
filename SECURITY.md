# Responsible Use Notice

`kali-security-bridge` exposes, via MCP, real offensive security tools —
`nmap`, `sqlmap`, `hydra`, `nuclei`, `ffuf`, `metasploit-framework`,
`impacket`, `netexec`, `bloodhound-python`, `chisel`, `ligolo-ng`, and many
others — executed inside a Kali Linux container. This is not a toy: using
it against a target without authorization is a crime in most jurisdictions
(in Brazil, for instance, it can fall under Law 12.737/2012 and the Marco
Civil da Internet; in the US, the Computer Fraud and Abuse Act; and
equivalent computer-misuse statutes apply in most other countries).

## Only use it on

- Systems you own, **or**
- Environments with explicit, written authorization (a pentest agreement,
  a bug bounty with a defined scope, your own lab)

## Controls already implemented in the project

- **Mandatory allowlist** (`manage_allowlist`) — no scan runs against a
  target that hasn't been explicitly added beforehand. Hostname entries
  match only on an exact match or a dot-bounded subdomain suffix (never a
  raw substring); IP/CIDR entries are compared as real network membership.
  This applies to every tool, including sessions (`session_exec`
  revalidates the session's target on every call, not just when it was
  opened) and pivoting — opening a `chisel`/`ligolo-ng` tunnel never adds
  anything to the allowlist, so a host only reachable through the tunnel
  still needs its own entry before any tool can scan it.
- **Confirmation gate on high-risk actions** — `request_high_risk_action()`
  issues a short-lived (10 minute), single-use token bound to an exact
  `(action, target)` pair. The following tools refuse to run without a
  valid `confirmation_token`:
  - `impacket_secretsdump` — dumps SAM/LSA/NTDS credential material
  - `impacket_psexec` — lateral movement via the SMB admin share
  - `run_mimikatz` — extracts credentials/hashes/tickets from memory
  - `enum_ad_netexec` in `sam`/`lsa`/`ntds`/`exec` modes
  - `start_chisel_tunnel` / `start_ligolo_tunnel` — opening a pivot into an
    internal network
- **Per-tool rate limiting**, to prevent accidental load spikes — tuned per
  category (offline hash cracking is more permissive than network brute
  forcing or Metasploit).
- **Local audit log** (`~/.kali-mcp/audit.log`) of every execution, with
  sensitive fields (passwords, hashes, tokens, credentials) redacted before
  logging — e.g. a password appears as `pa***23`, never in the clear.
- **Encrypted credential storage** — the `credentials` table in
  `~/.kali-mcp/findings.db` (hash values and cracked plaintext) is
  encrypted at rest with a local [Fernet](https://cryptography.io/en/latest/fernet/)
  key generated on first use at `~/.kali-mcp/secret.key` (created with
  `0600` permissions). **Anyone with both that key file and the database
  can decrypt stored credentials — treat `~/.kali-mcp/` as a secret
  directory**, back it up carefully, and never commit it or attach it to a
  bug report. Bulk queries (`list_credentials`) never return the encrypted
  columns; only fetching a specific credential by ID decrypts it.
- Execution via `docker exec` with an argument list (no `/bin/sh`),
  eliminating shell injection through the parameters passed to the tools.

These controls reduce the risk of **accidental misuse**, but they do not
replace explicit authorization — the allowlist only prevents repeating a
mistaken target, it doesn't verify that you have permission to test it.

## Higher-risk tools worth calling out explicitly

Beyond the original tool set, this project now includes several tools whose
blast radius is meaningfully larger than a read-only scan. All of them sit
behind the allowlist, and the ones marked ⚠️ also require the confirmation
gate described above:

| Tool | Risk |
|---|---|
| `impacket_secretsdump` ⚠️ | Extracts SAM/LSA secrets and NTDS.dit hashes — full credential material for the target domain if run against a DC |
| `impacket_psexec` ⚠️ | Arbitrary command execution on the target via the SMB admin share |
| `run_mimikatz` ⚠️ | Extracts plaintext passwords, hashes, and Kerberos tickets from LSASS memory |
| `start_chisel_tunnel` / `start_ligolo_tunnel` ⚠️ | Opens routed network access into whatever's behind the pivot host — treat like extending your scope, not a single scan |
| `enum_ad_netexec` (sam/lsa/ntds/exec modes) ⚠️ | Same class of risk as secretsdump/psexec, via netexec instead |
| `metasploit_run_module` | Exploit modules can crash the target service or leave artifacts; start with `auxiliary`/scanner modules |
| `brute_force_hydra`, `crack_hash_john`, `crack_hash_hashcat` | May lock accounts (network brute force) or take real CPU time; hash cracking is offline and low-risk to the target itself |
| `analyze_binary_angr`, `exploit_pwntools_helper` | Execute caller-supplied Python inside the container, sandboxed only by the container itself — review any generated script before running it |
| `test_file_upload` | Creates a harmless PHP file on the test server as PoC evidence |

## Mimikatz — opt-in only

Mimikatz is **not included in the image by default**. It's frequently
flagged by antivirus and blocked by some container registry policies, so
it's staged only when explicitly requested at build time:

```bash
docker compose build --build-arg INCLUDE_OFFENSIVE_BINARIES=true
```

`run_mimikatz()` checks for the binary at build time and refuses to run
with a clear error if the image was built without this flag.

## Supply-chain note: verify package names before installing them

While building the Docker image for this project, we found that the PyPI
package literally named `graphw00f` is **not** the real GraphQL-fingerprinting
tool — it's an inert placeholder ("Inert defensive-hold placeholder... NOT
the real graphw00f tool... registered to prevent dependency-confusion /
skilljacking abuse of an unclaimed PyPI name") registered specifically to
stop exactly this kind of mistake. The real tool only exists as a GitHub
repository (`github.com/dolevf/graphw00f`) and is what this project's
Dockerfile actually clones and pins to a specific tag.

The general lesson: **never assume a tool name mentioned in documentation
(including this project's own) maps 1:1 to an official package on PyPI/npm/
etc. — check first**, especially for security tooling, where a squatted
package name is a realistic supply-chain attack vector.

## Reporting vulnerabilities in this project itself

If you find a security flaw in this server's own code (e.g., an allowlist
bypass, a container escape, injection via tool parameters, a way to bypass
the confirmation gate, or a credential leaking into the audit log or a
non-encrypted store), open a private issue or contact the maintainer
directly — do not open a public issue with exploitation details before a
fix is available.
