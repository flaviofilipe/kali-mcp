# Responsible Use Notice

`kali-security-bridge` exposes, via MCP, real offensive security tools —
`nmap`, `sqlmap`, `hydra`, `nuclei`, `ffuf`, among others — executed inside a
Kali Linux container. This is not a toy: using it against a target without
authorization is a crime in most jurisdictions (in Brazil, for instance, it
can fall under Law 12.737/2012 and the Marco Civil da Internet; in the US,
the Computer Fraud and Abuse Act; and equivalent computer-misuse statutes
apply in most other countries).

## Only use it on

- Systems you own, **or**
- Environments with explicit, written authorization (a pentest agreement,
  a bug bounty with a defined scope, your own lab)

## Controls already implemented in the project

- **Mandatory allowlist** (`manage_allowlist`) — no scan runs against a
  target that hasn't been explicitly added beforehand
- **Per-tool rate limiting**, to prevent accidental load spikes
- **Local audit log** (`~/.kali-mcp/audit.log`) of every execution
- Execution via `docker exec` with an argument list (no `/bin/sh`),
  eliminating shell injection through the parameters passed to the tools

These controls reduce the risk of **accidental misuse**, but they do not
replace explicit authorization — the allowlist only prevents repeating a
mistaken target, it doesn't verify that you have permission to test it.

## Reporting vulnerabilities in this project itself

If you find a security flaw in this server's own code (e.g., an allowlist
bypass, a container escape, injection via tool parameters), open a private
issue or contact the maintainer directly — do not open a public issue with
exploitation details before a fix is available.
