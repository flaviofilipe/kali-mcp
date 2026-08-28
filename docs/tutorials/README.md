# Tutorials — connecting an AI client to kali-security-bridge

This project runs as a standard [MCP](https://modelcontextprotocol.io)
server and can be connected to any MCP-compatible client. There are two
fundamentally different ways to connect, and the tutorial you need depends
on which one applies to you:

| Your situation | Transport | Tutorial |
|---|---|---|
| The AI client runs **on the same machine** as this server (or you're fine opening a terminal there) | Local `stdio` — the client spawns `server.py` directly as a subprocess. No network, no auth, no TLS. | [Claude Code](./claude-code.md) |
| The AI client runs **on a different machine/device** than the server (your laptop, phone, a hosted client, etc.) | Remote HTTP with OAuth, exposed over a public HTTPS tunnel | [Remote HTTPS setup](./remote-https-setup.md) (one-time infra), then a per-client connector guide below |

Remote/HTTPS client guides (all assume you've completed
[Remote HTTPS setup](./remote-https-setup.md) first):

- [Claude Desktop](./claude-desktop.md)
- [ChatGPT](./chatgpt.md)

More clients (e.g. other MCP-compatible desktop apps, Cursor, Windsurf,
custom agents) follow the exact same remote-HTTPS pattern — the only
client-specific part is "where do I paste the server URL and click
connect." If you get one working with a client not listed here, a PR adding
`docs/tutorials/<client>.md` (copy an existing one as a template) is very
welcome — see [`CONTRIBUTING.md`](../../CONTRIBUTING.md).

## Why two paths at all?

Local `stdio` is simpler (no cloud account, no domain, no OAuth) but only
works when the client and the server are the same machine, because it's
literally the client spawning a child process and talking to it over
stdin/stdout — there is no network hop for anything to intercept, and
consequently no need for authentication or TLS. Where MCP clients often run
inside the same terminal/IDE process (like Claude Code) or as a Desktop app
on that same box, this is the right choice, and it's the fastest to get
running.

The remote path exists because some clients run on hardware that isn't the
one hosting your Kali container and your Docker socket — most commonly,
Claude Desktop or ChatGPT running on your day-to-day laptop, while the
actual pentest toolkit runs on a lab machine, a home server, or a cloud VM.
See [Remote HTTPS setup](./remote-https-setup.md#why-https-is-required) for
exactly why HTTPS (and not, say, a plain HTTP port or a VPN-only address)
is a hard requirement for this path, not just a recommendation.
