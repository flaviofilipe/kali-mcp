# Connecting Claude Code (local, stdio)

This is the simplest path: Claude Code spawns `server.py` itself as a local
subprocess and talks to it over stdin/stdout. No account, no domain, no
OAuth, no TLS — the OS itself is the security boundary (only a process
running as your user can spawn or attach to the server).

Use this when Claude Code runs on the **same machine** as the Kali
container. If it runs elsewhere, see [Remote HTTPS setup](./remote-https-setup.md) instead.

## Prerequisites

- **Docker** + **Docker Compose v2**, with your user able to run `docker`
  (in the `docker` group, or root)
- **[uv](https://docs.astral.sh/uv/)** — manages the Python 3.13
  environment for you, nothing to install manually
- **Claude Code** installed ([docs](https://docs.claude.com/en/docs/claude-code))

## 1. Clone and install dependencies

```bash
git clone <this-repository>
cd kali-mcp
uv sync
```

## 2. Build and start the Kali container

```bash
docker compose build
docker compose up -d

# confirm it's up and healthy
docker ps --filter name=kali-mcp-box
```

The first build takes a while (it compiles/downloads dozens of security
tools, including Metasploit and a full Python venv with angr/Volatility3 —
expect several minutes and a multi-GB image). See the main
[README](../../README.md#starting-the-docker-image) for build-time flags
like `INCLUDE_OFFENSIVE_BINARIES`.

## 3. Register the server with Claude Code

Add it to `~/.mcp.json` (create the file if it doesn't exist):

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

Replace `/absolute/path/to/kali-mcp` with the real path where you cloned
the repo (e.g. `/home/you/mcps/kali-mcp`) — Claude Code needs an absolute
path, not `~` or a relative one.

Alternatively, from inside a Claude Code session in this repo, you can run
`claude mcp add` interactively instead of hand-editing the JSON — see
`claude mcp --help`.

## 4. Restart Claude Code and verify

Restart Claude Code completely (MCP servers are loaded once at startup, not
hot-reloaded). Then ask it something like "list your available tools" or
just try `check_target_online` against `127.0.0.1` — you should see **63
tools** available under `kali-security-bridge`.

## Troubleshooting

**Tools don't show up at all.** Check that `docker ps --filter
name=kali-mcp-box` shows the container as `Up`/`healthy`, and that the
absolute paths in `~/.mcp.json` are correct — a wrong path fails silently
from Claude Code's UI in some versions; running the `args` command by hand
(`uv run --project /path server.py`) will surface the real error.

**Tool count looks stale after you (or a contributor) changed `server.py`
or a file under `tools/`.** Restart Claude Code — like any local stdio MCP
server, the process is spawned once at startup and never reloads code on
its own. This is the single most common "why don't I see my new tool"
issue; it applies just as much to the remote/HTTP path (see [Remote HTTPS
setup's troubleshooting section](./remote-https-setup.md#troubleshooting)).

**`Could not connect to Docker`** — the container isn't running, or your
user can't reach the Docker socket. Run `docker compose up -d` again and
check `groups` includes `docker` (or run as root/via `sudo`, adjusting the
socket permissions accordingly).
