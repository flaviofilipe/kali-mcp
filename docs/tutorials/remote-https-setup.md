# Remote HTTPS setup (Cloudflare Tunnel + AWS Cognito OAuth)

This is the one-time infrastructure setup for connecting an AI client that
runs on a **different machine** than your Kali container — most commonly
Claude Desktop or ChatGPT on your everyday laptop/phone, while the actual
toolkit runs on a lab box, home server, or cloud VM you control.

Once this is done, jump to the client-specific guide to actually add the
connector:

- [Claude Desktop](./claude-desktop.md)
- [ChatGPT](./chatgpt.md)

If your client runs on the *same* machine as the server, you don't need any
of this — use [Claude Code's local stdio setup](./claude-code.md) instead,
which has none of the moving parts below.

## Why HTTPS is required

This isn't a preference or a hardening recommendation — it's a hard
technical requirement, for two independent reasons:

**1. The OAuth handshake happens between the client vendor's own backend
and your server, not just inside your browser.** Both Claude Desktop and
ChatGPT implement the MCP remote-server flow the same way: when you add a
custom connector, *Anthropic's or OpenAI's own infrastructure* — not your
laptop — performs OAuth 2.1 dynamic client registration ([RFC
7591](https://www.rfc-editor.org/rfc/rfc7591)) against your server's
`/.well-known/oauth-authorization-server` and token endpoints, then later
exchanges authorization codes for tokens, also server-to-server. That
backend lives on the public internet. It cannot resolve or route to a
`localhost` address, a LAN IP, a Tailscale MagicDNS name (`*.ts.net`), a
WireGuard peer, or anything else that only exists on a private network —
only a real, publicly-resolvable domain works. This is the actual reason a
personal VPN/mesh network (Tailscale, ZeroTier, etc.) is not a substitute
here, no matter how convenient it is for everything else.

**2. Valid TLS is required for the same reason any OAuth provider requires
it:** tokens and authorization codes are bearer credentials in transit, and
neither vendor's backend will complete an OAuth flow, nor will the
in-app/browser login redirect succeed, against a plain-HTTP endpoint or a
self-signed certificate. You need a certificate a normal HTTPS client
trusts — Cloudflare Tunnel provides one for free, on a domain it manages
for you, with zero certificate handling on your end.

Put together: **local stdio has neither of these problems** because
there's no network hop at all (the client spawns the server directly), so
it needs neither OAuth nor TLS. The moment the client is a separate
machine, both become unavoidable — this applies to any client that follows
the standard MCP remote-auth flow, not just the two documented today, so
treat this page as the shared prerequisite for all of them.

## Architecture

```
Claude Desktop / ChatGPT (their backend performs the OAuth handshake)
        │  HTTPS + OAuth 2.1 (dynamic client registration)
        ▼
https://<your-tunnel>.trycloudflare.com/mcp
        │  Cloudflare Tunnel (cloudflared) — free TLS, no port-forwarding
        ▼
http://127.0.0.1:8765/mcp  ← server.py bound to loopback only
        │  FastMCP + AWS Cognito (OAuth Authorization Server)
        ▼
   docker exec (no shell) → kali-mcp-box container
```

Nothing here binds to `0.0.0.0` — the server only ever listens on
`127.0.0.1`, and `cloudflared` is what exposes it externally, over a tunnel
it initiates outbound (no inbound firewall rule or port-forward needed on
your router).

## Prerequisites

- Everything from [Claude Code's local setup](./claude-code.md) (Docker,
  `uv`, the container built and running) — this path builds on top of it,
  it doesn't replace it
- An **AWS account** (Cognito's free tier covers 50k MAUs/month — plenty
  for personal use or a small team)
- **AWS CLI** installed and configured (`aws configure`) with permissions
  to create Cognito resources
- **`cloudflared`** installed — see [Cloudflare's install
  docs](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation/).
  No Cloudflare account or domain needed to *try* this (a Quick Tunnel
  works with neither); an account + domain is recommended once you want a
  stable, permanent URL
- **systemd** (`systemctl --user`) if you want this to survive reboots and
  crashes on Linux — on macOS/other OSes, adapt to `launchd` or your
  process manager of choice

## Step 1 — Create the Cognito auth infrastructure (one time)

```bash
# User Pool with self-signup disabled — only you (or anyone you add
# manually) can ever log in
aws cognito-idp create-user-pool \
  --pool-name kali-mcp-bridge \
  --auto-verified-attributes email \
  --admin-create-user-config AllowAdminCreateUserOnly=true \
  --region us-east-1
# note the "Id" field in the output — that's your <POOL_ID> below

# Hosted UI (login page) domain — must be globally unique across all AWS accounts
aws cognito-idp create-user-pool-domain \
  --domain <your-unique-prefix> \
  --user-pool-id <POOL_ID> \
  --region us-east-1

# App Client with a secret, configured for the Authorization Code flow
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
# note "ClientId" and "ClientSecret" from the output — <CLIENT_ID> / <CLIENT_SECRET> below

# Your own login (self-signup is off, so only an admin — you — can create one)
aws cognito-idp admin-create-user \
  --user-pool-id <POOL_ID> \
  --username your-email@example.com \
  --user-attributes Name=email,Value=your-email@example.com Name=email_verified,Value=true \
  --message-action SUPPRESS --region us-east-1

aws cognito-idp admin-set-user-password \
  --user-pool-id <POOL_ID> --username your-email@example.com \
  --password '<strong-password>' --permanent --region us-east-1
```

`<your-cloudflare-domain>` in the callback URL is whatever tunnel URL you
get in Step 2 below — if you're using a Quick Tunnel (URL only known after
you start it), create the user pool client first with a placeholder, start
the tunnel, then `aws cognito-idp update-user-pool-client` with the real
callback URL. A named tunnel (fixed domain, set up before this step) avoids
that back-and-forth entirely.

## Step 2 — Start the Cloudflare Tunnel

```bash
# quick test — no Cloudflare account or domain needed, gives you a
# temporary https://<random-words>.trycloudflare.com URL
cloudflared tunnel --url http://127.0.0.1:8765

# for anything long-lived: create a named tunnel on a domain you control
# https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/
```

Note the URL cloudflared prints — that's `<your-cloudflare-domain>` above
and `KALI_MCP_PUBLIC_URL` below. **A Quick Tunnel's URL changes every time
the `cloudflared` process restarts** — fine for a five-minute test, a real
problem for anything you want to keep working, which is exactly why a named
tunnel (fixed domain) is worth setting up before you rely on this daily.

## Step 3 — Configure the server's environment

Create `.env.cognito` in the repo root (already `.gitignore`d — never
commit this):

```bash
COGNITO_USER_POOL_ID=<POOL_ID>
COGNITO_REGION=us-east-1
COGNITO_CLIENT_ID=<CLIENT_ID>
COGNITO_CLIENT_SECRET=<CLIENT_SECRET>
```

And export (or set in the systemd unit, Step 4) the transport variables:

```bash
KALI_MCP_TRANSPORT=http
KALI_MCP_HOST=127.0.0.1        # loopback only — cloudflared exposes it externally, never bind 0.0.0.0
KALI_MCP_PORT=8765
KALI_MCP_PUBLIC_URL=https://<your-cloudflare-domain>
```

Test it in the foreground first:

```bash
set -a; source .env.cognito; set +a
uv run --project . server.py
```

You should see FastMCP's banner and `Uvicorn running on
http://127.0.0.1:8765`. Leave `cloudflared` (Step 2) running in another
terminal at the same time — both processes need to be up together.

## Step 4 — Keep it running with systemd (recommended)

Stop the foreground run (Ctrl+C) and instead create
`~/.config/systemd/user/kali-mcp-http.service`:

```ini
[Unit]
Description=Kali MCP Bridge (HTTP via Cloudflare Tunnel)
After=docker.service network-online.target
Wants=docker.service network-online.target

[Service]
Type=simple
WorkingDirectory=/absolute/path/to/kali-mcp
Environment=KALI_MCP_TRANSPORT=http
Environment=KALI_MCP_HOST=127.0.0.1
Environment=KALI_MCP_PORT=8765
Environment=KALI_MCP_PUBLIC_URL=https://<your-cloudflare-domain>
EnvironmentFile=/absolute/path/to/kali-mcp/.env.cognito
ExecStart=/absolute/path/to/.local/bin/uv run --project /absolute/path/to/kali-mcp /absolute/path/to/kali-mcp/server.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

Replace every `/absolute/path/to/...` (including `uv`'s own path — check
with `which uv`) and the tunnel URL. Then:

```bash
systemctl --user daemon-reload
systemctl --user enable --now kali-mcp-http.service

# survive reboots even when you're not logged in interactively
loginctl enable-linger "$USER"
```

Keep `cloudflared` running persistently too — either as its own
`systemd --user` unit (same pattern as above, `ExecStart=cloudflared tunnel
--url http://127.0.0.1:8765` for a Quick Tunnel, or `cloudflared tunnel run
<name>` for a named one), or via `cloudflared service install` for a named
tunnel (see Cloudflare's docs).

## Verify it's working

```bash
systemctl --user status kali-mcp-http.service    # should be "active (running)"
curl -I https://<your-cloudflare-domain>/mcp     # expect HTTP 401 — that means
                                                  # the tunnel + server ARE reachable;
                                                  # 401 is "no OAuth token", not a failure
```

A `401` here is success, not an error — it means the request made it all
the way through the tunnel to FastMCP's auth layer, which correctly
rejected it for having no token. A connection error, timeout, or `502`
means the tunnel or the server itself isn't up — check
`systemctl --user status kali-mcp-http.service` and `ps aux | grep
cloudflared`.

Now proceed to your client's guide: [Claude Desktop](./claude-desktop.md) ·
[ChatGPT](./chatgpt.md).

## Troubleshooting

**I updated the code (pulled a new commit, merged a PR, edited a tool
myself) but the client still sees the old tools / old tool count.** Restart
the service — `uv run server.py` is a long-lived process here; it loads
`server.py` once at startup and does not hot-reload when files on disk
change:

```bash
systemctl --user restart kali-mcp-http.service
journalctl --user -u kali-mcp-http.service -n 30 --no-pager   # confirm a clean startup, no crash loop
```

This is the single most common point of confusion when testing changes
against the remote path — the same restart is needed for every code change,
not just the first deploy.

**The tunnel URL changed and the client can't connect anymore.** Expected
if you're using a Quick Tunnel and `cloudflared` restarted (crash, reboot,
manual restart) — a new random URL is issued every time. Either switch to
a named tunnel (stable domain) or, each time the URL changes: update
`KALI_MCP_PUBLIC_URL` in the systemd unit, update the Cognito app client's
callback URL (`aws cognito-idp update-user-pool-client`), restart the
service, and re-add the connector on the client side with the new URL.

**`401 Unauthorized` when the client tries to call a tool, even after
logging in.** Usually a stale/expired token on the client side — remove
and re-add the connector to force a fresh OAuth flow. If it persists,
check `journalctl --user -u kali-mcp-http.service` for the actual OAuth
error FastMCP logs.

**`Could not connect to Docker` inside tool results.** Same root cause and
fix as the local path — see [Claude Code's
troubleshooting](./claude-code.md#troubleshooting). The HTTP/OAuth layer
sits in front of the exact same `server.py` and Docker-exec logic; if
Docker itself isn't reachable, every tool call fails regardless of
transport.
