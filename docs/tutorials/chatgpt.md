# Connecting ChatGPT (remote, via Cloudflare Tunnel)

> **Verification status:** this guide follows OpenAI's documented pattern
> for custom MCP connectors (HTTPS + OAuth 2.1, same shape as Claude
> Desktop's), against the same server this project already exposes — but
> unlike the [Claude Desktop guide](./claude-desktop.md), it has not yet
> been exercised end-to-end against a live ChatGPT connector by this
> project's maintainers. OpenAI's exact UI/menu names can also change
> faster than this doc. If you connect successfully (or hit a snag), please
> open a PR updating this page — see
> [`CONTRIBUTING.md`](../../CONTRIBUTING.md).

**Before this page**, complete [Remote HTTPS
setup](./remote-https-setup.md) — ChatGPT's connector flow, like Claude
Desktop's, requires the server to be reachable over a real public HTTPS
domain (OpenAI's backend performs the OAuth handshake, not your browser
alone — see [why HTTPS is
required](./remote-https-setup.md#why-https-is-required)) with a Cognito
OAuth client already issued.

## Add the connector

1. In ChatGPT, open **Settings → Connectors** (on some plans/accounts this
   lives under a "Beta features" or "Developer mode" toggle first — enable
   it if you don't see Connectors directly).
2. Choose **Add custom connector** / **Create connector** (wording varies
   by ChatGPT version).
3. Fill in:
   - **Name:** `kali-security-bridge`
   - **MCP server URL:** `https://<your-cloudflare-domain>/mcp`
   - Leave any Client ID/Secret fields blank if offered — the server
     supports OAuth dynamic client registration, same as for Claude
     Desktop, so ChatGPT should be able to register itself automatically.
4. Save/continue — ChatGPT should open Cognito's hosted login page. Sign in
   with the email/password from [Remote HTTPS
   setup](./remote-https-setup.md#step-1--create-the-cognito-auth-infrastructure-one-time).
5. Once authenticated, the connector should list this server's 59 tools.

For OpenAI's own, always-current instructions on adding a custom MCP
connector, see their [platform
documentation](https://platform.openai.com/docs) and [help
center](https://help.openai.com/) — search for "connectors" or "MCP".

## Verify

Ask ChatGPT to use a low-risk tool, e.g. `check_target_online` against
`127.0.0.1`, and confirm you get a real tool response rather than a
connector error.

## Troubleshooting

Same root causes as Claude Desktop — see [Remote HTTPS setup's
troubleshooting section](./remote-https-setup.md#troubleshooting) and
[Claude Desktop's troubleshooting section](./claude-desktop.md#troubleshooting):
confirm the tunnel itself is reachable (`curl -I
https://<your-cloudflare-domain>/mcp` → `401`) before assuming the problem
is ChatGPT-specific, and remember the server needs a manual restart after
any code change.

If ChatGPT's connector setup diverges meaningfully from what's described
here (different auth requirements, a rejected callback URL, a different
manifest/discovery expectation), that's exactly the kind of gap this page
exists to get fixed via a PR once someone's actually walked through it.
