# Connecting Claude Desktop (remote, via Cloudflare Tunnel)

Use this when Claude Desktop runs on a **different machine** than your Kali
container (the common case — Desktop on your laptop, the server on a lab
box or home server).

**Before this page**, complete [Remote HTTPS
setup](./remote-https-setup.md) — it covers the AWS Cognito + Cloudflare
Tunnel infrastructure this guide assumes is already running, and explains
*why* it's required (short version: Anthropic's backend performs the OAuth
handshake against your server, and it can only reach a real public HTTPS
domain).

## Add the connector

1. Open Claude Desktop → **Settings** → **Connectors** → **Add custom
   connector**.
2. Fill in:
   - **Name:** `kali-security-bridge` (or anything you like — it's just a
     label)
   - **URL:** `https://<your-cloudflare-domain>/mcp`
3. Leave the advanced/Client ID fields blank — the server supports OAuth
   dynamic client registration (RFC 7591), so Desktop registers itself
   automatically. There's nothing to copy-paste from the Cognito setup
   here.
4. Save. Desktop opens Cognito's hosted login page in your browser — sign
   in with the email/password you created in [Remote HTTPS
   setup](./remote-https-setup.md#step-1--create-the-cognito-auth-infrastructure-one-time).
5. On success, you're redirected back and the connector shows as
   connected. All 61 tools become available the same way they would over
   local stdio.

## Verify

Ask Claude something that exercises a tool, e.g. "use check_target_online
against 127.0.0.1" — a real response (not a connector/auth error) confirms
the whole chain (Desktop → Cloudflare Tunnel → FastMCP/Cognito → Docker →
Kali container) is working end to end.

## Troubleshooting

- **Connector won't authenticate / login loop.** Confirm
  `curl -I https://<your-cloudflare-domain>/mcp` returns `401` (not a
  connection error) — see [Remote HTTPS setup's
  troubleshooting](./remote-https-setup.md#troubleshooting). If the tunnel
  itself is fine, double check the callback URL registered on the Cognito
  app client matches your current tunnel URL exactly.
- **Tools missing or the count looks wrong after an update.** The server
  process needs restarting after any code change —
  `systemctl --user restart kali-mcp-http.service` on the machine running
  the server, then remove/re-add the connector in Desktop if it cached an
  old tool list.
- **Everything worked before, stopped today.** If you're using a Quick
  Tunnel, its URL changes on every `cloudflared` restart — see [Remote
  HTTPS setup](./remote-https-setup.md#troubleshooting) for what to update.
