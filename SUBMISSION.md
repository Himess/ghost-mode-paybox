# Submission checklist (developer portal)

## 1. Project fields

- **Project name** (47/80): `Ghost Mode — private USDC for your PayBox agent`
- **What does your project do?** (250/280):
  `Gives your PayBox agent a private USDC balance on Base. Shield once, then pay addresses, friends or x402 APIs without linking your wallet: each spend is one PayBox signature verified inside a ZK proof. Plus an exposure scan of what your wallet leaks.`
- **Built plugin file**: `ghost-mode/plugin/dist/plugin.mjs` (only this file; no source maps, no `.env`).

## 2. Test & configure

| Setting | Value |
| --- | --- |
| Network host | the tunnel hostname, e.g. `achieving-window-commissioner-welding.trycloudflare.com` (exact host, no `https://`) |
| Environment variable `GHOST_SERVICE_URL` | `https://<same hostname>` |
| Environment variable `GHOST_POOL_ADDRESS` | the GhostPool the service reports in `/v1/info` (the plugin refuses a service that reports another pool) |
| Secrets | none required. Optional hardening: set `SERVICE_TOKEN` on the service and add a Secret for the service host with header `Authorization`, value `Bearer <token>`. |

After changing settings wait 30 seconds, then **Run checks again**, **Load tools** and run `ghost_setup` with `{}` (returns a message to sign; no network).

## 3. Tools (12)

`ghost_setup`, `ghost_address`, `ghost_recover`, `ghost_shield_authorize` (one signature, no ETH), `ghost_shield` (fallback: approve + deposit proposals), `ghost_balance`, `ghost_prepare`, `ghost_submit`, `ghost_job`, `ghost_exposure`, `ghost_report`, `ghost_receipt`.

## 4. Human contribution

Product concept, the design brief (decisions D1–D12), the "full ZK pool" scope decision, the data-provider choice and the approval of the review sprint plan are Semih's (see `docs/adr/`, "Decided by"). Implementation was done with Claude Code; an external design review was done with Claude (claude.ai) and is published in `docs/REVIEW-FOR-CLAUDE-WEB.md`.

## 5. Submit

Accept the MoonPay Hackathon Terms & Conditions and select **Submit Project** before Saturday 8pm New York time (00:00 UTC). Network hosts and variables can still be edited after the deadline (for example when the tunnel hostname changes); the code cannot.

## 6. Use it through an agent

Enable it under **Unofficial plugins** in PayBox, connect Claude (or another MCP host) to PayBox, then follow `docs/DEMO.md`.
