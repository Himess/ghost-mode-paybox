# ADR 0002: Use Alchemy as the chain-data provider for exposure scans and indexing

- Date: 2026-10-17
- Status: Accepted
- Decided by: Semih (Himess)

## Context

Two components need historical Base data:

- The indexer rebuilds the pool state from `GhostPool` events (`eth_getLogs` from
  `POOL_DEPLOY_BLOCK` to head).
- The exposure scan (R11) needs the full USDC transfer history of the user's own wallet.

Options checked on 2026-10-17:

| Provider | Finding |
| --- | --- |
| base.blockscout.com | API calls return HTTP 403 behind a Cloudflare challenge. |
| Blockscout PRO API | Needs an API key or an x402 payment: 0.003 USDC per call, x402 v2 `payment-required` header. |
| mainnet.base.org | Rate-limited. |
| drpc | `eth_getLogs` range capped at 10,000 blocks. |
| Tenderly | `eth_getLogs` range capped at 1,000 blocks. |
| publicnode | Archive access needs a token. |
| Envio HyperSync | Now needs a token. |
| Etherscan V2 | Free tier does not cover Base. |
| Alchemy | `eth_getLogs` over any block range up to 10,000 results; `alchemy_getAssetTransfers` returns an address's ERC-20 transfer history directly. |

PayBox's own `get_portfolio` returns balances, not transfer history.

## Decision

Use an Alchemy Base mainnet endpoint (`https://base-mainnet.g.alchemy.com/v2/<key>`) for the
indexer, relayer submissions, ASP root updates and the exposure scan.

## Consequences

- The key lives only in the Ghost service (`.secrets/alchemy.txt` outside the repository, or
  the `RPC_URL` environment variable). It is never bundled into the plugin, and the plugin
  never calls Alchemy directly; its only network host is the Ghost service.
- Single-provider dependency. `RPC_URL` can point the service at any other JSON-RPC provider;
  without a key the service falls back to `mainnet.base.org`, which is only adequate for short
  block ranges.
- Free-tier quotas apply; the indexer polls every 5 seconds and caches block timestamps.

## Alternatives considered

- Blockscout PRO with per-call x402 payments: workable and on-theme, but adds cost and latency
  to every scan and needs a paying wallet in the service.
- Public RPCs with range chunking: too slow or rate-limited for full-history scans.
