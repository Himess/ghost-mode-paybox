# Ghost Mode for PayBox

*Private by default. Provable on demand.*

Ghost Mode gives a PayBox user a private USDC balance on Base. The agent can shield funds,
pay an address, send to another Ghost user or pay an x402 API without the user's address
appearing in the spend. Every private spend is authorised by one PayBox wallet signature that
is verified inside a zero-knowledge proof, so the PayBox key never leaves PayBox.

> **Warning: experimental, unaudited, capped.** Contracts are unaudited and run on Base
> mainnet with a 100 USDC per-deposit cap and a 1,000 USDC pool cap. Use small amounts only.
> **Your ghost key is required to find and spend your private notes: if you lose it, you lose
> access to those funds.** Store it as a PayBox Secret. Known limitations are in `docs/ARCHITECTURE.md`.

## Live on Base mainnet

Run end to end on Base mainnet with a real PayBox wallet (Claude with the PayBox connector) on
2026-10-17. Demo video: <https://x.com/Himess__/status/2111607509169668293>

| Step | Transaction |
| --- | --- |
| One-signature, gasless shield (EIP-3009), 2 USDC | [0x7dc6…df51](https://basescan.org/tx/0x7dc6ba89237e943599045d934a3c039e17fa24fd8e9a4c11b0836fd3d268df51) |
| Association-set root published (deposit approved) | [0x3095…8eb7](https://basescan.org/tx/0x30953fe3754335f29259ed3d26010f073ffebb31b1b5dfb3ff95968770578eb7) |
| Private x402 payment: ZK spend (proof in ~6.4 s) | [0xde40…1c95](https://basescan.org/tx/0xde4007a8782d2b1fa3e42334db4aa2731aa651c0d88249c2cddb268e09981c95) |
| The merchant's settlement, paid by the Ghost relayer, not the user | [0x72a1…dfec](https://basescan.org/tx/0x72a1009af1c36247db2344fd13690226a424d249066a5043b2fad284c308dfec) |
| Private withdrawal (unshield) back to the PayBox wallet | [0x6c5c…d09e](https://basescan.org/tx/0x6c5ce862c98fbe8bf0f1fdab3c2c21278cd35c7179d776c05a15e5dbe8f6d09e) |
| Demo video run: shield, private x402 spend, settlement | [0x27ca…65f7](https://basescan.org/tx/0x27ca3e812b28717e68c187ea2979c037e5486e0d3b92d9365e4e4b4a55d465f7), [0xcb57…e263](https://basescan.org/tx/0xcb5754cdb2494c1b68eda70a3f8167c77e993edbcde9ab37bb00b0fe211de263), [0x1781…b63d](https://basescan.org/tx/0x1781b7a51ed4133ef7e96b59c167b708d7cb0b2ebfa45e7ad028ef6aa654b63d) |

The receipt of the first private x402 payment passes 8 of 8 checks on the public verification
page, which reads straight from a public Base RPC node: network, official pool, PayBox signature,
domain, transaction, intent binding, payout and time.

Known issue from the live run: one merchant (Blockscout's x402 endpoint) failed at its own
settlement step (`unexpected_response`) after our spend had landed. The automatic private refund
of the 0.002 USDC price then failed on an RPC error (`Missing or invalid parameters` from a
fallback RPC). A fix is pending; the relayer keeps the amount until then.

## How it works

1. **Setup.** One PayBox message signature reveals the wallet's public key; the plugin creates a
   ghost key (privacy keys) and a shareable ghost address bound to that PayBox wallet.
2. **Shield with one signature, no ETH.** The user signs one EIP-3009 `ReceiveWithAuthorization`
   in PayBox; the Ghost relayer submits `depositWithAuthorization` and keeps a small USDC fee.
   The authorization nonce binds the exact note and fee, and only the pool can redeem it. (Fallback:
   approve + deposit as two ordinary PayBox transactions.)
3. **Spend with one signature.** The plugin builds a 2-in/2-out join-split and an EIP-712
   `GhostSpend` message whose readable fields (token, private amount + hidden recipient tag,
   public amount + public recipient, fee, deadline) are derived from the real spend inside the circuit; it self-checks the package before asking for
   the signature and returns a `human_summary` the agent must show first. PayBox signs with
   `request_wallet_sign`; the Ghost service proves the Noir circuit, which recomputes the EIP-712
   digest and verifies the secp256k1 signature, and the relayer submits `transact`.
4. **Private x402.** The relayer is the payer of record: the pool pays it price + fee, it re-quotes
   the merchant, pays with a standard EIP-3009 authorization and returns the response. If the
   merchant fails after payment, the relayer re-deposits the price privately to the user.
5. **Provable on demand.** Every spend stores an encrypted memo for the sender inside the change
   note, so the full history is recoverable from the chain plus the ghost key. `ghost_receipt`
   (PayBox-signed intent) and `ghost_report` (scoped note openings) come with a link to a public
   verification page that checks everything in the browser against Base.
6. **Privacy operator.** The agent warns about linkable behaviour (same amount out as in, exiting
   right after shielding, small anonymity set) and can scan what the user's own wallet leaks.

## What we claim, and what we do not

| Claim | Status |
| --- | --- |
| Spend authority stays in PayBox | Every private spend needs a PayBox signature specific to that spend, verified inside the zero-knowledge proof on Base. |
| The service cannot steal funds | It cannot move notes without the user's signature. It **is** trusted for privacy: it sees the witness while proving. |
| Worst case of a compromise | A leaked ghost key or a compromised service costs privacy, not funds. A **lost** ghost key costs access to the notes. |
| The merchant does not see the user | For x402, the merchant is paid by the Ghost relayer. |
| Unlinkability | Cryptography breaks the on-chain link; practical privacy is only as large as the anonymity set, which is small today. |
| Approval screen honesty | Amount, recipients, fee and token are derived from the real spend and verified in the circuit. |
| Compliance | OFAC pre-screening, an association set and user-controlled disclosure. No ragequit yet; the ASP is centralised. |
| Works on mainnet | Proofs take ~7 s; `verify` costs ~4.1M gas; real proofs verify on Base. |
| Not claimed | Anonymous, untraceable, trustless, MEV protection, audited. |

## Plugin tools (12)

| Tool | What it does | Signature |
| --- | --- | --- |
| `ghost_setup` | Binds Ghost Mode to the PayBox wallet; returns the ghost key and a shareable ghost address; backs the key up encrypted | 1 message |
| `ghost_recover` | Recovers a lost ghost key from the encrypted backup | 1 message |
| `ghost_address` | Shows the shareable ghost address | — |
| `ghost_shield_authorize` | Shield USDC with one EIP-3009 authorization; the relayer pays gas | 1 typed data |
| `ghost_shield` | Fallback shield: approve + deposit proposals | 2 transactions |
| `ghost_balance` | Private balance (spendable, awaiting ASP, pending relay) and pool stats | — |
| `ghost_prepare` | Private spend: `send_ghost`, `pay_address`, `unshield` (optional random `delay_minutes`), `pay_x402`; self-checked, with `human_summary` and privacy warnings | — |
| `ghost_submit` | Hands the PayBox signature to the prover and relayer | 1 typed data (from prepare) |
| `ghost_job` | Status: scheduled, proving, relaying, paying, done, refunded, requote_needed, failed | — |
| `ghost_exposure` | What the user's own wallet leaks publicly, with a score and what Ghost Mode would hide | 1 message |
| `ghost_report` | Scoped disclosure package and a browser verification link | — |
| `ghost_receipt` | Proof of one payment (PayBox-signed intent and tx) and a browser verification link | — |

## Tests (all passing, 2026-10-17 21:55 UTC)

| Suite | Command | Result |
| --- | --- | --- |
| Contracts (Foundry) | `cd contracts && forge test` | 68/68 |
| Circuit: real witness + UltraHonk ZK proof + verify, both spend kinds | `cd service && npx tsx test/prove.ts` (`KIND=send_ghost`) | verified, ~7.7 s |
| SDK: memos, self-validation, tamper cases, proof over a memo-carrying spend | `npx tsx test/sdk.ts` | 15/15 |
| Verification page (receipts, reports, tampering, RPC failure) | `npx tsx test/verify.ts` | 29/29 |
| Relay delay, root refresh, restart re-arm | `npx tsx test/delay.ts` | 14/14 |
| x402 headers, re-quote, settlement parsing | `npx tsx test/x402.ts` | 12/12 |
| Dynamic fees | `npx tsx test/fees.ts` | 6/6 |
| Exposure analysis | `npx tsx test/exposure.ts` | 11/11 |
| Compact (EIP-2098) vs full signatures | `npx tsx test/sigtest.ts` | 20/20 |
| End to end: built plugin bundle over MCP stdio, anvil, real proofs, one-signature gasless shield, key recovery, ghost transfer, private payment, receipt, memo report, delayed unshield | `bash test/local-e2e.sh` | passed |
| Plugin MCP conformance + deterministic build | starter conformance | passed, 12 tools |
| Mainnet | real v1.1 proof against the deployed verifier (`eth_call`) | `true` (v1 verifier rejects it) |

## Repository layout

```
ghost-mode/
  circuits/
    transact/            Noir circuit (src/main.nr); target/ holds transact.json and vk.bin
    lib/                 vendored noir-lang/poseidon v0.4.0 and noir-lang/keccak256 v0.1.3
  contracts/             Foundry: GhostPool, MerkleTreeWithHistory, HonkVerifier (generated),
                         Poseidon libraries, tests, script/Deploy.s.sol
  plugin/                PayBox plugin (starter 1.0.2): src/plugin.ts (MCP tools),
                         src/core/ (primitives, spend builder), src/ghost/ (operator, service client)
  service/               Ghost service: indexer, ASP, prover, relayer, x402 payer, exposure scan;
                         src/zk/ (circuit compile), test/ (prover, exposure and e2e tests)
  docs/                  RESEARCH.md, ARCHITECTURE.md, adr/
```

## Prerequisites

- Node.js 24.21.0 and pnpm 11.11.0 (PayBox starter toolchain). PayBox supports macOS and
  Linux (Windows via WSL2); this build was developed on Windows 10 with a portable Node
  24.21.0 and Git Bash.
- Foundry (`forge`; developed with 1.8.5).
- For mainnet: optionally an Alchemy Base API key (full-history exposure scans; without it the scan uses public RPC and covers roughly the last 6 hours), a relayer EOA with ETH for gas and a small USDC float
  for x402 payments, and `cloudflared` (or any HTTPS reverse proxy) to expose the service.

## Build and test

Compile the circuit (writes `circuits/transact/target/transact.json`, `vk.bin` and
`contracts/src/HonkVerifier.sol`):

```bash
cd service
pnpm install --frozen-lockfile
npx tsx src/zk/compile.ts
```

Run the prover test (builds a spend, signs it with a throwaway key, proves and verifies;
prints timings and writes `test/fixtures/proof.json`; `KIND=send_ghost` for a ghost transfer):

```bash
npx tsx test/prove.ts
```

Contracts:

```bash
cd contracts
forge build
forge test
```

Plugin (type-check, two reproducible builds, MCP conformance; output `dist/plugin.mjs`):

```bash
cd plugin
pnpm install --frozen-lockfile
pnpm test
```

## Deploy and run

Deploy (the broadcaster becomes pool owner and ASP operator; use the relayer key so the
service can publish ASP roots):

```bash
cd contracts
forge script script/Deploy.s.sol --rpc-url $BASE_RPC_URL --broadcast --slow --private-key $PRIVATE_KEY
```

On Base the Poseidon and generic verifier libraries are already deployed; reuse them so only the
verifier (which embeds the circuit's verification key) and the pool are deployed:

```bash
forge script script/Deploy.s.sol --rpc-url $BASE_RPC_URL --broadcast --slow --private-key $PRIVATE_KEY \
  --libraries src/poseidon/PoseidonT3.sol:PoseidonT3:0xa6e3d33abef457db3a2f1504c91eee1a77375891 \
  --libraries src/poseidon/PoseidonT5.sol:PoseidonT5:0x95d619151c18632fd0e6271d8376a44da2a2290e \
  --libraries src/HonkVerifier.sol:RelationsLib:0x8f20b5662868e011d86db01657399e20c4890e91 \
  --libraries src/HonkVerifier.sol:ZKTranscriptLib:0xb3d028c39a88bbfbb56973fbb44638345749e96b
```

Run the service:

```bash
cd service
POOL_ADDRESS=0x... POOL_DEPLOY_BLOCK=<deploy block> npx tsx src/server.ts
```

Secrets are read from `../.secrets/` relative to the repository root (outside the repo, never
committed): `relayer.key` (relayer and ASP operator private key), `alchemy.txt` (Alchemy key),
optional `service-token.txt`. Environment variables override them.

| Variable | Default | Meaning |
| --- | --- | --- |
| `POOL_ADDRESS` | none | Deployed `GhostPool` |
| `POOL_DEPLOY_BLOCK` | 0 | First block to index |
| `RPC_URL` | Alchemy URL from `alchemy.txt`, else `https://mainnet.base.org` | JSON-RPC endpoint |
| `CHAIN_ID` | 8453 | Base mainnet |
| `TOKEN` | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` | Base USDC |
| `RELAYER_PRIVATE_KEY` | `relayer.key` | Relayer, x402 payer and ASP operator |
| `RELAYER_FEE` | 10000 (0.01 USDC) | Floor of the dynamic relayer fee, atomic units (actual fee = gas × gas price × ETH/USD × 1.2) |
| `X402_MAX_AMOUNT` | 1000000 (1 USDC) | x402 per-request cap |
| `ASP_DENYLIST` | empty | Comma-separated depositor addresses never approved |
| `ASP_DELAY_SECONDS` | 0 | Minimum deposit age before approval |
| `SERVICE_TOKEN` | `service-token.txt` | If set, requires `Authorization: Bearer <token>` |
| `PORT` | 8787 | HTTP port |
| `RATE_LIMIT_PER_MIN` | 60 | Per-IP limit on `/v1/*` (set 300 when all traffic arrives from PayBox) |
| `DATA_DIR`, `STATE_FILE` | `service/data/` | Persisted jobs (encrypted), shield jobs, ghost-key backups |
| `ETH_USD_FEED` | Chainlink ETH/USD on Base `0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70` | Dynamic relayer fees (gas × price × 1.2, floor 0.01 USDC) |

OFAC screening uses the SDN Ethereum address list vendored in `service/data/ofac-eth.txt` (source: 0xB10C/ofac-sanctioned-digital-currency-addresses, fetched 2026-10-17); sanctioned depositors are never approved by the ASP, and sanctioned senders, recipients and x402 payees are refused.

Build the public verification page before starting the service (served at `/verify`):

```bash
cd service
npx tsx src/verify/build.ts
```

Expose it over HTTPS, for example with a Cloudflare quick tunnel:

```bash
cloudflared tunnel --url http://localhost:8787
```

A local end-to-end run (anvil, mock USDC, deploy, service, built plugin bundle) is scripted in
`service/test/local-e2e.sh`; it uses anvil's public test keys and machine-specific paths.

## PayBox portal configuration

- Upload `plugin/dist/plugin.mjs`.
- Network host: the service hostname (for a quick tunnel, the `*.trycloudflare.com` host; it
  changes when the tunnel restarts, and hosts and variables can be edited after the deadline).
- Environment variable `GHOST_SERVICE_URL` = `https://<service host>`.
- Optional environment variable `GHOST_POOL_ADDRESS` = pool address; the plugin then refuses a
  service that reports a different pool.
- If `SERVICE_TOKEN` is set: add a Secret for the service host with header `Authorization`
  and value `Bearer <token>`.
- Users store the `ghk1_...` ghost key returned by `ghost_setup` as a PayBox Secret.

## Deployed addresses (Base mainnet)

| Contract | Address |
| --- | --- |
| **GhostPool v3 (current)** | [0x314EAAdE3E1a42627b5D2c6b1f87D0bbd67B8367](https://basescan.org/address/0x314EAAdE3E1a42627b5D2c6b1f87D0bbd67B8367) (block 52741965; circuit v1.1: split private/public amounts on the approval screen, derived change blinding, label ≠ 0, no recipient without a public payout) |
| **HonkVerifier v1.1 (current)** | [0x6f197e0b8Adf9D5984b837be76e31De7ADfA18C1](https://basescan.org/address/0x6f197e0b8Adf9D5984b837be76e31De7ADfA18C1) |
| GhostPool v2 (superseded, empty) | [0x71A5beb98d4Bf019C3AF21AF6DB7A8Cc3ce14421](https://basescan.org/address/0x71A5beb98d4Bf019C3AF21AF6DB7A8Cc3ce14421) (block 52741262; first one-signature shield pool) |
| GhostPool v1 (superseded, empty) | [0x1882d5b6910c418c79ee6997179d473bc884693d](https://basescan.org/address/0x1882d5b6910c418c79ee6997179d473bc884693d) |
| HonkVerifier v1 (superseded) | [0x519a6d1022586ca29071e6d8c7a92180d5397d4f](https://basescan.org/address/0x519a6d1022586ca29071e6d8c7a92180d5397d4f) |
| RelationsLib, ZKTranscriptLib | 0x8f20b5662868e011d86db01657399e20c4890e91, 0xb3d028c39a88bbfbb56973fbb44638345749e96b |
| PoseidonT3, PoseidonT5 | 0xa6e3d33abef457db3a2f1504c91eee1a77375891, 0x95d619151c18632fd0e6271d8376a44da2a2290e |
| Relayer / ASP operator / owner | 0x06cb7dDa8a2E453097085629A6bBfAf33EB9d78b |
| Pool deploy block | v1 52739791, v2 52741262, **v3 52741965** |

Deployment used 16.9M gas in total (about 0.00009 ETH). A real proof generated by the service
verifies against the deployed HonkVerifier on Base (`eth_call` returns true, ~4.08M gas for
`verify`; a tampered public input reverts with `SumcheckFailed`).

## Documentation

- `docs/ARCHITECTURE.md`: components, formulas, circuit, contracts, API, tools, trust model,
  limitations.
- `docs/RESEARCH.md`: research tasks R1-R11 and go/no-go gates G1-G5.
- `docs/adr/`: decision records with attribution.

## Credits

Designed by Semih (Himess); implemented with Claude Code.
