# Ghost Mode for PayBox: Phase 0 research

Date: 2026-10-17. Phase 0 ran in parallel with implementation (ADR 0001). Each section lists
the question, sources, findings and a recommendation. "Open" marks items not yet verified.
Decisions are recorded in `docs/adr/`; attribution is in each ADR and in `docs/DECISIONS.md`.

## R1. PayBox plugin platform

**Question.** Starter, manifest, tool definitions, proposal formats, sandbox limits, network
allowlist, environment, persistence, hosted testing, publication.

**Sources.** PayBox developer guide (local copy `research/requirements.md`, from
https://developer.paybox.sh/); MCP tools reference (`research/mcp-tools.md`,
https://docs.paybox.sh/reference/mcp-tools); PayLink Guard reference plugin
(https://github.com/theluckystrike/paylink-guard).

**Findings.**

- A plugin is a standard TypeScript MCP server bundled into one `dist/plugin.mjs`, at most
  10 MiB, UTF-8. Starter release 1.0.2, protocol version `2026-07-28`, Node 24.21.0,
  pnpm 11.11.0. `pnpm test` type-checks, builds twice (byte-identical), then runs conformance.
- Every operation runs in a fresh sandbox. No memory or disk survives between calls.
- 10-second budget per operation. Other limits: 256 KiB stdout and 16 KiB stderr per
  operation, 64 KiB combined input/output schema per tool, 256 tools.
- EVM proposals: exactly one unsigned call (`to`, `value`, `data`) per proposal, expiry
  within 5 minutes. An ERC-20 approval and the following call must be separate proposals.
  The transaction window shows network, sender, destination, native value and raw calldata;
  it does not decode token amounts. Plugin text is treated as untrusted.
- x402 proposals exist (`kind: "x402"`, Base or Solana USDC, HTTPS GET or POST up to 64 KiB
  JSON, no custom headers); PayBox pays from the user's wallet.
- Network: exact hostnames only, at most 16 network hosts per plugin. Secrets are brokered
  headers (host, header name, value) injected by PayBox; plugin code cannot read them.
  Non-secret configuration goes in environment variables. Owners can edit hosts, variables
  and secrets after the deadline without uploading new code.
- Plugin money tools always pause for user approval, even under autonomous grants.
- Hosted code cannot supply executable UI.
- Supported OS: macOS and Linux (Windows via WSL2); native Windows is unsupported. This
  project used a portable Node 24.21.0 (win-x64) with pnpm 11.11.0 on Windows 10.

**Recommendation.** Thin plugin, heavy work in a Ghost service reached through one network
host, asynchronous jobs polled by the agent (ADR 0007). Deposits as two proposals
(ADR 0006).

## R2. PayBox signatures

**Question.** How typed data and messages appear on the approval screen, signature format,
determinism, chains.

**Sources.** https://docs.paybox.sh/reference/mcp-tools (`request_wallet_sign`,
`get_request`); https://docs.paybox.sh/concepts/requests; EIP-712
(https://eips.ethereum.org/EIPS/eip-712); EIP-191 (https://eips.ethereum.org/EIPS/eip-191).

**Findings.**

- `request_wallet_sign` ops: `message` (EIP-191), `typedData` (EIP-712), `transaction`
  (EIP-1559, returns a serialized transaction), `authorization` (EIP-7702), `raw` (signs a
  pre-computed digest), plus Solana message/transaction ops.
- Results arrive through the request envelope (`pending_approval` with `approval_url`,
  `pending_signature`, `success`, `denied`, `error`); the agent polls `get_request`.
- An EVM MPC wallet uses one address across all `eip155:*` chains. `list_credentials`
  exposes the address, not the public key; `ghost_setup` therefore recovers the public key
  from a message signature.
- Open: determinism (same message signed twice gives the same signature?) not tested on a
  real PayBox wallet.
- Open: rendering of `GhostSpend` typed data on the PayBox approval screen not tested.
- Open: signature encoding assumed to be 65-byte `(r, s, v)`; the plugin rejects other
  lengths. High-s signatures are normalised before proving.
- Open: testnet availability not checked; the build targets Base mainnet with small amounts.

**Recommendation.** Do not derive keys from signatures unless the determinism test passes
(ADR 0008, ADR 0020). Run one real PayBox signing test of `GhostSpend` before the demo and
record the screen.

## R3. ZK stack

**Question.** Noir and bb versions, circuit cost, Noir/Solidity Poseidon compatibility,
proving time, verifier size and gas.

**Sources.** https://noir-lang.org/docs/; Barretenberg and bb.js
(https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg); bbup version map
(`research/bb-versions.json`); `service/src/zk/compile.ts`, `service/test/prove.ts`.

**Findings** (Windows 10 dev machine, bb.js WASM multithreaded, `verifierTarget: "evm"`):

| Metric | Value |
| --- | --- |
| Noir / bb.js | 1.0.0-beta.22 / 5.0.0-nightly.20260522 (bbup pairing) |
| Circuit size | N = 2^18 = 262,144 (`N`, `LOG_N = 18` in the generated verifier) |
| Public inputs | 14 (verifier `NUMBER_OF_PUBLIC_INPUTS = 22` includes 8 pairing-point limbs) |
| Witness generation | 409 ms |
| UltraHonk ZK proof | 6.7 s |
| Proof size | 9,536 bytes |
| Verification key | 1,888 bytes |
| Solidity verifier source | ~102 KB (`contracts/src/HonkVerifier.sol`) |
| On-chain `verify` / `transact` gas | `verify` ~4.08M gas (eth_estimateGas on Base mainnet with a real proof); `transact` ~1.27M plus verification (~5.4M total); `deposit` ~780k |
| Bytecode size | `forge build --sizes`: HonkVerifier 18,092 B, GhostPool 8,811 B, PoseidonT3 16,413 B, PoseidonT5 16,769 B, RelationsLib 7,913 B, ZKTranscriptLib 6,098 B, all under the 24,576-byte EIP-170 limit; deployed on Base mainnet at block 52739791 (16.9M gas total) |

- `nargo` has no Windows build for v1.0.0-rc.5; the circuit is compiled with
  `@noir-lang/noir_wasm` through an in-memory POSIX file system (ADR 0003).
- Poseidon compatibility: circomlib Poseidon in all three layers (ADR 0004).

**Recommendation.** Keep in-circuit ECDSA (G1 met). The figures above are for circuit v1;
circuit v1.1 (ADR 0018) hashes a 288-byte struct instead of 256 bytes and has not been
measured in this document.

## R4. Prior art and reuse

**Question.** What to reuse from existing privacy systems; licences.

**Sources.** 0xbow Privacy Pools (https://0xbow.io/,
https://github.com/0xbow-io/privacy-pools-core); Tornado Nova
(https://github.com/tornadocash/tornado-nova); Railgun (https://docs.railgun.org/).

**Findings.**

- Reused conceptually, no code copied:
  - Privacy Pools / 0xbow: ASP root membership, pool-assigned labels, precommitment
    deposits (ADR 0006, ADR 0011).
  - Tornado Nova: 2-in/2-out join-split with zero-value dummy inputs; incremental Merkle tree
    with root history.
  - Railgun: separation of spending and viewing keys.
- Third-party code in the repository:

| Component | Version | Licence | Notes |
| --- | --- | --- | --- |
| noir-lang/poseidon | v0.4.0 | Apache-2.0 (LICENSE file) | vendored, `circuits/lib/poseidon-0.4.0` |
| noir-lang/keccak256 | v0.1.3 | not included in the vendored copy; upstream licence to confirm (TODO) | vendored, `circuits/lib/keccak256-0.1.3`; test, benchmark and oracle-test modules stripped from `src/lib.nr` |
| poseidon-solidity (vimwitch) | 0.0.5 | MIT | `PoseidonT3.sol`, `PoseidonT5.sol` copied to `contracts/src/poseidon/` |
| poseidon-lite (vimwitch) | 0.3.0 | MIT | npm dependency |
| @aztec/bb.js | 5.0.0-nightly.20260522 | MIT (package.json); generated verifier header says Apache-2.0 | npm dependency; `HonkVerifier.sol` generated |
| @noir-lang/noir_js, noir_wasm | 1.0.0-beta.22 | MIT OR Apache-2.0 | npm dependencies |
| viem / @noble/curves | 2.51.3 / 1.9.1 | MIT | npm dependencies |
| forge-std | bundled | MIT / Apache-2.0 | Foundry test library |

- b402, LOGIA, SecretPay, Unlink and PrivateX402 (listed in the brief) were not reviewed.

**Recommendation.** Keep the licence table current; confirm the keccak256 upstream licence.

## R5. FHE vs ZK vs Railgun

**Question.** Does D1 (ZK UTXO pool) hold?

**Sources.** Brief section 3; Railgun docs (https://docs.railgun.org/); Zama docs
(https://docs.zama.ai/).

**Findings.**

- The requirement is to break the who-pays-whom link. FHE hides amounts and balances but
  sender and recipient addresses stay visible.
- Railgun requires its spending key outside PayBox, which defeats the "spend authority never
  leaves PayBox" property.
- Zama availability on Base and FHE latency were not measured.

**Recommendation.** Keep D1.

## R6. x402

**Question.** v1/v2 formats, payer requirements, Base USDC EIP-3009, relayer flow.

**Sources.** x402 (https://github.com/coinbase/x402, https://x402.org); EIP-3009
(https://eips.ethereum.org/EIPS/eip-3009); Base USDC
`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`; PayBox `pay_x402` docs; a live 402 from
`api.blockscout.com`.

**Findings.**

- v1: requirements in the JSON body `accepts`, price `maxAmountRequired`, network `base`,
  payment in the `X-PAYMENT` header.
- v2: requirements in a base64 JSON `PAYMENT-REQUIRED` header, price `amount`, network
  `eip155:8453`, payment in the `PAYMENT-SIGNATURE` header.
- The "exact" scheme on Base is an EIP-3009 `TransferWithAuthorization` signed by the payer.
  Base USDC's EIP-712 domain is name "USD Coin", version "2" (observed in the live 402).
- PayBox states that x402 needs a plain EOA payer. A pool contract cannot sign; ERC-1271
  payers would need facilitator support (not researched).
- PayBox's own x402 proposals pay from the user's wallet, which is public.

**Recommendation.** Relayer EOA as payer of record, v1 and v2 support, 1 USDC per-request
cap (ADR 0010).

## R7. Privacy key storage

**Question.** Where `nk` and the viewing key live.

**Sources.** https://docs.paybox.sh/reference/mcp-tools (`request_secret`);
`research/requirements.md` (secrets are brokered headers); R2.

**Findings.** See ADR 0008. Plugin code cannot read PayBox Secrets; signature-derived keys
depend on untested determinism; a key service or TEE was not feasible in time.

**Recommendation.** Random seed plus PayBox public key (`ghk1_...`) stored by the user as a
PayBox Secret, with an encrypted backup on the service (ADR 0020). Open: `request_secret` raw
reveal not tested (G5).

## R8. DeFi on Base

Not researched (stretch scope, ADR 0012).

## R9. MEV and honest claims

**Question.** What privacy and MEV claims are defensible.

**Sources.** Base documentation (https://docs.base.org/).

**Findings and claims.**

- The pool hides who pays whom: a spend shows the pool, the relayer, the public recipient (if
  any) and the amount leaving the pool, not which deposit funded it.
- It does not hide deposits: depositor address, amount and time are public.
- It does not hide that a relayer-submitted transaction exists, nor its timing. An optional
  random relay delay for `unshield` and `pay_address` (ADR 0019) weakens timing correlation.
- Ghost transfers hide the amount and the recipient; payments to an address reveal the
  recipient and the amount.
- MEV: Base transactions go to the sequencer's private mempool. No additional private
  orderflow is used and no further MEV protection is claimed. No swaps in v1.

**Recommendation.** Use only these claims in the README, demo and pitch.

## R10. ASP screening

**Question.** Screening sources, on-chain sanctions oracle on Base, ASP mechanics.

**Sources.** 0xbow Privacy Pools (https://0xbow.io/); Chainalysis sanctions oracle
(https://go.chainalysis.com/chainalysis-oracle-docs.html); `eth_getCode` on Base.

**Findings.** The Chainalysis oracle address `0x40C57923924B5c5c5455c48D93317139ADDaC8fb`
has no code on Base. See ADR 0011 for the policy and the ragequit deferral.

**Recommendation.** Deterministic ASP with a denylist and optional delay for the hackathon.
The OFAC SDN Ethereum address list was merged into the denylist during the sprint (ADR 0011).

## R11. Exposure scan data

**Question.** How to get an address's public Base footprint.

**Sources.** Alchemy (`alchemy_getAssetTransfers`,
https://docs.alchemy.com/reference/alchemy-getassettransfers); Blockscout
(https://base.blockscout.com/); provider tests summarised in ADR 0002; ERC-5564
(https://eips.ethereum.org/EIPS/eip-5564); ERC-6538 (https://eips.ethereum.org/EIPS/eip-6538).

**Findings.**

- Provider comparison and choice: ADR 0002 (Alchemy).
- Pipeline (`service/src/exposure.ts`): one parallel round of RPC calls, 4 s per request,
  about 5.5 s total: `alchemy_getAssetTransfers` in and out (external and ERC-20, one page),
  `eth_getLogs` for USDC `AuthorizationUsed` events of the wallet (EIP-3009 / x402
  footprint, with a receipt-probe fallback), ETH and USDC balances, nonce and code (EOA,
  EIP-7702 delegation or contract).
- Report: counterparties, x402 payees, recurring payments, activity clock and inferred time
  zone, amount fingerprint, balances, funding source; `privacyScore` = 100 minus penalties.
- Ownership: the plugin requires a fresh signed challenge from the scanned address; the
  service endpoint itself does not check ownership.
- x402 Bazaar `payTo` labelling (brief idea) is not used.
- ERC-5564 Announcer `0x55649E01B5Df198D18D95b5cc5051630cfD45564` and ERC-6538 Registry
  `0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538` are deployed on Base; considered for stealth
  payments, not used.

**Recommendation.** Keep the scan limited to the user's own wallet; label merchants later.

## Go/no-go gates

| Gate | Criterion | Result | Evidence / remaining work |
| --- | --- | --- | --- |
| G1 | ECDSA circuit proves in <= 10 s (target 5 s); verifier deployable, gas acceptable | PASS | 6.1-7.7 s on dev hardware (bb.js WASM in a worker thread), N = 2^18 for both circuit v1 and v1.1. Verifiers deployed on Base (v1 0x519a6d1022586ca29071e6d8c7a92180d5397d4f, v1.1 0x6f197e0b8Adf9D5984b837be76e31De7ADfA18C1); real proofs verify via eth_call (~4.08M gas for verify). |
| G2 | PayBox signature with readable fields, verifiable in-circuit | PASS in-circuit | EIP-712 fields are derived from the spend and verified in the proof; the change output is bound to the spender in-circuit; the plugin self-checks every package and returns a human_summary (ADR 0016). PayBox approval-screen rendering: pending the live PayBox test. Circuit v1.1 (deployed) shows `privateAmount`/`privateRecipient` and `publicAmount`/`publicRecipient` separately (ADR 0018). |
| G3 | Plugin reaches our hosts; async job pattern; bundle within limits | PASS | Thin client plus async jobs, one network host. Bundle 588,198 bytes (deterministic builds), MCP conformance passed with 12 tools; the local end-to-end run drives the built bundle over stdio, every call well under 10 s. |
| G4 | Relayer-paid private x402 end to end on Base mainnet | Implemented | v1 and v2 payer flow, re-quote before transact, refund to the spender on merchant failure, settlement tx in receipts (ADR 0015). Live x402 quotes verified against api.blockscout.com; the paid mainnet run is pending the live PayBox test. |
| G5 | `nk` / viewing key storage chosen and tested | PASS (local) | PayBox Secret plus an AES-GCM backup on the service released only to a fresh signature from the same wallet (`ghost_recover`); covered by the local end-to-end run, including rejection of another wallet. Signature determinism (R2) pending the live PayBox test (ADR 0020). |

## Design review (2026-10-17)

Semih commissioned an external design review from Claude (claude.ai) at 20:35 UTC (status
report: `docs/REVIEW-FOR-CLAUDE-WEB.md`) and adopted its findings and sprint plan as his
decisions (`docs/DECISIONS.md`). The review found no flaw that lets anyone steal funds. Its
17 findings and their status at 21:40 UTC:

| # | Severity | Finding | Status |
| --- | --- | --- | --- |
| 1 | High | PayBox side never tested with a real wallet (hosted checks, typed-data screen, signature format, proposals). | Open: pending the live PayBox test (G2, G4, G5, R2). |
| 2 | High | Ghost-key loss is loss of access to funds, not only privacy. | Fixed: claim corrected (ADR 0008); encrypted backup and `ghost_recover` (ADR 0020). R2 determinism pending. |
| 3 | High | x402: user funds stuck with the relayer if the merchant fails or the price changes. | Fixed: re-quote, refund note, settlement tx in receipts (ADR 0015). The official `@x402` client is not used. |
| 4 | High | Shield needs two approvals and ETH. | Fixed: one-signature gasless shield, GhostPool v2 (ADR 0013). |
| 5 | Medium | State in memory; service on a laptop behind a quick tunnel. | Persistence fixed (ADR 0014). Hosting: roadmap, VPS right after the deadline (ADR 0021). |
| 6 | Medium | Approval screen: atomic units, `amount` sums hidden and public value, opaque `recipientTag`, `to` shown when nothing is paid out. | Fixed off-chain: `human_summary` and self-checks (ADR 0016). Fixed on-chain: split amounts in the signed struct and `publicRecipient == 0` without a public payout (circuit v1.1 / GhostPool v3, deployed, ADR 0018). |
| 7 | Medium | An unreadable change ciphertext would lose the change note. | Fixed off-chain: the plugin trial-decrypts the change before signing (ADR 0016). Fixed on-chain: change blinding `H2(nk, nullifier0)` enforced in-circuit (circuit v1.1, deployed, ADR 0018). |
| 8 | Medium | Owner, relayer and ASP operator share one hot key; pause also froze `transact`. | Pause fixed: deposits only since v2 (ADR 0017). Owner is still the relayer address (README contract table). |
| 9 | Medium | Unauthenticated endpoints, RPC credit drain, DNS rebinding. | Per-IP rate limit and public-IP check for x402 URLs added; `SERVICE_TOKEN` bearer auth supported (ARCHITECTURE sections 5 and 11). |
| 10 | Medium | Symbolic ASP; no ragequit. | OFAC SDN pre-screening added (ADR 0011). Ragequit: roadmap (ADR 0021). |
| 11 | Medium | History and receipts tied to service memory; no `ovk`. | Fixed: sender memos and persistence (ADR 0014). |
| 12 | Medium | No visible part of "provable on demand". | Fixed: verification page `GET /verify` (ARCHITECTURE section 11). |
| 13 | Low | Fixed 0.01 USDC fee is below gas cost. | Fixed: dynamic fee, floor 0.01 USDC (ARCHITECTURE section 11). |
| 14 | Low | No `label != 0` check on live inputs (not exploitable today). | Fixed: circuit v1.1 (deployed, ADR 0018). |
| 15 | Low | A fixed dummy blinding would make a second dummy spend fail. | Checked: dummy blinding is random; the plugin checks nullifiers are distinct and unspent (ADR 0016). |
| 16 | Low | Starter's official `pnpm test` not run on Linux. | Open: no Linux (WSL2 or Docker) run is recorded in these documents. |
| 17 | Info | The prover sees the witness: trusted for privacy, not for funds. | Stated as an honest claim (ADR 0007). TEE prover: roadmap (ADR 0021). |

The review's "not tonight" list (circuit v1.1 changes, in-circuit readable text, ragequit,
cloud hosting, random delay, swap and vault adapters, TEE prover) was revisited by Semih at
21:30 UTC: circuit v1.1 (ADR 0018) and the relay delay (ADR 0019) are being built; the rest is
in the roadmap (ADR 0021).
