# Ghost Mode for PayBox: architecture

Status: hackathon build, 2026-10-17. Experimental, unaudited, capped. Decisions and their
attribution are in `docs/adr/` (index: `docs/DECISIONS.md`); measurements are in
`docs/RESEARCH.md`.

## 1. Components

| Component | Code | Role |
| --- | --- | --- |
| `transact` circuit | `circuits/transact/src/main.nr` | 2-in/2-out join-split over one asset; verifies the PayBox wallet's ECDSA signature over an EIP-712 `GhostSpend` digest. |
| `GhostPool` | `contracts/src/GhostPool.sol`, `MerkleTreeWithHistory.sol` | Deposits, `transact`, nullifier set, state tree (depth 16, 64 roots), ASP roots (16), caps, pause. |
| `HonkVerifier` | `contracts/src/HonkVerifier.sol` (generated) | UltraHonk ZK verifier, keccak transcript; links `RelationsLib`, `ZKTranscriptLib`. |
| Ghost service | `service/src/` | Indexer, ASP, prover (worker thread), relayer, x402 payer, exposure scan; JSON API. |
| PayBox plugin | `plugin/src/plugin.ts`, `core/`, `ghost/` | MCP tools; key parsing, note scanning, spend building, privacy checks, PayBox proposals. Stateless. |
| PayBox | external | Wallet (MoonX MPC), approvals, signing, transaction proposals. The only source of spend signatures. |

```
 User (chat)
   |
   v
 Agent (MCP host) ---- request_wallet_sign / get_request / request_secret ----> PayBox
   |                                                                          (MPC wallet,
   | use_plugin: ghost_*                                                       approvals)
   v                                                                             |
 Ghost plugin (PayBox sandbox, stateless, 10 s/call)                             | approve +
   | core/: Poseidon, notes, Merkle, X25519/AES-GCM, spend + EIP-712 builder     | deposit txs
   | ghost/: privacy operator, service client                                    | (user wallet)
   |                                                                             v
   | HTTPS, one network host (GHOST_SERVICE_URL)                  +------------------------+
   v                                                              | Base mainnet           |
 Ghost service (Node; Semih's machine via Cloudflare tunnel)      |  GhostPool             |
   indexer  --- eth_getLogs / reads (Alchemy RPC) ------------->  |  HonkVerifier (+2 libs)|
   ASP      --- setAspRoot ------------------------------------>  |  USDC (EIP-3009)       |
   prover   (bb.js WASM worker)                                   +------------------------+
   relayer  --- transact(proof, args) -------------------------->        ^
   x402     --- EIP-3009 authorization + paid request ---> merchant ----+ (settles via
   exposure --- alchemy_getAssetTransfers etc.                             its facilitator)
```

## 2. Data model

All hashes are circomlib Poseidon over BN254 (`Hn` = n inputs), p = BN254 scalar field.

| Item | Formula |
| --- | --- |
| Note | `{ asset, amount, ownerTag, blinding, label }` |
| pkHash | `H4(x_hi, x_lo, y_hi, y_lo)`, 128-bit big-endian limbs of the PayBox secp256k1 public key |
| ownerTag | `H2(pkHash, H1(nk))` |
| precommitment | `H2(ownerTag, blinding)` |
| commitment | `H4(asset, amount, label, precommitment)` |
| nullifier | `H3(commitment, leafIndex, nk)` |
| label (deposit) | `keccak256(abi.encodePacked(pool, depositCount)) mod p`; outputs inherit the input label |
| extDataHash | `keccak256(abi.encode(relayer, encryptedOutput0, encryptedOutput1)) mod p` |
| intent | `H5(nullifier0, nullifier1, outCommitment0, outCommitment1, extDataHash)` |
| Domain separator | EIP-712 domain `{ name: "GhostMode", version: "1", chainId, verifyingContract: pool }` |
| Merkle node | `H2(left, right)`, empty leaf 0, depth 16 (state tree and ASP tree) |
| Encrypted note | v1, 133 bytes: `0x01` / ephemeral X25519 key (32) / IV (12) / AES-256-GCM ciphertext of amount (8), blinding (32), label (32) / tag (16). v2 (`0x02`) adds a sender memo to the change note (ADR 0014) |
| Change blinding (circuit v1.1) | `H2(nk, nullifier0)`, enforced in-circuit (ADR 0018) |
| Ghost key | `ghk1_<32-byte seed hex>_<64-byte pubkey hex>`; `nk = keccak256(seed ‖ "ghost-mode:nk") mod p`, `viewPriv = sha256(seed ‖ "ghost-mode:ivk")` |
| Ghost address | `ghost:` + hex(ownerTag ‖ viewPub) + 4-byte keccak checksum |

## 3. Circuit `transact`

This section describes circuit v1 (GhostPool v1 and v2). Circuit v1.1 (GhostPool v3,
ADR 0018) keeps the public inputs, signs `GhostSpend(intent, token, privateAmount,
privateRecipient, publicAmount, publicRecipient, fee, deadline)` instead of constraint 7's
struct, requires `label != 0` for live inputs and derives the change blinding.

Public inputs, in verifier order (the pool builds the same array in `buildPublicInputs`):

| # | Name | Type | Supplied on-chain as |
| --- | --- | --- | --- |
| 0 | root | Field | `a.root` (must be a known state root) |
| 1 | aspRoot | Field | `a.aspRoot` (must be a known ASP root) |
| 2 | nullifier0 | Field | `a.nullifiers[0]` |
| 3 | nullifier1 | Field | `a.nullifiers[1]` |
| 4 | outCommitment0 | Field | `a.outCommitments[0]` |
| 5 | outCommitment1 | Field | `a.outCommitments[1]` |
| 6 | publicOut | u64 | `a.publicOut` (to recipient plus fee) |
| 7 | extDataHash | Field | computed by the pool |
| 8 | asset | Field | `uint160(token)` |
| 9 | recipient | Field | `uint160(a.recipient)` |
| 10 | fee | u64 | `a.fee` |
| 11 | deadline | u64 | `a.deadline` |
| 12 | domainHi | Field | `DOMAIN_SEPARATOR >> 128` |
| 13 | domainLo | Field | `DOMAIN_SEPARATOR & (2^128 - 1)` |

Private inputs: input amounts, blindings, labels, leaf indices and Merkle paths; ASP indices
and paths; `nk`; PayBox public key `(x, y)`; signature `(r, s)` (64 bytes, low-s); output
amounts, owner tags and blindings.

Constraints (in code order):

1. `ownerTag = H2(H4(pubkey limbs), H1(nk))`; both inputs use this owner tag.
2. At least one input has a non-zero amount; if both do, their labels are equal; the spend's
   label is that of the live input.
3. For each input: commitment recomputed; `H3(commitment, index, nk) == nullifier`; if the
   amount is non-zero, the commitment is in the state tree under `root` and the label is in
   the ASP tree under `aspRoot`. Zero-amount inputs are dummies (no membership check).
4. Each output commitment equals `H4(asset, amount, label, H2(ownerTag_j, blinding_j))`.
5. Value conservation: `in0 + in1 == out0 + out1 + publicOut` (all u64, no field wrap) and
   `publicOut >= fee`.
6. `intent = H5(nullifiers, outCommitments, extDataHash)`.
7. EIP-712 struct hash with keccak256 over `GhostSpend(intent, token = asset,
   amount = out0 + publicOut - fee, to = recipient, fee, deadline,
   recipientTag = out0 > 0 ? ownerTag_0 : 0)`; digest `keccak256(0x1901 ‖ domain ‖ structHash)`.
8. `ecdsa_secp256k1::verify_signature(pubkey, signature, digest)`.

Spend shapes built by `plugin/src/core/spend.ts`:

| Action | out0 | out1 | publicOut | recipient |
| --- | --- | --- | --- | --- |
| `send_ghost` | amount to recipient's ownerTag | change | fee | zero address |
| `pay_address`, `unshield` | 0 | change | amount + fee | target address |
| `pay_x402` | 0 | change | price + fee | relayer address |

## 4. Contracts

`GhostPool(token, verifier, owner, aspOperator, maxDeposit, tvlCap)`; `token`, `verifier`
and `DOMAIN_SEPARATOR` are immutable. No proxy, no upgrade path.

| Function | Access | Behaviour |
| --- | --- | --- |
| `deposit(amount, precommitment, encryptedNote)` | anyone, not paused | `0 < amount <= maxDeposit`, `amount < 2^64`, `precommitment < p`, balance + amount `<= tvlCap`; assigns label, computes commitment, `transferFrom`, inserts leaf. |
| `transact(proof, TransactArgs)` | anyone (relayers); v1: not paused; v2 and later: never paused (ADR 0017) | Known root and ASP root; nullifiers `< p`, distinct, unspent; outputs `< p`; `block.timestamp <= deadline`; u64 ranges; `fee <= publicOut`; non-zero recipient/relayer when paid (v3 also requires a zero recipient when nothing is paid out, ADR 0018); `verifier.verify`; marks nullifiers, inserts two leaves, pays `publicOut - fee` to recipient and `fee` to relayer. |
| `buildPublicInputs(args)`, `extDataHash(...)` | view / pure | Off-chain checks. |
| `setAspRoot(root)` | `aspOperator` | Pushes a non-zero ASP root into the 16-entry ring buffer. |
| `currentAspRoot()`, `isKnownAspRoot()`, `isKnownRoot()`, `getLastRoot()`, `nullifierSpent()`, `zeros(i)` | view | State queries. |
| `pause`, `unpause`, `setMaxDeposit`, `setTvlCap`, `setAspOperator`, `transferOwnership` | `owner` | Admin. |

Events: `NewCommitment(commitment, leafIndex, encryptedOutput)`, `Deposited(depositor,
commitment, label, amount, leafIndex)`, `NewNullifier(nullifier)`, `Transacted(relayer,
recipient, publicOut, fee)`, `AspRootUpdated(root, index)`, `AspOperatorUpdated`,
`OwnershipTransferred`, `Paused`, `Unpaused`, `MaxDepositUpdated`, `TvlCapUpdated`.

Deployment: `contracts/script/Deploy.s.sol` deploys `HonkVerifier` and `GhostPool`; forge
deploys and links the libraries (`PoseidonT3`, `PoseidonT5`, `RelationsLib`,
`ZKTranscriptLib`). The broadcaster becomes owner and ASP operator; the service's relayer key
must be the ASP operator.

## 5. Ghost service API

Base: `GHOST_SERVICE_URL`. JSON in and out; errors are HTTP 400 `{ "error": "..." }`. If
`SERVICE_TOKEN` is set, every route except `/health` requires `Authorization: Bearer <token>`.

| Method and path | Purpose |
| --- | --- |
| `GET /health` | Liveness. |
| `GET /v1/info` | `chainId`, `pool`, `token`, `relayer`, `relayerFee`, `x402MaxAmount`. |
| `GET /v1/state` | Syncs, then returns leaves (commitment, ciphertext, time, tx), deposits (label, amount, depositor), nullifiers, current root, ASP root and labels. Clients recompute both roots. |
| `POST /v1/x402/quote` | `{url, method, body?}`: probes the endpoint; returns `{free, status}` or `{version, price, payTo, network, asset}`. |
| `POST /v1/prepare` | `{package, x402?}`: validates chain, pool, relayer and deadline (> now + 60 s), re-quotes x402; returns `{prepare_id, expires_at}`. |
| `POST /v1/submit` | `{prepare_id, signature}`: recovers the signer from the EIP-712 digest, must match the package's public key; consumes the prepare; returns `{job_id}`. |
| `GET /v1/jobs/:id` | `status` (`queued`, `proving`, `relaying`, `paying`, `done`, `failed`; sprint additions `requote_needed` and `refunded` (ADR 0015) and `scheduled` (ADR 0019)), `txHash`, `timings`, `x402` result, `receipt` (typed data, signature, signer, nullifiers, commitments). |
| `POST /v1/exposure` | `{address}`: exposure report (RESEARCH R11). |

Background loop every 5 s: index new events, recompute the association set, publish a new ASP
root when it changed. Relayer transactions (`transact`, `setAspRoot`) are serialised by a
lock. Proofs run one at a time in a worker thread.

## 6. Plugin tools and agent flow

| Tool | Input | Output |
| --- | --- | --- |
| `ghost_setup` | none, then `{message, signature}` | Step 1: a setup message to sign (EIP-191). Step 2: `ghost_key`, `ghost_address`, `wallet_address` (from the recovered key). |
| `ghost_address` | `ghost_key` | Ghost address and bound wallet address. |
| `ghost_shield` | `ghost_key`, `amount_usdc`, `step` (`approve` / `deposit`) | One PayBox EVM proposal per step; round-amount advice. Max 100 USDC. |
| `ghost_balance` | `ghost_key` | Spendable and pending (ASP) balance, notes, pool stats. |
| `ghost_prepare` | `ghost_key`, `action`, `amount_usdc` / `to` / `url`, `method`, `body` | `prepare_id`, risk, warnings, summary, `sign_request` (`op: typedData`). Deadline now + 20 min. |
| `ghost_submit` | `prepare_id`, `signature` | `job_id`. |
| `ghost_job` | `job_id` | Status, tx hash, timings, x402 response. |
| `ghost_exposure` | `address`, then `{address, message, signature}` | Ownership challenge, then the exposure report. |
| `ghost_report` | `ghost_key`, `from`, `to` | Scoped disclosure package: note openings in the date range plus verification steps. |
| `ghost_receipt` | `job_id` | Signed typed data, signer, signature, nullifiers, output commitments, tx hash, verification steps. |

Agent flow for a private spend:

1. `ghost_prepare`. If `risk` is `high`, show the warnings and get the user's go-ahead.
2. PayBox `request_wallet_sign` with `{op: "typedData", typedData}`. On `pending_approval`,
   show `approval_url`; poll `get_request` until the signature arrives.
3. `ghost_submit` with `prepare_id` and the signature, once.
4. Poll `ghost_job` until `done` or `failed`; never re-run prepare or submit to finish.

Shield: `ghost_shield` step `approve` -> PayBox confirms -> step `deposit` -> PayBox confirms
-> ASP approves the label (next loop) -> note is spendable. Since GhostPool v2 the default is
`ghost_shield_authorize` (one signature, ADR 0013); this two-step path is the fallback. Key
recovery: `ghost_recover` (ADR 0020).

## 7. Privacy operator (`plugin/src/ghost/operator.ts`)

| Code | Severity | Rule | Applies to |
| --- | --- | --- | --- |
| `small_anonymity_set` | medium | Fewer than 5 distinct depositors in the pool | all spends |
| `amount_matches_deposit` | high | Exit amount within 1% of any deposit in the last 24 h | public exits |
| `timing_correlation` | medium | Exit within 30 min of the user's own latest deposit | public exits |
| `recipient_is_depositor` | high | Recipient address has deposited into the pool | public exits |
| `non_round_amount` | low | Amount is not a whole USDC | public exits |
| `round_deposit` | low | Deposit not a multiple of 5 USDC; suggests rounding up | shield |

Public exits are `pay_address`, `unshield` and `pay_x402`. Risk is the highest severity
present.

## 8. Trust model

| Component | Can | Cannot |
| --- | --- | --- |
| PayBox (MPC wallet) | Sign or refuse each spend under the user's approval mode; see and record each `GhostSpend` (amount, recipient, fee); hold the ghost key Secret | Nothing new is trusted to PayBox: it already holds the spend key |
| Agent | Read the ghost key it is given; request signatures; choose actions | Spend without a PayBox approval |
| Plugin | Build spends and proposals from the ghost key | Sign; reach hosts other than the service |
| Ghost service: indexer | Withhold or delay state (denial of service) | Forge state: clients recompute roots, the pool checks them |
| Ghost service: prover / prepare | See the full witness (`nk`, note openings, public key) and hold encrypted ghost-key backups (ADR 0020): privacy loss | Change a signed spend (the signature binds the intent) |
| Ghost service: relayer | Censor or delay; for x402, hold `price + fee` for one payment and fail to pay or refund (at most 1 USDC per request; ADR 0015) | Redirect funds or fees (bound by proof and `extDataHash`) |
| ASP operator | Approve or exclude labels; freeze spending | Move funds |
| Pool owner | Pause (v1: deposits and spends; v2 and later: deposits only, ADR 0017), change caps and ASP operator | Move funds, replace the verifier |
| Cloudflare tunnel | Read service traffic, including spend packages | Change a signed spend |
| Merchant | See the relayer as payer | Identify the user |
| Public chain observer | See deposits, spends, recipients of public exits, timing | Link a spend to a deposit beyond the anonymity set |

## 9. Security caps

- `maxDeposit` = 100 USDC per deposit, `tvlCap` = 1,000 USDC pool balance (set in
  `Deploy.s.sol`; owner-adjustable). The plugin also refuses deposits above 100 USDC.
- `pause()` stops deposits and spends in v1; deposits only in v2 and later (ADR 0017).
- x402 price cap 1 USDC per request (`X402_MAX_AMOUNT`); relayer fee 0.01 USDC
  (`RELAYER_FEE`) in the first build, dynamic with a 0.01 USDC floor since the sprint
  (section 11).
- Unaudited; small amounts only.

## 10. Known limitations

Fixed during implementation (found in documentation review, 2026-10-17):
- Change output is now bound to the spender in-circuit (`assert(out_owner_tags[1] == owner_tag)`);
  the verifier was regenerated before the mainnet deployment (ADR 0005).
- `/v1/prepare` rejects x402 spends that do not pay `price + fee` to the relayer (ADR 0010).
- x402 URLs must be public HTTPS hostnames on port 443 (no localhost, `.local`, private IPv4 or
  IPv6 literals). DNS rebinding was not handled in the first build; the sprint added a check
  that the resolved addresses are public (section 11).
- `/v1/exposure` re-verifies the signed, 15-minute challenge server-side, so scans are limited to
  the signer's own address. `SERVICE_TOKEN` remains optional hardening.

Fixed in the sprint: prepared spends, jobs and receipts were held in memory only; they are now
persisted under `service/data/` (ADR 0014).

Open:
1. No ragequit: denylisted deposits, and notes of a lost ghost key without a backup (ADR 0020),
   are locked (ADR 0011, roadmap ADR 0021).
2. Deposits are public; the anonymity set is small at launch.
3. Single relayer, single ASP, single indexer, single prover, all on one machine (VPS planned
   right after the deadline, ADR 0021).
4. Notes are found by trial-decrypting every leaf on each call.
5. Not yet verified: PayBox approval-screen rendering (G2), signature determinism and format
   (R2), Secret retrieval (G5), mainnet x402 end to end (G4); circuit v1.1 and GhostPool v3
   (ADR 0018) are being deployed.

## 11. Sprint additions (2026-10-17, 21:00–23:00 UTC)

Decided by Semih: the external design review's sprint plan (approved 21:00 UTC) and, from 21:30 UTC, the deferred improvements (ADRs 0018-0021). `docs/REVIEW-FOR-CLAUDE-WEB.md` is the status report sent to the reviewer. Rows without an ADR are sprint-plan packages (letters as in the review).

| Area | Change | ADR |
| --- | --- | --- |
| Shield | GhostPool v2 `depositWithAuthorization`: one EIP-3009 `ReceiveWithAuthorization` signature, relayer pays gas and keeps a USDC fee; nonce = `keccak256(abi.encode(pool, precommitment, keccak256(encryptedNote), fee))`; high-s normalised by the service. Plugin tool `ghost_shield_authorize`; the two-transaction `ghost_shield` stays as a fallback. Service: `GET /v1/shield/info`, `POST /v1/shield/prepare`, `POST /v1/shield/submit`, `GET /v1/shield/jobs/:id`. | 0013 |
| Pause | v2 pause blocks deposits only; `transact` is always available. | 0017 |
| History | Change notes are always emitted and carry a sender-encrypted memo (ciphertext v2); `ghost_report` rebuilds outgoing payments from the chain and the ghost key. Service state persisted under `service/data/`. | 0014 |
| x402 | Re-quote before `transact` (`requote_needed`), refund to the spender's ghost balance if the merchant fails after payment (`refunded`), settlement tx in the receipt. Spend packages carry `refundTo` (owner tag + viewing public key). | 0015 |
| Signing UX | Every signing tool returns `human_summary` and an exact `next_step`; the plugin self-checks each package (change decrypts with the user's key, no hidden outputs on public payouts, amounts, nullifiers, intent) before returning it. | 0016 |
| Key loss | `ghost_setup` stores an AES-GCM-encrypted backup of the ghost key on the service (key file outside the repo); `ghost_recover` releases it only to a fresh (15-minute) signature from the same PayBox wallet. Trust model unchanged: the service already sees spend witnesses. | 0020 |
| Disclosure | Public verification page at `GET /verify#pkg=<base64url>` (static, all checks in the browser against Base RPC): receipts (EIP-712 signer, nullifiers/commitments in the tx, intent recomputed from on-chain ciphertexts, payout) and reports (owner tag ↔ PayBox public key, every commitment recomputed and found on-chain). `ghost_receipt` and `ghost_report` return `verify_url`. | — (E) |
| Compliance | OFAC SDN Ethereum address list vendored under `service/data/` and merged into the ASP denylist; sanctioned senders are refused before a one-signature shield is relayed. | 0011 (H) |
| Relayer | Dynamic fees from gas price × Chainlink ETH/USD × 1.2 (floor 0.01 USDC); per-IP rate limit; x402 URLs must resolve to public IPs. | — (F, S) |
| Approval (deployed) | Circuit v1.1 and GhostPool v3 (`0x314EAAdE3E1a42627b5D2c6b1f87D0bbd67B8367`, verifier `0x6f197e0b8Adf9D5984b837be76e31De7ADfA18C1`): `GhostSpend` shows `privateAmount`/`privateRecipient` and `publicAmount`/`publicRecipient` separately; live inputs need `label != 0`; change blinding `H2(nk, nullifier0)` in-circuit; v3 requires a zero recipient when nothing is paid out. New verifier; Poseidon and verifier libraries reused; v2 stays as a fallback. | 0018 |
| Timing (deployed) | Optional random relay delay of 0-30 minutes for `unshield` and `pay_address` (plugin `delay_minutes`, job status `scheduled`, `scheduled_for`); not for x402 or ghost transfers. Roots refreshed at send time. Notes in flight are published as owner-only tags `H2(nullifier, nk)` and shown as `pending_relay`. | 0019 |
