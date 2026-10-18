# 13. One-signature, gasless shield with EIP-3009

Date: 2026-10-17

Decided by: Semih (Himess) — approved the review sprint plan at 21:00 UTC.
Proposed by: Claude (claude.ai) design review; implemented by Claude Code.

## Context

Shielding took two PayBox transactions (approve, then deposit) and needed ETH for gas. Many PayBox users hold only Base USDC, PayBox's default funding route.

## Decision

GhostPool v2 adds `depositWithAuthorization`. The user signs one EIP-3009 `ReceiveWithAuthorization` (readable in PayBox: from, to = pool, value, validity, nonce); the relayer submits it and receives `fee` in USDC; the note is created for `value - fee`.

- The nonce is `keccak256(abi.encode(pool, precommitment, keccak256(encryptedNote), fee))`, so the relayer cannot change the note or the fee.
- `receiveWithAuthorization` can only be redeemed by the pool itself. `transferWithAuthorization` was rejected because anyone could push it to the pool without creating a commitment.
- EIP-2612 permit was rejected: it does not bind the deposit contents and can be front-run.
- USDC rejects high-s signatures, so the service normalises them (`s' = n - s`, `v' = v xor 1`) before submitting.
- The circuit and verifier are unchanged; v2 reuses the deployed HonkVerifier and Poseidon libraries.
- The two-transaction path (approve + deposit) remains as a fallback if PayBox will not sign the authorization.

## Consequences

One signature and no ETH for the user. The relayer can censor a deposit but cannot alter it; the direct deposit stays available as an escape hatch. Deposits remain public.
