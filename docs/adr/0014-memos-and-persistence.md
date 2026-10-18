# 14. Self-encrypted payment memos and service persistence

Date: 2026-10-17

Decided by: Semih (Himess) — approved the review sprint plan at 21:00 UTC.
Proposed by: Claude (claude.ai) design review; implemented by Claude Code.

## Context

History and receipts lived in service memory, so a restart lost them, and the sender had no on-chain record of what they paid.

## Decision

- Every spend always emits the change note, even with zero change, and appends a memo encrypted to the sender: kind, counterparty, amount, fee, time and x402 host.
- Ciphertext format v2: `0x02 | ephPub(32) | iv(12) | ct(amount, blinding, label, memo) | tag(16)`; v1 notes (133 bytes) still decrypt.
- The ciphertext is bound by `extDataHash`, so it is covered by the PayBox signature and the proof.
- `ghost_report` rebuilds outgoing payments from the chain and the ghost key alone.
- The service persists prepared spends, jobs and receipt data to disk.

## Consequences

No contract or circuit change. Memos are as private as the ghost key. Their content is informational: it is not verified on-chain.
