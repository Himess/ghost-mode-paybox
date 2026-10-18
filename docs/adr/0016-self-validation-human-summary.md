# 16. Pre-signature self-validation and human summaries

Date: 2026-10-17

Decided by: Semih (Himess) — approved the review sprint plan at 21:00 UTC.
Proposed by: Claude (claude.ai) design review; implemented by Claude Code.

## Context

PayBox renders `GhostSpend` with atomic amounts and opaque fields. A faulty or malicious preparer could hide a mis-addressed change note or an extra hidden output.

## Decision

Before returning typed data, the plugin re-derives and checks:

- the change note decrypts with the user's own ghost key and matches its commitment;
- public payouts carry no hidden output and no hidden recipient tag;
- the displayed amount equals the spend;
- nullifiers are distinct and unspent;
- `extDataHash` and the intent are recomputed from the transaction fields.

Every signing tool returns a `human_summary` (for example "Pay 10.00 USDC → 0xBEEF…bEEF · fee 0.01 USDC · hidden recipient: none · expires 21:42 UTC") and an exact `next_step`. Tool descriptions require the agent to show the summary before requesting the signature.

## Consequences

A malformed package never reaches the signature step. Human-readable text verified inside the circuit remains future work, because it needs a circuit change.
