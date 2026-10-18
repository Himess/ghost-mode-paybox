# ADR 0018: Circuit v1.1 and GhostPool v3: split amounts on the approval screen

- Date: 2026-10-17 (decided at 21:30 UTC)
- Status: Implemented and deployed on Base mainnet (2026-10-17 ~21:40 UTC): HonkVerifier v1.1
  `0x6f197e0b8Adf9D5984b837be76e31De7ADfA18C1`, GhostPool v3 `0x314EAAdE3E1a42627b5D2c6b1f87D0bbd67B8367`
  (block 52741965). Circuit size unchanged (N = 2^18), proof ~7.7 s on dev hardware, a real v1.1 proof
  verifies on-chain (`eth_call` true) while the v1 verifier rejects it (`SumcheckFailed`). Local end-to-end
  run and 68 Foundry tests pass. v2 stays deployed (empty) as a fallback.
- Decided by: Semih (Himess) — 2026-10-17 21:30 UTC, "continue with the deferred improvements".
- Proposed by: Claude (claude.ai) design review (findings 6, 7 and 14, deferred as "v1.1 circuit
  changes"); implemented by Claude Code (AI assistant).
- Supersedes: the `GhostSpend` struct of ADR 0005 for GhostPool v3.

## Context

In circuit v1 (ADR 0005) the PayBox approval screen shows one `amount`, which is the hidden
output plus the public payout, and an opaque `recipientTag`. A preparer could inflate the total
and send part of it to another hidden recipient; the change is visible only as a different
`amount` and `recipientTag` in atomic units (review finding 6). Two smaller gaps were also
deferred to the next circuit change: live inputs are not required to have `label != 0`
(finding 14; not exploitable today, because no note with label 0 can be created), and a change
note whose ciphertext was prepared unreadable could not be found (finding 7). The plugin's
self-checks and `human_summary` (ADR 0016) cover these off-chain; v1.1 moves them into the
proof. The review had put all circuit changes out of scope for the night; Semih reversed this
at 21:30 UTC.

## Decision

- The PayBox wallet signs:

  ```
  GhostSpend(bytes32 intent,address token,uint256 privateAmount,bytes32 privateRecipient,uint256 publicAmount,address publicRecipient,uint256 fee,uint256 deadline)
  ```

  derived in-circuit from the real spend:
  - `privateAmount` = `out_amounts[0]`, the hidden output to another ghost owner;
  - `privateRecipient` = `out_owner_tags[0]` if `privateAmount != 0`, else zero;
  - `publicAmount` = `publicOut - fee`, what leaves the pool to `publicRecipient`, excluding
    the relayer fee;
  - `publicRecipient` = public input `recipient`;
  - `intent`, `token`, `fee`, `deadline` as in ADR 0005.

  This replaces the single `amount` (hidden plus public value) and the separate
  `recipientTag`, so the approval screen states both flows explicitly.
- Live inputs (non-zero amount) must have `label != 0` (finding 14).
- The change blinding is derived in-circuit: `out_blindings[1] = H2(nk, nullifier0)`
  (circomlib Poseidon with two inputs, as everywhere else; ADR 0004). A change note can then
  be found from the chain and the ghost key even if its ciphertext were unreadable
  (finding 7).
- GhostPool v3 additionally requires `publicRecipient == 0` when the public amount is zero
  (`publicOut == fee`), so a ghost transfer cannot show an unrelated address (finding 6).
- A new verifier is generated; the Poseidon and generic verifier libraries (`RelationsLib`,
  `ZKTranscriptLib`) are reused.
- GhostPool v2 stays deployed as a fallback.

## Consequences

- The pool's verifier address is immutable (ADR 0003), so v1.1 needs a new pool. v1 and v2
  notes are not spendable in v3; funds move by spending in the old pool.
- The domain separator changes with the new pool address; signatures for one pool are invalid
  in another.
- The plugin's typed-data builder and self-checks (ADR 0016), the service's signature check
  and the receipt verification page must use the new struct.
- Still not shown in-circuit: human-readable text and decimal amounts (roadmap, ADR 0021).

## Alternatives considered

- In-circuit human-readable text (review package I): a larger circuit change; deferred
  (ADR 0021).
- Keep v1 and rely on the plugin's off-chain self-checks (ADR 0016): the checks run in the
  component that builds the spend, and the approval screen would still not state the two
  flows separately.
