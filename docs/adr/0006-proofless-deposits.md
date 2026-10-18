# ADR 0006: Deposits without proofs (pool-assigned label, precommitment)

- Date: 2026-10-17
- Status: Accepted. Amended by ADR 0013: since GhostPool v2 the default shield is one EIP-3009 signature; the two-transaction path below is the fallback.
- Decided by: Semih (Himess) — approved on 2026-10-17 (design review and sprint plan).
- Proposed by: Claude Code (AI assistant); reviewed by Claude (claude.ai).

## Context

Shielding must work as plain PayBox transaction proposals. PayBox accepts one unsigned EVM
call per proposal; an ERC-20 approval and the deposit must be proposed separately. Its
transaction window shows the destination, native value and raw calldata, not a decoded token
amount. A deposit that needs a ZK proof would add a prover round trip before the user can
approve anything.

## Decision

Privacy Pools style deposits:

- The plugin picks a random `blinding`, computes `precommitment = Poseidon(ownerTag, blinding)`
  and encrypts the note to the user's own viewing key with label 0 (ADR 0009).
- `ghost_shield` returns two proposals in order: step `approve` (USDC `approve(pool, amount)`)
  and, after PayBox confirms it, step `deposit` (`GhostPool.deposit(amount, precommitment,
  encryptedNote)`).
- The pool assigns `label = keccak256(abi.encodePacked(pool, depositCount)) mod p` and computes
  `commitment = Poseidon(uint160(token), amount, label, precommitment)` with `PoseidonT5`.
- The pool emits `NewCommitment(commitment, leafIndex, encryptedNote)` and
  `Deposited(depositor, commitment, label, amount, leafIndex)`.

## Consequences

- No proof and no Ghost service involvement at deposit time; two PayBox approvals, and the
  user's wallet pays gas. Since GhostPool v2 the default shield is one EIP-3009 signature
  relayed by the service (ADR 0013); this path remains the fallback.
- The depositor cannot choose its label, so the ASP decides per deposit (ADR 0011). Every
  output of a later spend inherits the label.
- `ownerTag` is hidden behind the blinding; the depositor address, amount and time are public.
- The pool cannot validate the precommitment. A malformed precommitment only hurts the
  depositor (unspendable note); there is no ragequit (ADR 0011, roadmap ADR 0021).
- Checks at deposit: `0 < amount <= maxDeposit`, `amount < 2^64` (circuit amounts are u64),
  `precommitment < p`, pool balance plus amount `<= tvlCap`, not paused.

## Alternatives considered

- Tornado Nova style deposits through `transact` with a proof: one more prover round trip and
  a signature before the deposit can even be proposed.
- User-chosen labels: would let a depositor reuse an approved label.
