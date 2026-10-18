# ADR 0004: circomlib-compatible Poseidon over BN254; Merkle depth 16

- Date: 2026-10-17
- Status: Accepted
- Decided by: Semih (Himess) — approved on 2026-10-17 (design review and sprint plan).
- Proposed by: Claude Code (AI assistant); reviewed by Claude (claude.ai).

## Context

The same hash must be computed in three places: inside the circuit (notes, nullifiers, Merkle
paths, ASP paths), on-chain (deposit commitments and incremental tree inserts) and in
TypeScript (plugin note scanning, spend building, service indexer and ASP tree). A mismatch in
any one place makes notes unspendable.

## Decision

- Use circomlib-compatible Poseidon over the BN254 scalar field:
  - circuit: `noir-lang/poseidon` v0.4.0, `poseidon::bn254::hash_1` .. `hash_5` (vendored in
    `circuits/lib/poseidon-0.4.0`);
  - Solidity: `poseidon-solidity` 0.0.5 (`PoseidonT3` for 2 inputs, `PoseidonT5` for 4 inputs,
    in `contracts/src/poseidon/`);
  - TypeScript: `poseidon-lite` 0.3.0 (`poseidon1` .. `poseidon5`).
- Poseidon2 is not used. `Hn` / `H2(a, b)` in these documents means circomlib Poseidon with
  n / two inputs (`hash_2` in the circuit), not the Poseidon2 hash.
- State tree and ASP tree both have depth 16. Node = H2(left, right); empty leaf = 0;
  zeros(i + 1) = H2(zeros(i), zeros(i)); leaf index bit i = 0 means the running node is the
  left child at level i.
- On-chain: Tornado-style incremental tree (`MerkleTreeWithHistory`) with a 64-root history;
  the pool keeps the last 16 ASP roots.

## Rationale

Three independent, widely used and mutually compatible implementations exist for circomlib
Poseidon. Poseidon2 is cheaper in-circuit, but Solidity and TypeScript implementations that
match Noir's Poseidon2 would need extra verification that did not fit the time budget.

## Consequences

- Capacity: 65,536 leaves per tree. A deposit uses 1 leaf, a `transact` uses 2. When full,
  `_insert` reverts `MerkleTreeFull`; a new pool would be needed. Adequate for a capped pool.
- Cross-implementation agreement so far: the hard-coded `zeros()` table was generated with
  poseidon-lite, and `service/test/prove.ts` proves a spend whose commitments, nullifiers and
  roots were computed with poseidon-lite. On-chain agreement (PoseidonT3/T5 vs poseidon-lite)
  is covered by the Foundry tests (Poseidon vectors, the zeros chain and Merkle roots computed
  with poseidon-lite in Node; 52/52 at the v1 deployment), and a real proof verified on Base
  mainnet.
- Higher constraint count than Poseidon2; the measured proving time (6.7 s) still meets G1.
- Gas per tree insert (16 PoseidonT3 calls) was not measured separately; a whole `deposit`
  costs about 780k gas (RESEARCH R3).
