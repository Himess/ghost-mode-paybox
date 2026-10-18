# ADR 0003: Noir 1.0.0-beta.22 and bb.js 5.0.0-nightly.20260522 UltraHonk (EVM target)

- Date: 2026-10-17
- Status: Accepted
- Decided by: Semih (Himess) — approved on 2026-10-17 (design review and sprint plan).
- Proposed by: Claude Code (AI assistant); reviewed by Claude (claude.ai).
- Brief decision D2 (Semih): Noir + Barretenberg UltraHonk. This ADR records the version pins, verifier target and the Windows compile path.

## Context

Brief D2 chose Noir with Barretenberg UltraHonk: secp256k1 ECDSA and keccak are black-box
functions, there is no trusted setup, and a Solidity verifier can be generated. Concrete
versions had to be picked that are known to work together, run on the development machine
(Windows 10) and produce a verifier that Base can execute.

- Aztec's `bbup` tool maps each Noir version to a Barretenberg version in `bb-versions.json`
  (copy in `research/bb-versions.json`). Its newest entry is `1.0.0-beta.22` ->
  `5.0.0-nightly.20260522`.
- `nargo` has no Windows build for v1.0.0-rc.5.
- `@noir-lang/noir_wasm`'s Node file manager breaks on Windows drive paths.

## Decision

- Noir `1.0.0-beta.22` via npm (`@noir-lang/noir_wasm`, `@noir-lang/noir_js`).
- `@aztec/bb.js` `5.0.0-nightly.20260522`, the pairing listed in `bb-versions.json`.
- UltraHonk with `verifierTarget: "evm"` for the verification key, proofs and the Solidity
  verifier: keccak Fiat-Shamir transcript, zero-knowledge variant (the generated contract is
  `BaseZKHonkVerifier`/`HonkVerifier`).
- Compile in Node through an in-memory POSIX file system (`service/src/zk/noirFs.ts`);
  `service/src/zk/compile.ts` writes `circuits/transact/target/transact.json`,
  `circuits/transact/target/vk.bin` and `contracts/src/HonkVerifier.sol`.
- Prove in the Ghost service with bb.js WASM, multithreaded (one thread per CPU), one proof at
  a time, backend warmed at startup.

## Consequences

- Measured on the dev machine for circuit v1: N = 2^18 = 262,144, 14 public inputs, witness
  409 ms, proof 6.7 s, proof 9,536 bytes, VK 1,888 bytes (`docs/RESEARCH.md`, R3).
- The verifier's `NUMBER_OF_PUBLIC_INPUTS` is 22: the 14 circuit inputs plus 8 pairing-point
  limbs carried inside the proof. Callers pass exactly 14.
- `HonkVerifier` links two external libraries (`RelationsLib`, `ZKTranscriptLib`), so the
  verifier is three deployments.
- The VK is baked into `HonkVerifier.sol`. Any change to the circuit or to either version
  requires recompiling, regenerating the verifier and redeploying the pool (the pool's
  verifier address is immutable). Circuit v1.1 goes through this chain (ADR 0018).
- bb.js is a nightly pre-release; versions are pinned exactly in `service/package.json`.
- No `nargo test` on Windows: the circuit is exercised end to end by `service/test/prove.ts`
  (build spend, sign, execute, prove, verify).
- Native `bb` proving on Linux is a later optimisation; WASM already meets G1.

## Alternatives considered

- Newer Noir release candidates without a known bb pairing: risk of VK/verifier mismatch.
- WSL2 (PayBox's recommended setup) with native `nargo`/`bb`: not available on the dev
  machine in the time left.
- Poseidon-transcript (non-EVM) verifier target: cheaper proving, but the Solidity verifier
  requires the keccak transcript.
