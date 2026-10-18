# ADR 0008: Privacy key format and storage as a PayBox Secret (R7)

- Date: 2026-10-17
- Status: Accepted. Amended by ADR 0020 (encrypted backup and `ghost_recover`).
- Decided by: Semih (Himess) — approved on 2026-10-17 (design review and sprint plan).
- Proposed by: Claude Code (AI assistant); reviewed by Claude (claude.ai).
- Brief decision D4 (Semih): privacy keys are separate from spend authority. This ADR records the key format, derivation and storage.

## Context

Brief D4 separates privacy keys (`nk`, viewing key) from spend authority (the PayBox
signature). R7 asked where to store them. Deriving them from a PayBox signature would avoid
storage, but only works if MPC signatures are deterministic, which is untested (R2). Plugin
code cannot read PayBox Secrets (they are only injected as HTTP headers), and plugin
environment variables are per plugin, not per user.

## Decision

- Ghost key = random 32-byte seed plus the PayBox wallet's 64-byte uncompressed secp256k1
  public key (no `0x04` prefix), encoded as `ghk1_<seed hex>_<pubkey hex>`.
- Derivations (`plugin/src/core/primitives.ts`):
  - `nk = keccak256(seed || "ghost-mode:nk") mod p`
  - `viewPriv = sha256(seed || "ghost-mode:ivk")`, `viewPub = X25519(viewPriv)`
  - `pkHash = Poseidon(x_hi, x_lo, y_hi, y_lo)` over 128-bit big-endian limbs of the key
  - `ownerTag = Poseidon(pkHash, Poseidon(nk))`
  - ghost address = `ghost:` + hex(`ownerTag` (32 bytes) || `viewPub` (32 bytes)) + first
    4 bytes of keccak256 of that payload as a checksum.
- `ghost_setup` asks PayBox to sign a setup message (EIP-191), recovers the public key from
  the signature, generates the seed and returns the ghost key, ghost address and the wallet
  address derived from the recovered key. The signature is used only to learn the public key;
  no key material is derived from it.
- The user stores the ghost key as a PayBox Secret. The agent supplies it as the `ghost_key`
  argument of the ghost tools.

## Consequences

- Leak: the holder sees balances and history and can link spends; spending still needs a
  PayBox signature (the change-output gap found in documentation review was fixed before
  deployment, ADR 0005).
- Loss: notes are bound to `nk`; without the ghost key they cannot be found or spent, and
  there is no ragequit. Key loss therefore means loss of access to funds, not only of privacy
  (design review finding 2). Mitigation since the sprint: an encrypted backup on the service,
  released by `ghost_recover` to a fresh signature from the same PayBox wallet (ADR 0020).
- The key passes through the agent context, the plugin sandbox and (as witness data) the
  Ghost service.
- Before the first deposit, the agent should compare `wallet_address` returned by
  `ghost_setup` with the PayBox wallet address; a mismatch would bind notes to a key PayBox
  cannot sign for.
- Open (G5): retrieving the Secret with `request_secret` needs a grant that allows a raw
  reveal; not yet tested in PayBox.
- No rotation: a new key means a new ghost address; funds move by spending to it.

## Alternatives considered

- Derive keys from a PayBox signature: depends on untested MPC signature determinism (R2,
  pending the live PayBox test; ADR 0020).
- Key service or TEE (brief G5 fallback): not feasible before the deadline.
- Plugin environment variable: not secret and shared by all users of the plugin.
