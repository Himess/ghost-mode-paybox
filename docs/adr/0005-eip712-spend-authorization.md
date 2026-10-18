# ADR 0005: Spend authorization with an EIP-712 `GhostSpend` signature verified in-circuit

- Date: 2026-10-17
- Status: Accepted for circuit v1 (GhostPool v1 and v2). The `GhostSpend` struct below is superseded by ADR 0018 for circuit v1.1 (GhostPool v3).
- Decided by: Semih (Himess) — approved on 2026-10-17 (design review and sprint plan).
- Proposed by: Claude Code (AI assistant); reviewed by Claude (claude.ai).
- Brief decisions D3 and D9 (Semih): spend authority is the PayBox wallet's ECDSA signature, verified inside the circuit; prepare -> sign -> submit -> poll flow. This ADR records the detailed message encoding.

## Context

The PayBox key never leaves MoonX MPC. The agent can ask PayBox to sign an EIP-712 message
with `request_wallet_sign` op `typedData` and poll `get_request` for the signature. The brief
requires the approval screen to show readable fields and the signature to be bound to exactly
one spend.

## Decision

The PayBox wallet signs:

```
GhostSpend(bytes32 intent,address token,uint256 amount,address to,uint256 fee,uint256 deadline,bytes32 recipientTag)
domain: { name: "GhostMode", version: "1", chainId, verifyingContract: <GhostPool> }
```

- `intent = Poseidon(nullifier0, nullifier1, outCommitment0, outCommitment1, extDataHash)`.
- `extDataHash = keccak256(abi.encode(relayer, encryptedOutput0, encryptedOutput1)) mod p`.
- The circuit derives the readable fields from the real spend instead of taking them as
  inputs:
  - `token` = public input `asset`;
  - `amount` = `out_amounts[0] + public_out - fee` (value leaving to the recipient);
  - `to` = public input `recipient` (zero address for ghost transfers);
  - `fee`, `deadline` = public inputs;
  - `recipientTag` = `out_owner_tags[0]` if `out_amounts[0] != 0`, else zero.
- The circuit builds the 256-byte struct encoding, hashes it with keccak256, computes
  `digest = keccak256(0x19 0x01 || domainSeparator || structHash)` and verifies the secp256k1
  ECDSA signature against the PayBox public key (private input), which is bound to the notes
  through `ownerTag` (ADR 0008).
- The domain separator is a public input split into two 128-bit limbs (`domainHi`,
  `domainLo`) because a 256-bit value does not fit the BN254 field. The pool computes it in
  its constructor from `block.chainid` and `address(this)`.
- Signatures are normalised to low-s (`s -> n - s` when `s > n/2`) before proving; MPC signers
  may return high-s signatures.
- Before proving, the service recomputes the EIP-712 digest from the stored typed data,
  recovers the public key and compares it with the spend package's key. One prepared spend
  accepts one signature.

## Consequences

- Neither the signature nor the PayBox address appears on-chain; the proof does.
- Replay protection: nullifiers (single use), `deadline` (checked by the pool) and the domain
  separator (chain and pool).
- The relayer and the encrypted outputs are bound through `extDataHash`, so a relayer cannot
  redirect its fee or swap ciphertexts.
- Open (G2): how PayBox renders `GhostSpend` (field labels, `uint256` amounts in atomic units,
  `deadline` as a Unix timestamp, opaque `intent`/`recipientTag`) has not been checked on a
  real PayBox wallet.
- The design review (finding 6) noted that `amount` sums the hidden and the public value and
  that `recipientTag` is opaque. Mitigations: the plugin's self-checks and `human_summary`
  (ADR 0016) and, from circuit v1.1, separate `privateAmount`/`publicAmount` fields
  (ADR 0018).
- The change output (`out_owner_tags[1]`) is constrained to the spender's own `ownerTag`
  (`assert(out_owner_tags[1] == owner_tag)`), so a malicious preparer cannot redirect change
  that the approval screen does not show. This gap was found in documentation review and fixed
  before the mainnet deployment (circuit recompiled, verifier regenerated, 52 Foundry tests and
  the local end-to-end run re-passed).

## Alternatives considered

- Fixed-template EIP-191 message with the intent hex at a fixed offset (the brief's G2
  fallback): no readable fields in wallets that render typed data.
- Brief's original intent layout (Poseidon over chainId, pool, asset, amounts, recipient,
  relayer, fee, deadline): equivalent binding, but those values are already bound by the
  domain separator and the struct fields, so the intent only needs the nullifiers, outputs
  and external data.
