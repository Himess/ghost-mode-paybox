# ADR 0009: Note encryption with X25519 ECDH and AES-256-GCM

- Date: 2026-10-17
- Status: Accepted. Amended by ADR 0014 (ciphertext v2 with a sender memo) and ADR 0018 (change blinding derived in-circuit).
- Decided by: Semih (Himess) — approved on 2026-10-17 (design review and sprint plan).
- Proposed by: Claude Code (AI assistant); reviewed by Claude (claude.ai).

## Context

Recipients find their notes by scanning ciphertexts emitted in `NewCommitment` events. The
brief suggested X25519 with ChaCha20-Poly1305 and an `ovk` copy for the sender.

## Decision

- Ephemeral X25519 key per note; `key = sha256("ghost-mode:note" || sharedSecret || ephPub ||
  recipientViewPub)`; AES-256-GCM with a random 12-byte IV (`node:crypto`).
- Fixed 133-byte layout (v1): `0x01` (version) | ephPub (32) | IV (12) | ciphertext (72 =
  amount u64 big-endian 8 | blinding 32 | label 32) | GCM tag (16). Ciphertext v2 (`0x02`)
  adds a sender memo to the change note (ADR 0014); v1 notes still decrypt.
- Deposits encrypt label 0; the scanner takes the real label from the `Deposited` event with
  the same leaf index.
- Ghost transfer: output 0 encrypted to the recipient's `viewPub`, change encrypted to the
  sender's own `viewPub`; zero-value outputs carry empty ciphertext (`0x`). Since ADR 0014
  the change note is always emitted with a ciphertext, even with zero change.
- Scanning: trial-decrypt every leaf, then accept a note only if the recomputed commitment
  matches the on-chain commitment.
- No `ovk` sender copies; the self-encrypted memo in the change note (ADR 0014) replaces
  them.
- From circuit v1.1 the change blinding is derived in-circuit as `H2(nk, nullifier0)`
  (ADR 0018), so a change note can be found from the chain and the ghost key even if its
  ciphertext were unreadable (design review finding 7).

## Consequences

- Fixed-size ciphertexts reveal nothing about amounts. Ciphertexts are bound into
  `extDataHash`, so a relayer cannot replace them.
- No view tags: every call scans every leaf (the plugin is stateless). Acceptable at
  hackathon scale; cost grows linearly with the tree.
- Without `ovk` copies the sender could not decrypt what it sent from chain data; since
  ADR 0014 the change-note memo lets `ghost_report` rebuild outgoing payments from the chain
  and the ghost key.
- AES-256-GCM instead of ChaCha20-Poly1305: both are standard AEADs available in
  `node:crypto`; a fresh ephemeral key per note keeps the key/IV pair unique.
