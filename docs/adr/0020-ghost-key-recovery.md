# ADR 0020: Encrypted ghost-key backup on the service

- Date: 2026-10-17
- Status: Accepted. Implemented during the sprint; covered by the local end-to-end run
  (RESEARCH, gate G5). Not yet tested with a real PayBox wallet.
- Decided by: Semih (Himess) — approved as package R of the design review's sprint plan
  (21:00 UTC); confirmed with "continue with the deferred improvements" (21:30 UTC).
- Proposed by: Claude (claude.ai) design review (finding 2, package R); implemented by Claude
  Code (AI assistant).
- Amends: ADR 0008.

## Context

Notes are bound to `nk`. Losing the ghost key means losing access to the funds, not only to
privacy, and there is no ragequit (review finding 2; ADR 0008). Deriving the key from a PayBox
signature would remove the storage problem, but only if PayBox signatures are deterministic,
which is untested (R2).

## Decision

- `ghost_setup` stores the ghost key on the service, encrypted with AES-256-GCM under a master
  key file outside the repository (`../.secrets/backup.key`); backups are indexed by the PayBox
  wallet address (`POST /v1/keys/backup`).
- `ghost_recover` releases the key only to a fresh (15-minute) signature from the same PayBox
  wallet (`POST /v1/keys/recover`); a signature from another wallet is rejected.
- The PayBox Secret (ADR 0008) remains the primary copy.
- Deterministic key derivation from a PayBox signature remains possible only if PayBox
  signatures prove deterministic (R2, pending the live test).

## Consequences

- Trust model unchanged: the service already sees spend witnesses, including `nk` (ADR 0007).
- With the backup, control of the PayBox wallet is enough to recover the ghost key and so to
  spend; spend authority already rests with that wallet (ADR 0005).
- The service operator holds the master key and could decrypt backups; the backups add no new
  party but are another copy to protect.
- Recovery depends on the service and its disk; if both the Secret and the service data are
  lost, the notes are lost.

## Alternatives considered

- Seed derived from a PayBox signature: depends on R2.
- Key service in a TEE: infrastructure work (ADR 0021).
- No backup: key loss stays fund loss.
