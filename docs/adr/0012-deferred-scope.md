# ADR 0012: Deferred scope for the hackathon build

- Date: 2026-10-17
- Status: Accepted; its list of deferred items is superseded by ADR 0021 (2026-10-17 21:30 UTC).
- Decided by: Semih (Himess) — approved on 2026-10-17 (design review and sprint plan).
- Proposed by: Claude Code (AI assistant); reviewed by Claude (claude.ai).

Brief D12 (decided by Semih) already made the DeFi adapters stretch scope. This ADR records
what else is deferred after ADR 0001 and what exists instead.

| Deferred | Brief reference | What exists instead |
| --- | --- | --- |
| Swap and ERC-4626 vault adapters | D12 (stretch) | Unshield to the PayBox wallet, then use PayBox `request_swap` (public). |
| Ragequit | D6 | Hackathon ASP approves every non-denylisted deposit (ADR 0011). |
| `ovk` sender copies of outgoing notes | Data model | The sender's record is the PayBox-signed `GhostSpend` intent and the job receipt. |
| Public disclosure verification page | D7 | `ghost_report` returns a scoped package (note openings for a date range plus verification steps); `ghost_receipt` returns one payment's signed typed data, signer, signature, nullifiers, output commitments and transaction hash, which anyone can check against Base. Full audit = sharing the ghost key (not scoped). |
| Multi-asset pool | D5 | Notes and the circuit carry `asset`, but each pool is deployed for one token (immutable); v1 is USDC only. |
| Ghost session mode | G1 fallback | Not needed: proving takes 6.7 s per spend (G1 met). |
| Key service / TEE | G5 fallback | Ghost key stored as a PayBox Secret (ADR 0008). |
| Own facilitator and demo merchant | G4 fallback | Third-party x402 endpoints on Base, paid by the relayer (ADR 0010). |
| Private orderflow beyond Base's sequencer | D11 | Honest claims only (RESEARCH R9). |
| Stealth-address payments (ERC-5564 / ERC-6538) | R11 note | Ghost addresses (`ghost:` + ownerTag + viewing key). |
| Ghost address alias registry | Data model | Ghost addresses are shared as strings. |
| Decentralised or bonded relayers, ERC-1271 x402 payer | v2 list | Single relayer EOA, payment capped at 1 USDC per request. |

## Consequences

- The demo covers shield, private balance, ghost transfer, pay to address / unshield,
  private x402, exposure scan, disclosure report and receipt.
- Receipts depended on job data held in the Ghost service's memory (fixed by ADR 0014:
  persistence and sender memos).

## Status update (2026-10-17)

The current list of deferred items, with reasons, is ADR 0021. Changes since this ADR:

- Public disclosure verification page: built during the sprint (`GET /verify`,
  `docs/ARCHITECTURE.md` section 11).
- `ovk` sender copies: replaced by self-encrypted memos in the change note (ADR 0014).
- Ragequit, multi-asset pool and DeFi adapters, TEE / key service, cloud hosting and
  decentralised relayers remain deferred (ADR 0021).
