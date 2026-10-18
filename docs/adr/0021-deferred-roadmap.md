# ADR 0021: Deferred roadmap

- Date: 2026-10-17 (decided at 21:30 UTC)
- Status: Accepted. Supersedes the deferred list in ADR 0012.
- Decided by: Semih (Himess) — 2026-10-17 21:30 UTC, "continue with the deferred improvements";
  the items below are what is consciously not built.
- Proposed by: Claude (claude.ai) design review ("Yapılmayacaklar" list and ideal design);
  written up by Claude Code (AI assistant).

## Context

After the sprint plan (ADRs 0013-0017) Semih decided to continue with the deferred
improvements: circuit v1.1 and GhostPool v3 (ADR 0018), the relay delay (ADR 0019) and the
key backup (ADR 0020). This ADR records what remains unbuilt and why.

## Decision

| Not built | Reason | What exists instead |
| --- | --- | --- |
| Ragequit | Needs a separate commitment-ownership circuit and verifier: the nullifier depends on `nk`, which the contract cannot check (ADR 0011). | ASP with OFAC SDN pre-screening; unapproved deposits stay locked. |
| In-circuit human-readable text | Large circuit change. | v1.1 splits the amounts (ADR 0018); plugin `human_summary` and self-checks (ADR 0016). |
| TEE prover | Infrastructure (proving inside PayBox/MoonX or another TEE). | The service sees the witness; trusted for privacy, not for funds (ADR 0007). |
| Multi-ASP and timelocked admin | Further contract changes and independent operators. | One ASP; pause stops deposits only (ADR 0017); caps. |
| Swap and vault adapters | Need a multi-asset pool; each pool is one immutable token (brief D12, stretch). | Unshield, then PayBox `request_swap` (public). |
| Cloud hosting | Not before the deadline. Move the service from the laptop and quick tunnel to a VPS with a stable host right after it; network hosts and variables remain editable after the deadline, so no new upload is needed. | Laptop plus Cloudflare quick tunnel (ADR 0007). |
| Relayer batching | Helps only with several concurrent users. | Optional random delay for public exits (ADR 0019). |
| Per-depositor labels | Would weaken per-deposit screening: a later deposit could share an already approved label. | One label per deposit (ADR 0006); notes of different deposits cannot be merged in one spend. |

Still deferred from ADR 0012: own x402 facilitator and demo merchant, ERC-1271 or bonded and
decentralised relayers, private orderflow beyond Base's sequencer (D11), stealth-address
payments (ERC-5564 / ERC-6538) and a ghost-address alias registry. Built since ADR 0012:
the verification page (sprint package E) and sender memos (ADR 0014). Not needed: ghost
session mode (proving takes about 7 s).

## Consequences

- README and demo claims must not imply any item in the table.
- Ragequit is the main compliance gap: denylisted deposits, and notes whose ghost key is lost
  without a backup (ADR 0020), cannot be withdrawn.
