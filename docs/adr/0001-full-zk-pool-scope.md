# ADR 0001: Build the full ZK shielded pool before the deadline

- Date: 2026-10-17 (decided at about 19:45 UTC)
- Status: Accepted
- Decided by: Semih (Himess)

## Context

The hackathon deadline is 2026-10-17 20:00 New York time (2026-10-18 00:00 UTC). The brief
planned a Phase 0 (research, measurements, ADRs, go/no-go gates G1-G5), a stop for Semih's
approval, and then a seven-phase build. With about four hours left, Claude Code offered three
delivery scopes. The smaller ones dropped the shielded pool; the smallest was a read-only
plugin (exposure scan and privacy-operator advice, no pool).

## Decision

Build the full product core now: the Noir `transact` circuit with in-circuit verification of
the PayBox wallet's ECDSA signature, the `GhostPool` contract on Base mainnet, the Ghost
service (indexer, prover, relayer, ASP, x402 payer, exposure scan) and the PayBox plugin.
Accept the delivery risk.

## Consequences

- The brief's "no production code before approval" rule is waived for this build. Phase 0
  research and measurements ran in parallel with implementation and are recorded in
  `docs/RESEARCH.md`.
- Several gates are only partly verified at submission time (see the G1-G5 table in
  `docs/RESEARCH.md`): the PayBox approval-screen rendering (G2), the end-to-end mainnet x402
  run (G4) and the key storage test in PayBox (G5).
- Implementation decisions taken by Claude Code under time pressure were recorded as proposals
  (ADRs 0003-0012). Semih approved them on 2026-10-17 with the external design review and its
  sprint plan (`docs/DECISIONS.md`).
- Stretch scope is deferred (ADR 0012, superseded by the roadmap in ADR 0021). Contracts are
  unaudited and capped.

## Alternatives considered

- Read-only scope (exposure scan and privacy advice only): low risk, but it does not deliver
  the product's core claim (private spending authorised by PayBox).
- Intermediate reduced scopes: rejected for the same reason.
