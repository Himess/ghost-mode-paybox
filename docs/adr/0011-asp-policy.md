# ADR 0011: Hackathon ASP policy; ragequit deferred

- Date: 2026-10-17
- Status: Accepted. The denylist was extended with the OFAC SDN list during the sprint; ragequit stays on the roadmap (ADR 0021).
- Decided by: Semih (Himess) — approved on 2026-10-17 (design review and sprint plan).
- Proposed by: Claude Code (AI assistant); reviewed by Claude (claude.ai).
- Brief decision D6 (Semih): Privacy Pools style association set (ASP) with ragequit. This ADR records the hackathon screening policy and the ragequit deferral.

## Context

Every spend proves that its label is in the ASP tree whose root the pool knows. R10 asked for
screening sources. The Chainalysis sanctions oracle address
`0x40C57923924B5c5c5455c48D93317139ADDaC8fb` has no code on Base (checked with
`eth_getCode`), so there is no on-chain screening source to call from the ASP on Base.

## Decision

- The ASP (part of the Ghost service, `service/src/asp.ts`) approves deposits deterministically:
  all deposits in deposit order, minus depositors on `ASP_DENYLIST` (comma-separated
  addresses) and minus deposits younger than `ASP_DELAY_SECONDS` (default 0).
- The approved labels form a depth-16 Poseidon tree; the ASP operator key (the relayer key in
  this deployment) publishes its root with `GhostPool.setAspRoot`. The pool keeps the last
  16 ASP roots.
- The service serves the label list that matches the on-chain root so clients can build ASP
  paths; clients check the root before building a spend.
- Ragequit is deferred (roadmap: ADR 0021).
- Sprint update (review package H): the OFAC SDN Ethereum address list is vendored under
  `service/data/` and merged into the denylist; sanctioned senders are refused before a
  one-signature shield is relayed (ADR 0013).

## Consequences

- Anyone can recompute the association set from public `Deposited` events and the policy.
- Unapproved (denylisted) deposits cannot be spent privately and, without ragequit, cannot be
  withdrawn at all in v1.
- The ASP operator can freeze spending by publishing roots that exclude labels. In GhostPool v1
  the owner could also pause spends; since v2 pause stops deposits only (ADR 0017). Neither can
  move funds.
- Each new approved deposit costs one `setAspRoot` transaction paid by the operator.

## Why ragequit is deferred

A ragequit must also mark the note's nullifier as spent, otherwise the same note could be
ragequit and spent privately. The nullifier depends on `nk`, which the contract cannot check
without a commitment-ownership proof (Privacy Pools uses a separate ZK proof for this). A
`msg.sender == depositor` check alone is not safe. This needs a second circuit and verifier.

## Alternatives considered

- Off-chain sanctions lists (OFAC SDN) in the ASP: not integrated in the first build; added
  through the denylist hook during the sprint (see Decision).
- Approve-all without a denylist: removes the compliance story entirely.
