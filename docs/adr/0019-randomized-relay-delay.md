# ADR 0019: Optional randomized relay delay for public exits

- Date: 2026-10-17 (decided at 21:30 UTC)
- Status: Implemented and running in production (2026-10-17 ~21:55 UTC). Covered by `service/test/delay.ts`
  (14 checks) and the local end-to-end run (a delayed unshield is scheduled, its note shows as
  `pending_relay` and cannot be spent again, then it is relayed at the random time).
- Privacy detail: notes being relayed are published only as tags `H2(nullifier, nk)` (`pendingTags` in
  `/v1/state`), never as raw nullifiers. Raw nullifiers before relay would reveal the submit time to anyone
  polling the service and defeat the delay; only the note owner, who knows `nk`, can match a tag.
- Decided by: Semih (Himess) — 2026-10-17 21:30 UTC, "continue with the deferred improvements".
- Proposed by: Claude (claude.ai) design review ("ideal design: relayer random delay and
  batching"; package G, deferred for the night with "only as an option for unshield"); Claude
  Code self-review item 9; implemented by Claude Code (AI assistant).

## Context

The relayer submits a spend as soon as it is proved. An observer can match a public exit with
the user's deposit or activity by time; timing correlation is the most common practical leak,
and the privacy operator already warns about exits within 30 minutes of the user's own deposit
(`timing_correlation`, ARCHITECTURE section 7). The review deferred a delay because it
conflicts with x402 and costs demo time.

## Decision

- `unshield` and `pay_address` accept an optional relay delay of 0-30 minutes. The send time is
  drawn uniformly at random within the chosen window; until then the job has status
  `scheduled`.
- Not offered for `pay_x402`: the merchant needs immediate payment. Not offered for ghost
  transfers: they are already private (no public recipient or amount).
- The service refreshes the Merkle and ASP roots at send time. This needs no new signature,
  because the PayBox signature binds nullifiers, outputs and external data but not the roots;
  it keeps the proof valid when the pool's root history (64 state roots, 16 ASP roots) has
  moved on.
- Batching several users' spends remains future work (ADR 0021).

## Consequences

- Weakens time-based linking of a public exit to a deposit; it does not hide the exit's amount
  or recipient, and it adds little while the anonymity set is small.
- The user waits up to 30 minutes for the payout.
- The signed `deadline` must lie after the latest possible send time (`ghost_prepare` sets now
  + 20 minutes by default, ARCHITECTURE section 6).
- Scheduled jobs live in the service, so they rely on its persistence (ADR 0014) and uptime.

## Alternatives considered

- Fixed delay: easier to subtract than a uniformly random one.
- Relayer batching: needs several concurrent users to help; deferred.
- Delay for x402: rejected, merchants expect payment within the request.
