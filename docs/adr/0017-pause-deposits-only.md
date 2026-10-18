# 17. Pause stops deposits only

Date: 2026-10-17

Decided by: Semih (Himess) — approved the review sprint plan at 21:00 UTC.
Proposed by: Claude (claude.ai) design review; implemented by Claude Code.

## Context

In GhostPool v1, `pause` also blocked `transact`, so an admin holding a hot key could freeze user funds.

## Decision

In GhostPool v2, `pause` blocks `deposit` and `depositWithAuthorization` only. `transact`, and therefore every withdrawal, is always available.

## Consequences

The admin can stop new money from entering but cannot trap existing funds. Ownership should still move to a cold address.
