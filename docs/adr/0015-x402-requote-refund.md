# 15. x402 re-quote, refund and settlement receipts

Date: 2026-10-17

Decided by: Semih (Himess) — approved the review sprint plan at 21:00 UTC.
Proposed by: Claude (claude.ai) design review; implemented by Claude Code.

## Context

The relayer pays the merchant after the pool pays the relayer. A price change or a merchant failure could leave the user's money with the relayer.

## Decision

- Re-quote the endpoint after proving and before `transact`. If the price or payee changed, do not transact: status `requote_needed`, nothing is spent.
- If the merchant fails after `transact`, the relayer re-deposits the price as a new private note for the spender: status `refunded`. The spend package carries the spender's owner tag and viewing public key for this.
- Keep the settlement transaction from the `PAYMENT-RESPONSE` header in the receipt.

## Consequences

The relayer holds the user's money only for the duration of one payment. On merchant failure it could only keep the money by refusing to refund, which is visible and attributable.
