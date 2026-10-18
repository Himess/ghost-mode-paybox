# ADR 0010: Private x402 with the relayer as payer of record

- Date: 2026-10-17
- Status: Accepted. Amended by ADR 0015 (re-quote before `transact`, refund, settlement receipts).
- Decided by: Semih (Himess) — approved on 2026-10-17 (design review and sprint plan).
- Proposed by: Claude Code (AI assistant); reviewed by Claude (claude.ai).
- Brief decision D8 (Semih): the relayer is the x402 payer of record. This ADR records the flow details, protocol versions and the per-request cap.

## Context

x402 "exact" payments on Base are EIP-3009 `TransferWithAuthorization` signatures from the
payer. The pool cannot sign, and PayBox's own x402 proposals pay from the user's wallet, which
links the payment to the user's address. The plugin cannot reach arbitrary merchant hosts
(R1), so probing and fetching must happen in the Ghost service.

## Decision

1. `ghost_prepare` (action `pay_x402`, `url`, optional `method`/`body`) calls
   `POST /v1/x402/quote`. The service sends the unpaid request and parses the 402:
   - x402 v1: JSON body `accepts`, price in `maxAmountRequired`, network `base`;
   - x402 v2: base64 JSON in the `PAYMENT-REQUIRED` header, price in `amount`, network
     `eip155:8453`.
   It selects the `exact` requirement for Base USDC and rejects prices above
   `X402_MAX_AMOUNT` (default 1 USDC).
2. The plugin builds a spend whose public output is `price + fee` to the relayer address
   (`price` as the payment, `fee` as the relayer fee); change returns to the user.
3. `POST /v1/prepare` re-quotes the endpoint and requires the same price.
4. The user signs `GhostSpend` in PayBox (`amount` = price, `to` = relayer, `fee`; from circuit
   v1.1: `publicAmount` = price, `publicRecipient` = relayer, ADR 0018).
5. The job proves and relays `transact`, waits for the receipt, then the relayer signs an
   EIP-3009 authorization (`from` relayer, `to` payTo, `value` price, `validAfter` now - 600 s,
   `validBefore` now + `maxTimeoutSeconds` (default 120 s), random 32-byte nonce; domain name
   and version from the requirement's `extra`, default "USD Coin" / "2") and fetches the
   resource with `X-PAYMENT` (v1) or `PAYMENT-SIGNATURE` (v2).
6. The job stores the HTTP status, content type, body (truncated at 48,000 characters) and
   the `PAYMENT-RESPONSE` / `X-PAYMENT-RESPONSE` header; `ghost_job` returns them.

## Consequences

- The merchant and its facilitator see only the relayer's EOA; no merchant changes.
- The relayer needs ETH for gas and a USDC float: it pays the merchant from its own balance
  after the pool has paid it.
- Trust in the relayer is bounded by one payment: it holds `price + fee` and could fail to pay.
  In the first build a merchant failure after `transact` left the funds with the relayer and a
  refund was manual. ADR 0015 adds a re-quote before `transact` (`requote_needed`) and an
  automatic refund note to the spender (`refunded`).
- The signed intent names the relayer, not the merchant. A receipt for an x402 payment
  combines the signed intent with the relayer's EIP-3009 transfer to `payTo`.
- Fixed during implementation: `/v1/prepare` first checked only the quoted price against the
  client-supplied summary, so a crafted package could make the relayer pay a merchant from its
  float without being paid. It now rejects x402 spends that do not pay `price + fee` to the
  relayer (`docs/ARCHITECTURE.md` section 10).
- Payment headers are built by the service; the official `@x402` client library suggested in
  the design review (finding 3) is not used.

## Alternatives considered

- ERC-1271 smart-contract payer that pays atomically from the pool: needs facilitator support
  for contract signatures; v2 item in the brief.
- Own facilitator and demo merchant (brief G4 fallback): not built.
