# Ghost Mode demo script (2.5 minutes)

Recorded in Claude.ai (or any MCP host) with the PayBox connector and the Ghost Mode plugin enabled.
Lines in quotes are what the presenter types. Use test wallets and say so on screen.

| Time | Scene | What the viewer sees | Message |
| --- | --- | --- | --- |
| 0:00 | Title: *Your agent knows your life. The chain shouldn't.* | | |
| 0:05 | "What is my wallet leaking?" | `ghost_exposure`: sign a challenge (only your own wallet), then the score and three concrete leaks (counterparties, x402 payments, inferred time zone). | The glass wallet |
| 0:20 | "Turn on Ghost Mode and shield 5 USDC." | `ghost_setup` (one message signature, key backed up), then `ghost_shield_authorize`: **one** PayBox typed-data approval, close-up of the PayBox screen. No ETH needed; the relayer pays gas. | One signature |
| 0:40 | "Pay this API privately: https://api.blockscout.com/8453/api/v2/stats" | `ghost_prepare pay_x402` → `human_summary` → one signature → `ghost_job` returns the JSON. Basescan: the merchant was paid by the Ghost relayer, not by the user. | Private x402 — the PayBox-native moment |
| 1:05 | Close-up | The PayBox approval screen: `privateAmount` / `privateRecipient` (hidden flow) and `publicAmount` / `publicRecipient` (public flow), fee and deadline — each recomputed inside the circuit from the real spend — next to "this signature was verified inside the zero-knowledge proof", and the `transact` on Basescan. | Spend authority stays in PayBox; the screen cannot lie |
| 1:20 | "Send 2 USDC to Ayse's ghost address, privately." | One signature; on-chain only a pool transaction, no sender, recipient or amount. | Who you pay stays private |
| 1:35 | "Withdraw everything to my wallet." | The privacy operator warns (same amount as a recent deposit, exiting right after shielding) and suggests splitting and waiting. | The agent as privacy operator |
| 1:50 | "Give my accountant a report." | `ghost_report` → open `verify_url`: green checks for every note, the outgoing-payment records and the owner binding; edit one field → red. `ghost_receipt` for the API payment. | Provable on demand |
| 2:10 | Architecture card + pool stats ("N deposits, test wallets") | PayBox signs once; the signature is checked inside an UltraHonk proof (Noir, 2^18 gates, ~7 s); the pool verifies it on Base. Honest limits: small anonymity set, service trusted for privacy, unaudited caps. | Honesty and scale |
| 2:25 | *Ghost Mode for PayBox. Private by default. Provable on demand.* | | |

## Prompts that work well

- "Use the Ghost Mode plugin. Set it up for my Base wallet."
- "Shield 5 USDC with Ghost Mode." (the agent uses `ghost_shield_authorize`; fallback `ghost_shield` approve + deposit)
- "What's my ghost balance?"
- "Privately pay this x402 endpoint: <url>"
- "Privately send 2 USDC to ghost:…"
- "Scan what my wallet leaks." (requires signing a challenge; only your own wallet)
- "Make a receipt for that payment." / "Disclosure report for today."
- "I lost my ghost key." (`ghost_recover` with a fresh signature)

## Before recording

1. Service running and the tunnel URL set as `GHOST_SERVICE_URL` + network host in the portal; `GHOST_POOL_ADDRESS` matches the service.
2. Relayer funded with a little ETH on Base (gas only; it is repaid in USDC fees).
3. A PayBox EVM wallet with some Base USDC (ETH not needed for the one-signature shield).
4. A second ghost identity for "Ayse" (`ghost_setup` from a second test wallet).
5. Record a backup take as soon as the full flow works once.
