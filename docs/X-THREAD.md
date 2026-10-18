# X thread draft (edit freely before posting)

Each post is under 280 characters. Attach the demo video to post 1.

**1/**
Your AI agent knows your life. The chain shouldn't.

Ghost Mode gives your PayBox agent a private USDC balance on Base. Shield once, then pay people, addresses or x402 APIs without exposing your wallet.

Private by default. Provable on demand.

@MoonPay x PayBox hackathon

**2/**
The problem: every payment your agent makes (API calls, bookings, subscriptions) leaves from your public address. Counterparties, amounts, your time zone, your habits: public and permanent. Agents pay more often than humans, so the leak compounds.

**3/**
How it works: shield USDC into a ZK pool with ONE PayBox signature (EIP-3009, no ETH needed; the relayer pays gas). After that, each private payment is one more PayBox signature. Nothing else to install, no new seed phrase.

**4/**
The core idea: the PayBox wallet signs an EIP-712 intent, and that signature is verified INSIDE a zero-knowledge proof (Noir + UltraHonk, 2^18 gates, ~7 s). The key never leaves PayBox. A leaked privacy key cannot move funds.

**5/**
The approval screen can't lie: the hidden amount and recipient, the public amount and recipient, the fee and the deadline are all recomputed inside the circuit from the real spend. The plugin also self-checks every package before asking you to sign.

**6/**
Private x402: the merchant is paid by the Ghost relayer, not by your wallet. The pool pays the relayer; it re-quotes, pays with a standard x402 authorization and returns the response.

**7/**
The agent is your privacy operator: it warns before you withdraw the same amount you just deposited, can relay withdrawals at a random later time, and can scan what your own wallet already leaks.

**8/**
Provable on demand: give your accountant a receipt or a scoped report. A static verification page checks it in the browser against Base: the PayBox signature, the commitments, the nullifiers. It reveals only what you choose.

**9/**
Compliance and honesty: OFAC pre-screening, an association set, user-controlled disclosure. Unaudited and capped (100 USDC per deposit). The anonymity set is small today, and the prover is trusted for privacy, not for funds.

**10/**
It works on Base mainnet today. My PayBox agent paid an x402 API (trending coins) privately: ZK proof in 6.4 s, ~10 s end to end. The merchant was paid by the Ghost relayer, not my wallet.
Spend: basescan.org/tx/0xde4007a8782d2b1fa3e42334db4aa2731aa651c0d88249c2cddb268e09981c95
Settlement: basescan.org/tx/0x72a1009af1c36247db2344fd13690226a424d249066a5043b2fad284c308dfec

**11/**
Live on Base mainnet:
GhostPool 0x314EAAdE3E1a42627b5D2c6b1f87D0bbd67B8367
Verifier 0x6f197e0b8Adf9D5984b837be76e31De7ADfA18C1

Built for the @MoonPay x PayBox hackathon. Ghost Mode for PayBox.
