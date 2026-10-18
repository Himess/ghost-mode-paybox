# Ghost Mode for PayBox: decision index

All decisions are Semih's (Himess, project owner). The "Proposed by" column says where each
design came from. Full records: `docs/adr/`. All times are UTC on 2026-10-17.

## How decisions were made

Semih wrote the product brief, including decisions D1-D12. During the build he chose the full
ZK scope (ADR 0001, about 19:45) and Alchemy as the chain-data provider (ADR 0002). At 20:35 he
commissioned an external design review from Claude (claude.ai); the status report sent to the
reviewer is `docs/REVIEW-FOR-CLAUDE-WEB.md`. He adopted the review's findings and its sprint plan
as his decisions (sprint plan approved at 21:00; recorded at 21:30). That approval covers the
implementation details in ADRs 0003-0012, which Claude Code had proposed during the build. At
21:30 he also decided to go ahead with the improvements the review had deferred (ADRs
0018-0021). Claude Code (AI assistant) wrote the code and proposed the implementation details.
Semih did not write those details himself; he approved them.

Brief decisions (Semih): D1 ZK shielded UTXO pool (not FHE or Railgun) · D2 Noir +
Barretenberg UltraHonk · D3 spend authority = PayBox ECDSA signature verified in-circuit ·
D4 privacy keys separate from spend authority · D5 Base mainnet, USDC first · D6 ASP +
ragequit · D7 scoped disclosure + public verification page · D8 relayer as x402 payer of
record · D9 prepare -> sign -> submit -> poll · D10 agent as privacy operator · D11 MEV and
honest claims · D12 DeFi adapters as stretch scope.

## ADRs

| ADR | Title | Decided by | Date | Proposed by |
| --- | --- | --- | --- | --- |
| 0001 | Build the full ZK shielded pool before the deadline | Semih | 2026-10-17, ~19:45 | Scope options offered by Claude Code |
| 0002 | Alchemy as chain-data provider | Semih | 2026-10-17 | Provider tests by Claude Code |
| 0003 | Noir 1.0.0-beta.22 and bb.js UltraHonk, EVM target | Semih (D2; details approved via review and sprint plan) | 2026-10-17 | Claude Code; reviewed by Claude (claude.ai) |
| 0004 | circomlib Poseidon over BN254, Merkle depth 16 | Semih (approved via review and sprint plan) | 2026-10-17 | Claude Code; reviewed by Claude (claude.ai) |
| 0005 | EIP-712 `GhostSpend` verified in-circuit | Semih (D3, D9; encoding approved via review and sprint plan) | 2026-10-17 | Claude Code; reviewed by Claude (claude.ai) |
| 0006 | Deposits without proofs | Semih (approved via review and sprint plan) | 2026-10-17 | Claude Code; reviewed by Claude (claude.ai) |
| 0007 | Thin PayBox plugin plus a Ghost service | Semih (approved via review and sprint plan) | 2026-10-17 | Claude Code; reviewed by Claude (claude.ai) |
| 0008 | Privacy key format and storage as a PayBox Secret | Semih (D4; details approved via review and sprint plan) | 2026-10-17 | Claude Code; reviewed by Claude (claude.ai) |
| 0009 | Note encryption, X25519 + AES-256-GCM | Semih (approved via review and sprint plan) | 2026-10-17 | Claude Code; reviewed by Claude (claude.ai) |
| 0010 | Private x402, relayer as payer of record | Semih (D8; details approved via review and sprint plan) | 2026-10-17 | Claude Code; reviewed by Claude (claude.ai) |
| 0011 | Hackathon ASP policy; ragequit deferred | Semih (D6; policy approved via review and sprint plan) | 2026-10-17 | Claude Code; reviewed by Claude (claude.ai) |
| 0012 | Deferred scope (superseded by 0021) | Semih (approved via review and sprint plan) | 2026-10-17 | Claude Code; reviewed by Claude (claude.ai) |
| 0013 | One-signature, gasless shield (EIP-3009) | Semih (sprint plan) | 2026-10-17, 21:00 | Claude (claude.ai) review; implemented by Claude Code |
| 0014 | Self-encrypted memos and service persistence | Semih (sprint plan) | 2026-10-17, 21:00 | Claude (claude.ai) review; implemented by Claude Code |
| 0015 | x402 re-quote, refund and settlement receipts | Semih (sprint plan) | 2026-10-17, 21:00 | Claude (claude.ai) review; implemented by Claude Code |
| 0016 | Pre-signature self-validation and human summaries | Semih (sprint plan) | 2026-10-17, 21:00 | Claude (claude.ai) review; implemented by Claude Code |
| 0017 | Pause stops deposits only | Semih (sprint plan) | 2026-10-17, 21:00 | Claude (claude.ai) review; implemented by Claude Code |
| 0018 | Circuit v1.1 and GhostPool v3: split amounts | Semih (deferred improvements) | 2026-10-17, 21:30 | Claude (claude.ai) review; implemented by Claude Code (in progress) |
| 0019 | Optional randomized relay delay | Semih (deferred improvements) | 2026-10-17, 21:30 | Claude (claude.ai) review; implemented by Claude Code (in progress) |
| 0020 | Encrypted ghost-key backup on the service | Semih (sprint plan package R; confirmed 21:30) | 2026-10-17 | Claude (claude.ai) review; implemented by Claude Code |
| 0021 | Deferred roadmap | Semih (deferred improvements) | 2026-10-17, 21:30 | Claude (claude.ai) review; written up by Claude Code |

Review findings and their status: `docs/RESEARCH.md`, "Design review (2026-10-17)".
