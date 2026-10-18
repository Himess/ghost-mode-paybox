# ADR 0007: Thin PayBox plugin plus a Ghost service

- Date: 2026-10-17
- Status: Accepted. Amended by ADR 0014 (service state persisted to disk) and ADR 0020 (encrypted ghost-key backup on the service).
- Decided by: Semih (Himess) — approved on 2026-10-17 (design review and sprint plan).
- Proposed by: Claude Code (AI assistant); reviewed by Claude (claude.ai).

## Context

PayBox plugin constraints (R1, `research/requirements.md`):

- every operation runs in a fresh sandbox; no memory or disk survives between calls;
- 10-second budget per operation;
- one unsigned EVM call per transaction proposal;
- HTTPS only to exactly configured network hosts (at most 16), so the plugin cannot reach
  arbitrary x402 merchants or RPC providers chosen at run time;
- secrets are injected only as host-scoped HTTP headers, never readable by plugin code.

A private spend needs about 7 s of proving (R3) plus relaying and confirmation, and an x402
payment needs a payer that holds a key and calls the merchant. This is the brief's G3
fallback: heavy work moves to services, the plugin stays a thin client.

## Decision

- Plugin (`plugin/`): key parsing, note scanning (trial decryption), privacy-operator checks,
  spend construction and EIP-712 typed data, PayBox proposal envelopes. Its only network host
  is the Ghost service.
- Ghost service (`service/`, one Node process): indexer, ASP, prover, relayer, x402 payer and
  exposure scan, exposed as a small JSON API (`docs/ARCHITECTURE.md`).
- Long work runs as asynchronous jobs: `POST /v1/prepare` -> `prepare_id`, agent obtains the
  PayBox signature, `POST /v1/submit` -> `job_id`, agent polls `GET /v1/jobs/:id` through
  `ghost_job`. Plugin HTTP calls use 6-8.5 s timeouts.
- Hackathon hosting: the service runs on Semih's machine behind a Cloudflare quick tunnel. The
  plugin reads the service origin from `GHOST_SERVICE_URL` (non-secret environment variable,
  HTTPS required); the tunnel hostname is configured as the plugin's network host in the
  PayBox portal. Optional `GHOST_POOL_ADDRESS` pins the pool the service must report.

## Consequences

- The service is trusted for privacy (it receives the full witness, including `nk` and note
  openings) and for liveness, not for funds: it cannot produce a valid spend without a fresh
  PayBox signature over that spend (the change output is bound to the spender in-circuit,
  ADR 0005).
- Cloudflare terminates TLS for the quick tunnel and can read service traffic.
- Pool state is rebuilt from events. Prepared spends, jobs and receipt data were first held in
  memory only; since the sprint they are persisted under `service/data/` (ADR 0014).
- The service also holds encrypted ghost-key backups (ADR 0020).
- A quick-tunnel hostname changes on restart. The portal's network host and
  `GHOST_SERVICE_URL` must then be updated; PayBox allows owners to edit hosts and variables
  after the deadline without a new upload. Moving the service to a VPS with a stable host is
  planned right after the deadline (ADR 0021).
- If `SERVICE_TOKEN` is set, the service requires `Authorization: Bearer <token>`; configure
  it in the portal as a brokered header secret for the service host.

## Alternatives considered

- Proving inside the plugin sandbox: exceeds the 10 s budget together with network calls,
  and the bundle limit (10 MiB) leaves little room for bb.js WASM and the circuit.
- Separate deployed services (indexer, prover, relayer, keys): more moving parts than the
  remaining time allowed.
