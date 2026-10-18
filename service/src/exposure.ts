// Ghost Mode - exposure scan.
//
// Answers "what does the PUBLIC Base chain already reveal about this wallet?" for one
// address (the user's own PayBox wallet; the plugin enforces ownership separately).
//
//   scanExposure()    network layer: one parallel round of JSON-RPC calls (4 s timeout
//                     each, one page per transfer query, whole scan capped at ~5.5 s),
//                     plus a small receipt probe when full-history eth_getLogs is refused.
//                     Without Alchemy (non-*.alchemy.com host, or both transfer queries
//                     fail) it falls back to public-RPC mode: USDC Transfer /
//                     AuthorizationUsed logs over the most recent ~100k blocks, in 10k-block
//                     chunks from base-rpc.publicnode.com, whole scan capped at ~6.5 s.
//   analyzeExposure() pure analysis over the raw payloads, unit-testable offline.
//
// The RPC URL normally embeds an API key. It is never logged: every error produced here
// is built from the method name and HTTP status only, and server-supplied error text is
// redacted and truncated before it can reach a report.
//
// All money math is bigint on raw token units; amounts leave this module as decimal
// strings. Token symbols are attacker-controlled (spam tokens), so they never reach the
// report: non-USDC tokens are identified by contract address only.

import { formatUnits, getAddress, isAddress, keccak256, parseUnits, toHex } from "viem";

type Address = `0x${string}`;

export const BASE_CHAIN_ID = 8453;
export const BASE_USDC: Address = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
/** keccak256("AuthorizationUsed(address,bytes32)"): emitted by USDC for every EIP-3009 authorization. */
export const AUTHORIZATION_USED_TOPIC = keccak256(toHex("AuthorizationUsed(address,bytes32)"));

const USDC = BASE_USDC.toLowerCase();
const ZERO = "0x0000000000000000000000000000000000000000";
const REQUEST_TIMEOUT_MS = 4_000;
const TOTAL_BUDGET_MS = 5_500;
const PROBE_CAP = 25; // receipts checked when full-history eth_getLogs is unavailable
const PROBE_CONCURRENCY = 6;
const FACILITATOR_PROBE = 3; // receipts used to name the x402 facilitator when getLogs worked
const MAX_REPORT_BYTES = 12_000;
const USDC_ROUND = 1_000_000n; // 1 USDC
const ETH_ROUND = 10_000_000_000_000_000n; // 0.01 ETH
const DAY = 86_400;

// Public-RPC fallback (no Alchemy): bounded eth_getLogs scan of recent blocks.
export const PUBLIC_LOGS_RPC = "https://base-rpc.publicnode.com";
export const TRANSFER_TOPIC = keccak256(toHex("Transfer(address,address,uint256)"));
const PUBLIC_WINDOW_BLOCKS = 100_000; // ~55 h at 2 s per block
const PUBLIC_CHUNK_BLOCKS = 10_000; // inclusive range per eth_getLogs call
const PUBLIC_HEAD_MARGIN = 20; // the log node may be a few blocks ahead of rpcUrl's head
const PUBLIC_LOG_CONCURRENCY = 4;
const PUBLIC_TS_CAP = 40; // eth_getBlockByNumber lookups; the rest are estimated
const PUBLIC_TS_CONCURRENCY = 8;
const PUBLIC_LOGS_BUDGET_MS = 5_000;
const PUBLIC_BUDGET_MS = 6_500; // whole scan, measured from scanExposure() start
const BLOCK_SECONDS = 2;

// ---------------------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------------------

export type Severity = "high" | "medium" | "low";
export interface Finding { severity: Severity; title: string; detail: string }
export interface Penalty { reason: string; points: number }
export type X402Source = "eth_getLogs" | "receipt-probe" | "unavailable";
export type SourceStatus = "ok" | "partial" | "fallback" | "failed";

export interface CounterpartySummary {
  address: Address;
  direction: "in" | "out" | "both";
  inCount: number;
  outCount: number;
  count: number;
  usdcIn: string;
  usdcOut: string;
  usdcVolume: string;
  firstSeen: string | null;
  lastSeen: string | null;
  /** recurring | x402-payee | frequent | two-way | funding-source */
  flags: string[];
}

export interface RecurringPattern {
  kind: "subscription-like" | "recurring-income";
  counterparty: Address;
  /** "USDC", "ETH" or "token 0x1234...abcd" */
  asset: string;
  /** Amount rounded to 3 significant digits (the grouping key). */
  amount: string;
  count: number;
  cadence: string;
  medianIntervalHours: number | null;
  firstSeen: string | null;
  lastSeen: string | null;
}

export interface X402Footprint {
  source: X402Source;
  /** AuthorizationUsed events seen for this authorizer (exact with eth_getLogs, sampled with the probe). */
  authorizationCount: number;
  /** Extrapolated total when the receipt probe only covered part of the payments. */
  estimatedTotal: number | null;
  coverage: string;
  /** Authorizations matched to an outgoing USDC transfer (gives payee and amount). */
  matchedPayments: number;
  distinctPayees: number;
  payees: { address: Address; payments: number; usdc: string }[];
  totalUsdc: string;
  typicalPrice: string | null;
  /** Accounts that submitted the authorizations on-chain (x402 facilitators), when known. */
  facilitators: Address[];
  firstSeen: string | null;
  lastSeen: string | null;
}

export interface ActivityClock {
  samples: number;
  /** Outgoing actions (distinct transactions) per UTC hour, index 0 = 00:00-00:59 UTC. */
  histogramUtc: number[];
  /** Longest circular run of quiet hours; `end` is exclusive. */
  quietHoursUtc: { start: number; end: number; length: number } | null;
  aroundTheClock: boolean;
  /** Guess, assuming the quiet run is local 00:00-06:00 sleep. */
  inferredUtcOffset: number | null;
  offsetLabel: string | null;
  confidence: "low" | "medium" | "high" | null;
  note: string;
}

export interface AmountFingerprint {
  /** Outgoing USDC/ETH transfers considered. */
  considered: number;
  /** Not a multiple of 1 USDC / 0.01 ETH. */
  nonRound: number;
  nonRoundShare: number;
  examples: string[];
}

export interface ExposureReport {
  version: 1;
  chainId: typeof BASE_CHAIN_ID;
  address: Address;
  generatedAt: string;
  elapsedMs: number | null;
  /** false when a data source failed: the report then understates exposure. */
  complete: boolean;
  /** 0-100, 100 = nothing leaks. */
  privacyScore: number;
  penalties: Penalty[];
  findings: Finding[];
  recommendations: string[];
  totals: {
    transfersIn: number;
    transfersOut: number;
    selfTransfers: number;
    uniqueCounterparties: number;
    firstActivity: string | null;
    lastActivity: string | null;
    last30Days: number;
    usdcIn: string;
    usdcOut: string;
    ethIn: string;
    ethOut: string;
    otherTokenTransfers: number;
    /** Incoming non-USDC tokens from addresses never paid (airdrops / spam); excluded from the graph. */
    unsolicitedTokenTransfers: number;
    /** true when a 1000-transfer page was full, or only a recent block window was scanned (public-RPC mode), so older history was not read. */
    historyTruncated: boolean;
  };
  balances: { eth: string | null; usdc: string | null };
  account: { type: "eoa" | "eip7702" | "contract" | "unknown"; delegate: Address | null; nonce: number | null };
  fundingSource: { address: Address; asset: "ETH" | "USDC"; amount: string; at: string | null } | null;
  topCounterparties: CounterpartySummary[];
  x402Footprint: X402Footprint;
  recurring: RecurringPattern[];
  activityClock: ActivityClock;
  amountFingerprint: AmountFingerprint;
  dataQuality: {
    sources: { transfersOut: SourceStatus; transfersIn: SourceStatus; authorizations: SourceStatus; balances: SourceStatus; account: SourceStatus };
    notes: string[];
  };
}

/** One element of `alchemy_getAssetTransfers` -> result.transfers. */
export interface AlchemyTransfer {
  from: string;
  to: string | null;
  value: number | null;
  asset: string | null;
  category: string;
  hash: string;
  blockNum?: string;
  uniqueId?: string;
  rawContract?: { address?: string | null; value?: string | null; decimal?: string | null };
  /** timestampEstimated: public-RPC mode derived the time from a nearby block (2 s per block). */
  metadata?: { blockTimestamp?: string | null; timestampEstimated?: boolean };
}

export interface AuthorizationHit { txHash: string; nonce?: string | null }

/** Everything the analysis needs; produced by scanExposure, or by hand in tests. */
export interface RawExposure {
  /** Transfers sent by the wallet (newest first, max 1000); null when the query failed. */
  outgoing: AlchemyTransfer[] | null;
  incoming: AlchemyTransfer[] | null;
  outgoingTruncated?: boolean;
  incomingTruncated?: boolean;
  /** One entry per AuthorizationUsed(authorizer = wallet) log; null when unknown. */
  authorizations: AuthorizationHit[] | null;
  authorizationSource: X402Source;
  /** Receipt-probe coverage: receipts checked / outgoing USDC transactions in the window. */
  probe?: { checked: number; of: number } | null;
  facilitators?: string[];
  ethBalanceWei: bigint | null;
  usdcBalanceRaw: bigint | null;
  nonce: number | null;
  code: string | null;
  /** Already-sanitised data-quality notes. */
  notes?: string[];
  /**
   * Public-RPC mode: only this recent window was scanned (e.g. "roughly the last 2 days"),
   * so older history, the funding source and full x402 coverage are unknown.
   */
  historyWindow?: string | null;
}

// ---------------------------------------------------------------------------------------
// Network layer
// ---------------------------------------------------------------------------------------

type Rpc = <T>(method: string, params: unknown[], timeoutMs?: number) => Promise<T>;
interface JsonRpcResponse<T> { result?: T; error?: { code?: number; message?: string } }
interface TransfersPage { transfers?: AlchemyTransfer[]; pageKey?: string }
interface RpcLog { address?: string; topics?: string[]; data?: string; transactionHash?: string; blockNumber?: string; logIndex?: string; removed?: boolean }
interface RpcBlock { number?: string; timestamp?: string }
interface RpcReceipt { from?: string; logs?: RpcLog[] }

/**
 * Scan what the public chain reveals about `address`. Never throws for a partial outage
 * (see report.complete / dataQuality); throws only when the address is invalid or no
 * transfer data could be read at all (Alchemy and the public-RPC fallback both failed).
 * Non-Alchemy hosts go straight to public-RPC mode. `opts.now` (ms or s since epoch)
 * pins the report clock.
 */
export async function scanExposure(rpcUrl: string, address: `0x${string}`, opts?: { now?: number }): Promise<ExposureReport> {
  const started = Date.now();
  if (typeof address !== "string" || !isAddress(address, { strict: false })) throw new Error("scanExposure: invalid address");
  const wallet = address.toLowerCase() as Address;
  const topicWallet = `0x${wallet.slice(2).padStart(64, "0")}`;
  if (!isAlchemyHost(rpcUrl)) return scanPublicRpc(rpcUrl, wallet, topicWallet, started, opts, null);
  const call = createRpc(rpcUrl, started + TOTAL_BUDGET_MS);

  const transfers = (side: "fromAddress" | "toAddress") =>
    call<TransfersPage>("alchemy_getAssetTransfers", [{
      fromBlock: "0x0", toBlock: "latest", [side]: wallet, category: ["external", "erc20"],
      withMetadata: true, excludeZeroValue: true, maxCount: "0x3e8", order: "desc",
    }]);

  const [outR, inR, logsR, ethR, usdcR, nonceR, codeR] = await Promise.allSettled([
    transfers("fromAddress"),
    transfers("toAddress"),
    call<RpcLog[]>("eth_getLogs", [{ address: BASE_USDC, topics: [AUTHORIZATION_USED_TOPIC, topicWallet], fromBlock: "0x0", toBlock: "latest" }]),
    call<string>("eth_getBalance", [wallet, "latest"]),
    call<string>("eth_call", [{ to: BASE_USDC, data: `0x70a08231${topicWallet.slice(2)}` }, "latest"]),
    call<string>("eth_getTransactionCount", [wallet, "latest"]),
    call<string>("eth_getCode", [wallet, "latest"]),
  ]);

  const notes: string[] = [];
  const take = <T>(r: PromiseSettledResult<T>): T | null => {
    if (r.status === "fulfilled") return r.value;
    notes.push(errorText(r.reason));
    return null;
  };
  const outPage = take(outR);
  const inPage = take(inR);
  // alchemy_getAssetTransfers unavailable (method not supported, HTTP error, bad key...):
  // rebuild the same input from standard JSON-RPC over a recent block window.
  if (!outPage && !inPage) return scanPublicRpc(rpcUrl, wallet, topicWallet, started, opts, notes.slice(0, 2));
  const outgoing = outPage ? (outPage.transfers ?? []) : null;
  const incoming = inPage ? (inPage.transfers ?? []) : null;
  const outgoingTruncated = !!outPage?.pageKey;
  const incomingTruncated = !!inPage?.pageKey;

  let authorizations: AuthorizationHit[] | null = null;
  let authorizationSource: X402Source = "unavailable";
  let probe: RawExposure["probe"] = null;
  let facilitators: string[] = [];
  const logs = take(logsR);

  if (logs && Array.isArray(logs)) {
    authorizationSource = "eth_getLogs";
    const own = logs.filter((l) => !l.removed && isAuthLog(l, topicWallet) && typeof l.transactionHash === "string");
    authorizations = own.map((l) => ({ txHash: l.transactionHash!.toLowerCase(), nonce: l.topics?.[2] ?? null }));
    // Name the facilitator from the most recent few authorization transactions.
    const recent = [...new Set(
      [...own].sort((a, b) => Number(BigInt(b.blockNumber ?? "0x0") - BigInt(a.blockNumber ?? "0x0"))).map((l) => l.transactionHash!.toLowerCase()),
    )].slice(0, FACILITATOR_PROBE);
    if (recent.length) facilitators = (await probeReceipts(call, recent, wallet, topicWallet)).facilitators;
  } else if (outgoing) {
    // Full-history eth_getLogs refused (e.g. Alchemy free tier caps the block range) or
    // timed out. Every EIP-3009 authorization moves USDC out of the wallet in the same
    // transaction, so checking receipts of the newest outgoing USDC transfers is exact
    // for the transfers it covers.
    const usdcHashes = [...new Set(outgoing.filter(isUsdcTransfer).map((t) => t.hash.toLowerCase()))];
    if (usdcHashes.length === 0 && !outgoingTruncated) {
      authorizations = [];
      authorizationSource = "receipt-probe";
      probe = { checked: 0, of: 0 };
    } else if (usdcHashes.length) {
      const res = await probeReceipts(call, usdcHashes.slice(0, PROBE_CAP), wallet, topicWallet);
      if (res.checked > 0) {
        authorizations = res.hits;
        authorizationSource = "receipt-probe";
        probe = { checked: res.checked, of: usdcHashes.length };
        facilitators = res.facilitators;
        notes.push(`full-history eth_getLogs unavailable; checked receipts of ${res.checked} of ${usdcHashes.length} most recent outgoing USDC transactions instead`);
      }
      if (res.failed) notes.push(`${plural(res.failed, "receipt lookup")} failed`);
    }
  }

  const raw: RawExposure = {
    outgoing, incoming, outgoingTruncated, incomingTruncated, authorizations, authorizationSource, probe, facilitators,
    ethBalanceWei: hexToBig(take(ethR)),
    usdcBalanceRaw: hexToBig(take(usdcR)),
    nonce: hexToNum(take(nonceR)),
    code: hexOrNull(take(codeR)),
    notes,
  };
  const report = analyzeExposure(raw, wallet, opts?.now ?? Date.now());
  report.elapsedMs = Date.now() - started;
  return report;
}

/**
 * Public-RPC mode. Logs come from PUBLIC_LOGS_RPC (10k-block ranges, recent blocks only);
 * everything else goes to rpcUrl, retried on PUBLIC_LOGS_RPC on error. `prior` holds the
 * Alchemy failure notes when the Alchemy path was tried first (null: no Alchemy host).
 */
async function scanPublicRpc(
  rpcUrl: string, wallet: Address, topicWallet: string, started: number, opts: { now?: number } | undefined, prior: string[] | null,
): Promise<ExposureReport> {
  const end = started + PUBLIC_BUDGET_MS;
  const logsEnd = Math.min(end - 1_000, Date.now() + PUBLIC_LOGS_BUDGET_MS);
  const logsCall = createRpc(PUBLIC_LOGS_RPC, logsEnd);
  const primary = createRpc(rpcUrl, end);
  const call = rpcUrl.replace(/\/+$/, "") === PUBLIC_LOGS_RPC ? primary : withFallback(primary, createRpc(PUBLIC_LOGS_RPC, end));
  const fail = (why: string) => new Error(`exposure scan failed: ${[...(prior ?? []), why].slice(0, 3).join("; ")}`);

  const headP = call<RpcBlock | null>("eth_getBlockByNumber", ["latest", false]);
  const sideP = Promise.allSettled([
    call<string>("eth_getBalance", [wallet, "latest"]),
    call<string>("eth_call", [{ to: BASE_USDC, data: `0x70a08231${topicWallet.slice(2)}` }, "latest"]),
    call<string>("eth_getTransactionCount", [wallet, "latest"]),
    call<string>("eth_getCode", [wallet, "latest"]),
  ]);
  let head: { number: number; ts: number };
  try {
    const b = await headP;
    const n = hexToNum(b?.number ?? null);
    const ts = hexToNum(b?.timestamp ?? null);
    if (n === null || ts === null) throw new Error("eth_getBlockByNumber: malformed block");
    head = { number: n, ts };
  } catch (err) {
    await sideP;
    throw fail(errorText(err));
  }

  // Newest chunk first; the newest one ends at "latest" (the log node may be slightly ahead).
  const ranges: { from: number; to: number | "latest" }[] = [];
  for (let to = head.number, i = 0; i < PUBLIC_WINDOW_BLOCKS / PUBLIC_CHUNK_BLOCKS && to >= 0; i++) {
    const from = Math.max(0, to - (i === 0 ? PUBLIC_CHUNK_BLOCKS - PUBLIC_HEAD_MARGIN : PUBLIC_CHUNK_BLOCKS) + 1);
    ranges.push({ from, to: i === 0 ? "latest" : to });
    to = from - 1;
  }
  // Outgoing Transfer and AuthorizationUsed both carry the wallet in topic1: one query.
  const tasks = ranges.flatMap((_, i) => [{ i, side: "out" as const }, { i, side: "in" as const }]);
  const ok = { out: ranges.map(() => false), in: ranges.map(() => false) };
  const logs = { out: [] as RpcLog[], in: [] as RpcLog[] };
  let refusedAt = Number.POSITIVE_INFINITY;
  let refusal = "";
  let skipped = 0;
  let cursor = 0;
  const logWorker = async () => {
    while (cursor < tasks.length) {
      const task = tasks[cursor++]!;
      if (task.i > refusedAt) continue; // older blocks than a refused range: refused as well
      const r = ranges[task.i]!;
      try {
        const res = await logsCall<RpcLog[]>("eth_getLogs", [{
          address: BASE_USDC, fromBlock: toHex(r.from), toBlock: r.to === "latest" ? "latest" : toHex(r.to),
          topics: task.side === "out" ? [[TRANSFER_TOPIC, AUTHORIZATION_USED_TOPIC], topicWallet] : [TRANSFER_TOPIC, null, topicWallet],
        }]);
        if (!Array.isArray(res)) throw new Error("eth_getLogs: malformed response");
        logs[task.side].push(...res);
        ok[task.side][task.i] = true;
      } catch (err) {
        const msg = errorText(err);
        // A JSON-RPC / 4xx refusal (e.g. "archive requests require a token") applies to all
        // older ranges too; timeouts and rate limits only cost this one range.
        if (/rpc error|HTTP 4(?!29)\d\d/.test(msg)) {
          if (task.i < refusedAt) { refusedAt = task.i; refusal = msg; }
        } else skipped++;
      }
    }
  };
  await Promise.all(Array.from({ length: PUBLIC_LOG_CONCURRENCY }, logWorker));
  const anyOut = ok.out.some(Boolean);
  const anyIn = ok.in.some(Boolean);
  if (!anyOut && !anyIn) {
    await sideP;
    throw fail(refusal || `eth_getLogs: all ${tasks.length} block-range queries failed or timed out`);
  }

  const outgoing: AlchemyTransfer[] = [];
  const incoming: AlchemyTransfer[] = [];
  const auth: RpcLog[] = [];
  for (const l of logs.out) {
    if (isAuthLog(l, topicWallet)) { if (!l.removed && typeof l.transactionHash === "string") auth.push(l); continue; }
    const t = logToTransfer(l);
    if (t && t.from === wallet) outgoing.push(t);
  }
  for (const l of logs.in) {
    const t = logToTransfer(l);
    if (t && t.to === wallet) incoming.push(t);
  }
  const all = [...outgoing, ...incoming];
  const blockOf = (t: AlchemyTransfer) => hexToNum(t.blockNum ?? null);
  const byNewest = (a: AlchemyTransfer, b: AlchemyTransfer) => (blockOf(b) ?? 0) - (blockOf(a) ?? 0);
  outgoing.sort(byNewest);
  incoming.sort(byNewest);

  // Block timestamps: exact for the newest PUBLIC_TS_CAP distinct blocks, estimated (2 s per
  // block from the nearest known block) for the rest. Facilitator probe runs alongside.
  const known = new Map<number, number>([[head.number, head.ts]]);
  const distinct = [...new Set(all.map(blockOf).filter((b): b is number => b !== null))].sort((a, b) => b - a);
  const toFetch = distinct.filter((b) => !known.has(b)).slice(0, PUBLIC_TS_CAP);
  let tsCursor = 0;
  let tsFailed = 0;
  const tsWorker = async () => {
    while (tsCursor < toFetch.length) {
      const b = toFetch[tsCursor++]!;
      try {
        const ts = hexToNum((await call<RpcBlock | null>("eth_getBlockByNumber", [toHex(b), false]))?.timestamp ?? null);
        if (ts !== null) known.set(b, ts); else tsFailed++;
      } catch {
        tsFailed++;
      }
    }
  };
  const recentAuth = [...new Set(
    [...auth].sort((a, b) => Number(BigInt(b.blockNumber ?? "0x0") - BigInt(a.blockNumber ?? "0x0"))).map((l) => l.transactionHash!.toLowerCase()),
  )].slice(0, FACILITATOR_PROBE);
  const [, probeRes] = await Promise.all([
    Promise.all(Array.from({ length: Math.min(PUBLIC_TS_CONCURRENCY, toFetch.length) }, tsWorker)),
    recentAuth.length ? probeReceipts(call, recentAuth, wallet, topicWallet) : null,
  ]);
  const anchors = [...known.entries()];
  const estimatedBlocks = new Set<number>();
  for (const t of all) {
    const b = blockOf(t);
    let ts = b === null ? null : known.get(b) ?? null;
    if (b !== null && ts === null) {
      let best = anchors[0]!;
      for (const a of anchors) if (Math.abs(a[0] - b) < Math.abs(best[0] - b)) best = a;
      ts = best[1] + (b - best[0]) * BLOCK_SECONDS;
      estimatedBlocks.add(b);
    }
    t.metadata = ts === null ? { blockTimestamp: null } : { blockTimestamp: new Date(ts * 1000).toISOString(), ...(b !== null && estimatedBlocks.has(b) ? { timestampEstimated: true } : {}) };
  }

  // Window actually covered: from the oldest range that answered up to the head.
  const okIdx = ranges.map((_, i) => i).filter((i) => ok.out[i] || ok.in[i]);
  const oldestFrom = Math.min(...okIdx.map((i) => ranges[i]!.from));
  const window = windowLabel(((head.number - oldestFrom + 1) * BLOCK_SECONDS) / 3600);
  const notes = [`Public-RPC mode: USDC activity from ${window} only (${prior ? "Alchemy transfer API unavailable" : "no Alchemy key configured"})`];
  if (refusal && refusedAt > 0) notes.push(`older blocks not scanned, the public log RPC refused them: ${refusal}`);
  else if (refusal) notes.push(refusal);
  if (skipped) notes.push(`${plural(skipped, "eth_getLogs block-range query", "eth_getLogs block-range queries")} timed out or failed and ${skipped === 1 ? "was" : "were"} skipped`);
  if (estimatedBlocks.size) notes.push(`${estimatedBlocks.size} of ${distinct.length} block timestamps estimated at ${BLOCK_SECONDS} s per block`);
  if (tsFailed) notes.push(`${plural(tsFailed, "block timestamp lookup")} failed`);
  const [ethR, usdcR, nonceR, codeR] = await sideP;
  const take = <T>(r: PromiseSettledResult<T>): T | null => {
    if (r.status === "fulfilled") return r.value;
    notes.push(errorText(r.reason));
    return null;
  };
  const raw: RawExposure = {
    outgoing: anyOut ? outgoing : null,
    incoming: anyIn ? incoming : null,
    outgoingTruncated: false,
    incomingTruncated: false,
    authorizations: anyOut ? auth.map((l) => ({ txHash: l.transactionHash!.toLowerCase(), nonce: l.topics?.[2] ?? null })) : null,
    authorizationSource: anyOut ? "eth_getLogs" : "unavailable",
    probe: null,
    facilitators: probeRes?.facilitators ?? [],
    ethBalanceWei: hexToBig(take(ethR)),
    usdcBalanceRaw: hexToBig(take(usdcR)),
    nonce: hexToNum(take(nonceR)),
    code: hexOrNull(take(codeR)),
    notes: [...notes, ...(prior ?? []).slice(0, 1)],
    historyWindow: window,
  };
  const report = analyzeExposure(raw, wallet, opts?.now ?? Date.now());
  report.elapsedMs = Date.now() - started;
  return report;
}

/** Try `primary`; on any error retry once on `secondary`, reporting the primary error if both fail. */
function withFallback(primary: Rpc, secondary: Rpc): Rpc {
  return async <T>(method: string, params: unknown[], timeoutMs?: number): Promise<T> => {
    try {
      return await primary<T>(method, params, timeoutMs);
    } catch (err) {
      try { return await secondary<T>(method, params, timeoutMs); } catch { throw err; }
    }
  };
}

/** USDC Transfer log -> the alchemy_getAssetTransfers element shape the analyzer reads. */
function logToTransfer(l: RpcLog): AlchemyTransfer | null {
  const topics = l.topics ?? [];
  if (l.removed || l.address?.toLowerCase() !== USDC || topics[0]?.toLowerCase() !== TRANSFER_TOPIC || typeof l.transactionHash !== "string") return null;
  const from = topicAddress(topics[1]);
  const to = topicAddress(topics[2]);
  const raw = hexToBig(typeof l.data === "string" && l.data.length <= 66 ? l.data : null);
  if (!from || !to || raw === null) return null;
  const hash = l.transactionHash.toLowerCase();
  return {
    from, to, value: Number(formatUnits(raw, 6)), asset: "USDC", category: "erc20", hash,
    blockNum: l.blockNumber, uniqueId: `${hash}:log:${hexToNum(l.logIndex ?? null) ?? `${from}:${to}:${raw}`}`,
    rawContract: { address: USDC, value: toHex(raw), decimal: "0x6" },
    metadata: { blockTimestamp: null },
  };
}

function topicAddress(topic: string | undefined): string | null {
  return typeof topic === "string" && /^0x0{24}[0-9a-fA-F]{40}$/.test(topic) ? `0x${topic.slice(26).toLowerCase()}` : null;
}

function isAlchemyHost(rpcUrl: string): boolean {
  try {
    const host = new URL(rpcUrl).hostname.toLowerCase();
    return host === "alchemy.com" || host.endsWith(".alchemy.com");
  } catch {
    return false;
  }
}

function windowLabel(hours: number): string {
  if (hours >= 36) return `roughly the last ${Math.round(hours / 24)} days`;
  const h = Math.max(1, Math.round(hours));
  return h === 1 ? "roughly the last hour" : `roughly the last ${h} hours`;
}

function createRpc(rpcUrl: string, deadline: number): Rpc {
  const secrets = secretFragments(rpcUrl);
  let nextId = 1;
  return async <T>(method: string, params: unknown[], timeoutMs = REQUEST_TIMEOUT_MS): Promise<T> => {
    const ms = Math.min(timeoutMs, deadline - Date.now());
    if (ms < 200) throw new Error(`${method}: skipped, scan time budget used up`);
    let res: Response;
    try {
      res = await fetch(rpcUrl, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: nextId++, method, params }),
        signal: AbortSignal.timeout(ms),
      });
    } catch (err) {
      // Never surface the underlying error: undici messages can contain the URL (and key).
      throw new Error(`${method}: ${isAbort(err) ? `timed out after ${ms} ms` : "network error"}`);
    }
    if (!res.ok) {
      // Providers often put the reason (rate / range limit) in a JSON-RPC body on a 4xx.
      let detail = "";
      try {
        const err = ((await res.json()) as JsonRpcResponse<unknown>)?.error;
        if (err?.message) detail = `: ${sanitize(String(err.message), secrets)}`;
      } catch { /* not JSON */ }
      throw new Error(`${method}: HTTP ${res.status}${res.status === 429 ? " (rate limited)" : ""}${detail}`);
    }
    let body: JsonRpcResponse<T>;
    try {
      body = (await res.json()) as JsonRpcResponse<T>;
    } catch (err) {
      throw new Error(`${method}: ${isAbort(err) ? `timed out after ${ms} ms` : "malformed response"}`);
    }
    if (body?.error) throw new Error(`${method}: rpc error ${Number(body.error.code) || "?"}: ${sanitize(String(body.error.message ?? ""), secrets)}`);
    if (!body || !("result" in body)) throw new Error(`${method}: response without result`);
    return body.result as T;
  };
}

async function probeReceipts(call: Rpc, hashes: string[], wallet: string, topicWallet: string) {
  const hits: AuthorizationHit[] = [];
  const facilitators = new Set<string>();
  let checked = 0;
  let failed = 0;
  let cursor = 0;
  const worker = async () => {
    while (cursor < hashes.length) {
      const hash = hashes[cursor++]!;
      try {
        const rc = await call<RpcReceipt | null>("eth_getTransactionReceipt", [hash]);
        if (!rc) { failed++; continue; }
        checked++;
        let own = 0;
        for (const log of rc.logs ?? []) {
          if (!log.removed && isAuthLog(log, topicWallet)) { own++; hits.push({ txHash: hash, nonce: log.topics?.[2] ?? null }); }
        }
        const sender = rc.from?.toLowerCase();
        if (own && sender && sender !== wallet && isRealAddress(sender)) facilitators.add(sender);
      } catch {
        failed++;
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(PROBE_CONCURRENCY, hashes.length) }, worker));
  return { hits, checked, failed, facilitators: [...facilitators].sort() };
}

function isAuthLog(log: RpcLog, topicWallet: string): boolean {
  return log.address?.toLowerCase() === USDC
    && log.topics?.[0]?.toLowerCase() === AUTHORIZATION_USED_TOPIC
    && log.topics?.[1]?.toLowerCase() === topicWallet;
}

const isUsdcTransfer = (t: AlchemyTransfer) => t.category === "erc20" && t.rawContract?.address?.toLowerCase() === USDC;
const isAbort = (err: unknown) => {
  const name = (err as { name?: string } | null)?.name;
  return name === "TimeoutError" || name === "AbortError";
};
const errorText = (err: unknown) => (err instanceof Error ? err.message : "unknown error").slice(0, 240);

/** Path segments / query / credentials of the RPC URL that may carry an API key. */
function secretFragments(rpcUrl: string): string[] {
  try {
    const u = new URL(rpcUrl);
    return [...u.pathname.split("/"), u.search.slice(1), u.username, u.password].filter((s) => s.length >= 8);
  } catch {
    return [];
  }
}

function sanitize(message: string, secrets: string[]): string {
  let out = message;
  for (const s of secrets) out = out.split(s).join("***");
  return out.replace(/https?:\/\/\S+/g, "<url>").replace(/[^\x20-\x7e]/g, " ").slice(0, 160);
}

function hexToBig(v: string | null): bigint | null {
  if (typeof v !== "string" || !/^0x[0-9a-fA-F]*$/.test(v)) return null;
  return v === "0x" ? 0n : BigInt(v);
}
function hexToNum(v: string | null): number | null {
  const b = hexToBig(v);
  return b === null ? null : Number(b);
}
const hexOrNull = (v: string | null) => (typeof v === "string" && /^0x[0-9a-fA-F]*$/.test(v) ? v.toLowerCase() : null);

// ---------------------------------------------------------------------------------------
// Analysis (pure)
// ---------------------------------------------------------------------------------------

interface Tx {
  hash: string;
  dir: "in" | "out" | "self";
  cp: string; // counterparty, lowercase ("" when unknown, e.g. contract creation)
  asset: "ETH" | "USDC" | "TOKEN";
  token: string | null;
  decimals: number | null;
  raw: bigint | null;
  ts: number | null; // unix seconds
}

/**
 * Turn raw chain data into an ExposureReport. Pure and deterministic: `now` is ms (or s)
 * since epoch and only feeds generatedAt / "last 30 days".
 */
export function analyzeExposure(raw: RawExposure, address: string, now: number): ExposureReport {
  const wallet = address.toLowerCase();
  const nowSec = Math.floor(toMs(now) / 1000);
  const txs = normalizeTransfers([...(raw.outgoing ?? []), ...(raw.incoming ?? [])], wallet);
  const outs = txs.filter((t) => t.dir === "out");
  const ins = txs.filter((t) => t.dir === "in");
  const truncated = !!raw.outgoingTruncated || !!raw.incomingTruncated;
  const limited = !!raw.historyWindow; // public-RPC mode: recent block window only

  // Graph edges: ETH/USDC both ways, any token the wallet sent, and incoming tokens only
  // from addresses the wallet also paid (unsolicited incoming tokens are mostly spam).
  const paid = new Set(outs.map((t) => t.cp));
  const graph = txs.filter((t) => t.dir !== "self" && isRealAddress(t.cp) && (t.asset !== "TOKEN" || t.dir === "out" || paid.has(t.cp)));
  const unsolicited = ins.filter((t) => t.asset === "TOKEN" && !paid.has(t.cp)).length;

  // --- totals -------------------------------------------------------------------------
  const sum = (list: Tx[], asset: Tx["asset"]) => list.reduce((s, t) => (t.asset === asset && t.raw !== null ? s + t.raw : s), 0n);
  const times = txs.map((t) => t.ts).filter((x): x is number => x !== null);
  const first = times.length ? Math.min(...times) : null;
  const last = times.length ? Math.max(...times) : null;

  // --- funding source (only meaningful when the incoming history is complete) ----------
  let funding: ExposureReport["fundingSource"] = null;
  if (raw.incoming && !raw.incomingTruncated && !limited) {
    const f = ins
      .filter((t) => (t.asset === "USDC" || t.asset === "ETH") && isRealAddress(t.cp) && t.ts !== null && t.raw !== null && t.raw > 0n)
      .sort((a, b) => a.ts! - b.ts!)[0];
    if (f) funding = { address: cs(f.cp), asset: f.asset as "ETH" | "USDC", amount: formatUnits(f.raw!, f.decimals!), at: iso(f.ts) };
  }

  // --- x402 / EIP-3009 footprint -------------------------------------------------------
  const authCount = raw.authorizations?.length ?? 0;
  const authHashes = new Set((raw.authorizations ?? []).map((a) => a.txHash.toLowerCase()));
  const matched = outs.filter((t) => t.asset === "USDC" && t.raw !== null && authHashes.has(t.hash));
  const payeeAcc = new Map<string, { payments: number; usdc: bigint }>();
  for (const t of matched) {
    const p = payeeAcc.get(t.cp) ?? { payments: 0, usdc: 0n };
    p.payments++;
    p.usdc += t.raw!;
    payeeAcc.set(t.cp, p);
  }
  const payeeList = [...payeeAcc.entries()]
    .filter(([a]) => isRealAddress(a))
    .sort((a, b) => b[1].payments - a[1].payments || cmpBig(b[1].usdc, a[1].usdc) || a[0].localeCompare(b[0]));
  const probe = raw.probe ?? null;
  const partialProbe = raw.authorizationSource === "receipt-probe" && !!probe && probe.checked > 0 && probe.checked < probe.of;
  const matchedTimes = matched.map((t) => t.ts).filter((x): x is number => x !== null);
  const x402: X402Footprint = {
    source: raw.authorizationSource,
    authorizationCount: authCount,
    estimatedTotal: partialProbe ? Math.round((authCount * probe!.of) / probe!.checked) : null,
    coverage: raw.authorizationSource === "eth_getLogs"
      ? limited ? `${raw.historyWindow} (public-RPC eth_getLogs)` : "full history (eth_getLogs)"
      : raw.authorizationSource === "receipt-probe"
        ? probe && probe.of === 0 ? "no outgoing USDC transfers" : `receipts of ${probe?.checked ?? 0} of ${probe?.of ?? 0} most recent outgoing USDC transactions`
        : "unavailable",
    matchedPayments: matched.length,
    distinctPayees: payeeList.length,
    payees: payeeList.slice(0, 5).map(([a, p]) => ({ address: cs(a), payments: p.payments, usdc: formatUnits(p.usdc, 6) })),
    totalUsdc: formatUnits(matched.reduce((s, t) => s + t.raw!, 0n), 6),
    typicalPrice: matched.length ? formatUnits(typicalAmount(matched.map((t) => t.raw!)), 6) : null,
    facilitators: (raw.facilitators ?? []).filter(isRealAddress).slice(0, 3).map(cs),
    firstSeen: matchedTimes.length ? iso(Math.min(...matchedTimes)) : null,
    lastSeen: matchedTimes.length ? iso(Math.max(...matchedTimes)) : null,
  };

  // --- recurring patterns ----------------------------------------------------------------
  const groups = new Map<string, { t: Tx; rounded: bigint; times: number[]; count: number }>();
  for (const t of graph) {
    if (t.raw === null || t.raw <= 0n || t.decimals === null) continue;
    const rounded = roundSig(t.raw, 3);
    const key = `${t.cp}|${t.dir}|${t.asset === "TOKEN" ? t.token : t.asset}|${rounded}`;
    const g = groups.get(key) ?? { t, rounded, times: [], count: 0 };
    g.count++;
    if (t.ts !== null) g.times.push(t.ts);
    groups.set(key, g);
  }
  const recurringAll: RecurringPattern[] = [...groups.values()]
    .filter((g) => g.count >= 3)
    .sort((a, b) => b.count - a.count || a.t.cp.localeCompare(b.t.cp))
    .map((g) => {
      const c = cadenceOf(g.times);
      return {
        kind: g.t.dir === "in" ? "recurring-income" : "subscription-like",
        counterparty: cs(g.t.cp),
        asset: assetLabel(g.t),
        amount: formatUnits(g.rounded, g.t.decimals!),
        count: g.count,
        cadence: c.label,
        medianIntervalHours: c.medianHours,
        firstSeen: g.times.length ? iso(Math.min(...g.times)) : null,
        lastSeen: g.times.length ? iso(Math.max(...g.times)) : null,
      };
    });
  const recurringCps = new Set(recurringAll.map((r) => r.counterparty.toLowerCase()));

  // --- counterparties ------------------------------------------------------------------
  const cpAcc = new Map<string, { inCount: number; outCount: number; usdcIn: bigint; usdcOut: bigint; first: number | null; last: number | null }>();
  for (const t of graph) {
    const a = cpAcc.get(t.cp) ?? { inCount: 0, outCount: 0, usdcIn: 0n, usdcOut: 0n, first: null, last: null };
    if (t.dir === "in") a.inCount++; else a.outCount++;
    if (t.asset === "USDC" && t.raw !== null) { if (t.dir === "in") a.usdcIn += t.raw; else a.usdcOut += t.raw; }
    if (t.ts !== null) {
      a.first = a.first === null ? t.ts : Math.min(a.first, t.ts);
      a.last = a.last === null ? t.ts : Math.max(a.last, t.ts);
    }
    cpAcc.set(t.cp, a);
  }
  const fundingCp = funding?.address.toLowerCase();
  const topCounterparties: CounterpartySummary[] = [...cpAcc.entries()]
    .sort((a, b) => (b[1].inCount + b[1].outCount) - (a[1].inCount + a[1].outCount)
      || cmpBig(b[1].usdcIn + b[1].usdcOut, a[1].usdcIn + a[1].usdcOut) || a[0].localeCompare(b[0]))
    .slice(0, 8)
    .map(([addr, a]) => {
      const count = a.inCount + a.outCount;
      const flags: string[] = [];
      if (recurringCps.has(addr)) flags.push("recurring");
      if (payeeAcc.has(addr)) flags.push("x402-payee");
      if (count >= 10) flags.push("frequent");
      if (a.inCount && a.outCount) flags.push("two-way");
      if (addr === fundingCp) flags.push("funding-source");
      return {
        address: cs(addr),
        direction: a.inCount && a.outCount ? "both" : a.inCount ? "in" : "out",
        inCount: a.inCount,
        outCount: a.outCount,
        count,
        usdcIn: formatUnits(a.usdcIn, 6),
        usdcOut: formatUnits(a.usdcOut, 6),
        usdcVolume: formatUnits(a.usdcIn + a.usdcOut, 6),
        firstSeen: iso(a.first),
        lastSeen: iso(a.last),
        flags,
      };
    });

  // --- activity clock: the wallet's own actions, one sample per transaction ----------------
  const actionTimes = new Map<string, number>();
  for (const t of txs) if (t.dir !== "in" && t.ts !== null && !actionTimes.has(t.hash)) actionTimes.set(t.hash, t.ts);
  const histogram = new Array<number>(24).fill(0);
  for (const ts of actionTimes.values()) {
    const h = new Date(ts * 1000).getUTCHours();
    histogram[h] = (histogram[h] ?? 0) + 1;
  }
  const activityClock: ActivityClock = { histogramUtc: histogram, ...inferTimezone(histogram) };

  // --- amount fingerprints ---------------------------------------------------------------
  const fpList = outs.filter((t) => (t.asset === "USDC" || t.asset === "ETH") && t.raw !== null && t.raw > 0n);
  const nonRoundList = fpList.filter((t) => t.raw! % (t.asset === "USDC" ? USDC_ROUND : ETH_ROUND) !== 0n);
  const amountFingerprint: AmountFingerprint = {
    considered: fpList.length,
    nonRound: nonRoundList.length,
    nonRoundShare: fpList.length ? Math.round((nonRoundList.length / fpList.length) * 100) / 100 : 0,
    examples: [...new Set(nonRoundList.map((t) => `${formatUnits(t.raw!, t.decimals!)} ${t.asset}`))].slice(0, 3),
  };

  // --- account -------------------------------------------------------------------------
  const code = raw.code;
  const account: ExposureReport["account"] = {
    type: code === null ? "unknown" : code === "0x" ? "eoa" : code.startsWith("0xef0100") && code.length === 48 ? "eip7702" : "contract",
    delegate: code !== null && code.startsWith("0xef0100") && code.length === 48 && isRealAddress(`0x${code.slice(8)}`) ? cs(`0x${code.slice(8)}`) : null,
    nonce: raw.nonce,
  };

  // --- score, findings, recommendations -------------------------------------------------
  const penalties: Penalty[] = [];
  const findings: Finding[] = [];
  const penalize = (points: number, reason: string) => { if (points > 0) penalties.push({ reason, points }); };
  const uniqueCounterparties = cpAcc.size;

  const usdcBal = raw.usdcBalanceRaw ?? 0n;
  const ethBal = raw.ethBalanceWei ?? 0n;
  if (usdcBal > 0n || ethBal > 0n) {
    const large = usdcBal >= 1000n * USDC_ROUND;
    penalize(large ? 12 : 8, large ? "Large balance publicly visible" : "Current balance publicly visible");
    findings.push({
      severity: large ? "high" : "medium",
      title: "Anyone can see how much this wallet holds",
      detail: `The public chain shows ${trimFrac(formatUnits(usdcBal, 6), 2)} USDC and ${trimFrac(formatUnits(ethBal, 18), 6)} ETH at this address right now. Every service you pay learns your address, and with it your balance.`,
    });
  }

  if (txs.length > 0) {
    const n = txs.length;
    const nText = `${n}${truncated || limited ? "+" : ""} ${n === 1 ? "transfer" : "transfers"}`;
    penalize(n >= 100 ? 15 : n >= 20 ? 10 : 5, `${nText} publicly linked to this address`);
    if (uniqueCounterparties) penalize(uniqueCounterparties >= 20 ? 10 : uniqueCounterparties >= 5 ? 6 : 3, `Public contact graph of ${plural(uniqueCounterparties, "counterparty", "counterparties")}`);
    const top = topCounterparties[0];
    const topShare = top && graph.length >= 5 ? top.count / graph.length : 0;
    findings.push({
      severity: n >= 100 || uniqueCounterparties >= 20 ? "high" : n >= 10 ? "medium" : "low",
      title: "Your payment history is public, forever",
      detail: `${nText} (${outs.length} sent, ${ins.length} received) with ${plural(uniqueCounterparties, "different address", "different addresses")} can be read by anyone`
        + (first !== null && last !== null ? `, from ${day(first)} to ${day(last)} (last one ${ago(nowSec - last)})` : "") + "."
        + (top && topShare >= 0.4 ? ` ${Math.round(topShare * 100)}% of them involve one address (${short(top.address)}).` : "")
        + (raw.nonce ? ` The wallet also sent ${plural(raw.nonce, "transaction")} itself, each signed with its key.` : ""),
    });
  }

  if (authCount > 0) {
    const c = x402.estimatedTotal ?? authCount;
    penalize(c >= 100 ? 15 : c >= 10 ? 12 : 8, `${c}${x402.estimatedTotal !== null ? " (estimated)" : ""} x402 / EIP-3009 payment authorizations signed by this wallet`);
    if (x402.distinctPayees >= 3) penalize(5, `${x402.distinctPayees} distinct x402 payees identifiable`);
    const topPayee = x402.payees[0];
    findings.push({
      severity: c >= 10 || x402.distinctPayees >= 3 ? "high" : "medium",
      title: "Your pay-per-request (x402) payments are traceable",
      detail: `This wallet signed ${x402.estimatedTotal !== null ? "about " : ""}${plural(c, "gasless USDC payment authorization")}, which is how x402 API payments settle. Each one is recorded on-chain with your address as the payer`
        + (topPayee ? (x402.distinctPayees === 1 ? `, revealing the service you pay (${short(topPayee.address)}, ${plural(topPayee.payments, "payment")})` : `, revealing ${x402.distinctPayees} services you pay, mainly ${short(topPayee.address)} (${plural(topPayee.payments, "payment")})`) : "")
        + (x402.typicalPrice ? `. Typical price: ${x402.typicalPrice} USDC` : "")
        + (x402.facilitators[0] ? `. They were submitted by ${short(x402.facilitators[0])}, a facilitator that sees every one of them` : "") + ".",
    });
  }

  if (recurringAll.length) {
    penalize(Math.min(15, recurringAll.length * 5), plural(recurringAll.length, "repeating payment pattern"));
    const r = recurringAll[0]!;
    findings.push({
      severity: "medium",
      title: "Repeating payments look like subscriptions",
      detail: `Found ${plural(recurringAll.length, "repeating pattern")}, e.g. ${r.amount} ${r.asset} ${r.kind === "recurring-income" ? "from" : "to"} ${short(r.counterparty)} ${r.count} times (${r.cadence}). The same payee and amount make it easy to guess what you pay for and when the next payment is due.`,
    });
  }

  if (activityClock.inferredUtcOffset !== null && activityClock.quietHoursUtc && activityClock.confidence) {
    const q = activityClock.quietHoursUtc;
    penalize(activityClock.confidence === "high" ? 10 : activityClock.confidence === "medium" ? 6 : 3, `Active hours suggest time zone ${activityClock.offsetLabel} (${activityClock.confidence} confidence)`);
    const region = REGIONS[activityClock.inferredUtcOffset];
    findings.push({
      severity: activityClock.confidence === "high" ? "high" : activityClock.confidence === "medium" ? "medium" : "low",
      title: "Your activity hints at your time zone",
      detail: `This wallet almost never acts between ${pad2(q.start)}:00 and ${pad2(q.end)}:00 UTC. If that is when you sleep, you are probably in ${activityClock.offsetLabel}${region ? ` (e.g. ${region})` : ""}. This is a guess with ${activityClock.confidence} confidence, based on ${plural(activityClock.samples, "outgoing transaction")}.`,
    });
  } else if (activityClock.aroundTheClock && activityClock.samples >= 24) {
    penalize(3, "Round-the-clock activity marks the wallet as automated");
    findings.push({
      severity: "low",
      title: "Your wallet is active around the clock",
      detail: "Outgoing activity happens at almost every hour of the day, which looks like an automated agent. That hides your time zone, but it tells observers this address is a bot wallet.",
    });
  }

  if (amountFingerprint.nonRound > 0) {
    const share = amountFingerprint.nonRoundShare;
    const strong = share >= 0.5 && amountFingerprint.considered >= 5;
    penalize(strong ? 10 : share >= 0.2 ? 5 : 2, `${Math.round(share * 100)}% of outgoing amounts are non-round (linkable)`);
    findings.push({
      severity: strong ? "medium" : "low",
      title: "Exact amounts make your payments linkable",
      detail: `${Math.round(share * 100)}% of the payments you sent (${amountFingerprint.nonRound} of ${amountFingerprint.considered}) use non-round amounts such as ${amountFingerprint.examples[0] ?? "-"}. A distinctive amount can be matched to a deposit, withdrawal or invoice elsewhere.`,
    });
  }

  if (funding) {
    penalize(8, "Funding source is publicly visible");
    findings.push({
      severity: "medium",
      title: "Where your money came from is visible",
      detail: `The first funds came from ${short(funding.address)} (${funding.amount} ${funding.asset}${funding.at ? ` on ${funding.at.slice(0, 10)}` : ""}). If that is an exchange account or another wallet of yours, it links this wallet back to you.`,
    });
  }

  if (account.type === "eip7702" || account.type === "contract") {
    penalize(2, account.type === "eip7702" ? "EIP-7702 delegation reveals the wallet software" : "Contract code reveals the wallet software");
    findings.push({
      severity: "low",
      title: "Your wallet type is visible",
      detail: account.type === "eip7702" && account.delegate
        ? `This address is an EIP-7702 smart account delegated to ${short(account.delegate)}. That contract identifies the wallet software you use.`
        : "This address is a smart-contract wallet; its code identifies the wallet software you use.",
    });
  }

  const rank: Record<Severity, number> = { high: 0, medium: 1, low: 2 };
  findings.sort((a, b) => rank[a.severity] - rank[b.severity]);
  const points = penalties.reduce((s, p) => s + p.points, 0);
  const privacyScore = Math.max(0, Math.min(100, 100 - points));

  const recommendations: string[] = [];
  if (penalties.length === 0) {
    recommendations.push("Nothing notable leaks yet. Shield funds into Ghost Mode before you start paying, so this address never builds a public history.");
  } else {
    recommendations.push("Shield your USDC into the Ghost Mode pool: shielded funds, and payments made from them, are no longer tied to this public address or its balance.");
    if (authCount > 0) recommendations.push("Pay x402 APIs through the Ghost relayer, so payments come out of the shielded pool and no authorization signed by this wallet reaches the chain.");
    if (recurringAll.length) recommendations.push("Move recurring payments to Ghost Mode, so the same payee, amount and schedule can no longer be matched to you.");
    if (amountFingerprint.nonRound > 0) recommendations.push("Shield and pay in round amounts (e.g. 5.00 USDC, not 4.9731): unique amounts let anyone match a deposit to a withdrawal or a payment.");
    recommendations.push("Don't withdraw the same amount you deposited, or right after depositing: matching amounts and timing can link both sides of the pool.");
    if (activityClock.inferredUtcOffset !== null) recommendations.push("Vary when your agent pays, or batch payments, so on-chain timestamps stop revealing your daily rhythm and time zone.");
  }

  const sources: ExposureReport["dataQuality"]["sources"] = {
    transfersOut: raw.outgoing === null ? "failed" : raw.outgoingTruncated || limited ? "partial" : "ok",
    transfersIn: raw.incoming === null ? "failed" : raw.incomingTruncated || limited ? "partial" : "ok",
    authorizations: raw.authorizationSource === "eth_getLogs" ? (limited ? "partial" : "ok") : raw.authorizationSource === "receipt-probe" ? "fallback" : "failed",
    balances: raw.ethBalanceWei === null && raw.usdcBalanceRaw === null ? "failed" : raw.ethBalanceWei === null || raw.usdcBalanceRaw === null ? "partial" : "ok",
    account: raw.nonce === null && raw.code === null ? "failed" : raw.nonce === null || raw.code === null ? "partial" : "ok",
  };
  const notes = [...(raw.notes ?? [])];
  if (truncated) notes.push("only the 1000 most recent transfers per direction were read; first activity and totals cover that window");

  return fitReport({
    version: 1,
    chainId: BASE_CHAIN_ID,
    address: isRealAddress(wallet) ? cs(wallet) : (wallet as Address),
    generatedAt: new Date(toMs(now)).toISOString(),
    elapsedMs: null,
    complete: !limited && !Object.values(sources).includes("failed") && !(balancesIncomplete(sources)),
    privacyScore,
    penalties,
    findings: findings.slice(0, 10),
    recommendations: recommendations.slice(0, 6),
    totals: {
      transfersIn: ins.length,
      transfersOut: outs.length,
      selfTransfers: txs.length - ins.length - outs.length,
      uniqueCounterparties,
      firstActivity: iso(first),
      lastActivity: iso(last),
      last30Days: times.filter((t) => t >= nowSec - 30 * DAY).length,
      usdcIn: formatUnits(sum(ins, "USDC"), 6),
      usdcOut: formatUnits(sum(outs, "USDC"), 6),
      ethIn: formatUnits(sum(ins, "ETH"), 18),
      ethOut: formatUnits(sum(outs, "ETH"), 18),
      otherTokenTransfers: txs.filter((t) => t.asset === "TOKEN").length,
      unsolicitedTokenTransfers: unsolicited,
      historyTruncated: truncated || limited,
    },
    balances: {
      eth: raw.ethBalanceWei === null ? null : formatUnits(raw.ethBalanceWei, 18),
      usdc: raw.usdcBalanceRaw === null ? null : formatUnits(raw.usdcBalanceRaw, 6),
    },
    account,
    fundingSource: funding,
    topCounterparties,
    x402Footprint: x402,
    recurring: recurringAll.slice(0, 5),
    activityClock,
    amountFingerprint,
    dataQuality: { sources, notes: notes.slice(0, 6) },
  });
}

const balancesIncomplete = (s: ExposureReport["dataQuality"]["sources"]) => s.balances === "partial" || s.account === "partial";

/**
 * Find the longest circular run of quiet UTC hours and, assuming it is local 00:00-06:00
 * sleep, guess the UTC offset. A bin is quiet when it holds <= 2% of the samples.
 */
export function inferTimezone(histogram: number[]): Omit<ActivityClock, "histogramUtc"> {
  const hist = Array.from({ length: 24 }, (_, i) => Math.max(0, Math.floor(histogram[i] ?? 0)));
  const samples = hist.reduce((a, b) => a + b, 0);
  const none = { samples, quietHoursUtc: null, aroundTheClock: false, inferredUtcOffset: null, offsetLabel: null, confidence: null } as const;
  if (samples === 0) return { ...none, note: "No outgoing activity to analyse." };
  const threshold = Math.floor(samples / 50);
  const quiet = hist.map((c) => c <= threshold);
  let best = { start: 0, length: 0, weight: Number.POSITIVE_INFINITY };
  for (let s = 0; s < 24; s++) {
    if (!quiet[s] || quiet[(s + 23) % 24]) continue; // runs start right after an active hour
    let length = 0;
    let weight = 0;
    while (length < 24 && quiet[(s + length) % 24]) { weight += hist[(s + length) % 24]!; length++; }
    if (length > best.length || (length === best.length && weight < best.weight)) best = { start: s, length, weight };
  }
  if (best.length < 3) {
    return { ...none, aroundTheClock: true, note: "Activity is spread over (almost) every hour of the day; there is no sleep window to infer a time zone from." };
  }
  let off = 3 - (best.start + best.length / 2); // local 03:00 = middle of the quiet run
  off = ((off % 24) + 24) % 24;
  if (off > 12) off -= 24;
  const offset = Math.round(off);
  const plausible = best.length >= 4 && best.length <= 14;
  const confidence = !plausible || samples < 15 ? "low" : samples >= 60 ? "high" : samples >= 25 ? "medium" : "low";
  const end = (best.start + best.length) % 24;
  const label = `UTC${offset >= 0 ? "+" : "-"}${Math.abs(offset)}`;
  return {
    samples,
    quietHoursUtc: { start: best.start, end, length: best.length },
    aroundTheClock: false,
    inferredUtcOffset: offset,
    offsetLabel: label,
    confidence,
    note: `Quiet ${pad2(best.start)}:00-${pad2(end)}:00 UTC. If that is local night (00:00-06:00), the owner is probably around ${label}. A guess: ${confidence} confidence from ${samples} samples.`,
  };
}

function normalizeTransfers(list: AlchemyTransfer[], wallet: string): Tx[] {
  const seen = new Set<string>();
  const out: Tx[] = [];
  for (const t of list) {
    if (!t || typeof t.hash !== "string") continue;
    const from = (t.from ?? "").toLowerCase();
    const to = (t.to ?? "").toLowerCase();
    if (from !== wallet && to !== wallet) continue;
    const token = t.rawContract?.address ? t.rawContract.address.toLowerCase() : null;
    // Self-transfers come back from both queries: dedupe on Alchemy's uniqueId.
    const id = t.uniqueId ?? `${t.hash}:${t.category}:${token ?? ""}:${from}:${to}:${t.rawContract?.value ?? t.value ?? ""}`;
    if (seen.has(id)) continue;
    seen.add(id);
    // Identify USDC by contract, never by symbol (spam tokens reuse "USDC").
    const asset: Tx["asset"] = t.category === "external" ? "ETH" : token === USDC ? "USDC" : "TOKEN";
    const decimals = asset === "ETH" ? 18 : asset === "USDC" ? 6 : parseDecimals(t.rawContract?.decimal);
    const dir: Tx["dir"] = from === wallet && to === wallet ? "self" : from === wallet ? "out" : "in";
    out.push({
      hash: t.hash.toLowerCase(),
      dir,
      cp: dir === "self" ? wallet : dir === "out" ? to : from,
      asset,
      token,
      decimals,
      raw: rawAmount(t, decimals),
      ts: parseTs(t.metadata?.blockTimestamp),
    });
  }
  return out;
}

function rawAmount(t: AlchemyTransfer, decimals: number | null): bigint | null {
  const hex = t.rawContract?.value;
  if (typeof hex === "string" && /^0x[0-9a-fA-F]+$/.test(hex)) return BigInt(hex);
  if (hex === "0x") return 0n;
  if (typeof t.value !== "number" || decimals === null || !Number.isFinite(t.value) || t.value < 0) return null;
  const s = t.value.toFixed(Math.min(decimals, 20)); // fallback only: decimal-adjusted float
  if (s.includes("e")) return null;
  try { return parseUnits(s, decimals); } catch { return null; }
}

function parseDecimals(d: string | null | undefined): number | null {
  if (d == null || d === "") return null;
  const n = d.startsWith("0x") ? parseInt(d, 16) : parseInt(d, 10);
  return Number.isInteger(n) && n >= 0 && n <= 36 ? n : null;
}

function parseTs(s: string | null | undefined): number | null {
  if (!s) return null;
  const ms = Date.parse(s);
  return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
}

/** Round to `sig` significant digits (integer math), e.g. 9_989_999 -> 9_990_000. */
function roundSig(v: bigint, sig: number): bigint {
  if (v <= 0n) return v;
  const digits = v.toString().length;
  if (digits <= sig) return v;
  const f = 10n ** BigInt(digits - sig);
  return ((v + f / 2n) / f) * f;
}

/** Most frequent amount (if it repeats), else the lower median. */
function typicalAmount(values: bigint[]): bigint {
  const freq = new Map<bigint, number>();
  for (const v of values) freq.set(v, (freq.get(v) ?? 0) + 1);
  let best: bigint | null = null;
  let bestN = 0;
  for (const [v, n] of freq) if (n > bestN || (n === bestN && best !== null && v < best)) { best = v; bestN = n; }
  if (best !== null && bestN >= 2) return best;
  const sorted = [...values].sort(cmpBig);
  return sorted[Math.floor((sorted.length - 1) / 2)]!;
}

function cadenceOf(times: number[]): { label: string; medianHours: number | null } {
  const ts = [...times].sort((a, b) => a - b);
  if (ts.length < 2) return { label: "unknown", medianHours: null };
  const gaps = ts.slice(1).map((t, i) => t - ts[i]!).sort((a, b) => a - b);
  const h = gaps[Math.floor(gaps.length / 2)]! / 3600;
  const label = h < 0.5 ? "in bursts"
    : h <= 2 ? "about hourly"
    : h >= 20 && h <= 28 ? "daily"
    : h >= 144 && h <= 192 ? "weekly"
    : h >= 624 && h <= 840 ? "monthly"
    : h < 48 ? `every ~${Math.round(h)} h` : `every ~${Math.round(h / 24)} days`;
  return { label, medianHours: Math.round(h * 10) / 10 };
}

/** Trim list fields until the serialized report fits in MAX_REPORT_BYTES. */
function fitReport(r: ExposureReport): ExposureReport {
  const enc = new TextEncoder();
  const cuts: Array<() => boolean> = [
    () => r.topCounterparties.length > 4 && !!r.topCounterparties.pop(),
    () => r.recurring.length > 2 && !!r.recurring.pop(),
    () => r.x402Footprint.payees.length > 2 && !!r.x402Footprint.payees.pop(),
    () => r.dataQuality.notes.length > 2 && !!r.dataQuality.notes.pop(),
    () => r.findings.length > 5 && !!r.findings.pop(),
    () => r.amountFingerprint.examples.length > 1 && !!r.amountFingerprint.examples.pop(),
  ];
  while (enc.encode(JSON.stringify(r)).length > MAX_REPORT_BYTES) if (!cuts.some((cut) => cut())) break;
  return r;
}

const REGIONS: Record<number, string> = {
  [-10]: "Hawaii", [-8]: "US/Canada Pacific", [-7]: "US Mountain", [-6]: "US Central, Mexico", [-5]: "US Eastern, Colombia",
  [-4]: "Atlantic, Venezuela", [-3]: "Brazil, Argentina", [0]: "UK, Portugal, West Africa", [1]: "Central Europe, Nigeria",
  [2]: "Eastern Europe, South Africa", [3]: "Turkey, Moscow, East Africa", [4]: "UAE", [5]: "Pakistan, India", [6]: "Bangladesh",
  [7]: "Thailand, Vietnam", [8]: "China, Singapore", [9]: "Japan, Korea", [10]: "Eastern Australia", [12]: "New Zealand",
};

function isRealAddress(a: string): boolean { return /^0x[0-9a-f]{40}$/.test(a.toLowerCase()) && a.toLowerCase() !== ZERO; }
const cs = (a: string) => getAddress(a.toLowerCase()) as Address;
const short = (a: string) => `${a.slice(0, 6)}...${a.slice(-4)}`;
const cmpBig = (a: bigint, b: bigint) => (a < b ? -1 : a > b ? 1 : 0);
const pad2 = (h: number) => String(h).padStart(2, "0");
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const toMs = (now: number) => (now < 1e12 ? now * 1000 : now);
const iso = (ts: number | null) => (ts === null ? null : new Date(ts * 1000).toISOString().replace(".000Z", "Z"));
const day = (ts: number) => new Date(ts * 1000).toISOString().slice(0, 10);
const assetLabel = (t: Tx) => (t.asset === "TOKEN" ? `token ${short(t.token ?? "0x?")}` : t.asset);

function trimFrac(s: string, max: number): string {
  const [i, f] = s.split(".");
  if (!f || f.length <= max) return s;
  const cut = f.slice(0, max).replace(/0+$/, "");
  return cut ? `${i}.${cut}` : i === "0" ? s : i!; // keep dust visible instead of printing 0
}

function ago(sec: number): string {
  if (sec < 0) return "in the future";
  if (sec < 3600) return `${Math.max(1, Math.round(sec / 60))} min ago`;
  if (sec < 2 * DAY) return `${Math.round(sec / 3600)} h ago`;
  return `${Math.round(sec / DAY)} days ago`;
}
