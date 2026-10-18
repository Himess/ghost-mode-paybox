// Exposure scan tests. Run: npx tsx test/exposure.ts
//  1. analyzeExposure on a deterministic synthetic wallet (recurring payments, x402
//     authorizations, quiet-hours time zone inference, score bounds, report size).
//  2. scanExposure against a mocked JSON-RPC endpoint (free-tier eth_getLogs refusal ->
//     receipt probe, a hanging request, HTTP 401, key redaction).
//  3. scanExposure public-RPC fallback (no Alchemy) against a mocked JSON-RPC endpoint.
//  4. If ../../../.secrets/alchemy.txt exists: a live Base scan, printing only a compact
//     summary. The key and any URL containing it are never printed.
//     EXPOSURE_LIVE_PUBLIC=1 instead runs one live public-RPC (no key) scan of LIVE_ADDRESS.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { getAddress, toHex } from "viem";
import {
  AUTHORIZATION_USED_TOPIC, BASE_USDC, PUBLIC_LOGS_RPC, TRANSFER_TOPIC, analyzeExposure, inferTimezone, scanExposure,
  type AlchemyTransfer, type ExposureReport, type RawExposure,
} from "../src/exposure.js";

const here = dirname(fileURLToPath(import.meta.url));
const KEY_FILE = resolve(here, "../../../.secrets/alchemy.txt");
const LIVE_ADDRESS = "0x3304E22DDaa22bCdC5fCa2269b418046aE7b566A" as const;

// --- tiny runner ---------------------------------------------------------------------------
const results: { name: string; ok: boolean; err?: string }[] = [];
let secretKey = "";
const redact = (s: string) => (secretKey ? s.split(secretKey).join("***") : s);
async function test(name: string, fn: () => unknown | Promise<unknown>) {
  try {
    await fn();
    results.push({ name, ok: true });
    console.log(`ok   ${name}`);
  } catch (e) {
    const err = redact(e instanceof Error ? e.message : String(e)).slice(0, 600);
    results.push({ name, ok: false, err });
    console.log(`FAIL ${name}\n     ${err}`);
  }
}

// --- synthetic wallet ------------------------------------------------------------------------
const W = "0x7a1e5b6c3d2f4e8a9b0c1d2e3f405162738495a6";
const API = "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"; // x402 API, 0.01 USDC per call
const SUB = "0x5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b"; // monthly 9.99 USDC
const FRIEND = "0xf0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0"; // non-round one-offs
const SHOP = "0xbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef"; // round 25 USDC x2
const ETHR = "0xe7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7"; // one ETH payment
const EXCH = "0x3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c"; // first funder
const FACIL = "0xfacefacefacefacefacefacefacefacefaceface"; // x402 facilitator
const DELEGATE = "0xde1e9a7ede1e9a7ede1e9a7ede1e9a7ede1e9a7e";
const SPAM_TOKEN = "0x5ca45ca45ca45ca45ca45ca45ca45ca45ca45ca4";
const ZERO = `0x${"0".repeat(40)}`;
const USDC = BASE_USDC.toLowerCase();
const NOW = Date.UTC(2026, 9, 17, 12, 0); // 2026-10-17T12:00Z
const pad32 = (a: string) => `0x${a.slice(2).toLowerCase().padStart(64, "0")}`;

let hashSeq = 0;
const nextHash = () => `0x${(++hashSeq).toString(16).padStart(64, "0")}`;
const at = (m: number, d: number, h: number, min = 0) => new Date(Date.UTC(2026, m - 1, d, h, min)).toISOString();

function usdc(from: string, to: string, raw: bigint, ts: string, hash = nextHash()): AlchemyTransfer {
  return {
    from, to, value: Number(raw) / 1e6, asset: "USDC", category: "erc20", hash, uniqueId: `${hash}:log:0`, blockNum: "0x1",
    rawContract: { address: USDC, value: toHex(raw), decimal: "0x6" }, metadata: { blockTimestamp: ts },
  };
}
function eth(from: string, to: string, wei: bigint, ts: string): AlchemyTransfer {
  const hash = nextHash();
  return {
    from, to, value: Number(wei) / 1e18, asset: "ETH", category: "external", hash, uniqueId: `${hash}:external`, blockNum: "0x1",
    rawContract: { address: null, value: toHex(wei), decimal: "0x12" }, metadata: { blockTimestamp: ts },
  };
}
function spam(from: string, ts: string): AlchemyTransfer {
  const hash = nextHash();
  return {
    from, to: W, value: 1000, asset: "Visit scam.example to claim", category: "erc20", hash, uniqueId: `${hash}:log:3`, blockNum: "0x1",
    rawContract: { address: SPAM_TOKEN, value: toHex(10n ** 21n), decimal: "0x12" }, metadata: { blockTimestamp: ts },
  };
}
const byTimeDesc = (a: AlchemyTransfer, b: AlchemyTransfer) => Date.parse(b.metadata!.blockTimestamp!) - Date.parse(a.metadata!.blockTimestamp!);

function buildFixture() {
  hashSeq = 0;
  const apiPayments = Array.from({ length: 30 }, (_, i) => usdc(W, API, 10_000n, at(7, 1 + i, 3 + (i % 18), 7))); // UTC 03-20 only
  const self = usdc(W, W, 1_000_000n, at(7, 20, 11));
  const outgoing = [
    ...apiPayments,
    ...[6, 7, 8, 9, 10].map((m) => usdc(W, SUB, 9_990_000n, at(m, 1, 9, 15))),
    usdc(W, FRIEND, 12_345_678n, at(8, 10, 12, 30)),
    usdc(W, FRIEND, 3_141_592n, at(8, 20, 15, 45)),
    usdc(W, SHOP, 25_000_000n, at(9, 5, 10)),
    usdc(W, SHOP, 25_000_000n, at(9, 12, 17)),
    eth(W, ETHR, 13_700_000_000_000_000n, at(7, 15, 8, 20)),
    self,
  ].sort(byTimeDesc);
  const incoming = [
    usdc(EXCH, W, 500_000_000n, at(5, 30, 14)),
    eth(EXCH, W, 50_000_000_000_000_000n, at(5, 30, 14, 5)),
    usdc(ZERO, W, 100_000_000n, at(6, 15, 10)), // CCTP-style mint: not a counterparty
    spam("0x1111111111111111111111111111111111111111", at(6, 2, 1)),
    spam("0x2222222222222222222222222222222222222222", at(7, 2, 2)),
    spam("0x3333333333333333333333333333333333333333", at(8, 2, 3)),
    self, // self-transfers come back from both queries
  ].sort(byTimeDesc);
  const apiHashes = apiPayments.map((t) => t.hash);
  const raw: RawExposure = {
    outgoing, incoming, outgoingTruncated: false, incomingTruncated: false,
    authorizations: [...apiHashes.map((txHash) => ({ txHash })), { txHash: `0x${"de".repeat(32)}` }], // +1 older than the window
    authorizationSource: "eth_getLogs", probe: null, facilitators: [FACIL],
    ethBalanceWei: 12_300_000_000_000_000n, usdcBalanceRaw: 312_500_000n, nonce: 3, code: `0xef0100${DELEGATE.slice(2)}`, notes: [],
  };
  return { raw, outgoing, incoming, apiHashes };
}

const jsonSize = (r: ExposureReport) => new TextEncoder().encode(JSON.stringify(r)).length;

// --- 1. pure analysis --------------------------------------------------------------------------
await test("analyze: totals, dedupe, spam filtering", () => {
  const r = analyzeExposure(buildFixture().raw, W, NOW);
  assert.equal(r.address, getAddress(W));
  assert.equal(r.generatedAt, "2026-10-17T12:00:00.000Z");
  assert.equal(r.totals.transfersOut, 40);
  assert.equal(r.totals.transfersIn, 6);
  assert.equal(r.totals.selfTransfers, 1, "self transfer deduped across both queries");
  assert.equal(r.totals.uniqueCounterparties, 6, "API, SUB, FRIEND, SHOP, ETHR, EXCH (no spam, no 0x0)");
  assert.equal(r.totals.usdcOut, "115.73727");
  assert.equal(r.totals.usdcIn, "600");
  assert.equal(r.totals.ethOut, "0.0137");
  assert.equal(r.totals.ethIn, "0.05");
  assert.equal(r.totals.unsolicitedTokenTransfers, 3);
  assert.equal(r.totals.firstActivity, "2026-05-30T14:00:00Z");
  assert.equal(r.totals.lastActivity, "2026-10-01T09:15:00Z");
  assert.equal(r.totals.historyTruncated, false);
  const json = JSON.stringify(r);
  assert.ok(!json.includes("scam.example"), "token symbols never reach the report");
  assert.ok(!r.topCounterparties.some((c) => c.address.toLowerCase().startsWith("0x1111")), "spam sender not a counterparty");
  assert.equal(r.balances.usdc, "312.5");
  assert.equal(r.balances.eth, "0.0123");
  assert.deepEqual(r.account, { type: "eip7702", delegate: getAddress(DELEGATE), nonce: 3 });
  assert.equal(r.complete, true);
});

await test("analyze: x402 footprint from authorizations", () => {
  const x = analyzeExposure(buildFixture().raw, W, NOW).x402Footprint;
  assert.equal(x.source, "eth_getLogs");
  assert.equal(x.authorizationCount, 31);
  assert.equal(x.estimatedTotal, null);
  assert.equal(x.matchedPayments, 30, "the 31st authorization is older than the transfer window");
  assert.equal(x.distinctPayees, 1);
  assert.deepEqual(x.payees, [{ address: getAddress(API), payments: 30, usdc: "0.3" }]);
  assert.equal(x.totalUsdc, "0.3");
  assert.equal(x.typicalPrice, "0.01");
  assert.deepEqual(x.facilitators, [getAddress(FACIL)]);
});

await test("analyze: recurring subscription-like patterns", () => {
  const r = analyzeExposure(buildFixture().raw, W, NOW);
  const sub = r.recurring.find((p) => p.counterparty === getAddress(SUB));
  assert.ok(sub, "monthly 9.99 USDC detected");
  assert.equal(sub.kind, "subscription-like");
  assert.equal(sub.count, 5);
  assert.equal(sub.amount, "9.99");
  assert.equal(sub.asset, "USDC");
  assert.equal(sub.cadence, "monthly");
  const api = r.recurring.find((p) => p.counterparty === getAddress(API));
  assert.ok(api && api.count === 30 && api.amount === "0.01" && api.cadence === "daily");
  assert.equal(r.recurring.length, 2, "2x SHOP / 2x FRIEND stay below the 3-occurrence threshold");
  const top = r.topCounterparties[0]!;
  assert.equal(top.address, getAddress(API));
  for (const f of ["recurring", "x402-payee", "frequent"]) assert.ok(top.flags.includes(f), `top flag ${f}`);
  const exch = r.topCounterparties.find((c) => c.address === getAddress(EXCH));
  assert.ok(exch && exch.direction === "in" && exch.flags.includes("funding-source") && exch.usdcIn === "500");
  assert.ok(r.topCounterparties.length <= 8);
});

await test("analyze: quiet hours -> UTC+3 guess", () => {
  const c = analyzeExposure(buildFixture().raw, W, NOW).activityClock;
  assert.equal(c.samples, 41, "40 outgoing txs + 1 self-transfer");
  assert.equal(c.histogramUtc.length, 24);
  assert.deepEqual(c.quietHoursUtc, { start: 21, end: 3, length: 6 });
  assert.equal(c.inferredUtcOffset, 3);
  assert.equal(c.offsetLabel, "UTC+3");
  assert.equal(c.confidence, "medium");
});

await test("analyze: amount fingerprints, funding source, score, findings", () => {
  const r = analyzeExposure(buildFixture().raw, W, NOW);
  assert.equal(r.amountFingerprint.considered, 40);
  assert.equal(r.amountFingerprint.nonRound, 38, "only the two 25 USDC payments are round");
  assert.equal(r.amountFingerprint.nonRoundShare, 0.95);
  assert.deepEqual(r.fundingSource, { address: getAddress(EXCH), asset: "USDC", amount: "500", at: "2026-05-30T14:00:00Z" });
  const points = r.penalties.reduce((s, p) => s + p.points, 0);
  assert.equal(r.privacyScore, Math.max(0, 100 - points));
  assert.equal(r.privacyScore, 28);
  assert.ok(r.penalties.every((p) => Number.isInteger(p.points) && p.points > 0 && p.reason.length > 0));
  assert.equal(r.findings[0]!.severity, "high");
  const order = { high: 0, medium: 1, low: 2 };
  assert.ok(r.findings.every((f, i, a) => i === 0 || order[a[i - 1]!.severity] <= order[f.severity]), "findings sorted by severity");
  assert.ok(r.findings.some((f) => f.title.includes("time zone")));
  const recs = r.recommendations.join(" ");
  for (const w of ["Shield", "Ghost relayer", "round amounts", "same amount"]) assert.ok(recs.includes(w), `recommendation mentions ${w}`);
  assert.ok(jsonSize(r) < 12_000, `report is ${jsonSize(r)} bytes`);
});

await test("analyze: empty wallet scores 100", () => {
  const r = analyzeExposure({
    outgoing: [], incoming: [], authorizations: [], authorizationSource: "eth_getLogs",
    ethBalanceWei: 0n, usdcBalanceRaw: 0n, nonce: 0, code: "0x",
  }, W, NOW);
  assert.equal(r.privacyScore, 100);
  assert.deepEqual(r.penalties, []);
  assert.deepEqual(r.findings, []);
  assert.equal(r.recommendations.length, 1);
  assert.equal(r.account.type, "eoa");
  assert.equal(r.activityClock.inferredUtcOffset, null);
  assert.equal(r.fundingSource, null);
});

await test("analyze: heavy wallet clamps to >= 0 and stays < 12 KB", () => {
  hashSeq = 1000;
  const addr = (i: number) => `0x${(0xc0000 + i).toString(16).padStart(40, "0")}`;
  const outgoing: AlchemyTransfer[] = [];
  for (let i = 0; i < 1000; i++) {
    const recurring = i < 60; // 20 counterparties x 3 identical payments
    // active 06-23 UTC only -> high-confidence UTC+0 guess
    outgoing.push(usdc(W, addr(recurring ? i % 20 : i), recurring ? 5_000_000n : BigInt(1_000_003 + i * 7919), at(1 + (i % 9), 1 + (i % 28), 6 + (i % 18), i % 60)));
  }
  const incoming = Array.from({ length: 999 }, (_, i) => usdc(addr(5000 + i), W, BigInt(2_000_000_000 + i), at(1 + (i % 9), 1 + (i % 28), (i * 7) % 24)));
  const raw: RawExposure = {
    outgoing, incoming, outgoingTruncated: true, incomingTruncated: false,
    authorizations: outgoing.map((t) => ({ txHash: t.hash })), authorizationSource: "eth_getLogs",
    ethBalanceWei: 10n ** 18n, usdcBalanceRaw: 50_000n * 1_000_000n, nonce: 4000, code: "0x6080604052",
    notes: ["eth_getLogs: something went wrong ".repeat(10), "a", "b", "c", "d", "e", "f"],
  };
  const r = analyzeExposure(raw, W, NOW);
  const points = r.penalties.reduce((s, p) => s + p.points, 0);
  assert.ok(points > 100, `penalties ${points} should exceed 100 to exercise the clamp`);
  assert.equal(r.privacyScore, 0);
  assert.ok(r.topCounterparties.length <= 8 && r.recurring.length <= 5 && r.x402Footprint.payees.length <= 5);
  assert.equal(r.x402Footprint.authorizationCount, 1000);
  assert.equal(r.x402Footprint.distinctPayees, 960);
  assert.ok(r.fundingSource !== null);
  assert.equal(r.activityClock.offsetLabel, "UTC+0");
  assert.equal(r.activityClock.confidence, "high");
  assert.equal(r.account.type, "contract");
  assert.equal(r.totals.historyTruncated, true);
  assert.ok(jsonSize(r) < 12_000, `report is ${jsonSize(r)} bytes`);
  // Truncated incoming history: the earliest funder is unknowable, so none is claimed.
  assert.equal(analyzeExposure({ ...raw, incomingTruncated: true }, W, NOW).fundingSource, null);
  // Round-the-clock activity is reported as "looks automated", not as a time zone.
  const bot = analyzeExposure({ ...raw, outgoing: outgoing.map((t, i) => ({ ...t, metadata: { blockTimestamp: at(1 + (i % 9), 1 + (i % 28), i % 24) } })) }, W, NOW);
  assert.equal(bot.activityClock.aroundTheClock, true);
  assert.equal(bot.activityClock.inferredUtcOffset, null);
  assert.ok(bot.findings.some((f) => f.title.includes("around the clock")));
});

await test("inferTimezone: US Eastern, wrap-around, round-the-clock, empty", () => {
  const eastern = Array.from({ length: 24 }, (_, h) => (h >= 5 && h < 11 ? 0 : 5)); // quiet 05-11 UTC
  const e = inferTimezone(eastern);
  assert.equal(e.inferredUtcOffset, -5);
  assert.equal(e.offsetLabel, "UTC-5");
  assert.equal(e.confidence, "high");
  const wrap = inferTimezone(Array.from({ length: 24 }, (_, h) => (h >= 22 || h < 4 ? 0 : 2))); // quiet 22-04 UTC
  assert.deepEqual(wrap.quietHoursUtc, { start: 22, end: 4, length: 6 });
  assert.equal(wrap.inferredUtcOffset, 2);
  assert.equal(wrap.confidence, "medium");
  const bot = inferTimezone(new Array(24).fill(10));
  assert.equal(bot.aroundTheClock, true);
  assert.equal(bot.inferredUtcOffset, null);
  const tiny = inferTimezone([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  assert.equal(tiny.confidence, "low", "two samples cannot give more than low confidence");
  assert.equal(inferTimezone(new Array(24).fill(0)).samples, 0);
});

// --- 2. scanExposure against a mocked RPC --------------------------------------------------------
const FAKE_KEY = "FAKEKEYdoNotLeak0123456789abcdef";
const FAKE_URL = `https://base-mainnet.g.alchemy.com/v2/${FAKE_KEY}`;
class RpcFail extends Error { constructor(public code: number, message: string) { super(message); } }
type Handler = (params: any[], signal: AbortSignal | undefined) => unknown;
const realFetch = globalThis.fetch;

function installMock(handlers: Record<string, Handler>, calls: string[], hosts?: string[]) {
  globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body));
    calls.push(body.method);
    hosts?.push(`${new URL(String(input)).host} ${body.method}`);
    const reply = (o: object) => new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, ...o }), { headers: { "content-type": "application/json" } });
    const h = handlers[body.method];
    if (!h) return reply({ error: { code: -32601, message: "method not found" } });
    try {
      const result = await h(body.params, init?.signal ?? undefined);
      return result instanceof Response ? result : reply({ result });
    } catch (e) {
      if (e instanceof RpcFail) return reply({ error: { code: e.code, message: e.message } });
      throw e;
    }
  }) as typeof fetch;
}

function baseHandlers(fx: ReturnType<typeof buildFixture>): Record<string, Handler> {
  const api = new Set(fx.apiHashes);
  return {
    alchemy_getAssetTransfers: ([p]) => ({ transfers: p.fromAddress ? fx.outgoing : fx.incoming }),
    eth_getBalance: () => toHex(12_300_000_000_000_000n),
    eth_call: ([c]) => { assert.equal(c.to, BASE_USDC); return pad32(toHex(312_500_000n)); },
    eth_getTransactionCount: () => "0x3",
    eth_getCode: () => `0xef0100${DELEGATE.slice(2)}`,
    eth_getTransactionReceipt: ([hash]) => (api.has(hash)
      ? { from: FACIL, logs: [{ address: USDC, topics: [AUTHORIZATION_USED_TOPIC, pad32(W), `0x${"ab".repeat(32)}`], transactionHash: hash }] }
      : { from: W, logs: [] }),
  };
}

await test("scan (mock): free-tier eth_getLogs refusal -> receipt probe, key redacted", async () => {
  const fx = buildFixture();
  const calls: string[] = [];
  installMock({
    ...baseHandlers(fx),
    eth_getLogs: ([f]) => {
      assert.deepEqual(f.topics, [AUTHORIZATION_USED_TOPIC, pad32(W)]);
      assert.equal(f.fromBlock, "0x0");
      throw new RpcFail(-32600, `Under the Free tier plan, you can make eth_getLogs requests with up to a 10 block range. (${FAKE_URL})`);
    },
  }, calls);
  try {
    const t0 = Date.now();
    const r = await scanExposure(FAKE_URL, getAddress(W), { now: NOW });
    assert.ok(Date.now() - t0 < 6000);
    // Oracle: the 25 newest distinct outgoing USDC tx hashes, of which the API ones carry an authorization.
    const usdcHashes = [...new Set(fx.outgoing.filter((t) => t.rawContract?.address === USDC).map((t) => t.hash))];
    const probed = usdcHashes.slice(0, 25);
    const hits = probed.filter((h) => fx.apiHashes.includes(h)).length;
    const x = r.x402Footprint;
    assert.equal(x.source, "receipt-probe");
    assert.equal(x.authorizationCount, hits);
    assert.equal(x.estimatedTotal, Math.round((hits * usdcHashes.length) / 25));
    assert.ok(x.coverage.includes(`25 of ${usdcHashes.length}`));
    assert.deepEqual(x.facilitators, [getAddress(FACIL)]);
    assert.equal(calls.filter((m) => m === "eth_getTransactionReceipt").length, 25);
    assert.equal(r.dataQuality.sources.authorizations, "fallback");
    assert.equal(r.activityClock.inferredUtcOffset, 3);
    assert.equal(r.balances.usdc, "312.5");
    const json = JSON.stringify(r);
    assert.ok(!json.includes(FAKE_KEY), "API key must never appear in the report");
    assert.ok(r.dataQuality.notes.some((n) => n.includes("eth_getLogs") && n.includes("10 block range")));
    assert.ok(jsonSize(r) < 12_000);
  } finally {
    globalThis.fetch = realFetch;
  }
});

await test("scan (mock): full getLogs + one hanging request still finishes < 6 s", async () => {
  const fx = buildFixture();
  const calls: string[] = [];
  installMock({
    ...baseHandlers(fx),
    eth_getLogs: () => [...fx.apiHashes, `0x${"de".repeat(32)}`].map((h, i) => ({
      address: USDC, topics: [AUTHORIZATION_USED_TOPIC, pad32(W), toHex(i, { size: 32 })], transactionHash: h, blockNumber: toHex(100 + i), removed: false,
    })),
    eth_getCode: (_p, signal) => new Promise((_, reject) => signal?.addEventListener("abort", () => reject(signal.reason))),
  }, calls);
  // AbortSignal.timeout timers are unref'd; a real hung fetch holds a socket that keeps the
  // event loop alive, the mock holds nothing, so keep the process alive for this test.
  const keepAlive = setInterval(() => {}, 1000);
  try {
    const t0 = Date.now();
    const r = await scanExposure(FAKE_URL, getAddress(W), { now: NOW });
    const ms = Date.now() - t0;
    assert.ok(ms < 6000 && ms >= 3900, `took ${ms} ms`);
    assert.ok(r.elapsedMs !== null && r.elapsedMs < 6000);
    assert.equal(r.x402Footprint.source, "eth_getLogs");
    assert.equal(r.x402Footprint.authorizationCount, 31);
    assert.equal(r.x402Footprint.matchedPayments, 30);
    assert.deepEqual(r.x402Footprint.facilitators, [getAddress(FACIL)]);
    assert.ok(calls.filter((m) => m === "eth_getTransactionReceipt").length <= 3, "only a 3-receipt facilitator probe");
    assert.equal(r.account.type, "unknown");
    assert.equal(r.complete, false);
    assert.ok(r.dataQuality.notes.some((n) => n.startsWith("eth_getCode: timed out")));
  } finally {
    clearInterval(keepAlive);
    globalThis.fetch = realFetch;
  }
});

await test("scan (mock): HTTP 401 everywhere rejects without leaking the key", async () => {
  installMock(Object.fromEntries(
    ["alchemy_getAssetTransfers", "eth_getLogs", "eth_getBalance", "eth_call", "eth_getTransactionCount", "eth_getCode"]
      .map((m) => [m, () => new Response(`Must be authenticated! ${FAKE_KEY}`, { status: 401 })]),
  ), []);
  try {
    await assert.rejects(scanExposure(FAKE_URL, getAddress(W)), (e: Error) => {
      assert.ok(e.message.includes("HTTP 401"));
      assert.ok(!e.message.includes(FAKE_KEY));
      return true;
    });
    await assert.rejects(scanExposure(FAKE_URL, "0x1234" as `0x${string}`), /invalid address/);
  } finally {
    globalThis.fetch = realFetch;
  }
});

// --- 3. public-RPC fallback (no Alchemy) against a mocked RPC -------------------------------------
const HEAD = 40_000_000;
const HEAD_TS = Math.floor(NOW / 1000);
const blockTs = (b: number) => HEAD_TS - (HEAD - b) * 2; // exactly 2 s per block, so estimates are exact
const isoTs = (ts: number) => new Date(ts * 1000).toISOString().replace(".000Z", "Z");
interface MockLog { address: string; topics: string[]; data: string; blockNumber: string; transactionHash: string; logIndex: string; removed: boolean }

function fallbackChain() {
  const logs: MockLog[] = [];
  let seq = 0;
  const tx = () => `0x${(0xfb000 + ++seq).toString(16).padStart(64, "0")}`;
  const transfer = (from: string, to: string, raw: bigint, block: number) => {
    const hash = tx();
    logs.push({ address: USDC, topics: [TRANSFER_TOPIC, pad32(from), pad32(to)], data: toHex(raw, { size: 32 }), blockNumber: toHex(block), transactionHash: hash, logIndex: "0x0", removed: false });
    return hash;
  };
  // 50 x402 payments of 0.01 USDC, ~57 min apart (HEAD-100 ... HEAD-83,400), each with its AuthorizationUsed log.
  const apiHashes = Array.from({ length: 50 }, (_, i) => {
    const b = HEAD - 100 - i * 1_700;
    const hash = transfer(W, API, 10_000n, b);
    logs.push({ address: USDC, topics: [AUTHORIZATION_USED_TOPIC, pad32(W), toHex(i, { size: 32 })], data: "0x", blockNumber: toHex(b), transactionHash: hash, logIndex: "0x1", removed: false });
    return hash;
  });
  transfer(W, FRIEND, 12_345_678n, HEAD - 5_000);
  transfer(W, FRIEND, 3_141_592n, HEAD - 60_000);
  for (const b of [HEAD - 2_000, HEAD - 30_000, HEAD - 70_000]) transfer(EXCH, W, 100_000_000n, b);
  transfer(W, W, 1_000_000n, HEAD - 10); // self-transfer: returned by both queries
  transfer(W, SHOP, 25_000_000n, HEAD - 150_000); // older than the ~100k-block window
  transfer(SHOP, FRIEND, 1n, HEAD - 50); // unrelated
  return { logs, apiHashes };
}

type LogFilter = { address: string; fromBlock: string; toBlock: string; topics: (string | string[] | null)[] };
function fallbackHandlers(
  chain: ReturnType<typeof fallbackChain>, ranges: Array<[number, number]>,
  opts: { hang?: (from: number, f: LogFilter) => boolean; refuseOlderThan?: number } = {},
): Record<string, Handler> {
  const num = (tag: string) => (tag === "latest" ? HEAD : Number(BigInt(tag)));
  const match = (want: string | string[] | null | undefined, have: string | undefined) => want == null || (Array.isArray(want) ? want.includes(have!) : want === have);
  return {
    alchemy_getAssetTransfers: () => { throw new RpcFail(-32601, "the method alchemy_getAssetTransfers does not exist/is not available"); },
    eth_getBlockByNumber: ([tag]) => { const b = num(tag); return { number: toHex(b), timestamp: toHex(blockTs(b)) }; },
    eth_getLogs: ([f]: LogFilter[], signal) => {
      const from = num(f!.fromBlock);
      const to = num(f!.toBlock);
      if (to - from + 1 > 10_000) throw new RpcFail(-32602, "block range exceeds 10000");
      assert.equal(f!.address, BASE_USDC);
      ranges.push([from, to]);
      if (opts.refuseOlderThan !== undefined && from < opts.refuseOlderThan) {
        throw new RpcFail(-32602, "Archive requests require a personal token. Get one at: https://www.allnodes.com/publicnode");
      }
      if (opts.hang?.(from, f!)) return new Promise((_, reject) => signal?.addEventListener("abort", () => reject(signal.reason)));
      return chain.logs.filter((l) => {
        const b = Number(BigInt(l.blockNumber));
        return b >= from && b <= to && f!.topics.every((t, i) => match(t, l.topics[i]));
      });
    },
    eth_getBalance: () => toHex(12_300_000_000_000_000n),
    eth_call: () => pad32(toHex(312_500_000n)),
    eth_getTransactionCount: () => "0x3",
    eth_getCode: () => "0x",
    eth_getTransactionReceipt: ([hash]) => ({ from: FACIL, logs: chain.logs.filter((l) => l.transactionHash === hash) }),
  };
}

await test("scan (mock): alchemy_getAssetTransfers rejected -> public-RPC fallback, hung chunk skipped, < 7 s", async () => {
  const chain = fallbackChain();
  const calls: string[] = [];
  const hosts: string[] = [];
  const ranges: Array<[number, number]> = [];
  // The incoming query of the oldest chunk hangs until its 4 s timeout.
  installMock(fallbackHandlers(chain, ranges, { hang: (from, f) => from < HEAD - 90_000 && f.topics[1] === null }), calls, hosts);
  const keepAlive = setInterval(() => {}, 1000);
  try {
    const t0 = Date.now();
    const r = await scanExposure(FAKE_URL, getAddress(W), { now: NOW });
    const ms = Date.now() - t0;
    assert.ok(ms < 7000 && ms >= 3900, `took ${ms} ms`);
    assert.ok(r.elapsedMs !== null && r.elapsedMs < 7000);
    assert.equal(calls.filter((m) => m === "alchemy_getAssetTransfers").length, 2);
    // 10 chunks x (outgoing+authorizations, incoming), each <= 10,000 blocks, ~100k blocks in all.
    assert.equal(ranges.length, 20);
    assert.ok(ranges.every(([f, t]) => t - f + 1 <= 10_000));
    assert.equal(Math.min(...ranges.map(([f]) => f)), HEAD - 99_979);
    const pn = new URL(PUBLIC_LOGS_RPC).host;
    assert.equal(hosts.filter((h) => h === `${pn} eth_getLogs`).length, 20, "chunked logs go to the public log RPC");
    assert.equal(calls.filter((m) => m === "eth_getBlockByNumber").length, 41, "head + at most 40 block lookups");
    assert.equal(r.dataQuality.notes[0], "Public-RPC mode: USDC activity from roughly the last 2 days only (Alchemy transfer API unavailable)");
    assert.ok(r.dataQuality.notes.some((n) => n.includes("1 eth_getLogs block-range query timed out")), r.dataQuality.notes.join(" | "));
    assert.ok(r.dataQuality.notes.some((n) => n.includes("16 of 56 block timestamps estimated")), r.dataQuality.notes.join(" | "));
    assert.equal(r.complete, false);
    assert.equal(r.totals.historyTruncated, true);
    assert.deepEqual(r.dataQuality.sources, { transfersOut: "partial", transfersIn: "partial", authorizations: "partial", balances: "ok", account: "ok" });
    assert.equal(r.totals.transfersOut, 52);
    assert.equal(r.totals.transfersIn, 3);
    assert.equal(r.totals.selfTransfers, 1, "self transfer deduped across both queries");
    assert.equal(r.totals.usdcOut, "15.98727");
    assert.equal(r.totals.usdcIn, "300");
    assert.equal(r.totals.lastActivity, isoTs(blockTs(HEAD - 10)));
    assert.equal(r.totals.firstActivity, isoTs(blockTs(HEAD - 83_400)), "estimated timestamp of the oldest payment");
    assert.equal(r.fundingSource, null, "the first funder is unknowable from a 2-day window");
    const x = r.x402Footprint;
    assert.equal(x.source, "eth_getLogs");
    assert.ok(x.coverage.includes("public-RPC"));
    assert.equal(x.authorizationCount, 50);
    assert.equal(x.matchedPayments, 50);
    assert.deepEqual(x.payees, [{ address: getAddress(API), payments: 50, usdc: "0.5" }]);
    assert.deepEqual(x.facilitators, [getAddress(FACIL)]);
    assert.equal(r.activityClock.samples, 53, "52 outgoing + 1 self-transfer");
    assert.equal(r.balances.usdc, "312.5");
    assert.equal(r.account.type, "eoa");
    assert.ok(r.findings.some((f) => f.title.includes("x402")));
    const json = JSON.stringify(r);
    assert.ok(!json.includes(FAKE_KEY), "API key must never appear in the report");
    assert.ok(jsonSize(r) < 12_000);
  } finally {
    clearInterval(keepAlive);
    globalThis.fetch = realFetch;
  }
});

await test("scan (mock): non-Alchemy rpcUrl goes straight to public-RPC mode", async () => {
  const calls: string[] = [];
  const hosts: string[] = [];
  installMock(fallbackHandlers(fallbackChain(), []), calls, hosts);
  try {
    const r = await scanExposure("https://mainnet.base.org", getAddress(W), { now: NOW });
    assert.ok(r.elapsedMs !== null && r.elapsedMs < 7000);
    assert.equal(calls.filter((m) => m === "alchemy_getAssetTransfers").length, 0);
    assert.equal(r.dataQuality.notes[0], "Public-RPC mode: USDC activity from roughly the last 2 days only (no Alchemy key configured)");
    const pn = new URL(PUBLIC_LOGS_RPC).host;
    assert.ok(hosts.filter((h) => h.endsWith(" eth_getLogs")).every((h) => h.startsWith(`${pn} `)));
    for (const m of ["eth_getBalance", "eth_call", "eth_getTransactionCount", "eth_getCode", "eth_getBlockByNumber"]) assert.ok(hosts.includes(`mainnet.base.org ${m}`), m);
    assert.equal(r.totals.transfersOut, 52);
    assert.equal(r.totals.transfersIn, 3);
    assert.equal(r.x402Footprint.authorizationCount, 50);
    assert.equal(r.complete, false);
  } finally {
    globalThis.fetch = realFetch;
  }
});

await test("scan (mock): public log RPC refuses older ranges -> newest chunk only, window stated", async () => {
  const ranges: Array<[number, number]> = [];
  installMock(fallbackHandlers(fallbackChain(), ranges, { refuseOlderThan: HEAD - 10_000 }), []);
  try {
    const r = await scanExposure("https://mainnet.base.org", getAddress(W), { now: NOW });
    assert.ok(ranges.length <= 6, `older chunks not requested after the refusal (${ranges.length} log calls)`);
    assert.equal(r.dataQuality.notes[0], "Public-RPC mode: USDC activity from roughly the last 6 hours only (no Alchemy key configured)");
    assert.ok(r.dataQuality.notes.some((n) => n.includes("refused") && n.includes("personal token") && !n.includes("allnodes.com")), r.dataQuality.notes.join(" | "));
    assert.equal(r.totals.transfersOut, 7, "6 x402 payments + 1 FRIEND payment in the newest 9,980 blocks");
    assert.equal(r.totals.transfersIn, 1);
    assert.equal(r.x402Footprint.authorizationCount, 6);
    assert.equal(r.complete, false);
  } finally {
    globalThis.fetch = realFetch;
  }
});

// --- 4. live scan (only when the key file exists, or EXPOSURE_LIVE_PUBLIC=1 for public-RPC mode) ----
if (process.env.EXPOSURE_LIVE_PUBLIC) {
  await test(`live public-RPC scan ${LIVE_ADDRESS}`, async () => {
    const r = await scanExposure("https://mainnet.base.org", LIVE_ADDRESS);
    const summary = {
      score: r.privacyScore,
      elapsedMs: r.elapsedMs,
      complete: r.complete,
      transfersOut: r.totals.transfersOut,
      transfersIn: r.totals.transfersIn,
      x402: r.x402Footprint.authorizationCount,
      sources: r.dataQuality.sources,
      notes: r.dataQuality.notes.map((n) => n.slice(0, 160)),
    };
    console.log(`     ${JSON.stringify(summary)}`);
    assert.ok(r.elapsedMs !== null && r.elapsedMs < 7000, `live public scan took ${r.elapsedMs} ms`);
    assert.ok(r.dataQuality.notes[0]?.startsWith("Public-RPC mode: USDC activity from roughly the last"));
    assert.equal(r.complete, false);
  });
} else if (existsSync(KEY_FILE)) {
  secretKey = readFileSync(KEY_FILE, "utf8").trim();
  if (!secretKey) {
    console.log("skip live scan: key file is empty");
  } else {
    await test(`live scan ${LIVE_ADDRESS}`, async () => {
      const r = await scanExposure(`https://base-mainnet.g.alchemy.com/v2/${secretKey}`, LIVE_ADDRESS);
      const summary = {
        score: r.privacyScore,
        elapsedMs: r.elapsedMs,
        complete: r.complete,
        transfersOut: r.totals.transfersOut,
        transfersIn: r.totals.transfersIn,
        counterparties: r.totals.uniqueCounterparties,
        truncated: r.totals.historyTruncated,
        x402: { source: r.x402Footprint.source, count: r.x402Footprint.authorizationCount, est: r.x402Footprint.estimatedTotal, payees: r.x402Footprint.distinctPayees },
        recurring: r.recurring.length,
        timezone: r.activityClock.offsetLabel ? `${r.activityClock.offsetLabel} (${r.activityClock.confidence})` : r.activityClock.aroundTheClock ? "around-the-clock" : null,
        account: r.account.type,
        findings: r.findings.length,
        reportBytes: jsonSize(r),
        sources: r.dataQuality.sources,
        notes: r.dataQuality.notes.map((n) => redact(n).slice(0, 160)),
      };
      console.log(`     ${redact(JSON.stringify(summary))}`);
      assert.ok(r.elapsedMs !== null && r.elapsedMs < 6000, `live scan took ${r.elapsedMs} ms`);
      assert.ok(r.privacyScore >= 0 && r.privacyScore <= 100);
      assert.ok(jsonSize(r) < 12_000);
      assert.ok(!JSON.stringify(r).includes(secretKey), "key must never appear in the report");
    });
  }
} else {
  console.log("skip live scan: .secrets/alchemy.txt not found (offline fixtures + mocked RPC only)");
}

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} passed`);
process.exit(failed.length ? 1 : 0);
