// Disclosure verification tests. Run: npx tsx test/verify.ts   (from ghost-mode/service)
// Builds synthetic ghost-receipt / ghost-report packages with the real Ghost Mode primitives
// (../../plugin/src/core/primitives.ts) and a viem local account, serves the matching chain
// data from a mock ChainReader, and checks that every item passes, then that tampering with
// one field makes exactly the related item fail. Also covers the JSON-RPC reader (fallback,
// de-duplication) and the built page (self-contained, CSP-pinned) when it exists.
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { encodeAbiParameters, encodeEventTopics, getAddress, hexToBytes, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  EIP712_DOMAIN_TYPE, H1, SPEND_TYPES, commitmentOf, encryptNote, extDataHashOf, formatGhostKey, ghostDomain, intentOf,
  nullifierOf, parseGhostKey, randomField, toHex32,
} from "../../plugin/src/core/primitives.js";
import {
  OFFICIAL_POOLS, RpcUnavailableError, USDC_BY_CHAIN, decodePackageParam, encodePackageParam, erc20TransferEvent, formatUsdc,
  ghostPoolEvents, parsePackage, verifyPackage, type ChainReader, type ReceiptPackage, type ReportPackage, type RpcBlock,
  type RpcLog, type RpcReceipt, type Verification,
} from "../src/verify/core.js";
import { JsonRpcReader } from "../src/verify/rpc.js";
import { VERIFY_PAGE_FILE, verifyLink, verifyPageCsp, verifyPageHtml } from "../src/verify/index.js";

// --- tiny runner ---------------------------------------------------------------------------
const results: { name: string; ok: boolean; err?: string }[] = [];
async function test(name: string, fn: () => unknown | Promise<unknown>) {
  try {
    await fn();
    results.push({ name, ok: true });
    console.log(`ok   ${name}`);
  } catch (e) {
    const err = (e instanceof Error ? e.message : String(e)).slice(0, 800);
    results.push({ name, ok: false, err });
    console.log(`FAIL ${name}\n     ${err}`);
  }
}

// --- fixtures --------------------------------------------------------------------------------
const CHAIN_ID = 8453;
const POOL = getAddress(OFFICIAL_POOLS[CHAIN_ID]![0]!);
const USDC = getAddress(USDC_BY_CHAIN[CHAIN_ID]!);
const MERCHANT = getAddress("0xbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef");
const RELAYER = getAddress("0x5e1a7e5e1a7e5e1a7e5e1a7e5e1a7e5e1a7e5e1a");
const ZERO = "0x0000000000000000000000000000000000000000";
const ASSET = BigInt(USDC);
const BLOCK_TIME = 1_792_000_000; // 2026-10-15
const FEE = 10_000n; // 0.01 USDC

const payerAccount = privateKeyToAccount(generatePrivateKey());
const payerPub = hexToBytes(payerAccount.publicKey).slice(1); // drop 0x04
const payer = parseGhostKey(formatGhostKey(hexToBytes(generatePrivateKey()), payerPub));
const friendAccount = privateKeyToAccount(generatePrivateKey());
const friend = parseGhostKey(formatGhostKey(hexToBytes(generatePrivateKey()), hexToBytes(friendAccount.publicKey).slice(1)));

const txHashOf = (n: number) => `0x${n.toString(16).padStart(64, "0")}` as Hex;
const blockHex = (n: number) => `0x${n.toString(16)}`;

// Log builders with real ABI encoding.
const poolLog = (topics: Hex[], data: Hex): RpcLog => ({ address: POOL.toLowerCase(), topics, data });
const logNullifier = (n: bigint) => poolLog(encodeEventTopics({ abi: ghostPoolEvents, eventName: "NewNullifier", args: { nullifier: n } }) as Hex[], "0x");
const logCommitment = (c: bigint, leafIndex: number, enc: Hex) =>
  poolLog(encodeEventTopics({ abi: ghostPoolEvents, eventName: "NewCommitment", args: { commitment: c } }) as Hex[],
    encodeAbiParameters([{ type: "uint32" }, { type: "bytes" }], [leafIndex, enc]));
const logDeposited = (depositor: Hex, c: bigint, label: bigint, amount: bigint, leafIndex: number) =>
  poolLog(encodeEventTopics({ abi: ghostPoolEvents, eventName: "Deposited", args: { depositor, commitment: c } }) as Hex[],
    encodeAbiParameters([{ type: "uint256" }, { type: "uint256" }, { type: "uint32" }], [label, amount, leafIndex]));
const logTransacted = (relayer: Hex, recipient: Hex, publicOut: bigint, fee: bigint) =>
  poolLog(encodeEventTopics({ abi: ghostPoolEvents, eventName: "Transacted", args: { relayer, recipient } }) as Hex[],
    encodeAbiParameters([{ type: "uint256" }, { type: "uint256" }], [publicOut, fee]));
const logUsdc = (from: Hex, to: Hex, value: bigint): RpcLog => ({
  address: USDC.toLowerCase(),
  topics: encodeEventTopics({ abi: erc20TransferEvent, eventName: "Transfer", args: { from, to } }) as Hex[],
  data: encodeAbiParameters([{ type: "uint256" }], [value]),
});

class MockReader implements ChainReader {
  receipts = new Map<string, RpcReceipt>();
  blocks = new Map<string, RpcBlock>();
  constructor(public chain = CHAIN_ID, public down = false) {}
  describe() {
    return "mock://chain";
  }
  async chainId() {
    if (this.down) throw new RpcUnavailableError("RPC unreachable (mock: connection refused)");
    return this.chain;
  }
  async getReceipt(h: string) {
    if (this.down) throw new RpcUnavailableError("RPC unreachable (mock: connection refused)");
    return structuredClone(this.receipts.get(h.toLowerCase()) ?? null);
  }
  async getBlock(n: string) {
    if (this.down) throw new RpcUnavailableError("RPC unreachable (mock: connection refused)");
    return this.blocks.get(BigInt(n).toString()) ?? null;
  }
  add(txHash: Hex, block: number, logs: RpcLog[], status = "0x1", time = BLOCK_TIME) {
    this.receipts.set(txHash.toLowerCase(), { status, blockNumber: blockHex(block), transactionHash: txHash, logs });
    this.blocks.set(String(block), { number: blockHex(block), timestamp: blockHex(time) });
  }
}

type Spend = { pkg: ReceiptPackage; logs: RpcLog[]; change: { commitment: bigint; amount: bigint; blinding: bigint; label: bigint; leafIndex: number } };

/** A spend exactly as plugin/src/core/spend.ts builds it, signed by the payer's PayBox wallet. */
async function makeSpend(opts: { ghost: boolean; txHash: Hex; amount: bigint; sumIn: bigint; deadline?: number; leaf0: number }): Promise<Spend> {
  const label = randomField();
  const n0 = nullifierOf(commitmentOf({ asset: ASSET, amount: opts.sumIn, ownerTag: payer.ownerTag, blinding: randomField(), label }), 1, payer.nk);
  const n1 = nullifierOf(commitmentOf({ asset: ASSET, amount: 0n, ownerTag: payer.ownerTag, blinding: randomField(), label }), 0, payer.nk);
  const change = opts.sumIn - opts.amount - FEE;
  const out0 = opts.ghost ? { amount: opts.amount, ownerTag: friend.ownerTag, blinding: randomField() } : { amount: 0n, ownerTag: payer.ownerTag, blinding: randomField() };
  const out1 = { amount: change, ownerTag: payer.ownerTag, blinding: randomField() };
  const c0 = commitmentOf({ asset: ASSET, label, ...out0 });
  const c1 = commitmentOf({ asset: ASSET, label, ...out1 });
  const enc0: Hex = opts.ghost ? encryptNote(friend.viewPub, out0.amount, out0.blinding, label) : "0x";
  const enc1: Hex = encryptNote(payer.viewPub, out1.amount, out1.blinding, label);
  const recipient: Hex = opts.ghost ? ZERO : MERCHANT;
  const publicOut = opts.ghost ? FEE : opts.amount + FEE;
  const intent = intentOf(n0, n1, c0, c1, extDataHashOf(RELAYER, enc0, enc1));
  const deadline = opts.deadline ?? BLOCK_TIME + 600;
  const message = {
    intent: toHex32(intent), token: USDC,
    privateAmount: String(out0.amount), privateRecipient: opts.ghost ? toHex32(friend.ownerTag) : toHex32(0n),
    publicAmount: String(publicOut - FEE), publicRecipient: recipient, fee: String(FEE), deadline: String(deadline),
  };
  const domain = ghostDomain(CHAIN_ID, POOL);
  const signature = await payerAccount.signTypedData({
    domain, types: SPEND_TYPES, primaryType: "GhostSpend",
    message: { ...message, privateAmount: BigInt(message.privateAmount), publicAmount: BigInt(message.publicAmount), fee: FEE, deadline: BigInt(deadline) },
  });
  const pkg: ReceiptPackage = {
    kind: "ghost-receipt", version: 1, chainId: CHAIN_ID, pool: POOL, txHash: opts.txHash, signer: payerAccount.address, signature,
    typedData: {
      domain, types: { EIP712Domain: [...EIP712_DOMAIN_TYPE], GhostSpend: [...SPEND_TYPES.GhostSpend] }, primaryType: "GhostSpend", message,
    },
    nullifiers: [n0.toString(), n1.toString()], outCommitments: [c0.toString(), c1.toString()],
    memo: { kind: opts.ghost ? "send_ghost" : "pay_address", counterparty: opts.ghost ? "ghost:friend" : "Acme Coffee", amount: String(BigInt(message.privateAmount) + BigInt(message.publicAmount)), fee: String(FEE), time: BLOCK_TIME, host: "acme.example" },
  };
  const toRecipient = publicOut - FEE;
  const logs = [
    logNullifier(n0), logNullifier(n1), logCommitment(c0, opts.leaf0, enc0), logCommitment(c1, opts.leaf0 + 1, enc1),
    ...(toRecipient ? [logUsdc(POOL, recipient, toRecipient)] : []), logUsdc(POOL, RELAYER, FEE), logTransacted(RELAYER, recipient, publicOut, FEE),
  ];
  return { pkg, logs, change: { commitment: c1, amount: change, blinding: out1.blinding, label, leafIndex: opts.leaf0 + 1 } };
}

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v));
const status = (r: Verification, id: string) => {
  const c = r.checks.find((x) => x.id === id);
  assert.ok(c, `check ${id} missing; have ${r.checks.map((x) => x.id).join(",")}`);
  return c.status;
};
const failing = (r: Verification) => r.checks.filter((c) => c.status === "fail" || c.status === "error").map((c) => c.id).sort();
const explain = (r: Verification) => r.checks.map((c) => `${c.status.padEnd(5)} ${c.id}: ${c.summary}`).join("\n     ");

async function expectOnly(pkg: unknown, reader: ChainReader, ids: string[]) {
  const r = await verifyPackage(parsePackage(clone(pkg)), reader);
  assert.deepEqual(failing(r), [...ids].sort(), `unexpected failures:\n     ${explain(r)}`);
  assert.equal(r.ok, ids.length === 0);
  return r;
}

// --- tests -----------------------------------------------------------------------------------
const reader = new MockReader();
const PAY_TX = txHashOf(0xa1), GHOST_TX = txHashOf(0xa2), DEP_TX = txHashOf(0xa3);
const pay = await makeSpend({ ghost: false, txHash: PAY_TX, amount: 10_000_000n, sumIn: 15_010_000n, leaf0: 4 });
const ghostPay = await makeSpend({ ghost: true, txHash: GHOST_TX, amount: 2_500_000n, sumIn: 5_000_000n, leaf0: 6 });
reader.add(PAY_TX, 100, pay.logs);
reader.add(GHOST_TX, 101, ghostPay.logs);

await test("formatUsdc / base64url fragment round trip", () => {
  assert.equal(formatUsdc(10_000_000n), "10.00");
  assert.equal(formatUsdc(10_000n), "0.01");
  assert.equal(formatUsdc(1_234_567_891n), "1,234.567891");
  const enc = encodePackageParam(pay.pkg);
  assert.ok(/^[A-Za-z0-9_-]+$/.test(enc));
  assert.deepEqual(decodePackageParam(enc), clone(pay.pkg));
  const link = verifyLink("https://ghost.example/verify", pay.pkg, "http://127.0.0.1:8545");
  assert.ok(link.startsWith("https://ghost.example/verify#pkg=") && link.endsWith("&rpc=http%3A%2F%2F127.0.0.1%3A8545"));
});

await test("receipt (public payment): every item passes", async () => {
  const r = await expectOnly(pay.pkg, reader, []);
  for (const id of ["network", "pool", "signature", "domain", "transaction", "intent", "payout", "time"]) assert.equal(status(r, id), "pass", id);
  assert.equal(status(r, "memo"), "info");
  assert.match(r.headline, /paid 10\.00 USDC to 0xbeEF…beEF \(fee 0\.01\) in tx 0x00000000…0000a1, authorised by their PayBox wallet/i);
});

await test("receipt (ghost transfer): passes and says the amount went privately", async () => {
  const r = await expectOnly(ghostPay.pkg, reader, []);
  assert.match(r.headline, /paid 2\.50 USDC privately to ghost recipient/);
  assert.match(r.checks.find((c) => c.id === "payout")!.summary, /sent privately to ghost recipient/);
});

await test("receipt tamper: amount → signature + payout fail", async () => {
  const p = clone(pay.pkg); p.typedData.message.publicAmount = "20000000";
  await expectOnly(p, reader, ["signature", "payout"]);
});
await test("receipt tamper: recipient → signature + payout fail", async () => {
  const p = clone(pay.pkg); p.typedData.message.publicRecipient = getAddress("0x1111111111111111111111111111111111111111");
  await expectOnly(p, reader, ["signature", "payout"]);
});
await test("receipt tamper: claimed signer → signature fails", async () => {
  const p = clone(pay.pkg); p.signer = friendAccount.address;
  await expectOnly(p, reader, ["signature"]);
});
await test("receipt tamper: signature byte → signature fails", async () => {
  const p = clone(pay.pkg); p.signature = `${p.signature.slice(0, 20)}${p.signature[20] === "0" ? "1" : "0"}${p.signature.slice(21)}`;
  await expectOnly(p, reader, ["signature"]);
});
await test("receipt tamper: nullifier → transaction + intent fail", async () => {
  const p = clone(pay.pkg); p.nullifiers[0] = (BigInt(p.nullifiers[0]) + 1n).toString();
  await expectOnly(p, reader, ["transaction", "intent"]);
});
await test("receipt tamper: output commitment → transaction + intent + payout fail", async () => {
  const p = clone(pay.pkg); p.outCommitments[1] = (BigInt(p.outCommitments[1]) + 1n).toString();
  await expectOnly(p, reader, ["transaction", "intent", "payout"]);
});
await test("receipt tamper: intent (re-signed) → intent fails", async () => {
  const p = clone(pay.pkg);
  p.typedData.message.intent = toHex32(BigInt(p.typedData.message.intent) + 1n);
  const m = p.typedData.message;
  p.signature = await payerAccount.signTypedData({ domain: ghostDomain(CHAIN_ID, POOL), types: SPEND_TYPES, primaryType: "GhostSpend",
    message: { ...m, intent: m.intent as Hex, token: m.token as Hex, privateRecipient: m.privateRecipient as Hex, publicRecipient: m.publicRecipient as Hex,
      privateAmount: BigInt(m.privateAmount), publicAmount: BigInt(m.publicAmount), fee: BigInt(m.fee), deadline: BigInt(m.deadline) } });
  await expectOnly(p, reader, ["intent"]);
});
await test("receipt tamper: pool → official pool + domain + chain checks fail", async () => {
  const p = clone(pay.pkg); p.pool = getAddress("0x2222222222222222222222222222222222222222");
  await expectOnly(p, reader, ["pool", "domain", "transaction", "intent", "payout"]);
});
await test("receipt tamper: fee → signature + payout fail", async () => {
  const p = clone(pay.pkg); p.typedData.message.fee = "0";
  await expectOnly(p, reader, ["signature", "payout"]);
});
await test("receipt tamper: tx hash → transaction not found", async () => {
  const p = clone(pay.pkg); p.txHash = txHashOf(0xdead);
  const r = await expectOnly(p, reader, ["transaction", "intent", "payout", "time"]);
  assert.match(r.checks.find((c) => c.id === "transaction")!.summary, /not found/);
});
await test("receipt: reverted tx fails; relayer swap breaks the intent; missing USDC transfer fails payout", async () => {
  const r2 = new MockReader();
  r2.add(PAY_TX, 100, pay.logs, "0x0");
  await expectOnly(pay.pkg, r2, ["transaction"]);
  const r3 = new MockReader();
  const otherRelayer = getAddress("0x3333333333333333333333333333333333333333");
  r3.add(PAY_TX, 100, [...pay.logs.slice(0, -1), logTransacted(otherRelayer, MERCHANT, 10_010_000n, FEE)]);
  await expectOnly(pay.pkg, r3, ["intent", "payout"]);
  const r4 = new MockReader();
  r4.add(PAY_TX, 100, pay.logs.filter((l) => !(l.address === USDC.toLowerCase() && l.data.endsWith((10_000_000n).toString(16)))));
  await expectOnly(pay.pkg, r4, ["payout"]);
});
await test("receipt: included after the deadline → time fails", async () => {
  const late = await makeSpend({ ghost: false, txHash: txHashOf(0xb1), amount: 1_000_000n, sumIn: 2_000_000n, deadline: BLOCK_TIME - 1, leaf0: 10 });
  const r = new MockReader();
  r.add(late.pkg.txHash as Hex, 120, late.logs);
  await expectOnly(late.pkg, r, ["time"]);
});
await test("receipt: wrong network / RPC unreachable are reported as such", async () => {
  const wrong = await expectOnly(pay.pkg, Object.assign(new MockReader(1), { receipts: reader.receipts, blocks: reader.blocks }), ["network"]);
  assert.match(wrong.checks[0]!.summary, /chain 1/);
  const down = await verifyPackage(parsePackage(clone(pay.pkg)), new MockReader(CHAIN_ID, true));
  assert.equal(down.counts.fail, 0, explain(down));
  assert.ok(down.counts.error >= 5);
  assert.match(down.checks.find((c) => c.id === "transaction")!.summary, /Could not verify — RPC unreachable/);
  assert.match(down.headline, /Could not finish/);
});
await test("receipt: malformed packages are rejected with readable errors", () => {
  assert.throws(() => parsePackage({ kind: "ghost-receipt", version: 2 }), /version/);
  const p = clone(pay.pkg) as unknown as Record<string, unknown>;
  p.nullifiers = ["1"];
  assert.throws(() => parsePackage(p), /nullifiers/);
  assert.throws(() => parsePackage({ kind: "nope" }), /Unknown package kind/);
});

// Report: one deposit note (leaf 3) and the change note of the public payment above.
const depositAmount = 15_010_000n, depositLabel = randomField(), depositBlinding = randomField();
const depositCommitment = commitmentOf({ asset: ASSET, amount: depositAmount, ownerTag: payer.ownerTag, blinding: depositBlinding, label: depositLabel });
reader.add(DEP_TX, 90, [
  logCommitment(depositCommitment, 3, encryptNote(payer.viewPub, depositAmount, depositBlinding, 0n)),
  logDeposited(payerAccount.address, depositCommitment, depositLabel, depositAmount, 3),
], "0x1", BLOCK_TIME - 3600);
const report: ReportPackage = {
  kind: "ghost-report", version: 1, chainId: CHAIN_ID, pool: POOL, token: USDC, walletAddress: payerAccount.address,
  pubKey: `0x${Buffer.from(payerPub).toString("hex")}`, nkHash: H1(payer.nk).toString(), ownerTag: payer.ownerTag.toString(),
  period: { from: "2026-10-01T00:00:00Z", to: "2026-10-31T23:59:59Z" },
  notes: [
    { leafIndex: 3, txHash: DEP_TX, commitment: depositCommitment.toString(), amount: depositAmount.toString(), blinding: depositBlinding.toString(),
      label: depositLabel.toString(), source: "deposit", time: BLOCK_TIME - 3600 },
    { leafIndex: pay.change.leafIndex, txHash: PAY_TX, commitment: pay.change.commitment.toString(), amount: pay.change.amount.toString(),
      blinding: pay.change.blinding.toString(), label: pay.change.label.toString(), source: "transfer", time: BLOCK_TIME,
      memo: { kind: "change", counterparty: "Acme Coffee", amount: "10000000", fee: "10000", time: BLOCK_TIME, host: "acme.example" } },
  ],
};
const n0id = (r: Verification) => r.checks.filter((c) => c.id.startsWith("note-")).map((c) => c.id);

await test("report: every item passes, totals per source", async () => {
  const r = await expectOnly(report, reader, []);
  for (const id of ["network", "pool", "token", "owner"]) assert.equal(status(r, id), "pass", id);
  assert.equal(n0id(r).length, 2);
  const totals = r.checks.find((c) => c.id === "totals")!;
  assert.match(totals.summary, /20\.01 USDC in 2 note\(s\): deposits 15\.01, transfers and change 5\.00/);
  assert.match(r.headline, /2 verified shielded note\(s\) totalling 20\.01 USDC belong to PayBox wallet/);
  assert.match(r.scope ?? "", /proves only the listed notes in the stated period/);
  assert.ok(r.checks.find((c) => c.id === n0id(r)[0])!.details.some((d) => d.label === "Depositor" && d.value.includes("(this wallet)")));
  assert.ok(r.checks.find((c) => c.id === n0id(r)[1])!.details.some((d) => d.label.startsWith("memo.counterparty")));
});
await test("report: 0x04-prefixed pubKey is accepted", async () => {
  const p = clone(report); p.pubKey = `0x04${p.pubKey.slice(2)}`;
  await expectOnly(p, reader, []);
});
await test("report tamper: note amount → that note fails", async () => {
  const p = clone(report); p.notes[0]!.amount = "25000000";
  const r = await verifyPackage(parsePackage(p), reader);
  assert.deepEqual(failing(r), [n0id(r)[0]!], explain(r));
});
await test("report tamper: blinding / label / leafIndex → that note fails", async () => {
  for (const mutate of [
    (p: ReportPackage) => (p.notes[1]!.blinding = (BigInt(p.notes[1]!.blinding) + 1n).toString()),
    (p: ReportPackage) => (p.notes[0]!.label = (BigInt(p.notes[0]!.label) + 1n).toString()),
    (p: ReportPackage) => (p.notes[1]!.leafIndex += 1),
  ]) {
    const p = clone(report); mutate(p);
    const r = await verifyPackage(parsePackage(p), reader);
    assert.equal(failing(r).length, 1, explain(r));
    assert.ok(failing(r)[0]!.startsWith("note-"), explain(r));
  }
});
await test("report tamper: walletAddress → owner binding fails", async () => {
  const p = clone(report); p.walletAddress = friendAccount.address;
  await expectOnly(p, reader, ["owner"]);
});
await test("report tamper: ownerTag → owner binding and every note fail", async () => {
  const p = clone(report); p.ownerTag = friend.ownerTag.toString();
  const r = await verifyPackage(parsePackage(p), reader);
  assert.deepEqual(failing(r), ["owner", ...n0id(r)].sort(), explain(r));
});
await test("report tamper: nkHash → owner binding fails", async () => {
  const p = clone(report); p.nkHash = (BigInt(p.nkHash) + 1n).toString();
  await expectOnly(p, reader, ["owner"]);
});
await test("report tamper: period excluding the notes → notes fail", async () => {
  const p = clone(report); p.period = { from: "2026-11-01T00:00:00Z", to: "2026-11-30T00:00:00Z" };
  const r = await verifyPackage(parsePackage(p), reader);
  assert.deepEqual(failing(r), n0id(r).sort(), explain(r));
  assert.match(r.checks.find((c) => c.id === n0id(r)[0])!.summary, /outside the stated period/);
});
await test("report tamper: deposit source on a transfer note → note fails", async () => {
  const p = clone(report); p.notes[1]!.source = "deposit";
  const r = await verifyPackage(parsePackage(p), reader);
  assert.deepEqual(failing(r), [n0id(r)[1]!], explain(r));
});

// --- JSON-RPC reader --------------------------------------------------------------------------
await test("rpc: falls back to the second endpoint and de-duplicates requests", async () => {
  const calls: string[] = [];
  const fakeFetch = async (url: string, init: { body: string }) => {
    calls.push(url);
    const { id, method } = JSON.parse(init.body);
    if (url.includes("primary")) return { ok: false, status: 503, json: async () => ({}) };
    const result = method === "eth_chainId" ? "0x2105" : method === "eth_getTransactionReceipt" ? { status: "0x1", blockNumber: "0x1", transactionHash: PAY_TX, logs: [] } : null;
    return { ok: true, status: 200, json: async () => ({ jsonrpc: "2.0", id, result }) };
  };
  const r = new JsonRpcReader(["https://primary.example", "https://fallback.example"], { fetch: fakeFetch, minIntervalMs: 0 });
  assert.equal(await r.chainId(), 8453);
  assert.equal(r.describe(), "https://fallback.example");
  const [a, b] = await Promise.all([r.getReceipt(PAY_TX), r.getReceipt(PAY_TX)]);
  assert.equal(a!.transactionHash, PAY_TX);
  assert.deepEqual(a, b);
  assert.deepEqual(calls, ["https://primary.example", "https://fallback.example", "https://fallback.example"]);
});
await test("rpc: all endpoints down → RpcUnavailableError naming each host", async () => {
  const r = new JsonRpcReader(["https://a.example", "https://b.example"], {
    fetch: async () => { throw new TypeError("Failed to fetch"); }, minIntervalMs: 0,
  });
  await assert.rejects(r.chainId(), (e: unknown) => e instanceof RpcUnavailableError && /a\.example: network error.*b\.example: network error/.test(e.message));
});

// --- built page --------------------------------------------------------------------------------
await test("built page is self-contained and CSP-pinned", () => {
  if (!existsSync(VERIFY_PAGE_FILE)) throw new Error("dist/verify.html missing: run npx tsx src/verify/build.ts first");
  const html = verifyPageHtml();
  assert.ok(html.includes("<title>Ghost Mode Verify</title>"));
  assert.match(html, /script-src 'sha256-[A-Za-z0-9+/=]+'/);
  assert.ok(!/<(script|link|img|iframe)[^>]+(src|href)=/i.test(html), "external resource reference");
  assert.ok(!html.includes("__GHOST_VERIFY"), "placeholder left in page");
  assert.equal(verifyPageHtml(), html, "cached");
  assert.match(verifyPageCsp(), /^default-src 'none'; script-src 'sha256-/);
});

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} passed`);
process.exit(failed.length ? 1 : 0);
