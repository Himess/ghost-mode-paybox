// x402 unit tests: header encoding (v1/v2), PAYMENT-RESPONSE parsing, requote mismatch logic, SSRF guards.
// Uses a throwaway relayer key and mocked fetch/DNS/token domain; the only live call is an UNPAID GET
// to a public 402 endpoint (parsing check). Never makes a real payment.
//   npx tsx test/x402.ts
import assert from "node:assert/strict";
import { recoverTypedDataAddress, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const testKey = generatePrivateKey();
process.env.RELAYER_PRIVATE_KEY = testKey; // never the production relayer
process.env.RPC_URL ??= "https://mainnet.base.org,https://base-rpc.publicnode.com";
process.env.POOL_ADDRESS ??= "0x1882d5b6910c418c79ee6997179d473bc884693d";
const x = await import("../src/x402.js");
const { config } = await import("../src/config.js");

const USDC = config.token;
const PAY_TO = "0x1111111111111111111111111111111111111111";
const real = { ...x.x402Deps };
let passed = 0;
async function test(name: string, fn: () => unknown) {
  try {
    await fn();
    passed++;
    console.log(`ok   ${name}`);
  } catch (err) {
    console.log(`FAIL ${name}\n     ${(err as Error).message}`);
    process.exitCode = 1;
  } finally {
    Object.assign(x.x402Deps, real);
  }
}
const decode = (v: string) => JSON.parse(Buffer.from(v, "base64").toString("utf8"));
const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64");

const requirement = (over: Record<string, unknown> = {}) => ({
  scheme: "exact", network: "eip155:8453", asset: USDC, payTo: PAY_TO, amount: "2000", maxTimeoutSeconds: 60,
  extra: { name: "USD Coin", version: "2" }, ...over,
});
const resource = { url: "https://merchant.example.com/data", description: "test", mimeType: "application/json" };

/** Mock merchant: answers 402 (v2 header) until paid, then `paid` response. Records request headers. */
function mockMerchant(opts: { amount?: string; payTo?: string; status?: number; v1?: boolean; paidStatus?: number; paidHeaders?: Record<string, string> } = {}) {
  const seen: Record<string, string>[] = [];
  x.x402Deps.lookup = async () => ["93.184.215.14"];
  x.x402Deps.tokenDomain = async () => ({ name: "USD Coin", version: "2" });
  x.x402Deps.fetch = async (_url: string, init?: RequestInit) => {
    const headers = (init?.headers ?? {}) as Record<string, string>;
    seen.push(headers);
    if (headers["PAYMENT-SIGNATURE"] || headers["X-PAYMENT"]) {
      return new Response(JSON.stringify({ ok: true }), { status: opts.paidStatus ?? 200, headers: { "content-type": "application/json", ...(opts.paidHeaders ?? {}) } });
    }
    if (opts.status && opts.status !== 402) return new Response("free", { status: opts.status });
    const req = requirement({ amount: opts.amount ?? "2000", payTo: opts.payTo ?? PAY_TO });
    if (opts.v1) {
      const { amount, ...rest } = req;
      return new Response(JSON.stringify({ x402Version: 1, accepts: [{ ...rest, network: "base", maxAmountRequired: amount }] }), { status: 402, headers: { "content-type": "application/json" } });
    }
    return new Response("{}", { status: 402, headers: { "payment-required": b64({ x402Version: 2, resource, accepts: [requirement({ network: "solana" }), req] }) } });
  };
  return seen;
}
const REQ = { url: "https://merchant.example.com/data", method: "GET" as const };

await test("v2 quote parses PAYMENT-REQUIRED and picks the Base USDC requirement", async () => {
  mockMerchant();
  const q = await x.quoteX402(REQ);
  assert.ok(!("free" in q));
  assert.equal(q.version, 2);
  assert.equal(q.price, 2000n);
  assert.equal(q.payTo.toLowerCase(), PAY_TO);
  assert.equal(q.requirement.network, "eip155:8453");
  assert.deepEqual(q.resource, resource);
});

await test("v1 quote parses the JSON accepts body", async () => {
  mockMerchant({ v1: true });
  const q = await x.quoteX402(REQ);
  assert.ok(!("free" in q));
  assert.equal(q.version, 1);
  assert.equal(q.price, 2000n);
});

await test("v2 header: PAYMENT-SIGNATURE = {x402Version 2, resource, accepted verbatim, payload}", async () => {
  const seen = mockMerchant({ paidHeaders: { "payment-response": b64({ success: true, transaction: `0x${"ab".repeat(32)}`, network: "eip155:8453", payer: "0x0" }) } });
  const q = await x.quoteX402(REQ);
  assert.ok(!("free" in q));
  const paid = await x.payX402(REQ, q);
  assert.equal(paid.status, 200);
  const header = seen.at(-1)!["PAYMENT-SIGNATURE"]!;
  assert.ok(header, "PAYMENT-SIGNATURE header sent");
  assert.equal(seen.at(-1)!["X-PAYMENT"], undefined);
  const doc = decode(header);
  assert.deepEqual(Object.keys(doc).sort(), ["accepted", "payload", "resource", "x402Version"]);
  assert.equal(doc.x402Version, 2);
  assert.deepEqual(doc.accepted, q.requirement);
  assert.deepEqual(doc.resource, resource);
  const a = doc.payload.authorization;
  assert.deepEqual(Object.keys(a).sort(), ["from", "nonce", "to", "validAfter", "validBefore", "value"]);
  assert.equal(a.from, privateKeyToAccount(testKey).address);
  assert.equal(a.to.toLowerCase(), PAY_TO);
  assert.equal(a.value, "2000");
  assert.match(a.nonce, /^0x[0-9a-f]{64}$/);
  for (const k of ["value", "validAfter", "validBefore"]) assert.equal(typeof a[k], "string");
  assert.ok(Number(a.validBefore) - Number(a.validAfter) <= 600 + 60 + 5);
  const signer = await recoverTypedDataAddress({
    domain: { name: "USD Coin", version: "2", chainId: 8453, verifyingContract: USDC },
    types: { TransferWithAuthorization: [
      { name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" },
      { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" },
    ] },
    primaryType: "TransferWithAuthorization",
    message: { ...a, value: BigInt(a.value), validAfter: BigInt(a.validAfter), validBefore: BigInt(a.validBefore) },
    signature: doc.payload.signature as Hex,
  });
  assert.equal(signer, privateKeyToAccount(testKey).address, "EIP-3009 signature recovers to the relayer");
  assert.equal(paid.settlementTx, `0x${"ab".repeat(32)}`);
  assert.equal(paid.settlement?.success, true);
  assert.equal(paid.nonce, a.nonce);
});

await test("v1 header: X-PAYMENT = {x402Version 1, scheme exact, network base, payload}", async () => {
  const seen = mockMerchant({ v1: true, paidHeaders: { "x-payment-response": b64({ success: true, txHash: `0x${"cd".repeat(32)}` }) } });
  const q = await x.quoteX402(REQ);
  assert.ok(!("free" in q));
  const paid = await x.payX402(REQ, q);
  const header = seen.at(-1)!["X-PAYMENT"]!;
  assert.ok(header, "X-PAYMENT header sent");
  assert.equal(seen.at(-1)!["PAYMENT-SIGNATURE"], undefined);
  const doc = decode(header);
  assert.deepEqual(Object.keys(doc).sort(), ["network", "payload", "scheme", "x402Version"]);
  assert.equal(doc.x402Version, 1);
  assert.equal(doc.scheme, "exact");
  assert.equal(doc.network, "base");
  assert.equal(doc.payload.authorization.value, "2000");
  assert.equal(paid.settlementTx, `0x${"cd".repeat(32)}`);
});

await test("encodePaymentHeader round-trips both versions", () => {
  const payload = { signature: "0x01" as Hex, authorization: { from: PAY_TO as Hex, to: PAY_TO as Hex, value: "1", validAfter: "0", validBefore: "9", nonce: `0x${"00".repeat(32)}` as Hex } };
  const q2 = { version: 2, requirement: requirement(), price: 2000n, resource, payTo: PAY_TO as Hex };
  const h2 = x.encodePaymentHeader(q2, payload);
  assert.equal(h2.name, "PAYMENT-SIGNATURE");
  assert.deepEqual(decode(h2.value), { x402Version: 2, resource, accepted: requirement(), payload });
  const h1 = x.encodePaymentHeader({ ...q2, version: 1 }, payload);
  assert.equal(h1.name, "X-PAYMENT");
  assert.deepEqual(decode(h1.value), { x402Version: 1, scheme: "exact", network: "base", payload });
});

await test("parsePaymentResponse: transaction / txHash / garbage", () => {
  const tx = `0x${"12".repeat(32)}`;
  assert.equal(x.parsePaymentResponse(b64({ success: true, transaction: tx, network: "eip155:8453" })).settlementTx, tx);
  assert.equal(x.parsePaymentResponse(b64({ success: true, txHash: tx })).settlementTx, tx);
  const failed = x.parsePaymentResponse(b64({ success: false, errorReason: "insufficient_funds", transaction: "" }));
  assert.equal(failed.settlementTx, undefined);
  assert.equal(failed.settlement?.success, false);
  assert.equal(failed.settlement?.errorReason, "insufficient_funds");
  assert.deepEqual(x.parsePaymentResponse("not base64 json"), {});
  assert.deepEqual(x.parsePaymentResponse(undefined), {});
});

await test("requote: unchanged terms pass and return the fresh quote", async () => {
  mockMerchant();
  const stored = await x.quoteX402(REQ);
  assert.ok(!("free" in stored));
  const r = await x.requote(REQ, stored);
  assert.ok("quote" in r, JSON.stringify(r, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));
  assert.equal(r.quote.price, 2000n);
});

await test("requote: price change, payTo change, no-402, and endpoint errors all block transact", async () => {
  mockMerchant();
  const stored = await x.quoteX402(REQ);
  assert.ok(!("free" in stored));
  mockMerchant({ amount: "3000" });
  let r = await x.requote(REQ, stored);
  assert.ok("mismatch" in r && /price changed from 2000 to 3000/.test(r.mismatch));
  mockMerchant({ payTo: "0x2222222222222222222222222222222222222222" });
  r = await x.requote(REQ, stored);
  assert.ok("mismatch" in r && /payee changed/.test(r.mismatch));
  mockMerchant({ status: 200 });
  r = await x.requote(REQ, stored);
  assert.ok("mismatch" in r && /no longer asks for payment \(HTTP 200\)/.test(r.mismatch));
  mockMerchant();
  x.x402Deps.fetch = async () => { throw new Error("connect ETIMEDOUT"); };
  r = await x.requote(REQ, stored);
  assert.ok("mismatch" in r && /Could not re-quote/.test(r.mismatch));
  assert.equal(x.requoteMismatch(stored, { ...stored }), undefined);
});

await test("quote rejects an EIP-712 domain that differs from the token's", async () => {
  mockMerchant();
  x.x402Deps.tokenDomain = async () => ({ name: "USDC", version: "2" });
  await assert.rejects(() => x.quoteX402(REQ), /EIP-712 domain/);
});

await test("quote rejects an OFAC-sanctioned payee", async () => {
  mockMerchant({ payTo: "0x0330070FD38Ec3bB94F58FA55D40368271E9e54A" });
  await assert.rejects(() => x.quoteX402(REQ), /OFAC/);
});

await test("SSRF guards: private literals, private DNS answers, redirects", async () => {
  for (const ip of ["127.0.0.1", "10.1.2.3", "172.20.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "::ffff:7f00:1"]) {
    assert.equal(x.isPrivateAddress(ip), true, ip);
  }
  for (const ip of ["93.184.215.14", "1.1.1.1", "2606:4700:4700::1111"]) assert.equal(x.isPrivateAddress(ip), false, ip);
  assert.throws(() => x.assertPublicUrl("http://merchant.example.com/"), /HTTPS/);
  assert.throws(() => x.assertPublicUrl("https://127.0.0.1/"), /public hostname/);
  assert.throws(() => x.assertPublicUrl("https://localhost/"), /public hostname/);
  x.x402Deps.lookup = async () => ["93.184.215.14", "10.0.0.7"];
  await assert.rejects(() => x.assertPublicHost("https://rebind.example.com/"), /private or reserved/);
  mockMerchant();
  x.x402Deps.fetch = async () => new Response(null, { status: 302, headers: { location: "http://169.254.169.254/" } });
  await assert.rejects(() => x.quoteX402(REQ), /redirected/);
});

// Live, unpaid: Blockscout's x402-gated stats endpoint answers 402 with a base64 payment-required header.
await test("live (unpaid): api.blockscout.com 402 parses to 2000 atomic USDC on eip155:8453", async () => {
  let q;
  try {
    q = await x.quoteX402({ url: "https://api.blockscout.com/8453/api/v2/stats", method: "GET" });
  } catch (err) {
    if (/fetch failed|ETIMEDOUT|ENOTFOUND|aborted|timeout|resolve/i.test((err as Error).message)) {
      console.log(`     SKIP (network): ${(err as Error).message.split("\n")[0]}`);
      return;
    }
    throw err;
  }
  if ("free" in q) { console.log(`     NOTE endpoint answered HTTP ${q.status} without 402`); return; }
  assert.equal(q.version, 2);
  assert.equal(q.price, 2000n);
  assert.equal(q.requirement.network, "eip155:8453");
  assert.deepEqual(q.requirement.extra, { name: "USD Coin", version: "2" });
  console.log(`     live quote: v${q.version} price=${q.price} payTo=${q.payTo} (on-chain USDC domain matched)`);
});

console.log(`${passed} passed${process.exitCode ? ", some FAILED" : ""}`);
