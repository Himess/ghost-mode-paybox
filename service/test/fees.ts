// Relayer fee tests: fee math (ceil, 1.2 margin, floor), the 80% acceptance window, and a live read of the
// verified Chainlink ETH/USD feed on Base (read-only).
//   npx tsx test/fees.ts
import assert from "node:assert/strict";

process.env.RPC_URL ??= "https://mainnet.base.org,https://base-rpc.publicnode.com";
process.env.RELAYER_PRIVATE_KEY = ""; // read-only: no relayer needed
const f = await import("../src/fees.js");

let passed = 0;
async function test(name: string, fn: () => unknown) {
  try {
    await fn();
    passed++;
    console.log(`ok   ${name}`);
  } catch (err) {
    console.log(`FAIL ${name}\n     ${(err as Error).message}`);
    process.exitCode = 1;
  }
}

await test("transact fee = ceil(5.4M gas x 0.005 gwei x $2500 x 1.2) = 0.081 USDC", () => {
  assert.equal(f.feeFor(f.GAS_UNITS.transact, 5_000_000n, 2500n * 10n ** 8n, 8), 81_000n);
});

await test("shield fee uses 900k gas and hits the 0.01 USDC floor at low gas", () => {
  // 900k x 0.005 gwei x $2500 x 1.2 = 0.0135 USDC
  assert.equal(f.feeFor(f.GAS_UNITS.shield, 5_000_000n, 2500n * 10n ** 8n, 8), 13_500n);
  assert.equal(f.feeFor(f.GAS_UNITS.shield, 1_000_000n, 2500n * 10n ** 8n, 8), 10_000n);
  assert.equal(f.FEE_FLOOR, 10_000n);
});

await test("fee rounds up to the next atomic unit", () => {
  // 5.4M x 1_000_001 wei x $3000.12345678 x 1.2 = 19_440.82 -> 19_441 (above floor)
  assert.equal(f.feeFor(f.GAS_UNITS.transact, 1_000_001n, 300_012_345_678n, 8), 19_441n);
  assert.equal(f.feeFor(1n, 1n, 1n, 8, 0n), 1n);
});

await test("signed fee accepted from 80% of the current fee", () => {
  const fees = { transact: 100_000n, shield: 20_000n, ethUsd: 2500, gasPriceWei: 1n, updatedAt: Date.now() };
  assert.equal(f.feeAcceptable(80_000n, "transact", fees), true);
  assert.equal(f.feeAcceptable(79_999n, "transact", fees), false);
  assert.equal(f.feeAcceptable(16_000n, "shield", fees), true);
  assert.equal(f.feeAcceptable(15_999n, "shield", fees), false);
});

await test("before any update the fees sit at the floor", () => {
  const fees = f.relayerFees();
  assert.equal(fees.transact, 10_000n);
  assert.equal(fees.shield, 10_000n);
});

await test("live: Chainlink ETH/USD feed on Base verifies and yields fees >= floor", async () => {
  const fees = await f.updateFees();
  if (fees.updatedAt === 0) { console.log("     SKIP (feed/RPC unreachable; floor kept)"); return; }
  assert.ok(fees.ethUsd > 100 && fees.ethUsd < 100_000, `ethUsd ${fees.ethUsd}`);
  assert.ok(fees.transact >= 10_000n && fees.shield >= 10_000n);
  assert.ok(fees.transact >= fees.shield);
  assert.equal(f.relayerFees().transact, fees.transact);
  const { config } = await import("../src/config.js");
  assert.equal(config.relayerFee, fees.transact, "config.relayerFee follows the live transact fee");
  console.log(`     live: ETH/USD=${fees.ethUsd} gasPrice=${fees.gasPriceWei} wei transact=${fees.transact} shield=${fees.shield}`);
});

console.log(`${passed} passed${process.exitCode ? ", some FAILED" : ""}`);
