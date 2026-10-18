// Relay-delay tests (offline): delaySeconds validation, scheduledFor sampling, stale-root refresh with the real
// Merkle primitives, prepare -> submit -> "scheduled" -> persisted -> restart re-arm, and restart handling.
// No RPC (RPC_URL points at a closed local port), no proving, throwaway relayer key and temp state file.
//   npx tsx test/delay.ts
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const dir = mkdtempSync(join(tmpdir(), "ghost-delay-test-"));
const POOL = "0x000000000000000000000000000000000000dEaD" as Hex;
process.env.STATE_FILE = join(dir, "state.json"); // never the production data/state.json
process.env.RELAYER_PRIVATE_KEY = generatePrivateKey(); // never the production relayer
process.env.RPC_URL = "http://127.0.0.1:9"; // nothing listens there: an accidental RPC call fails fast
process.env.CHAIN_ID = "31337";
process.env.POOL_ADDRESS = POOL;
process.env.RELAYER_FEE = "10000";

const j = await import("../src/jobs.js");
const store = await import("../src/store.js");
const P = await import("../../plugin/src/core/primitives.js");

let passed = 0;
async function test(name: string, fn: () => unknown) {
  try {
    await fn();
    passed++;
    console.log(`ok   ${name}`);
  } catch (err) {
    console.log(`FAIL ${name}\n     ${(err as Error).stack?.split("\n").slice(0, 3).join("\n     ")}`);
    process.exitCode = 1;
  }
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v));

// ---------------------------------------------------------------------------------------------
// 1. Validation
// ---------------------------------------------------------------------------------------------
const NOW = 1_800_000_000;
const pkgOf = (kind: string, deadline: number | string) => ({ kind, tx: { deadline: String(deadline) } });

await test("no delay: absent, null and 0 are accepted for every kind", () => {
  for (const kind of ["unshield", "pay_address", "send_ghost", "pay_x402"]) {
    for (const raw of [undefined, null, 0]) assert.equal(j.validateDelay(pkgOf(kind, NOW + 120), raw, NOW), 0);
  }
});

await test("bounds: delaySeconds must be an integer from 0 to 1800", () => {
  const ok = pkgOf("unshield", NOW + 1800 + 600);
  assert.equal(j.validateDelay(ok, 1, NOW), 1);
  assert.equal(j.validateDelay(ok, 1800, NOW), 1800);
  for (const bad of [-1, 1801, 1.5, Number.NaN, Number.POSITIVE_INFINITY, "60", true, {}, [60]]) {
    assert.throws(() => j.validateDelay(ok, bad, NOW), /integer from 0 to 1800/, `accepted ${JSON.stringify(bad)}`);
  }
});

await test("kinds: only unshield and pay_address may be delayed", () => {
  const d = NOW + 3600;
  assert.equal(j.validateDelay(pkgOf("unshield", d), 60, NOW), 60);
  assert.equal(j.validateDelay(pkgOf("pay_address", d), 60, NOW), 60);
  assert.throws(() => j.validateDelay(pkgOf("pay_x402", d), 60, NOW), /pay_x402: x402 payments must be paid immediately/);
  assert.throws(() => j.validateDelay(pkgOf("send_ghost", d), 60, NOW), /send_ghost: ghost transfers are already private/);
  assert.throws(() => j.validateDelay(pkgOf("mystery", d), 60, NOW), /only supported for unshield and pay_address/);
  assert.throws(() => j.validateDelay(undefined, 60, NOW), /only supported for unshield and pay_address/);
});

await test("deadline margin: package.tx.deadline >= now + delaySeconds + 600", () => {
  assert.equal(j.validateDelay(pkgOf("unshield", NOW + 300 + 600), 300, NOW), 300);
  assert.equal(j.validateDelay(pkgOf("pay_address", NOW + 1800 + 600), 1800, NOW), 1800);
  assert.throws(() => j.validateDelay(pkgOf("unshield", NOW + 300 + 599), 300, NOW), /deadline too short for the requested delay/);
  assert.throws(() => j.validateDelay(pkgOf("pay_address", NOW + 1800 + 599), 1800, NOW), /deadline too short for the requested delay/);
  assert.throws(() => j.validateDelay(pkgOf("unshield", "soon"), 10, NOW), /deadline too short for the requested delay/);
});

// ---------------------------------------------------------------------------------------------
// 2. scheduledFor sampling
// ---------------------------------------------------------------------------------------------
await test("pickScheduledFor: endpoints with a stub RNG, and crypto.randomInt stays in [now, now + delay] whole seconds", () => {
  const t = 1_700_000_000_123;
  assert.equal(j.pickScheduledFor(30, t, () => 0), t);
  assert.equal(j.pickScheduledFor(30, t, (_min, max) => max - 1), t + 30_000);
  assert.equal(j.pickScheduledFor(0, t), t);
  const seen = new Set<number>();
  for (let i = 0; i < 3000; i++) {
    const at = j.pickScheduledFor(5, t);
    assert.ok(at >= t && at <= t + 5000 && (at - t) % 1000 === 0, `out of range: ${at - t}`);
    seen.add(at - t);
  }
  assert.equal(seen.size, 6, "every second of a 5 s window (both ends included) should be drawn");
});

// ---------------------------------------------------------------------------------------------
// 3. Fresh roots at send time (synthetic indexer state built with the real primitives)
// ---------------------------------------------------------------------------------------------
const asset = BigInt("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
const ownerTag = P.randomField();
const notes = Array.from({ length: 9 }, (_, i) => ({ asset, amount: BigInt(1_000 + i), ownerTag, blinding: P.randomField(), label: BigInt(100 + (i % 3)) }));
const commitments = notes.map((n) => P.commitmentOf(n));
const OLD_LEAVES = 5; // the package was built when the tree had 5 leaves ...
const oldTree = new P.MerkleTree(P.TREE_DEPTH, commitments.slice(0, OLD_LEAVES));
const newTree = new P.MerkleTree(P.TREE_DEPTH, commitments); // ... and 4 more were added during the delay
const oldAspLabels = [99n, 100n, 101n]; // label 101 at index 2
const newAspLabels = [100n, 101n, 102n, 103n]; // 99 was dropped from the set: label 101 moved to index 1
const oldAsp = new P.MerkleTree(P.ASP_DEPTH, oldAspLabels);
const newAsp = new P.MerkleTree(P.ASP_DEPTH, newAspLabels);
const zeroPath = (depth: number) => Array.from({ length: depth }, (_, i) => String(P.zeroAt(i)));

/** Independent Merkle check: hash `leaf` up `path` at `index`. */
function rootFromPath(leaf: bigint, index: number, path: string[]): bigint {
  return path.reduce((node, sib, level) => ((index >> level) & 1 ? P.H2(BigInt(sib), node) : P.H2(node, BigInt(sib))), leaf);
}

/** A stale package spending leaf 1 (+ leaf 4 when `twoInputs`, else a dummy), both label 101. */
function stalePackage(twoInputs = false) {
  const live = (leaf: number) => ({ amount: String(notes[leaf]!.amount), label: "101", index: String(leaf), path: oldTree.path(leaf).map(String), aspIndex: "2", aspPath: oldAsp.path(2).map(String) });
  const dummy = { amount: "0", label: "101", index: "0", path: zeroPath(P.TREE_DEPTH), aspIndex: "0", aspPath: zeroPath(P.ASP_DEPTH) };
  const ins = [live(1), twoInputs ? live(4) : dummy];
  return {
    circuitInputs: {
      root: String(oldTree.root), asp_root: String(oldAsp.root),
      nullifiers: ["11", "22"], out_commitments: ["33", "44"],
      in_amounts: ins.map((i) => i.amount), in_labels: ins.map((i) => i.label), in_indices: ins.map((i) => i.index),
      in_paths: ins.map((i) => i.path), asp_indices: ins.map((i) => i.aspIndex), asp_paths: ins.map((i) => i.aspPath),
    },
    tx: { root: String(oldTree.root), aspRoot: String(oldAsp.root), nullifiers: ["11", "22"] },
  };
}

/** Fake chain + indexer: the indexer only learns the new leaves / ASP set when sync(true) runs. */
function fakeChain(known: { roots: bigint[]; asp: bigint[] }, opts: { leaves?: bigint[]; labels?: bigint[]; failCheck?: boolean } = {}) {
  const calls = { sync: 0, rootChecks: [] as bigint[], aspChecks: [] as bigint[] };
  const st = { leaves: commitments.slice(0, OLD_LEAVES).map((commitment) => ({ commitment })), publishedAsp: { labels: oldAspLabels } };
  const deps = {
    state: st,
    isKnownRoot: async (r: bigint) => { if (opts.failCheck) throw new Error("fetch failed: http://127.0.0.1:9/secret-key"); calls.rootChecks.push(r); return known.roots.includes(r); },
    isKnownAspRoot: async (r: bigint) => { if (opts.failCheck) throw new Error("fetch failed"); calls.aspChecks.push(r); return known.asp.includes(r); },
    sync: async (force: boolean) => {
      assert.equal(force, true, "the job must force a sync");
      calls.sync++;
      st.leaves = (opts.leaves ?? commitments).map((commitment) => ({ commitment }));
      st.publishedAsp = { labels: opts.labels ?? newAspLabels };
    },
  };
  return { deps, calls };
}

await test("roots still known: no sync, package untouched", async () => {
  const pkg = stalePackage();
  const before = clone(pkg);
  const { deps, calls } = fakeChain({ roots: [oldTree.root, newTree.root], asp: [oldAsp.root, newAsp.root] });
  assert.deepEqual(await j.ensureFreshRoots(pkg, deps), { root: false, aspRoot: false });
  assert.equal(calls.sync, 0);
  assert.deepEqual(pkg, before);
});

await test("both roots stale: sync(true), then root/in_paths/asp_* rebuilt from the indexer; dummy input untouched", async () => {
  const pkg = stalePackage();
  const before = clone(pkg);
  const { deps, calls } = fakeChain({ roots: [newTree.root], asp: [newAsp.root] }); // old roots fell out of the histories
  assert.deepEqual(await j.ensureFreshRoots(pkg, deps), { root: true, aspRoot: true });
  assert.equal(calls.sync, 1);
  const ci = pkg.circuitInputs;
  assert.equal(ci.root, String(newTree.root));
  assert.equal(pkg.tx.root, String(newTree.root));
  assert.deepEqual(ci.in_paths[0], newTree.path(1).map(String));
  assert.equal(rootFromPath(commitments[1]!, 1, ci.in_paths[0]!), newTree.root);
  assert.equal(ci.asp_root, String(newAsp.root));
  assert.equal(pkg.tx.aspRoot, String(newAsp.root));
  assert.equal(ci.asp_indices[0], "1");
  assert.deepEqual(ci.asp_paths[0], newAsp.path(1).map(String));
  assert.equal(rootFromPath(101n, 1, ci.asp_paths[0]!), newAsp.root);
  // Dummy input and everything the signature binds are unchanged.
  assert.deepEqual(ci.in_paths[1], before.circuitInputs.in_paths[1]);
  assert.equal(ci.asp_indices[1], before.circuitInputs.asp_indices[1]);
  assert.deepEqual(ci.asp_paths[1], before.circuitInputs.asp_paths[1]);
  for (const k of ["nullifiers", "out_commitments", "in_amounts", "in_labels", "in_indices"] as const) assert.deepEqual(ci[k], before.circuitInputs[k]);
  assert.deepEqual(pkg.tx.nullifiers, before.tx.nullifiers);
  // The rebuilt roots were re-checked against the pool before proving.
  assert.ok(calls.rootChecks.includes(newTree.root) && calls.aspChecks.includes(newAsp.root));
});

await test("two live inputs: both Merkle and ASP paths rebuilt", async () => {
  const pkg = stalePackage(true);
  const { deps } = fakeChain({ roots: [newTree.root], asp: [newAsp.root] });
  await j.ensureFreshRoots(pkg, deps);
  const ci = pkg.circuitInputs;
  for (const [i, leaf] of [[0, 1], [1, 4]] as const) {
    assert.deepEqual(ci.in_paths[i], newTree.path(leaf).map(String));
    assert.equal(rootFromPath(commitments[leaf]!, leaf, ci.in_paths[i]!), newTree.root);
    assert.equal(ci.asp_indices[i], "1");
    assert.deepEqual(ci.asp_paths[i], newAsp.path(1).map(String));
  }
});

await test("only the ASP root stale: Merkle witness kept, ASP witness rebuilt", async () => {
  const pkg = stalePackage();
  const before = clone(pkg);
  const { deps } = fakeChain({ roots: [oldTree.root, newTree.root], asp: [newAsp.root] });
  assert.deepEqual(await j.ensureFreshRoots(pkg, deps), { root: false, aspRoot: true });
  assert.equal(pkg.circuitInputs.root, before.circuitInputs.root);
  assert.equal(pkg.tx.root, before.tx.root);
  assert.deepEqual(pkg.circuitInputs.in_paths, before.circuitInputs.in_paths);
  assert.equal(pkg.circuitInputs.asp_root, String(newAsp.root));
});

await test("refresh failures: label left the ASP, indexer leaf mismatch, rebuilt root unknown", async () => {
  const noLabel = fakeChain({ roots: [newTree.root], asp: [] }, { labels: [100n, 102n] });
  await assert.rejects(j.ensureFreshRoots(stalePackage(), noLabel.deps), /no longer in the association set/);
  const forged = commitments.slice();
  forged[1] = P.randomField();
  const mismatch = fakeChain({ roots: [], asp: [newAsp.root] }, { leaves: forged });
  await assert.rejects(j.ensureFreshRoots(stalePackage(), mismatch.deps), /indexer leaf 1 does not match/);
  const behind = fakeChain({ roots: [], asp: [newAsp.root] }); // pool knows neither the old nor the rebuilt root
  await assert.rejects(j.ensureFreshRoots(stalePackage(), behind.deps), /could not rebuild a root the pool knows/);
});

await test("freshness check RPC error: proving continues with the package's roots (previous behaviour)", async () => {
  const pkg = stalePackage();
  const before = clone(pkg);
  const { deps, calls } = fakeChain({ roots: [], asp: [] }, { failCheck: true });
  assert.deepEqual(await j.ensureFreshRoots(pkg, deps), { root: false, aspRoot: false });
  assert.equal(calls.sync, 0);
  assert.deepEqual(pkg, before);
});

// ---------------------------------------------------------------------------------------------
// 4. prepare -> submit -> "scheduled" -> persisted -> restart re-arm (real storePrepared / submit / store)
// ---------------------------------------------------------------------------------------------
const user = privateKeyToAccount(generatePrivateKey());
const relayer = privateKeyToAccount(process.env.RELAYER_PRIVATE_KEY as Hex);
const recipient = privateKeyToAccount(generatePrivateKey()).address;
const NK = "4242424242424242424242424242424242424242"; // stand-in witness secret: must never reach a job or the file in clear

async function signedPackage(kind: string, deadline: number) {
  const primaryType = Object.keys(P.SPEND_TYPES)[0]! as keyof typeof P.SPEND_TYPES;
  const fields = P.SPEND_TYPES[primaryType] as readonly { name: string; type: string }[];
  const message = Object.fromEntries(fields.map((f) => [f.name,
    f.type === "address" ? recipient : f.type === "bytes32" ? P.toHex32(P.randomField()) : f.name === "deadline" ? String(deadline) : "10000"]));
  const domain = P.ghostDomain(31337, POOL);
  const signature = await user.signTypedData({ domain, types: P.SPEND_TYPES, primaryType, message } as never);
  const pkg = {
    version: 1, kind, chainId: 31337, pool: POOL, pubKey: user.publicKey,
    circuitInputs: { ...stalePackage().circuitInputs, nk: NK },
    tx: { ...stalePackage().tx, relayer: relayer.address, fee: "10000", recipient, deadline: String(deadline), publicOut: "20000" },
    typedData: { domain, types: { EIP712Domain: P.EIP712_DOMAIN_TYPE, ...P.SPEND_TYPES }, primaryType, message },
  };
  return { pkg, signature };
}

await test("storePrepared enforces the delay rules", async () => {
  const now = Math.floor(Date.now() / 1000);
  const tooShort = await signedPackage("unshield", now + 900);
  assert.throws(() => j.storePrepared(tooShort.pkg as never, undefined, 600), /deadline too short for the requested delay/);
  const ghost = await signedPackage("send_ghost", now + 7200);
  assert.throws(() => j.storePrepared(ghost.pkg as never, undefined, 60), /send_ghost/);
  assert.throws(() => j.storePrepared(ghost.pkg as never, undefined, 1801), /integer from 0 to 1800/);
});

await test("submit with delaySeconds: job is \"scheduled\" with scheduledFor in [now, now + delay]; persisted; re-armed after restart", async () => {
  const delay = 1800;
  const { pkg, signature } = await signedPackage("pay_address", Math.floor(Date.now() / 1000) + delay + 700);
  const { prepare_id } = j.storePrepared(pkg as never, undefined, delay);
  const t0 = Date.now();
  const { job_id } = await j.submit(prepare_id, signature);
  const t1 = Date.now();
  // Everything below up to restorePersisted() is synchronous, so the real timer cannot fire in between
  // (re-arming replaces it with the stub; the real pipeline would try to prove).
  const job = j.getJob(job_id)!;
  assert.equal(job.status, "scheduled");
  assert.equal(typeof job.scheduledFor, "string");
  const at = Date.parse(job.scheduledFor!);
  assert.equal(new Date(at).toISOString(), job.scheduledFor);
  assert.ok(at >= t0 && at <= t1 + delay * 1000, `scheduledFor out of window: ${job.scheduledFor}`);
  const publicJson = JSON.stringify(job);
  assert.ok(!publicJson.includes("circuitInputs") && !publicJson.includes(NK), "GET /v1/jobs/:id must not expose the witness");

  store.saveNow();
  assert.ok(!readFileSync(process.env.STATE_FILE!, "utf8").includes(NK), "state file must be encrypted at rest");
  const saved = store.loadState();
  const savedJob = (saved.jobs as { id: string; status: string; scheduledFor?: string }[]).find((x) => x.id === job_id);
  assert.equal(savedJob?.status, "scheduled");
  assert.equal(savedJob?.scheduledFor, job.scheduledFor);
  const savedSpend = (saved.prepared as { jobId?: string; signature?: string; delaySeconds?: number }[]).find((x) => x.jobId === job_id);
  assert.equal(savedSpend?.signature, signature);
  assert.equal(savedSpend?.delaySeconds, delay);

  // "Restart" 150 ms before the scheduled time (fake clock): the job must stay scheduled and start ~150 ms later.
  const started: { id: string; at: number; hasSignature: boolean }[] = [];
  const restoredAt = Date.now();
  const counts = j.restorePersisted(saved, { now: at - 150, start: (jb, spend) => { if (jb.id === job_id) started.push({ id: jb.id, at: Date.now(), hasSignature: spend.signature === signature }); } });
  assert.ok(counts.rearmed >= 1);
  assert.equal(j.getJob(job_id)?.status, "scheduled");
  await sleep(60);
  assert.equal(started.length, 0, "started before its scheduled time");
  await sleep(300);
  assert.equal(started.length, 1);
  assert.ok(started[0]!.at - restoredAt >= 140, `started after ${started[0]!.at - restoredAt} ms`);
  assert.ok(started[0]!.hasSignature);
  await assert.rejects(j.submit(prepare_id, signature), /Unknown or expired prepare_id/);
});

// ---------------------------------------------------------------------------------------------
// 5. Restart handling with a fake clock
// ---------------------------------------------------------------------------------------------
await test("restart: scheduled jobs re-armed (past -> now, future -> remaining time); lost/expired/in-flight -> failed", async () => {
  const T = Date.now() + 3_600_000; // the service comes back an hour later on the fake clock
  const jobOf = (idSuffix: string, status: string, scheduledFor?: number) => ({
    id: `job_${idSuffix.padEnd(24, "0")}`, kind: "unshield", status, createdAt: T - 600_000, updatedAt: T - 600_000, timings: {},
    ...(scheduledFor !== undefined ? { scheduledFor: new Date(scheduledFor).toISOString() } : {}),
  });
  const spendOf = (jobId: string, expiresAt: number) => ({ id: `prep_${jobId.slice(4)}`, pkg: { kind: "unshield" }, expiresAt, delaySeconds: 900, jobId, signature: "0x01" });
  const future = jobOf("aa", "scheduled", T + 150);
  const past = jobOf("bb", "scheduled", T - 300_000);
  const expired = jobOf("cc", "scheduled", T - 60_000);
  const tooClose = jobOf("dd", "scheduled", T + 10_000);
  const lost = jobOf("ee", "scheduled", T + 1_000);
  const proving = jobOf("ff", "proving");
  const relaying = jobOf("ab", "relaying");
  const done = jobOf("ac", "done");
  const saved = {
    prepared: [spendOf(future.id, T + 1_200_000), spendOf(past.id, T + 1_200_000), spendOf(expired.id, T - 1), spendOf(tooClose.id, T + 30_000)],
    jobs: [future, past, expired, tooClose, lost, proving, relaying, done],
  };
  const started: { id: string; after: number }[] = [];
  const t0 = Date.now();
  const counts = j.restorePersisted(saved, { now: T, start: (jb) => started.push({ id: jb.id, after: Date.now() - t0 }) });
  assert.deepEqual(counts, { interrupted: 2, rearmed: 2, expired: 3 });
  assert.equal(j.getJob(future.id)?.status, "scheduled");
  assert.equal(j.getJob(past.id)?.status, "scheduled");
  for (const x of [expired, tooClose]) assert.match(String(j.getJob(x.id)?.error), /deadline passed \(or is too close\)/);
  assert.match(String(j.getJob(lost.id)?.error), /lost across a service restart/);
  for (const x of [expired, tooClose, lost, proving, relaying]) assert.equal(j.getJob(x.id)?.status, "failed");
  for (const x of [proving, relaying]) assert.match(String(j.getJob(x.id)?.error), /service restarted during processing/);
  assert.equal(j.getJob(done.id)?.status, "done");
  await sleep(40);
  assert.deepEqual(started.map((s) => s.id), [past.id], "a job whose time passed must start right away, and only it");
  await sleep(300);
  assert.deepEqual(started.map((s) => s.id), [past.id, future.id]);
  assert.ok(started[1]!.after >= 140, `future job started after ${started[1]!.after} ms`);
});

store.saveNow();
rmSync(dir, { recursive: true, force: true });
console.log(`\n${passed} passed${process.exitCode ? ", some FAILED" : ""}`);
process.exit(process.exitCode ?? 0);
