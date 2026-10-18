// Prepared spends and the asynchronous prove -> (x402 requote) -> relay -> (x402 pay | refund) pipeline.
// Prepared spends and jobs are persisted via store.ts so /v1/jobs/:id survives restarts.
// Public payouts (unshield / pay_address) can ask for a randomized relay delay (delaySeconds): the job waits in
// "scheduled" until a uniformly random time in [submit, submit + delaySeconds], then runs the normal pipeline.
import { randomBytes, randomInt } from "node:crypto";
import { hashTypedData, hexToBytes, maxUint256, recoverPublicKey, type Hex } from "viem";
import { publicKeyToAddress } from "viem/accounts";
import { erc20Abi, ghostPoolAbi } from "./abi.js";
import { config } from "./config.js";
import { feeAcceptable, relayerFees } from "./fees.js";
import { publicClient, relayerAccount, state, sync, walletClient, withRelayerLock } from "./indexer.js";
import { prove } from "./prover.js";
import { isSanctioned } from "./ofac.js";
import { bindStore, loadState, scheduleSave, type PersistedState } from "./store.js";
import { payX402, requote, voidAuthorization, type Settlement, type X402Quote, type X402Request } from "./x402.js";
import { signatureToCircuit, type SpendPackage } from "../../plugin/src/core/spend.js";
import { ASP_DEPTH, FIELD_SIZE, H2, MerkleTree, TREE_DEPTH, encryptNote, precommitmentOf, randomField } from "../../plugin/src/core/primitives.js";

type Prepared = {
  id: string; pkg: SpendPackage; x402?: { request: X402Request; quote: X402Quote }; expiresAt: number;
  /** Requested relay delay window in seconds (0 = relay at once). */
  delaySeconds?: number;
  /** Set once a delayed spend is submitted: the scheduled job that owns it and the PayBox signature. Never on the job. */
  jobId?: string; signature?: Hex;
};
export type JobStatus =
  | "scheduled" | "queued" | "proving" | "requote_needed" | "relaying" | "paying" | "refunding" | "refunded" | "done" | "failed";
type Job = {
  id: string; kind: string; status: JobStatus; createdAt: number; updatedAt: number;
  /** Delayed jobs only: ISO time at which the job leaves "scheduled" and starts proving + relaying. */
  scheduledFor?: string;
  txHash?: Hex; error?: string; timings: Record<string, number>;
  /** Private refund deposit (GhostPool.deposit to the user's refundTo note) after a failed merchant payment. */
  refundTxHash?: Hex;
  x402?: {
    status: number; contentType: string; body: string; paymentResponse?: string; payTo: Hex; price: string;
    settlementTx?: Hex; settlement?: Settlement; error?: string;
  };
  receipt?: { nullifiers: string[]; outCommitments: string[]; publicOut: string; fee: string; recipient: Hex; deadline: string; typedData: unknown; signature: Hex; signer: Hex };
};
export type RefundTo = { ownerTag: bigint; viewPub: Uint8Array };

const IN_FLIGHT: JobStatus[] = ["queued", "proving", "relaying", "paying", "refunding"];
const prepared = new Map<string, Prepared>();
const jobs = new Map<string, Job>();
/** Submitted delayed spends waiting for their scheduled time, by job id (persisted with the prepared spends). */
const armed = new Map<string, Prepared>();
const timers = new Map<string, ReturnType<typeof setTimeout>>();
const id = (prefix: string) => `${prefix}_${randomBytes(12).toString("hex")}`;

/** Spends accepted by submit and not yet final, by job id (delayed and immediate). */
const openSpends = new Map<string, Prepared>();
const FINAL: JobStatus[] = ["done", "failed", "refunded", "requote_needed"];

/**
 * Pending-note tags for clients: H2(nullifier, nk) for every input of a submitted spend that is not final yet.
 * Raw nullifiers are NOT published before relay: that would reveal the submit time and defeat the random delay.
 * Only the note owner (who knows nk) can match a tag to their note.
 */
export function pendingTags(): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const [jobId, p] of [...openSpends, ...armed]) {
    if (seen.has(jobId)) continue;
    seen.add(jobId);
    const job = jobs.get(jobId);
    if (!job || FINAL.includes(job.status)) { openSpends.delete(jobId); continue; }
    const nk = BigInt(p.pkg.circuitInputs.nk);
    for (const n of p.pkg.tx.nullifiers) out.push(H2(BigInt(n), nk).toString());
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Relay delay
// ---------------------------------------------------------------------------------------------
export const MAX_DELAY_SECONDS = 1800;
/** The spend deadline must leave this long after the latest possible start time (proving + relaying + slack). */
export const DELAY_DEADLINE_MARGIN_SECONDS = 600;
const DELAYABLE_KINDS = new Set(["unshield", "pay_address"]);
/** A restored scheduled spend needs at least this much time left before its deadline (same as storePrepared). */
const MIN_DEADLINE_LEFT_MS = 60_000;

/**
 * Validates the optional `delaySeconds` of POST /v1/prepare and returns it (0 when absent).
 * Integer 0..1800; a non-zero delay only for unshield / pay_address, and only when
 * package.tx.deadline >= now + delaySeconds + 600.
 */
export function validateDelay(pkg: { kind?: unknown; tx?: { deadline?: unknown } } | undefined, raw: unknown, nowSeconds = Math.floor(Date.now() / 1000)): number {
  if (raw === undefined || raw === null) return 0;
  if (typeof raw !== "number" || !Number.isInteger(raw) || raw < 0 || raw > MAX_DELAY_SECONDS) {
    throw new Error(`delaySeconds must be an integer from 0 to ${MAX_DELAY_SECONDS}.`);
  }
  if (raw === 0) return 0;
  const kind = pkg?.kind;
  if (kind === "pay_x402") throw new Error("delaySeconds is not allowed for pay_x402: x402 payments must be paid immediately.");
  if (kind === "send_ghost") throw new Error("delaySeconds is not allowed for send_ghost: ghost transfers are already private.");
  if (!DELAYABLE_KINDS.has(String(kind))) throw new Error("delaySeconds is only supported for unshield and pay_address spends.");
  const deadline = Number(pkg?.tx?.deadline);
  if (!(deadline >= nowSeconds + raw + DELAY_DEADLINE_MARGIN_SECONDS)) {
    throw new Error(`Spend deadline too short for the requested delay: it must be at least now + delaySeconds + ${DELAY_DEADLINE_MARGIN_SECONDS} s. Prepare again with a later deadline or a shorter delay.`);
  }
  return raw;
}

/** Uniformly random start time (ms) in [nowMs, nowMs + windowSeconds s], whole seconds, from the CSPRNG. */
export function pickScheduledFor(windowSeconds: number, nowMs = Date.now(), rand: (min: number, max: number) => number = (min, max) => randomInt(min, max)): number {
  return nowMs + rand(0, Math.max(0, Math.floor(windowSeconds)) + 1) * 1000;
}

type StartFn = (job: Job, spend: Prepared) => void;

/** Starts the pipeline of a scheduled job at job.scheduledFor (immediately if that time has passed). */
function armJob(job: Job, spend: Prepared, opts: { now?: number; start?: StartFn } = {}) {
  const due = Date.parse(job.scheduledFor ?? "");
  const wait = Number.isFinite(due) ? Math.max(0, due - (opts.now ?? Date.now())) : 0;
  clearTimeout(timers.get(job.id));
  timers.set(job.id, setTimeout(() => {
    timers.delete(job.id);
    (opts.start ?? startScheduled)(job, spend);
  }, wait));
}

function startScheduled(job: Job, spend: Prepared) {
  if (job.status !== "scheduled" || armed.get(job.id) !== spend || !spend.signature) return;
  // From here on the job behaves like an immediate spend: the witness leaves the store, and a restart
  // while proving or relaying marks the job failed.
  armed.delete(job.id);
  scheduleSave();
  void run(job, spend, spend.signature);
}

// ---------------------------------------------------------------------------------------------
// Fresh roots at send time
// ---------------------------------------------------------------------------------------------
/** The parts of a spend package that carry Merkle / ASP membership witnesses (not bound by the PayBox signature). */
export type RootFields = {
  circuitInputs: {
    root: string; asp_root: string; in_amounts: string[]; in_labels: string[]; in_indices: string[];
    in_paths: string[][]; asp_indices: string[]; asp_paths: string[][];
  };
  tx: { root: string; aspRoot: string };
};
export type RootState = { leaves: { commitment: bigint }[]; publishedAsp: { labels: bigint[] } };
export type RootDeps = {
  isKnownRoot: (root: bigint) => Promise<boolean>;
  isKnownAspRoot: (root: bigint) => Promise<boolean>;
  sync: (force: boolean) => Promise<void>;
  state: RootState;
};

const chainRootDeps: RootDeps = {
  isKnownRoot: (root) => publicClient.readContract({ address: config.pool, abi: ghostPoolAbi, functionName: "isKnownRoot", args: [root] }),
  isKnownAspRoot: (root) => publicClient.readContract({ address: config.pool, abi: ghostPoolAbi, functionName: "isKnownAspRoot", args: [root] }),
  sync,
  state,
};

function rootFromPath(leaf: bigint, index: number, path: readonly (string | bigint)[]): bigint {
  let node = leaf;
  let i = index;
  for (const sibling of path) {
    node = i & 1 ? H2(BigInt(sibling), node) : H2(node, BigInt(sibling));
    i >>= 1;
  }
  return node;
}

/**
 * Recomputes, from indexer state, the state-tree (`tree`) and/or ASP (`asp`) membership witnesses of every live
 * input (in_amounts[i] != "0") and the matching roots in both circuitInputs and tx. Dummy inputs are left untouched.
 * Mutates `pkg`. Throws if the indexer's leaf at an input's index is not the leaf the package was built for, or if an
 * input's label is no longer in the published association set.
 */
export function rebuildRoots(pkg: RootFields, st: RootState, which: { tree: boolean; asp: boolean } = { tree: true, asp: true }): void {
  const ci = pkg.circuitInputs;
  const live = ci.in_amounts.flatMap((amount, i) => (BigInt(amount) !== 0n ? [i] : []));
  if (which.tree) {
    const leaves = st.leaves.map((l) => l.commitment);
    const tree = new MerkleTree(TREE_DEPTH, leaves);
    for (const i of live) {
      const index = Number(ci.in_indices[i]);
      if (!Number.isSafeInteger(index) || index < 0 || index >= leaves.length) throw new Error(`input ${i}: leaf ${ci.in_indices[i]} is not in the indexed tree yet`);
      // Leaves are append-only: the package's old path must still lead from this leaf to the package's old root.
      if (rootFromPath(leaves[index]!, index, ci.in_paths[i]!) !== BigInt(ci.root)) throw new Error(`input ${i}: indexer leaf ${index} does not match the spend package`);
      ci.in_paths[i] = tree.path(index).map(String);
    }
    ci.root = tree.root.toString();
    pkg.tx.root = ci.root;
  }
  if (which.asp) {
    const labels = st.publishedAsp.labels;
    const aspTree = new MerkleTree(ASP_DEPTH, labels);
    for (const i of live) {
      const label = BigInt(ci.in_labels[i]!);
      const index = labels.findIndex((l) => l === label);
      if (index < 0) throw new Error(`input ${i}: its deposit is no longer in the association set, so it cannot be spent privately`);
      ci.asp_indices[i] = String(index);
      ci.asp_paths[i] = aspTree.path(index).map(String);
    }
    ci.asp_root = aspTree.root.toString();
    pkg.tx.aspRoot = ci.asp_root;
  }
}

/**
 * Right before proving: if the package's state root fell out of the pool's 64-root history (or its ASP root out of
 * the 16-root ASP history), force an indexer sync and rebuild the stale witnesses. Returns what was rebuilt.
 * If the freshness check itself cannot be made (RPC error), proving continues with the package's roots and the
 * relay simulation decides, as before this check existed.
 */
export async function ensureFreshRoots(pkg: RootFields, deps: RootDeps = chainRootDeps): Promise<{ root: boolean; aspRoot: boolean }> {
  const ci = pkg.circuitInputs;
  let rootKnown: boolean;
  let aspKnown: boolean;
  try {
    [rootKnown, aspKnown] = await Promise.all([deps.isKnownRoot(BigInt(ci.root)), deps.isKnownAspRoot(BigInt(ci.asp_root))]);
  } catch (err) {
    console.error(`[jobs] root freshness check failed (${cleanError(err, 200)}); proving with the package's roots`);
    return { root: false, aspRoot: false };
  }
  if (rootKnown && aspKnown) return { root: false, aspRoot: false };
  await deps.sync(true);
  rebuildRoots(pkg, deps.state, { tree: !rootKnown, asp: !aspKnown });
  const [rootOk, aspOk] = await Promise.all([
    rootKnown ? true : deps.isKnownRoot(BigInt(ci.root)),
    aspKnown ? true : deps.isKnownAspRoot(BigInt(ci.asp_root)),
  ]);
  if (!rootOk) throw new Error("the package's Merkle root expired and the indexer could not rebuild a root the pool knows; nothing was sent, prepare again");
  if (!aspOk) throw new Error("the package's ASP root expired and the published association set is not on-chain yet; nothing was sent, prepare again");
  return { root: !rootKnown, aspRoot: !aspKnown };
}

/** First lines of an error, without RPC URLs (they can embed API keys) or calldata dumps. */
export function cleanError(err: unknown, max = 600): string {
  const message = String((err as Error)?.message ?? err);
  return message.split("\n").map((l) => l.trim()).filter(Boolean).slice(0, 3).join(" ")
    .replace(/https?:\/\/[^\s"'<>]+/g, (u) => { try { return new URL(u).host; } catch { return "<url>"; } })
    .replace(/0x[0-9a-fA-F]{200,}/g, (h) => `${h.slice(0, 10)}…`)
    .slice(0, max);
}

// ---------------------------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------------------------
// Scheduled spends (with their signature) are stored next to the prepared spends, so they share the at-rest
// encryption; they are never part of the job object that GET /v1/jobs/:id returns.
bindStore(() => ({ prepared: [...prepared.values(), ...armed.values()], jobs: [...jobs.values()] }));

/**
 * Restores persisted prepared spends and jobs after a restart. Jobs still "scheduled" are re-armed (started at
 * scheduledFor, or right away if it passed) when their spend is intact and its deadline is not too close; jobs that
 * were mid-pipeline are marked failed as before. `now` and `start` are injectable for tests.
 */
export function restorePersisted(saved: PersistedState, opts: { now?: number; start?: StartFn } = {}) {
  const now = opts.now ?? Date.now();
  const savedArmed = new Map<string, Prepared>();
  for (const raw of saved.prepared as Prepared[]) {
    if (!raw?.id || !raw.pkg) continue;
    if (raw.x402?.quote) raw.x402.quote.price = BigInt(raw.x402.quote.price as unknown as string);
    if (raw.jobId) { savedArmed.set(raw.jobId, raw); continue; }
    if (!(raw.expiresAt > now)) continue;
    prepared.set(raw.id, raw);
  }
  let interrupted = 0;
  let rearmed = 0;
  let expired = 0;
  for (const raw of saved.jobs as Job[]) {
    if (!raw?.id) continue;
    if (raw.status === "scheduled") {
      const spend = savedArmed.get(raw.id);
      if (spend?.signature && spend.expiresAt - now > MIN_DEADLINE_LEFT_MS) {
        jobs.set(raw.id, raw);
        armed.set(raw.id, spend);
        armJob(raw, spend, opts);
        rearmed++;
        continue;
      }
      raw.error = spend
        ? "the spend deadline passed (or is too close) after a service restart; nothing was sent, prepare again"
        : "the scheduled spend was lost across a service restart; nothing was sent, prepare again";
      raw.status = "failed";
      raw.updatedAt = now;
      expired++;
    } else if (IN_FLIGHT.includes(raw.status)) {
      raw.error = raw.error ? `service restarted during processing; check ghost_balance (${raw.error})` : "service restarted during processing; check ghost_balance";
      raw.status = "failed";
      raw.updatedAt = now;
      interrupted++;
    }
    jobs.set(raw.id, raw);
  }
  return { interrupted, rearmed, expired };
}

{
  const saved = loadState();
  const { interrupted, rearmed, expired } = restorePersisted(saved);
  if (saved.jobs.length || saved.prepared.length) {
    console.error(`[store] loaded ${jobs.size} job(s), ${prepared.size} prepared spend(s)${interrupted ? `; ${interrupted} interrupted job(s) marked failed` : ""}${rearmed ? `; ${rearmed} scheduled job(s) re-armed` : ""}${expired ? `; ${expired} scheduled job(s) could not be resumed` : ""}`);
    scheduleSave();
  }
}

function parseRefundTo(pkg: SpendPackage): RefundTo | undefined {
  const r = (pkg as { refundTo?: { ownerTag?: unknown; viewPub?: unknown } }).refundTo;
  if (r === undefined || r === null) return undefined;
  if (typeof r.ownerTag !== "string" || !/^\d{1,78}$/.test(r.ownerTag) || BigInt(r.ownerTag) >= FIELD_SIZE
    || typeof r.viewPub !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(r.viewPub)) {
    throw new Error("Spend package refundTo must be { ownerTag: decimal field element, viewPub: 32-byte 0x hex }.");
  }
  return { ownerTag: BigInt(r.ownerTag), viewPub: hexToBytes(r.viewPub as Hex) };
}

export function storePrepared(pkg: SpendPackage, x402?: Prepared["x402"], delaySeconds?: unknown) {
  if (pkg?.version !== 1) throw new Error("Unsupported spend package version.");
  const delay = validateDelay(pkg, delaySeconds);
  if (pkg.chainId !== config.chainId || pkg.pool.toLowerCase() !== config.pool.toLowerCase()) throw new Error("Spend package targets a different pool.");
  if (!relayerAccount || pkg.tx.relayer.toLowerCase() !== relayerAccount.address.toLowerCase()) throw new Error("Spend package names a different relayer.");
  if (!/^\d{1,30}$/.test(String(pkg.tx.fee)) || !feeAcceptable(BigInt(pkg.tx.fee))) {
    throw new Error(`Relayer fee too low: signed ${pkg.tx.fee}, current ${relayerFees().transact} atomic USDC. Refresh ghost state and prepare again.`);
  }
  if (pkg.kind === "pay_x402" && !x402) throw new Error("pay_x402 spends must be prepared together with their x402 request.");
  if (isSanctioned(String(pkg.tx.recipient))) throw new Error("The recipient is on the OFAC SDN list; the relayer will not relay this spend.");
  if (x402) parseRefundTo(pkg); // validate early; a missing refundTo only matters if a refund is ever needed
  const deadline = Number(pkg.tx.deadline);
  if (deadline <= Math.floor(Date.now() / 1000) + 60) throw new Error("Spend deadline too close.");
  const entry: Prepared = { id: id("prep"), pkg, x402, expiresAt: deadline * 1000, delaySeconds: delay };
  prepared.set(entry.id, entry);
  for (const [key, p] of prepared) if (p.expiresAt < Date.now()) prepared.delete(key);
  scheduleSave();
  return { prepare_id: entry.id, expires_at: new Date(entry.expiresAt).toISOString() };
}

export async function submit(prepareId: string, signature: Hex) {
  const p = prepared.get(prepareId);
  if (!p || p.expiresAt < Date.now()) throw new Error("Unknown or expired prepare_id. Run ghost_prepare again.");
  const { EIP712Domain: _domain, ...types } = p.pkg.typedData.types;
  const digest = hashTypedData({ ...p.pkg.typedData, types } as never);
  const recovered = await recoverPublicKey({ hash: digest, signature });
  if (recovered.toLowerCase() !== p.pkg.pubKey.toLowerCase()) {
    throw new Error("Signature was not produced by the PayBox wallet bound to this ghost key, or the typed data was altered.");
  }
  prepared.delete(prepareId); // one signature, one spend
  const now = Date.now();
  const job: Job = { id: id("job"), kind: p.pkg.kind, status: "queued", createdAt: now, updatedAt: now, timings: {} };
  const delay = p.delaySeconds ?? 0;
  if (delay > 0) {
    // Uniform in [now, now + delay]; the window shrinks only if submit came so late after prepare that the full
    // window would leave less than DELAY_DEADLINE_MARGIN_SECONDS before the signed deadline.
    const window = Math.max(0, Math.min(delay, Math.floor((p.expiresAt - now) / 1000) - DELAY_DEADLINE_MARGIN_SECONDS));
    job.status = "scheduled";
    job.scheduledFor = new Date(pickScheduledFor(window, now)).toISOString();
    const spend: Prepared = { ...p, jobId: job.id, signature };
    jobs.set(job.id, job);
    openSpends.set(job.id, spend);
    armed.set(job.id, spend);
    scheduleSave();
    armJob(job, spend);
    return { job_id: job.id };
  }
  jobs.set(job.id, job);
  openSpends.set(job.id, p);
  scheduleSave();
  void run(job, p, signature);
  return { job_id: job.id };
}

export function getJob(jobId: string) {
  return jobs.get(jobId);
}

function set(job: Job, status: JobStatus, extra: Partial<Job> = {}) {
  Object.assign(job, extra, { status, updatedAt: Date.now() });
  scheduleSave();
}

/**
 * Re-deposits `amount` into the pool as a new note owned by the user (refundTo), from the relayer.
 * If an EIP-3009 authorization was signed, it is first voided (cancelAuthorization) so the merchant can
 * never settle it after the refund; an authorization that was already settled is not refunded.
 */
async function refund(job: Job, pkg: SpendPackage, amount: bigint, nonce: Hex | undefined): Promise<Hex> {
  const to = parseRefundTo(pkg);
  if (!to) throw new Error("spend package has no refundTo; cannot refund privately");
  return refundPrivately(to, amount, nonce, (hash) => { job.refundTxHash = hash; scheduleSave(); });
}

/** Relayer -> pool deposit of `amount` as a fresh note for `to` (label assigned by the pool). Exported for fork tests. */
export async function refundPrivately(to: RefundTo, amount: bigint, nonce: Hex | undefined, onHash?: (hash: Hex) => void): Promise<Hex> {
  const wallet = walletClient;
  const account = relayerAccount;
  if (!wallet || !account) throw new Error("relayer wallet not configured");
  return withRelayerLock(async () => {
    if (nonce && (await voidAuthorization(nonce)) === "used") {
      throw new Error("the payment authorization was already used on-chain (the merchant settled it), so the relayer does not refund it");
    }
    const allowance = await publicClient.readContract({ address: config.token, abi: erc20Abi, functionName: "allowance", args: [account.address, config.pool] });
    if (allowance < amount) {
      const { request } = await publicClient.simulateContract({ account, address: config.token, abi: erc20Abi, functionName: "approve", args: [config.pool, maxUint256] });
      const approveHash = await wallet.writeContract(request);
      const r = await publicClient.waitForTransactionReceipt({ hash: approveHash, timeout: 60_000 });
      if (r.status !== "success") throw new Error(`USDC approve reverted in ${approveHash}`);
    }
    const blinding = randomField();
    const { request } = await publicClient.simulateContract({
      account, address: config.pool, abi: ghostPoolAbi, functionName: "deposit",
      args: [amount, precommitmentOf(to.ownerTag, blinding), encryptNote(to.viewPub, amount, blinding, 0n)],
    });
    const hash = await wallet.writeContract(request);
    onHash?.(hash);
    const receipt = await publicClient.waitForTransactionReceipt({ hash, timeout: 120_000 });
    if (receipt.status !== "success") throw new Error(`refund deposit reverted in ${hash}`);
    return hash;
  });
}

async function run(job: Job, p: Prepared, signature: Hex) {
  try {
    set(job, "proving");
    // The signature does not bind the roots: refresh them if they left the pool's root histories (e.g. after a delay).
    const tRoots = Date.now();
    const refreshed = await ensureFreshRoots(p.pkg);
    job.timings.rootCheckMs = Date.now() - tRoots;
    if (refreshed.root || refreshed.aspRoot) {
      console.error(`[job ${job.id}] rebuilt stale ${[refreshed.root && "Merkle root", refreshed.aspRoot && "ASP root"].filter(Boolean).join(" and ")} before proving`);
    }
    const proof = await prove({ ...p.pkg.circuitInputs, signature: signatureToCircuit(signature) });
    job.timings.witnessMs = proof.witnessMs;
    job.timings.proveMs = proof.proveMs;

    // x402: the merchant's terms must still match what the user signed for before any funds move.
    let quote = p.x402?.quote;
    if (p.x402) {
      const t = Date.now();
      const fresh = await requote(p.x402.request, p.x402.quote);
      job.timings.requoteMs = Date.now() - t;
      if ("mismatch" in fresh) {
        set(job, "requote_needed", { error: fresh.mismatch });
        return;
      }
      quote = fresh.quote;
    }

    set(job, "relaying");
    const t = p.pkg.tx;
    const args = {
      root: BigInt(t.root), aspRoot: BigInt(t.aspRoot),
      nullifiers: [BigInt(t.nullifiers[0]!), BigInt(t.nullifiers[1]!)] as const,
      outCommitments: [BigInt(t.outCommitments[0]!), BigInt(t.outCommitments[1]!)] as const,
      publicOut: BigInt(t.publicOut), recipient: t.recipient, fee: BigInt(t.fee), deadline: BigInt(t.deadline),
      relayer: t.relayer, encryptedOutput0: t.encryptedOutput0, encryptedOutput1: t.encryptedOutput1,
    };
    if (!walletClient) throw new Error("Relayer wallet not configured.");
    const t0 = Date.now();
    const wallet = walletClient;
    const receipt = await withRelayerLock(async () => {
      const { request } = await publicClient.simulateContract({
        account: relayerAccount, address: config.pool, abi: ghostPoolAbi, functionName: "transact", args: [proof.proof, args],
      });
      const hash = await wallet.writeContract(request);
      job.txHash = hash;
      scheduleSave();
      return publicClient.waitForTransactionReceipt({ hash, timeout: 120_000 });
    });
    const hash = receipt.transactionHash;
    job.timings.relayMs = Date.now() - t0;
    if (receipt.status !== "success") throw new Error(`transact reverted in ${hash}`);
    job.receipt = {
      nullifiers: t.nullifiers, outCommitments: t.outCommitments, publicOut: t.publicOut, fee: t.fee, recipient: t.recipient, deadline: t.deadline,
      typedData: p.pkg.typedData, signature, signer: publicKeyToAddress(p.pkg.pubKey),
    };
    scheduleSave();
    void sync(true);

    if (p.x402 && quote) {
      set(job, "paying");
      const t1 = Date.now();
      let merchantError: string | undefined;
      let nonce: Hex | undefined;
      try {
        const paid = await payX402(p.x402.request, quote);
        nonce = paid.nonce;
        const { nonce: _n, validBefore: _v, ...result } = paid;
        job.x402 = { ...result, payTo: quote.payTo, price: quote.price.toString() };
        if (paid.status === 402) merchantError = "merchant answered HTTP 402 again after payment";
        else if (paid.status < 200 || paid.status > 299) merchantError = `merchant answered HTTP ${paid.status} after payment`;
        if (merchantError && paid.settlement?.errorReason) merchantError += ` (${paid.settlement.errorReason})`;
      } catch (err) {
        nonce = (err as { payment?: { nonce?: Hex } }).payment?.nonce;
        merchantError = `merchant payment failed: ${cleanError(err, 300)}`;
        job.x402 = { status: 0, contentType: "", body: "", payTo: quote.payTo, price: quote.price.toString(), error: merchantError };
      }
      job.timings.x402Ms = Date.now() - t1;
      if (merchantError) {
        if (job.x402) job.x402.error = merchantError;
        set(job, "refunding");
        const t2 = Date.now();
        try {
          const refundTxHash = await refund(job, p.pkg, quote.price, nonce);
          job.timings.refundMs = Date.now() - t2;
          set(job, "refunded", {
            refundTxHash,
            error: `${merchantError}; ${quote.price} atomic USDC refunded privately to your ghost balance (relayer fee kept).`,
          });
        } catch (err) {
          job.timings.refundMs = Date.now() - t2;
          set(job, "failed", { error: `${merchantError}; refund failed: ${cleanError(err, 300)}` });
          console.error(`[job ${job.id}] x402 payment failed and refund failed: ${job.error}`);
        }
        void sync(true);
        return;
      }
    }
    set(job, "done");
  } catch (err) {
    set(job, "failed", { error: cleanError(err) });
    console.error(`[job ${job.id}] failed: ${job.error}`);
  }
}
