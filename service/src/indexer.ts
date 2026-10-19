// Indexer: rebuilds the pool's public state (leaves, encrypted notes, deposits,
// nullifiers) from events. Nothing here is trusted: clients recompute the roots.
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { createPublicClient, createWalletClient, defineChain, fallback, http, type Hex, type Log } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base } from "viem/chains";
import { ghostPoolAbi } from "./abi.js";
import { config, SERVICE_ROOT } from "./config.js";
import { ASP_DEPTH, MerkleTree, TREE_DEPTH } from "../../plugin/src/core/primitives.js";

export const chain = config.chainId === 8453 ? base : defineChain({
  id: config.chainId, name: `chain-${config.chainId}`, nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: [config.rpcUrl] } },
});
// RPC_URL may list several endpoints (comma-separated); requests fall back in order.
const rpcUrls = config.rpcUrl.split(",").map((u) => u.trim()).filter(Boolean);
const transport = (timeout: number) => rpcUrls.length > 1
  ? fallback(rpcUrls.map((u) => http(u, { timeout, retryCount: 1 })))
  : http(rpcUrls[0], { timeout, retryCount: 2 });
export const publicClient = createPublicClient({ chain, pollingInterval: 1_000, transport: transport(20_000) });
export const relayerAccount = config.relayerKey ? privateKeyToAccount(config.relayerKey) : undefined;
export const walletClient = relayerAccount
  ? createWalletClient({ account: relayerAccount, chain, transport: transport(30_000) })
  : undefined;

// Serialises every transaction sent by the relayer key (ASP updates and transacts) to avoid nonce races.
let relayerQueue: Promise<unknown> = Promise.resolve();
export function withRelayerLock<T>(fn: () => Promise<T>): Promise<T> {
  const run = relayerQueue.then(fn, fn);
  relayerQueue = run.catch(() => undefined);
  return run;
}

type Leaf = { index: number; commitment: bigint; encrypted: Hex; blockNumber: bigint; blockTime: number; txHash: Hex };
type Deposit = { leafIndex: number; label: bigint; amount: bigint; depositor: Hex; blockTime: number; txHash: Hex };

export const state = {
  leaves: [] as Leaf[],
  deposits: [] as Deposit[],
  nullifiers: new Set<string>(),
  lastBlock: config.poolDeployBlock > 0n ? config.poolDeployBlock - 1n : 0n,
  root: 0n,
  onchainAspRoot: 0n,
  publishedAsp: { root: 0n, labels: [] as bigint[] },
  syncedAt: 0,
};

// Snapshot of the indexed pool state (data/index.json). A restart resumes from lastBlock instead of re-reading
// the pool's whole history: free public RPCs refuse or rate-limit archive eth_getLogs ranges.
const DATA_DIR = process.env.DATA_DIR ?? resolve(SERVICE_ROOT, "data");
const INDEX_FILE = resolve(DATA_DIR, "index.json");

function loadSnapshot() {
  if (!existsSync(INDEX_FILE)) return;
  try {
    const s = JSON.parse(readFileSync(INDEX_FILE, "utf8"));
    if (s.v !== 1 || s.chainId !== config.chainId || String(s.pool).toLowerCase() !== config.pool.toLowerCase()) return;
    state.leaves = s.leaves.map((l: Record<string, string | number>) => ({
      index: Number(l.index), commitment: BigInt(l.commitment!), encrypted: l.encrypted as Hex,
      blockNumber: BigInt(l.blockNumber!), blockTime: Number(l.blockTime), txHash: l.txHash as Hex,
    }));
    state.deposits = s.deposits.map((d: Record<string, string | number>) => ({
      leafIndex: Number(d.leafIndex), label: BigInt(d.label!), amount: BigInt(d.amount!),
      depositor: d.depositor as Hex, blockTime: Number(d.blockTime), txHash: d.txHash as Hex,
    }));
    state.nullifiers = new Set<string>(s.nullifiers);
    state.lastBlock = BigInt(s.lastBlock);
    console.error(`[indexer] resumed from snapshot at block ${state.lastBlock} (${state.leaves.length} leaves)`);
  } catch (err) {
    console.error(`[indexer] ignoring unreadable snapshot: ${(err as Error).message}`);
  }
}

function saveSnapshot() {
  try {
    mkdirSync(DATA_DIR, { recursive: true });
    const tmp = `${INDEX_FILE}.tmp`;
    writeFileSync(tmp, JSON.stringify({
      v: 1, chainId: config.chainId, pool: config.pool, lastBlock: state.lastBlock.toString(),
      leaves: state.leaves.map((l) => ({ ...l, commitment: l.commitment.toString(), blockNumber: l.blockNumber.toString() })),
      deposits: state.deposits.map((d) => ({ ...d, label: d.label.toString(), amount: d.amount.toString() })),
      nullifiers: [...state.nullifiers],
    }));
    renameSync(tmp, INDEX_FILE);
  } catch (err) {
    console.error(`[indexer] could not save snapshot: ${(err as Error).message}`);
  }
}

function resetIndex() {
  state.leaves = [];
  state.deposits = [];
  state.nullifiers = new Set<string>();
  state.lastBlock = config.poolDeployBlock > 0n ? config.poolDeployBlock - 1n : 0n;
  rmSync(INDEX_FILE, { force: true });
}

loadSnapshot();

const blockTimes = new Map<bigint, number>();
async function blockTime(n: bigint): Promise<number> {
  const cached = blockTimes.get(n);
  if (cached !== undefined) return cached;
  const block = await publicClient.getBlock({ blockNumber: n });
  blockTimes.set(n, Number(block.timestamp));
  return Number(block.timestamp);
}

let syncing: Promise<void> | undefined;
const maxLogChunk = BigInt(process.env.LOG_CHUNK ?? 50_000);
let logChunk = maxLogChunk;
let rootMismatches = 0;
export function sync(force = false): Promise<void> {
  if (!config.pool) return Promise.resolve();
  if (!force && Date.now() - state.syncedAt < 2_000) return Promise.resolve();
  syncing ??= doSync().finally(() => { syncing = undefined; });
  return syncing;
}

async function doSync() {
  const head = await publicClient.getBlockNumber();
  const startBlock = state.lastBlock;
  while (head > state.lastBlock) {
    const fromBlock = state.lastBlock + 1n;
    const toBlock = fromBlock + logChunk - 1n < head ? fromBlock + logChunk - 1n : head;
    let logs;
    try {
      logs = await publicClient.getLogs({ address: config.pool, events: ghostPoolAbi.filter((x) => x.type === "event"), fromBlock, toBlock });
    } catch (err) {
      // Providers cap eth_getLogs ranges (Alchemy free tier, public RPCs): shrink and retry.
      if (logChunk > 10n) { logChunk = logChunk / 5n > 10n ? logChunk / 5n : 10n; continue; }
      throw err;
    }
    // A transient error must not leave every later sync crawling in 10-block steps: grow back after a success.
    if (logChunk < maxLogChunk) logChunk = logChunk * 2n < maxLogChunk ? logChunk * 2n : maxLogChunk;
    const sorted = (logs as (Log & { eventName: string; args: Record<string, unknown> })[]).sort((a, b) =>
      a.blockNumber === b.blockNumber ? Number(a.logIndex) - Number(b.logIndex) : Number(a.blockNumber! - b.blockNumber!));
    for (const log of sorted) {
      const time = await blockTime(log.blockNumber!);
      const args = log.args;
      if (log.eventName === "NewCommitment") {
        state.leaves.push({
          index: Number(args.leafIndex), commitment: args.commitment as bigint, encrypted: args.encryptedOutput as Hex,
          blockNumber: log.blockNumber!, blockTime: time, txHash: log.transactionHash!,
        });
      } else if (log.eventName === "Deposited") {
        state.deposits.push({
          leafIndex: Number(args.leafIndex), label: args.label as bigint, amount: args.amount as bigint,
          depositor: args.depositor as Hex, blockTime: time, txHash: log.transactionHash!,
        });
      } else if (log.eventName === "NewNullifier") {
        state.nullifiers.add((args.nullifier as bigint).toString());
      }
    }
    state.leaves.sort((a, b) => a.index - b.index);
    state.lastBlock = toBlock;
  }
  const [root, aspRoot] = await Promise.all([
    publicClient.readContract({ address: config.pool, abi: ghostPoolAbi, functionName: "getLastRoot" }),
    publicClient.readContract({ address: config.pool, abi: ghostPoolAbi, functionName: "currentAspRoot" }),
  ]);
  const local = new MerkleTree(TREE_DEPTH, state.leaves.map((l) => l.commitment)).root;
  if (local !== root) {
    // One mismatch can be a race (a transaction landed between getLogs and getLastRoot); three in a row means
    // the local index (or a stale snapshot) is wrong, so rebuild it from the deploy block.
    rootMismatches++;
    console.error(`[indexer] local root ${local} != on-chain ${root} (${rootMismatches}/3)`);
    if (rootMismatches >= 3) {
      console.error("[indexer] rebuilding the index from the pool's deploy block");
      rootMismatches = 0;
      resetIndex();
    }
  } else {
    rootMismatches = 0;
    if (state.lastBlock !== startBlock || !existsSync(INDEX_FILE)) saveSnapshot();
  }
  state.root = root;
  state.onchainAspRoot = aspRoot;
  state.syncedAt = Date.now();
}

/** Deterministic association set: deposits in order, minus denylisted depositors and too-fresh deposits. */
export function approvedLabels(nowSeconds = Math.floor(Date.now() / 1000)): bigint[] {
  return state.deposits
    .filter((d) => !config.aspDenylist.has(d.depositor.toLowerCase()) && nowSeconds - d.blockTime >= config.aspDelaySeconds)
    .map((d) => d.label);
}

export function aspTreeFor(labels: bigint[]) {
  return new MerkleTree(ASP_DEPTH, labels);
}

export function serializeState() {
  return {
    chainId: config.chainId,
    pool: config.pool,
    token: config.token,
    relayer: relayerAccount?.address ?? null,
    relayerFee: config.relayerFee.toString(),
    root: state.root.toString(),
    leaves: state.leaves.map((l) => ({ index: l.index, commitment: l.commitment.toString(), encrypted: l.encrypted, blockTime: l.blockTime, txHash: l.txHash })),
    deposits: state.deposits.map((d) => ({ ...d, label: d.label.toString(), amount: d.amount.toString() })),
    nullifiers: [...state.nullifiers],
    asp: { root: state.publishedAsp.root.toString(), labels: state.publishedAsp.labels.map(String) },
    syncedAt: state.syncedAt,
  };
}
