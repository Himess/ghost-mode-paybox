// Indexer: rebuilds the pool's public state (leaves, encrypted notes, deposits,
// nullifiers) from events. Nothing here is trusted: clients recompute the roots.
import { createPublicClient, createWalletClient, defineChain, fallback, http, type Hex, type Log } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base } from "viem/chains";
import { ghostPoolAbi } from "./abi.js";
import { config } from "./config.js";
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

const blockTimes = new Map<bigint, number>();
async function blockTime(n: bigint): Promise<number> {
  const cached = blockTimes.get(n);
  if (cached !== undefined) return cached;
  const block = await publicClient.getBlock({ blockNumber: n });
  blockTimes.set(n, Number(block.timestamp));
  return Number(block.timestamp);
}

let syncing: Promise<void> | undefined;
let logChunk = BigInt(process.env.LOG_CHUNK ?? 50_000);
export function sync(force = false): Promise<void> {
  if (!config.pool) return Promise.resolve();
  if (!force && Date.now() - state.syncedAt < 2_000) return Promise.resolve();
  syncing ??= doSync().finally(() => { syncing = undefined; });
  return syncing;
}

async function doSync() {
  const head = await publicClient.getBlockNumber();
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
  if (local !== root) console.error(`[indexer] local root ${local} != on-chain ${root}; resyncing next round`);
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
