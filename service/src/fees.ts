// Dynamic relayer fees in USDC atomic units (6 decimals), refreshed every 60 s:
//   fee = ceil(gasUnits x gasPrice x ETHUSD x 1.2), floor 0.01 USDC.
// ETH/USD comes from the Chainlink feed on Base, verified on-chain (description must contain "ETH / USD")
// before first use. On any failure the last good value (or the floor) is kept.
import { parseAbi, type Hex } from "viem";
import { config } from "./config.js";
import { publicClient } from "./indexer.js";

export const ETH_USD_FEED = (process.env.ETH_USD_FEED ?? "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70") as Hex;
export const GAS_UNITS = { transact: 5_400_000n, shield: 900_000n } as const;
export const FEE_FLOOR = config.relayerFeeFloor > 10_000n ? config.relayerFeeFloor : 10_000n;
const MAX_FEED_AGE_SECONDS = 6 * 3600; // Base ETH/USD heartbeat is 20 min; older data counts as a failed read.

const feedAbi = parseAbi([
  "function description() view returns (string)",
  "function decimals() view returns (uint8)",
  "function latestRoundData() view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)",
]);

export type RelayerFees = { transact: bigint; shield: bigint; ethUsd: number; gasPriceWei: bigint; updatedAt: number };

/** ceil(gasUnits * gasPriceWei * (answer / 10^decimals) * 1.2 * 10^6 / 10^18), at least the floor. */
export function feeFor(gasUnits: bigint, gasPriceWei: bigint, answer: bigint, decimals: number, floor = FEE_FLOOR): bigint {
  const num = gasUnits * gasPriceWei * answer * 12n * 10n ** 6n;
  const den = 10n ** 18n * 10n ** BigInt(decimals) * 10n;
  const fee = (num + den - 1n) / den;
  return fee < floor ? floor : fee;
}

let current: RelayerFees = { transact: FEE_FLOOR, shield: FEE_FLOOR, ethUsd: 0, gasPriceWei: 0n, updatedAt: 0 };
let feed: { decimals: number; description: string } | undefined;

async function verifyFeed() {
  const [description, decimals] = await Promise.all([
    publicClient.readContract({ address: ETH_USD_FEED, abi: feedAbi, functionName: "description" }),
    publicClient.readContract({ address: ETH_USD_FEED, abi: feedAbi, functionName: "decimals" }),
  ]);
  if (!description.includes("ETH / USD")) throw new Error(`feed ${ETH_USD_FEED} describes "${description.slice(0, 40)}", not ETH / USD`);
  if (decimals > 36) throw new Error(`feed ${ETH_USD_FEED} reports ${decimals} decimals`);
  feed = { decimals, description };
  console.error(`[fees] verified Chainlink feed ${ETH_USD_FEED}: "${description}", ${decimals} decimals`);
}

export async function updateFees(): Promise<RelayerFees> {
  try {
    if (!feed) await verifyFeed();
    const [round, gasPriceWei] = await Promise.all([
      publicClient.readContract({ address: ETH_USD_FEED, abi: feedAbi, functionName: "latestRoundData" }),
      publicClient.getGasPrice(),
    ]);
    const [, answer, , updatedAt] = round;
    if (answer <= 0n) throw new Error("feed returned a non-positive price");
    if (Math.floor(Date.now() / 1000) - Number(updatedAt) > MAX_FEED_AGE_SECONDS) throw new Error(`feed is stale (updated ${updatedAt})`);
    if (gasPriceWei <= 0n) throw new Error("RPC returned a zero gas price");
    const decimals = feed!.decimals;
    current = {
      transact: feeFor(GAS_UNITS.transact, gasPriceWei, answer, decimals),
      shield: feeFor(GAS_UNITS.shield, gasPriceWei, answer, decimals),
      ethUsd: Number(answer) / 10 ** decimals,
      gasPriceWei,
      updatedAt: Date.now(),
    };
    config.relayerFee = current.transact; // keeps /v1/state (indexer serializeState) on the live transact fee
  } catch (err) {
    console.error(`[fees] update failed, keeping transact=${current.transact} shield=${current.shield}: ${String((err as Error).message ?? err).split("\n")[0]!.slice(0, 200)}`);
  }
  return current;
}

let timer: ReturnType<typeof setInterval> | undefined;
export function startFeeUpdater(intervalMs = 60_000): Promise<RelayerFees> {
  const first = updateFees();
  if (!timer) {
    timer = setInterval(() => void updateFees(), intervalMs);
    timer.unref?.();
  }
  return first;
}

export function relayerFees(): RelayerFees {
  return { ...current };
}

/** A signed fee is acceptable when it is at least 80% of the current fee (tolerates refreshes between state fetch and prepare). */
export function feeAcceptable(signedFee: bigint, kind: "transact" | "shield" = "transact", fees: RelayerFees = current): boolean {
  return signedFee * 10n >= fees[kind] * 8n;
}
