import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Hex } from "viem";
import { sanctionedAddresses } from "./ofac.js";

const here = dirname(fileURLToPath(import.meta.url));
export const SERVICE_ROOT = resolve(here, "..");
export const REPO_ROOT = resolve(SERVICE_ROOT, "..");
const SECRETS = resolve(REPO_ROOT, "../.secrets");

// Minimal .env loader (service/.env, never committed).
const envFile = resolve(SERVICE_ROOT, ".env");
if (existsSync(envFile)) {
  for (const line of readFileSync(envFile, "utf8").split(/\r?\n/)) {
    const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
    if (m && process.env[m[1]!] === undefined) process.env[m[1]!] = m[2]!.replace(/^"|"$/g, "");
  }
}

const secret = (name: string) => {
  const file = resolve(SECRETS, name);
  return existsSync(file) ? readFileSync(file, "utf8").trim() : undefined;
};

function rpcUrl(): string {
  if (process.env.RPC_URL) return process.env.RPC_URL;
  const key = secret("alchemy.txt");
  return key ? `https://base-mainnet.g.alchemy.com/v2/${key}` : "https://mainnet.base.org";
}

const alchemyKey = secret("alchemy.txt");

export const config = {
  port: Number(process.env.PORT ?? 8787),
  chainId: Number(process.env.CHAIN_ID ?? 8453),
  rpcUrl: rpcUrl(),
  pool: (process.env.POOL_ADDRESS ?? "") as Hex,
  poolDeployBlock: BigInt(process.env.POOL_DEPLOY_BLOCK ?? 0),
  token: (process.env.TOKEN ?? "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913") as Hex,
  relayerKey: (process.env.RELAYER_PRIVATE_KEY ?? secret("relayer.key") ?? "") as Hex,
  // Current transact fee. Starts at the floor and is refreshed every 60 s by fees.ts (startFeeUpdater), which
  // also keeps this field in sync so every consumer (state serialization, /v1/info, prepare checks) sees the live fee.
  relayerFee: BigInt(process.env.RELAYER_FEE ?? 10_000),
  relayerFeeFloor: BigInt(process.env.RELAYER_FEE ?? 10_000), // 0.01 USDC minimum for transact and shield
  aspDelaySeconds: Number(process.env.ASP_DELAY_SECONDS ?? 0),
  // Manual denylist (ASP_DENYLIST) merged with the vendored OFAC SDN list: sanctioned depositors are never approved.
  aspDenylist: new Set([...(process.env.ASP_DENYLIST ?? "").toLowerCase().split(",").map((a) => a.trim()).filter(Boolean), ...sanctionedAddresses()]),
  // Optional shared secret. When set, every route except /health and /verify* requires "Authorization: Bearer <token>".
  // The PayBox portal injects it as a host-scoped `Authorization` secret, so agents never see the token.
  serviceToken: process.env.SERVICE_TOKEN ?? secret("service-token.txt"),
  x402MaxAmount: BigInt(process.env.X402_MAX_AMOUNT ?? 1_000_000), // 1 USDC per request
  // The exposure scan needs Alchemy's alchemy_getAssetTransfers.
  exposureRpcUrl: alchemyKey ? `https://base-mainnet.g.alchemy.com/v2/${alchemyKey}` : (process.env.RPC_URL ?? "https://mainnet.base.org").split(",")[0]!.trim(),
  // Persisted prepared spends + jobs (store.ts). Override for side-by-side test instances.
  stateFile: resolve(SERVICE_ROOT, process.env.STATE_FILE ?? "data/state.json"),
  // Per-client-IP request budget on /v1/* (fixed 60 s window).
  rateLimitPerMin: Number(process.env.RATE_LIMIT_PER_MIN ?? 60),
  circuitPath: process.env.CIRCUIT_PATH ?? resolve(REPO_ROOT, "circuits/transact/target/transact.json"),
};
