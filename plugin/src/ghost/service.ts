// Thin HTTPS client for the Ghost Mode service (indexer, prover, relayer, ASP).
// The base URL is a non-secret environment variable configured in the PayBox portal.
import type { Hex } from "viem";
import type { PoolState } from "../core/spend.js";

export class ServiceError extends Error {}

export function serviceUrl(): string {
  const raw = process.env.GHOST_SERVICE_URL?.trim();
  if (!raw) throw new ServiceError("GHOST_SERVICE_URL is not configured for this plugin. Set it in the PayBox developer portal.");
  const url = new URL(raw);
  const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !(local && url.protocol === "http:")) throw new ServiceError("GHOST_SERVICE_URL must use HTTPS.");
  return url.origin;
}

async function call<T>(path: string, init?: { method?: "GET" | "POST"; body?: unknown; timeoutMs?: number }): Promise<T> {
  const res = await fetch(`${serviceUrl()}${path}`, {
    method: init?.method ?? "GET",
    headers: { accept: "application/json", ...(init?.body === undefined ? {} : { "content-type": "application/json" }) },
    body: init?.body === undefined ? undefined : JSON.stringify(init.body),
    signal: AbortSignal.timeout(init?.timeoutMs ?? 6_000),
  }).catch((err: Error) => {
    throw new ServiceError(`Ghost service unreachable (${err.name === "TimeoutError" ? "timeout" : err.message}).`);
  });
  const text = await res.text();
  let data: any;
  try { data = text ? JSON.parse(text) : {}; } catch { throw new ServiceError(`Ghost service returned non-JSON (HTTP ${res.status}).`); }
  if (!res.ok) throw new ServiceError(String(data?.error ?? `HTTP ${res.status}`));
  return data as T;
}

export type ServiceInfo = { chainId: number; pool: Hex; token: Hex; relayer: Hex; relayerFee: string; x402MaxAmount: string };

export async function getInfo(): Promise<ServiceInfo> {
  const info = await call<ServiceInfo>("/v1/info");
  const pinned = process.env.GHOST_POOL_ADDRESS?.trim();
  if (pinned && pinned.toLowerCase() !== info.pool.toLowerCase()) throw new ServiceError("Service pool does not match the pinned GHOST_POOL_ADDRESS.");
  return info;
}

export async function getState(): Promise<PoolState> {
  const s = await call<any>("/v1/state", { timeoutMs: 7_000 });
  const pinned = process.env.GHOST_POOL_ADDRESS?.trim();
  if (pinned && pinned.toLowerCase() !== String(s.pool).toLowerCase()) throw new ServiceError("Service pool does not match the pinned GHOST_POOL_ADDRESS.");
  if (!s.pool || !s.relayer) throw new ServiceError("Ghost pool is not deployed or the relayer is offline.");
  return {
    chainId: s.chainId, pool: s.pool, token: s.token, relayer: s.relayer, relayerFee: BigInt(s.relayerFee), root: BigInt(s.root),
    leaves: s.leaves.map((l: any) => ({ ...l, commitment: BigInt(l.commitment) })),
    deposits: s.deposits.map((d: any) => ({ ...d, label: BigInt(d.label), amount: BigInt(d.amount) })),
    nullifiers: new Set<string>(s.nullifiers),
    pending: new Set<string>(Array.isArray(s.pendingTags) ? s.pendingTags.map(String) : []),
    asp: { root: BigInt(s.asp.root), labels: s.asp.labels.map((l: string) => BigInt(l)) },
  };
}

export const quoteX402 = (body: { url: string; method: string; body?: unknown }) =>
  call<{ free?: boolean; status?: number; version?: number; price?: string; payTo?: Hex; network?: string }>("/v1/x402/quote", { method: "POST", body, timeoutMs: 7_000 });
export const prepare = (body: unknown) => call<{ prepare_id: string; expires_at: string }>("/v1/prepare", { method: "POST", body, timeoutMs: 7_000 });
export const submit = (body: { prepare_id: string; signature: Hex }) => call<{ job_id: string }>("/v1/submit", { method: "POST", body, timeoutMs: 8_500 });
export const getJob = (jobId: string) => call<any>(`/v1/jobs/${jobId}`, { timeoutMs: 8_500 });
export const exposure = (address: Hex, message: string, signature: Hex) =>
  call<any>("/v1/exposure", { method: "POST", body: { address, message, signature }, timeoutMs: 8_500 });

// Single-signature shield (GhostPool v2) and helpers.
export type ShieldInfo = { chainId: number; pool: Hex; token: Hex; relayer: Hex | null; fee: string; usdcName: string; usdcVersion: string; supported: boolean; maxDeposit: string };
export const shieldInfo = () => call<ShieldInfo>("/v1/shield/info", { timeoutMs: 7_000 });
export const shieldPrepare = (pkg: unknown) =>
  call<{ prepare_id: string; expires_at: string; typedData: any }>("/v1/shield/prepare", { method: "POST", body: { package: pkg }, timeoutMs: 7_000 });
export const shieldSubmit = (body: { prepare_id: string; signature: Hex }) => call<{ job_id: string }>("/v1/shield/submit", { method: "POST", body, timeoutMs: 8_500 });
export const getShieldJob = (jobId: string) => call<any>(`/v1/shield/jobs/${jobId}`, { timeoutMs: 8_500 });
export const verifyUrl = (pkg: unknown) => `${serviceUrl()}/verify#pkg=${Buffer.from(JSON.stringify(pkg)).toString("base64url")}`;
export const backupKey = (body: { ghost_key: string; message: string; signature: Hex }) =>
  call<{ backed_up: boolean; keys_for_wallet: number }>("/v1/keys/backup", { method: "POST", body, timeoutMs: 6_000 });
export const recoverKeys = (body: { address: Hex; message: string; signature: Hex }) =>
  call<{ ghost_keys: string[]; created_at: string[] }>("/v1/keys/recover", { method: "POST", body, timeoutMs: 6_000 });
