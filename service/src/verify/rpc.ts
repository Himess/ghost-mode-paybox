// Minimal JSON-RPC ChainReader for the verification page: serialized requests (one at a
// time, lightly paced), de-duplicated by (method, params), with fallback endpoints.
import { RpcUnavailableError, type ChainReader, type RpcBlock, type RpcReceipt } from "./core.js";

export const DEFAULT_RPCS: Record<number, string[]> = {
  8453: ["https://mainnet.base.org", "https://base-rpc.publicnode.com"],
};

export function defaultRpcUrls(chainId: number): string[] {
  return DEFAULT_RPCS[chainId] ?? [];
}

type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body: string; signal?: AbortSignal }) => Promise<{
  ok: boolean; status: number; json(): Promise<unknown>;
}>;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export class JsonRpcReader implements ChainReader {
  private active = 0;
  private queue: Promise<unknown> = Promise.resolve();
  private cache = new Map<string, Promise<unknown>>();
  private lastSent = 0;
  private id = 1;
  requests = 0;

  constructor(
    private readonly urls: string[],
    private readonly opts: { fetch?: FetchLike; timeoutMs?: number; minIntervalMs?: number; onRequest?: (count: number, url: string) => void } = {},
  ) {
    if (!urls.length) throw new Error("No RPC endpoint configured.");
  }

  describe(): string {
    return this.urls[this.active]!;
  }

  chainId(): Promise<number> {
    return this.call<string>("eth_chainId", []).then((h) => Number(BigInt(h)));
  }
  getReceipt(txHash: string): Promise<RpcReceipt | null> {
    return this.call<RpcReceipt | null>("eth_getTransactionReceipt", [txHash.toLowerCase()]);
  }
  getBlock(blockNumber: string): Promise<RpcBlock | null> {
    return this.call<RpcBlock | null>("eth_getBlockByNumber", [`0x${BigInt(blockNumber).toString(16)}`, false]);
  }

  call<T>(method: string, params: unknown[]): Promise<T> {
    const key = `${method}:${JSON.stringify(params)}`;
    const hit = this.cache.get(key);
    if (hit) return hit as Promise<T>;
    const run = this.queue.then(() => this.send(method, params));
    this.queue = run.catch(() => undefined);
    // A null receipt may simply not be indexed yet; do not cache failures.
    run.catch(() => this.cache.delete(key));
    this.cache.set(key, run);
    return run as Promise<T>;
  }

  private async send(method: string, params: unknown[]): Promise<unknown> {
    const errors: string[] = [];
    for (let i = this.active; i < this.urls.length; i++) {
      const url = this.urls[i]!;
      for (let attemptNo = 0; attemptNo < 3; attemptNo++) {
        try {
          const result = await this.post(url, method, params);
          this.active = i;
          return result;
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          const rateLimited = /429|rate|limit|too many/i.test(msg);
          if (rateLimited && attemptNo < 2) {
            await sleep(800 * (attemptNo + 1));
            continue;
          }
          errors.push(`${hostOf(url)}: ${msg}`);
          break;
        }
      }
    }
    throw new RpcUnavailableError(`RPC unreachable (${errors.join("; ")})`);
  }

  private async post(url: string, method: string, params: unknown[]): Promise<unknown> {
    const gap = (this.opts.minIntervalMs ?? 120) - (Date.now() - this.lastSent);
    if (gap > 0) await sleep(gap);
    this.lastSent = Date.now();
    this.requests++;
    this.opts.onRequest?.(this.requests, url);
    const f: FetchLike = this.opts.fetch ?? ((u, init) => fetch(u, init));
    const ctrl = typeof AbortController !== "undefined" ? new AbortController() : undefined;
    const timer = setTimeout(() => ctrl?.abort(), this.opts.timeoutMs ?? 15000);
    let res;
    try {
      res = await f(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: this.id++, method, params }),
        signal: ctrl?.signal,
      });
    } catch (e) {
      const aborted = e instanceof Error && e.name === "AbortError";
      throw new Error(aborted ? "request timed out" : `network error (${e instanceof Error ? e.message : String(e)}; the node may be down or block browser requests)`);
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      throw new Error("invalid JSON response");
    }
    const b = body as { result?: unknown; error?: { code?: number; message?: string } };
    if (b && b.error) throw new Error(`JSON-RPC error ${b.error.code ?? ""} ${String(b.error.message ?? "").slice(0, 160)}`.trim());
    if (!b || !("result" in b)) throw new Error("malformed JSON-RPC response");
    return b.result;
  }
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
