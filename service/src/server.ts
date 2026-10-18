// Ghost Mode service: indexer + ASP + prover + relayer + x402 payer + exposure scan.
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createHash, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import { getAddress, isAddress, recoverMessageAddress, type Hex } from "viem";
import { refreshAsp } from "./asp.js";
import { config } from "./config.js";
import { relayerAccount, serializeState, state, sync } from "./indexer.js";
import { feeAcceptable, relayerFees, startFeeUpdater } from "./fees.js";
import { cleanError, getJob, storePrepared, submit, pendingTags } from "./jobs.js";
import { ofacListInfo } from "./ofac.js";
import { warmProver } from "./prover.js";
import { extraRoute } from "./routes.js";
import { assertPublicUrl, quoteX402, type X402Request } from "./x402.js";

const json = (res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) => {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", ...headers });
  res.end(JSON.stringify(body, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));
};

async function readBody(req: IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > 512 * 1024) throw new Error("Request body too large.");
    chunks.push(chunk as Buffer);
  }
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {};
}

function x402Request(body: any): X402Request {
  const url = assertPublicUrl(String(body?.url ?? ""));
  const method = body?.method === "POST" ? "POST" : "GET";
  return { url: url.toString(), method, body: method === "POST" ? body?.body ?? {} : undefined };
}

// Per-client-IP fixed-window rate limit on /v1/*. Behind Cloudflare the client IP is cf-connecting-ip; if the
// origin is reachable directly that header can be spoofed, so firewall the origin to Cloudflare ranges.
const RATE_WINDOW_MS = 60_000;
const hits = new Map<string, { count: number; resetAt: number }>();
function clientIp(req: IncomingMessage): string {
  const raw = req.headers["cf-connecting-ip"];
  const cf = (Array.isArray(raw) ? raw[0] : raw)?.trim();
  return cf && isIP(cf) ? cf : req.socket.remoteAddress ?? "unknown";
}
/** Seconds until the window resets when the client is over budget, else undefined. */
function rateLimited(req: IncomingMessage): number | undefined {
  if (!(config.rateLimitPerMin > 0)) return undefined;
  const now = Date.now();
  const ip = clientIp(req);
  let bucket = hits.get(ip);
  if (!bucket || bucket.resetAt <= now) {
    if (hits.size >= 10_000) for (const [k, v] of hits) if (v.resetAt <= now) hits.delete(k);
    bucket = { count: 0, resetAt: now + RATE_WINDOW_MS };
    hits.set(ip, bucket);
  }
  bucket.count++;
  return bucket.count > config.rateLimitPerMin ? Math.max(1, Math.ceil((bucket.resetAt - now) / 1000)) : undefined;
}

/** Constant-time Bearer token check (hashing first equalises lengths). */
function tokenMatches(header: string | undefined): boolean {
  const digest = (v: string) => createHash("sha256").update(v).digest();
  return timingSafeEqual(digest(header ?? ""), digest(`Bearer ${config.serviceToken}`));
}

async function route(req: IncomingMessage, res: ServerResponse) {
  const url = new URL(req.url ?? "/", "http://localhost");
  if (url.pathname === "/health") return json(res, 200, { ok: true });
  // The disclosure verification page is public (auditors open it in a browser); everything else may require the token.
  const isPublic = url.pathname === "/verify" || url.pathname.startsWith("/verify/");
  if (url.pathname.startsWith("/v1/")) {
    const retryAfter = rateLimited(req);
    if (retryAfter) return json(res, 429, { error: "rate limited", retryAfterSeconds: retryAfter }, { "retry-after": String(retryAfter) });
  }
  // SERVICE_TOKEN is optional. The PayBox portal injects it as a host-scoped `Authorization` secret
  // ("Bearer <token>") on calls to this host, so agents and plugin code never see the token itself.
  if (!isPublic && config.serviceToken && !tokenMatches(req.headers.authorization)) return json(res, 401, { error: "unauthorized" });

  if (req.method === "GET" && url.pathname === "/v1/info") {
    const fees = relayerFees();
    return json(res, 200, {
      chainId: config.chainId, pool: config.pool, token: config.token, relayer: relayerAccount?.address,
      relayerFee: fees.transact, fees: { transact: fees.transact, shield: fees.shield, ethUsd: fees.ethUsd },
      x402MaxAmount: config.x402MaxAmount, ofac: ofacListInfo(),
    });
  }
  if (req.method === "GET" && url.pathname === "/v1/state") {
    await sync();
    return json(res, 200, { ...serializeState(), pendingTags: pendingTags() });
  }
  if (req.method === "POST" && url.pathname === "/v1/x402/quote") {
    const quote = await quoteX402(x402Request(await readBody(req)));
    if ("free" in quote) return json(res, 200, { free: true, status: quote.status });
    return json(res, 200, { version: quote.version, price: quote.price, payTo: quote.payTo, network: quote.requirement.network, asset: quote.requirement.asset });
  }
  if (req.method === "POST" && url.pathname === "/v1/prepare") {
    const body = await readBody(req);
    let x402;
    if (body.x402) {
      const request = x402Request(body.x402);
      const quote = await quoteX402(request);
      if ("free" in quote) throw new Error("That endpoint did not ask for payment (no HTTP 402).");
      const pkg = body.package;
      if (quote.price.toString() !== String(pkg?.summary?.amount)) throw new Error("x402 price changed since the quote; prepare again.");
      // The relayer fronts the merchant payment, so the spend itself must pay it price + fee.
      if (pkg?.kind !== "pay_x402" || String(pkg?.tx?.recipient).toLowerCase() !== relayerAccount?.address.toLowerCase()
        || BigInt(pkg.tx.publicOut) - BigInt(pkg.tx.fee) < quote.price || !feeAcceptable(BigInt(pkg.tx.fee))) {
        throw new Error("x402 spend must pay the quoted price plus fee to the relayer.");
      }
      x402 = { request, quote };
    }
    // Optional randomized relay delay (unshield / pay_address only), validated and stored by storePrepared.
    return json(res, 200, storePrepared(body.package, x402, body.delaySeconds));
  }
  if (req.method === "POST" && url.pathname === "/v1/submit") {
    const body = await readBody(req);
    if (typeof body.prepare_id !== "string" || !/^0x[0-9a-fA-F]{128,130}$/.test(body.signature ?? "")) throw new Error("Need prepare_id and a 65-byte hex signature.");
    return json(res, 200, await submit(body.prepare_id, body.signature as Hex));
  }
  const jobMatch = /^\/v1\/jobs\/(job_[0-9a-f]{24})$/.exec(url.pathname);
  if (req.method === "GET" && jobMatch) {
    const job = getJob(jobMatch[1]!);
    return job ? json(res, 200, job) : json(res, 404, { error: "unknown job" });
  }
  if (req.method === "POST" && url.pathname === "/v1/exposure") {
    const body = await readBody(req);
    if (!isAddress(body.address ?? "")) throw new Error("Need an EVM address.");
    // Ownership proof, re-checked here so the scan cannot be pointed at someone else's wallet.
    const m = /^Ghost Mode exposure scan\nAddress: (0x[0-9a-fA-F]{40})\nIssued: (\S+)$/.exec(String(body.message ?? ""));
    const age = m ? Date.now() - Date.parse(m[2]!) : NaN;
    if (!m || m[1]!.toLowerCase() !== String(body.address).toLowerCase() || !(age >= -60_000 && age <= 15 * 60_000)) throw new Error("Need a fresh signed exposure challenge.");
    const signer = await recoverMessageAddress({ message: body.message, signature: body.signature as Hex });
    if (signer.toLowerCase() !== String(body.address).toLowerCase()) throw new Error("Challenge not signed by this address.");
    const { scanExposure } = await import("./exposure.js");
    return json(res, 200, await scanExposure(config.exposureRpcUrl, getAddress(body.address)));
  }
  if (await extraRoute(req, res, url)) return;
  return json(res, 404, { error: "not found" });
}

const server = createServer((req, res) => {
  // Access log without bodies or query strings (no keys, signatures or packages are logged).
  const started = Date.now();
  res.on("finish", () => {
    const path = (req.url ?? "/").split("?")[0]!.split("#")[0]!;
    if (path !== "/health") console.error(`[http] ${req.method} ${path} ${res.statusCode} ${Date.now() - started}ms`);
  });
  route(req, res).catch((err: Error) => {
    if (res.headersSent) return void res.end();
    // First line only, RPC URLs reduced to their host (they can embed API keys).
    json(res, 400, { error: cleanError((err?.message ?? String(err)).split("\n")[0]!, 500) });
  });
});

async function loop() {
  try {
    await sync(true);
    await refreshAsp();
  } catch (err) {
    console.error(`[loop] ${(err as Error).message.split("\n")[0]}`);
  }
  setTimeout(loop, 5_000);
}

server.listen(config.port, () => {
  console.error(`ghost service on :${config.port} pool=${config.pool || "(unset)"} relayer=${relayerAccount?.address ?? "(none)"} rpc=${config.rpcUrl.split(",").map((u) => new URL(u.trim()).host).join(",")}`);
  if (process.env.WARM_PROVER !== "0") void warmProver();
  void startFeeUpdater();
  void loop();
});
export { state };
