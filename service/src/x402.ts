// Minimal x402 client: the relayer is the payer of record. Supports v1 (JSON body `accepts`, X-PAYMENT /
// X-PAYMENT-RESPONSE headers) and v2 (PAYMENT-REQUIRED / PAYMENT-SIGNATURE / PAYMENT-RESPONSE headers),
// "exact" scheme with an EIP-3009 TransferWithAuthorization on Base USDC.
// Manual encoder on purpose: the official clients (@x402/core + @x402/evm 2.28.0, x402 1.2.0) would add deps
// (zod, @x402/core) to the node_modules a running production instance loads lazily from. Shapes follow the specs:
//   v2 PAYMENT-SIGNATURE = base64(JSON {x402Version: 2, resource, accepted: <chosen requirement verbatim>, payload})
//   v1 X-PAYMENT         = base64(JSON {x402Version: 1, scheme: "exact", network: "base", payload})
//   payload = {signature, authorization: {from, to, value, validAfter, validBefore, nonce}} (all strings)
import { randomBytes } from "node:crypto";
import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";
import { bytesToHex, getAddress, parseAbi, parseSignature, type Hex } from "viem";
import { config } from "./config.js";
import { isSanctioned } from "./ofac.js";
import { publicClient, relayerAccount, walletClient } from "./indexer.js";

export type X402Request = { url: string; method: "GET" | "POST"; body?: unknown };
export type Requirement = {
  scheme: string; network: string; asset: string; payTo: string; maxTimeoutSeconds?: number;
  amount?: string; maxAmountRequired?: string; extra?: { name?: string; version?: string }; resource?: string;
  [key: string]: unknown;
};
export type X402Quote = { version: number; requirement: Requirement; price: bigint; resource?: unknown; payTo: Hex };
export type Settlement = { success?: boolean; transaction?: string; network?: string; payer?: string; errorReason?: string };
export type X402Payment = {
  status: number; contentType: string; body: string; paymentResponse?: string;
  settlement?: Settlement; settlementTx?: Hex; nonce: Hex; validBefore: string;
};

export const usdcAbi = parseAbi([
  "function name() view returns (string)",
  "function version() view returns (string)",
  "function authorizationState(address authorizer, bytes32 nonce) view returns (bool)",
  "function cancelAuthorization(address authorizer, bytes32 nonce, uint8 v, bytes32 r, bytes32 s)",
]);

/** Cached EIP-712 domain of config.token, read on-chain (the token verifies signatures against these values). */
let domainCache: Promise<{ name: string; version: string }> | undefined;
function onchainTokenDomain() {
  domainCache ??= Promise.all([
    publicClient.readContract({ address: config.token, abi: usdcAbi, functionName: "name" }),
    publicClient.readContract({ address: config.token, abi: usdcAbi, functionName: "version" }),
  ]).then(([name, version]) => ({ name, version }), (err) => { domainCache = undefined; throw err; });
  return domainCache;
}

/** Network seams, overridable in tests. */
export const x402Deps = {
  fetch: (input: string, init?: RequestInit) => fetch(input, init),
  lookup: async (host: string): Promise<string[]> => (await lookup(host, { all: true, verbatim: true })).map((a) => a.address),
  tokenDomain: onchainTokenDomain,
};

const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64");
const isBaseUsdc = (r: Requirement) =>
  r?.scheme === "exact" && (r.network === "base" || r.network === `eip155:${config.chainId}`)
  && typeof r.asset === "string" && r.asset.toLowerCase() === config.token.toLowerCase();

// ---------------------------------------------------------------------------------------------
// SSRF guards. The service fetches user-supplied URLs, so both the literal host and every address it
// resolves to must be public. Residual risk: DNS rebinding (fetch re-resolves after our check; a hostile
// resolver can answer differently the second time). Redirects are not followed, which closes the
// redirect-to-internal variant; full pinning would need a custom undici dispatcher (not bundled here).
// ---------------------------------------------------------------------------------------------
const blocked = new BlockList();
for (const [net, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
  ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) blocked.addSubnet(net, prefix, "ipv4");
for (const [net, prefix] of [
  ["::", 128], ["::1", 128], ["fc00::", 7], ["fe80::", 10], ["fec0::", 10], ["ff00::", 8], ["2001:db8::", 32],
  ["64:ff9b::", 96], ["64:ff9b:1::", 48], ["100::", 64], ["2001::", 32], ["2002::", 16],
] as const) blocked.addSubnet(net, prefix, "ipv6");

export function isPrivateAddress(address: string): boolean {
  const ip = address.replace(/^\[|\]$/g, "").split("%")[0]!;
  const family = isIP(ip);
  if (family === 4) return blocked.check(ip, "ipv4");
  if (family === 6) {
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
    if (mapped) return blocked.check(mapped[1]!, "ipv4");
    if (/^::ffff:/i.test(ip)) return true; // hex-form IPv4-mapped: refuse rather than decode
    return blocked.check(ip, "ipv6");
  }
  return true; // not an IP at all: refuse
}

/** Refuses URLs that point at this machine or private networks (the service fetches them). */
export function assertPublicUrl(raw: string): URL {
  const url = new URL(raw);
  if (url.protocol !== "https:" || (url.port && url.port !== "443") || url.username || url.password) throw new Error("x402 endpoints must be plain HTTPS on port 443.");
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal") || host.includes(":")
    || (isIP(host) === 4 && isPrivateAddress(host)) || !host.includes(".")) {
    throw new Error("x402 endpoint must be a public hostname.");
  }
  return url;
}

/** assertPublicUrl plus DNS: every resolved address must be public. */
export async function assertPublicHost(raw: string): Promise<URL> {
  const url = assertPublicUrl(raw);
  const host = url.hostname.toLowerCase();
  const addresses = isIP(host) ? [host] : await x402Deps.lookup(host).catch(() => [] as string[]);
  if (addresses.length === 0) throw new Error(`x402 endpoint host ${host} does not resolve.`);
  if (addresses.some(isPrivateAddress)) throw new Error("x402 endpoint resolves to a private or reserved address.");
  return url;
}

function init(req: X402Request, extra: Record<string, string> = {}): RequestInit {
  const headers: Record<string, string> = { accept: "application/json", ...extra };
  if (req.method === "POST") headers["content-type"] = "application/json";
  return {
    method: req.method, headers, body: req.method === "POST" ? JSON.stringify(req.body ?? {}) : undefined,
    redirect: "manual", signal: AbortSignal.timeout(15_000),
  };
}

const decodeB64Json = (value: string) => JSON.parse(Buffer.from(value.trim(), "base64").toString("utf8"));

export async function quoteX402(req: X402Request): Promise<X402Quote | { free: true; status: number }> {
  await assertPublicHost(req.url);
  const res = await x402Deps.fetch(req.url, init(req));
  const discard = () => void res.body?.cancel().catch(() => undefined);
  if (res.status >= 300 && res.status < 400) { discard(); throw new Error(`x402 endpoint redirected (HTTP ${res.status}); use the final URL.`); }
  if (res.status !== 402) { discard(); return { free: true, status: res.status }; }
  let doc: { x402Version?: number; accepts?: Requirement[]; resource?: unknown };
  const header = res.headers.get("payment-required");
  try {
    if (header) { discard(); doc = { x402Version: 2, ...decodeB64Json(header) }; }
    else doc = (await res.json()) as typeof doc;
  } catch {
    throw new Error("Endpoint answered 402 without a readable payment requirement.");
  }
  const requirement = (Array.isArray(doc.accepts) ? doc.accepts : []).find(isBaseUsdc);
  if (!requirement) throw new Error("The endpoint does not accept exact USDC on Base.");
  const raw = requirement.amount ?? requirement.maxAmountRequired ?? "0";
  if (!/^\d{1,30}$/.test(String(raw))) throw new Error("Endpoint quoted a malformed price.");
  const price = BigInt(raw);
  if (price <= 0n) throw new Error("Endpoint quoted a zero price.");
  if (price > config.x402MaxAmount) throw new Error(`Price ${price} exceeds the relayer's per-request cap ${config.x402MaxAmount}.`);
  if (isSanctioned(requirement.payTo)) throw new Error("The x402 payee is on the OFAC SDN list; the relayer will not pay it.");
  // The token checks the signature against its own EIP-712 domain; a requirement advertising another
  // name/version would make the merchant's facilitator reject (or mis-verify) the authorization.
  const domain = await x402Deps.tokenDomain();
  if ((requirement.extra?.name !== undefined && requirement.extra.name !== domain.name)
    || (requirement.extra?.version !== undefined && requirement.extra.version !== domain.version)) {
    throw new Error(`Endpoint's USDC EIP-712 domain (${requirement.extra?.name}/${requirement.extra?.version}) does not match the token (${domain.name}/${domain.version}).`);
  }
  return { version: doc.x402Version === 2 ? 2 : 1, requirement, price, resource: doc.resource, payTo: getAddress(requirement.payTo) };
}

/** Why a fresh quote no longer matches the one the user signed for, or undefined when it still does. */
export function requoteMismatch(stored: X402Quote, fresh: X402Quote | { free: true; status: number }): string | undefined {
  if ("free" in fresh) return `The endpoint no longer asks for payment (HTTP ${fresh.status}); nothing was spent. Fetch it directly or prepare again.`;
  if (fresh.price !== stored.price) return `The x402 price changed from ${stored.price} to ${fresh.price} atomic USDC; nothing was spent. Prepare again.`;
  if (fresh.payTo.toLowerCase() !== stored.payTo.toLowerCase()) return `The x402 payee changed from ${stored.payTo} to ${fresh.payTo}; nothing was spent. Prepare again.`;
  return undefined;
}

/** Re-quotes right before the spend is relayed. Never throws: failures become a mismatch reason. */
export async function requote(req: X402Request, stored: X402Quote): Promise<{ quote: X402Quote } | { mismatch: string }> {
  try {
    const fresh = await quoteX402(req);
    const mismatch = requoteMismatch(stored, fresh);
    return mismatch ? { mismatch } : { quote: fresh as X402Quote };
  } catch (err) {
    return { mismatch: `Could not re-quote the x402 endpoint (${String((err as Error).message ?? err).split("\n")[0]!.slice(0, 200)}); nothing was spent. Prepare again.` };
  }
}

export type PaymentPayload = {
  signature: Hex;
  authorization: { from: Hex; to: Hex; value: string; validAfter: string; validBefore: string; nonce: Hex };
};

/** The request header carrying the payment, per x402 version. */
export function encodePaymentHeader(quote: X402Quote, payload: PaymentPayload): { name: string; value: string } {
  return quote.version >= 2
    ? { name: "PAYMENT-SIGNATURE", value: b64({ x402Version: 2, resource: quote.resource, accepted: quote.requirement, payload }) }
    : { name: "X-PAYMENT", value: b64({ x402Version: 1, scheme: "exact", network: "base", payload }) };
}

/** Parses PAYMENT-RESPONSE (v2) / X-PAYMENT-RESPONSE (v1): base64 JSON settlement receipt. */
export function parsePaymentResponse(value: string | null | undefined): { settlement?: Settlement; settlementTx?: Hex } {
  if (!value) return {};
  try {
    const doc = decodeB64Json(value) as Record<string, unknown>;
    const settlement: Settlement = {
      success: typeof doc.success === "boolean" ? doc.success : undefined,
      transaction: typeof doc.transaction === "string" ? doc.transaction : undefined,
      network: typeof doc.network === "string" ? doc.network : undefined,
      payer: typeof doc.payer === "string" ? doc.payer : undefined,
      errorReason: typeof doc.errorReason === "string" ? doc.errorReason.slice(0, 200) : undefined,
    };
    const tx = [doc.transaction, doc.txHash, doc.transactionHash].find((v) => typeof v === "string" && /^0x[0-9a-fA-F]{64}$/.test(v)) as Hex | undefined;
    return { settlement, settlementTx: tx };
  } catch {
    return {};
  }
}

export async function payX402(req: X402Request, quote: X402Quote): Promise<X402Payment> {
  if (!relayerAccount) throw new Error("Relayer key not configured.");
  await assertPublicHost(req.url);
  const domain = await x402Deps.tokenDomain();
  const now = Math.floor(Date.now() / 1000);
  const authorization = {
    from: relayerAccount.address,
    to: quote.payTo,
    value: quote.price,
    validAfter: BigInt(now - 600),
    validBefore: BigInt(now + Math.min(Math.max(Number(quote.requirement.maxTimeoutSeconds ?? 120) || 120, 30), 3600)),
    nonce: bytesToHex(randomBytes(32)) as Hex,
  };
  const signature = await relayerAccount.signTypedData({
    domain: { name: domain.name, version: domain.version, chainId: config.chainId, verifyingContract: getAddress(config.token) },
    types: {
      TransferWithAuthorization: [
        { name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" },
        { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" },
      ],
    },
    primaryType: "TransferWithAuthorization",
    message: authorization,
  });
  const payload: PaymentPayload = {
    signature,
    authorization: { ...authorization, value: authorization.value.toString(), validAfter: authorization.validAfter.toString(), validBefore: authorization.validBefore.toString() },
  };
  const header = encodePaymentHeader(quote, payload);
  const base = { nonce: authorization.nonce, validBefore: authorization.validBefore.toString() };
  let res: Response;
  try {
    res = await x402Deps.fetch(req.url, init(req, { [header.name]: header.value }));
  } catch (err) {
    throw Object.assign(new Error(`merchant request failed after signing payment: ${String((err as Error).message ?? err).split("\n")[0]}`), { payment: base });
  }
  const text = await res.text().catch(() => "");
  const paymentResponse = res.headers.get("payment-response") ?? res.headers.get("x-payment-response") ?? undefined;
  return {
    ...base,
    status: res.status,
    contentType: res.headers.get("content-type") ?? "",
    body: text.length > 48_000 ? `${text.slice(0, 48_000)}…[truncated]` : text,
    paymentResponse,
    ...parsePaymentResponse(paymentResponse),
  };
}

/** True once an EIP-3009 authorization nonce was used (merchant settled) or canceled. */
export async function authorizationUsed(nonce: Hex): Promise<boolean> {
  if (!relayerAccount) throw new Error("Relayer key not configured.");
  return publicClient.readContract({ address: config.token, abi: usdcAbi, functionName: "authorizationState", args: [relayerAccount.address, nonce] });
}

/**
 * Makes sure an unsettled authorization can never be settled later (so a refund cannot be double-paid):
 * returns "used" if the merchant already settled it, "canceled" once cancelAuthorization is mined.
 * Call inside withRelayerLock.
 */
export async function voidAuthorization(nonce: Hex): Promise<"used" | "canceled"> {
  if (!relayerAccount || !walletClient) throw new Error("Relayer key not configured.");
  if (await authorizationUsed(nonce)) return "used";
  const domain = await x402Deps.tokenDomain();
  const sig = await relayerAccount.signTypedData({
    domain: { name: domain.name, version: domain.version, chainId: config.chainId, verifyingContract: getAddress(config.token) },
    types: { CancelAuthorization: [{ name: "authorizer", type: "address" }, { name: "nonce", type: "bytes32" }] },
    primaryType: "CancelAuthorization",
    message: { authorizer: relayerAccount.address, nonce },
  });
  const { r, s, yParity } = parseSignature(sig);
  try {
    const { request } = await publicClient.simulateContract({
      account: relayerAccount, address: config.token, abi: usdcAbi, functionName: "cancelAuthorization",
      args: [relayerAccount.address, nonce, 27 + (yParity ?? 0), r, s],
    });
    const hash = await walletClient.writeContract(request);
    const receipt = await publicClient.waitForTransactionReceipt({ hash, timeout: 60_000 });
    if (receipt.status === "success") return "canceled";
  } catch (err) {
    if (await authorizationUsed(nonce).catch(() => false)) return "used";
    throw err;
  }
  if (await authorizationUsed(nonce)) return "used";
  throw new Error("cancelAuthorization did not take effect");
}
