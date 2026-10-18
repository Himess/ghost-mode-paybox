// Ghost Mode disclosure verification: pure logic shared by the public verification page
// (src/verify/client.ts, bundled by src/verify/build.ts) and the Node tests (test/verify.ts).
//
// Everything here is deterministic given (package, chain data). Chain data comes from a
// ChainReader (JSON-RPC in the browser, a mock in tests); nothing else leaves the page.
import {
  decodeEventLog, encodeAbiParameters, getAddress, isAddress, keccak256, parseAbi, recoverTypedDataAddress, type Hex,
} from "viem";
import { poseidon1 } from "poseidon-lite/poseidon1";
import { poseidon2 } from "poseidon-lite/poseidon2";
import { poseidon4 } from "poseidon-lite/poseidon4";
import { poseidon5 } from "poseidon-lite/poseidon5";

// ---------------------------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------------------------
export const FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const BASE_CHAIN_ID = 8453;
export const USDC_DECIMALS = 6;
export const USDC_BY_CHAIN: Record<number, string> = { 8453: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" };
/** Official GhostPool deployments. Events from any other contract prove nothing. */
export const OFFICIAL_POOLS: Record<number, string[]> = {
  // GhostPool v3 (circuit v1.1, GhostSpend v1.1). v1/v2 used the earlier GhostSpend layout and hold no funds.
  8453: ["0x314eaade3e1a42627b5d2c6b1f87d0bbd67b8367"],
};
export const CHAIN_NAMES: Record<number, string> = { 8453: "Base", 31337: "local dev chain (anvil)" };
export const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

export const P1 = (a: bigint) => poseidon1([a]);
export const P2 = (a: bigint, b: bigint) => poseidon2([a, b]);
export const P4 = (a: bigint, b: bigint, c: bigint, d: bigint) => poseidon4([a, b, c, d]);
export const P5 = (a: bigint, b: bigint, c: bigint, d: bigint, e: bigint) => poseidon5([a, b, c, d, e]);

export const ghostPoolEvents = parseAbi([
  "event NewCommitment(uint256 indexed commitment, uint32 leafIndex, bytes encryptedOutput)",
  "event Deposited(address indexed depositor, uint256 indexed commitment, uint256 label, uint256 amount, uint32 leafIndex)",
  "event NewNullifier(uint256 indexed nullifier)",
  "event Transacted(address indexed relayer, address indexed recipient, uint256 publicOut, uint256 fee)",
]);
export const erc20TransferEvent = parseAbi(["event Transfer(address indexed from, address indexed to, uint256 value)"]);

/** GhostSpend v1.1 (circuit v1.1, GhostPool v3): hidden flow and public flow are signed separately. */
export const GHOST_SPEND_TYPE = [
  { name: "intent", type: "bytes32" },
  { name: "token", type: "address" },
  { name: "privateAmount", type: "uint256" },
  { name: "privateRecipient", type: "bytes32" },
  { name: "publicAmount", type: "uint256" },
  { name: "publicRecipient", type: "address" },
  { name: "fee", type: "uint256" },
  { name: "deadline", type: "uint256" },
] as const;
const EIP712_DOMAIN_TYPE = [
  { name: "name", type: "string" },
  { name: "version", type: "string" },
  { name: "chainId", type: "uint256" },
  { name: "verifyingContract", type: "address" },
] as const;

// ---------------------------------------------------------------------------------------------
// Package shapes
// ---------------------------------------------------------------------------------------------
export type Memo = Record<string, unknown>;

export type ReceiptPackage = {
  kind: "ghost-receipt";
  version: 1;
  chainId: number;
  pool: string;
  txHash: string;
  signer: string;
  signature: string;
  typedData: {
    domain: { name: string; version: string; chainId: number | string; verifyingContract: string };
    types: Record<string, { name: string; type: string }[]>;
    primaryType: string;
    message: { intent: string; token: string; privateAmount: string; privateRecipient: string; publicAmount: string; publicRecipient: string; fee: string; deadline: string };
  };
  nullifiers: [string, string];
  outCommitments: [string, string];
  memo?: Memo;
};

export type ReportNote = {
  leafIndex: number;
  txHash: string;
  commitment: string;
  amount: string;
  blinding: string;
  label: string;
  source: "deposit" | "transfer";
  time?: number | string;
  memo?: Memo;
};

export type ReportPackage = {
  kind: "ghost-report";
  version: 1;
  chainId: number;
  pool: string;
  token: string;
  walletAddress: string;
  pubKey: string;
  nkHash: string;
  ownerTag: string;
  period: { from: number | string; to: number | string };
  notes: ReportNote[];
};

export type DisclosurePackage = ReceiptPackage | ReportPackage;

export class PackageError extends Error {}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const need = (cond: unknown, msg: string): void => {
  if (!cond) throw new PackageError(msg);
};
const isUint = (v: unknown) => (typeof v === "string" && /^(\d+|0x[0-9a-fA-F]+)$/.test(v)) || (typeof v === "number" && Number.isSafeInteger(v) && v >= 0);
const isFieldStr = (v: unknown) => isUint(v) && BigInt(v as string) < FIELD_SIZE;
const isTxHash = (v: unknown) => typeof v === "string" && /^0x[0-9a-fA-F]{64}$/.test(v);
const isBytes32 = isTxHash;
const isAddr = (v: unknown) => typeof v === "string" && isAddress(v, { strict: false });

/** Validates the JSON shape (not the cryptography) and returns a typed package. */
export function parsePackage(input: unknown): DisclosurePackage {
  need(isObj(input), "The package is not a JSON object.");
  const p = input as Record<string, unknown>;
  need(p.kind === "ghost-receipt" || p.kind === "ghost-report", `Unknown package kind ${JSON.stringify(p.kind)}; expected "ghost-receipt" or "ghost-report".`);
  need(p.version === 1, `Unsupported package version ${JSON.stringify(p.version)}; this page understands version 1.`);
  need(typeof p.chainId === "number" && Number.isSafeInteger(p.chainId) && p.chainId > 0, "chainId must be a positive integer.");
  need(isAddr(p.pool), "pool must be a 0x address.");
  if (p.kind === "ghost-receipt") {
    need(isTxHash(p.txHash), "txHash must be a 0x-prefixed 32-byte hash.");
    need(isAddr(p.signer), "signer must be a 0x address.");
    need(typeof p.signature === "string" && /^0x[0-9a-fA-F]{128,130}$/.test(p.signature), "signature must be a 0x hex 64- or 65-byte signature.");
    const td = p.typedData;
    need(isObj(td) && isObj(td.domain) && isObj(td.types) && isObj(td.message), "typedData must contain domain, types and message.");
    const t = td as Record<string, Record<string, unknown>>;
    const m = t.message!;
    need(isBytes32(m.intent), "typedData.message.intent must be bytes32 hex.");
    need(isAddr(m.token) && isAddr(m.publicRecipient), "typedData.message.token and .publicRecipient must be addresses.");
    need(isUint(m.privateAmount) && isUint(m.publicAmount) && isUint(m.fee) && isUint(m.deadline), "typedData.message privateAmount, publicAmount, fee and deadline must be unsigned integers (decimal strings).");
    need(isBytes32(m.privateRecipient), "typedData.message.privateRecipient must be bytes32 hex.");
    need(Array.isArray(p.nullifiers) && p.nullifiers.length === 2 && p.nullifiers.every(isFieldStr), "nullifiers must be two decimal field elements.");
    need(Array.isArray(p.outCommitments) && p.outCommitments.length === 2 && p.outCommitments.every(isFieldStr), "outCommitments must be two decimal field elements.");
    need(p.memo === undefined || isObj(p.memo), "memo, when present, must be an object.");
    return p as unknown as ReceiptPackage;
  }
  need(isAddr(p.token), "token must be a 0x address.");
  need(isAddr(p.walletAddress), "walletAddress must be a 0x address.");
  need(typeof p.pubKey === "string" && /^0x(04)?[0-9a-fA-F]{128}$/.test(p.pubKey), "pubKey must be 0x + 128 hex (uncompressed secp256k1 key without the 04 prefix).");
  need(isFieldStr(p.nkHash) && isFieldStr(p.ownerTag), "nkHash and ownerTag must be decimal field elements.");
  need(isObj(p.period), "period must be an object {from, to}.");
  need(Array.isArray(p.notes), "notes must be an array.");
  (p.notes as unknown[]).forEach((n, i) => {
    need(isObj(n), `notes[${i}] must be an object.`);
    const note = n as Record<string, unknown>;
    need(typeof note.leafIndex === "number" && Number.isSafeInteger(note.leafIndex) && note.leafIndex >= 0, `notes[${i}].leafIndex must be a non-negative integer.`);
    need(isTxHash(note.txHash), `notes[${i}].txHash must be a 32-byte hash.`);
    need(isFieldStr(note.commitment) && isFieldStr(note.blinding) && isFieldStr(note.label), `notes[${i}] commitment, blinding and label must be decimal field elements.`);
    need(isUint(note.amount), `notes[${i}].amount must be an unsigned integer (atomic USDC, decimal string).`);
    need(note.source === "deposit" || note.source === "transfer", `notes[${i}].source must be "deposit" or "transfer".`);
    need(note.memo === undefined || isObj(note.memo), `notes[${i}].memo, when present, must be an object.`);
  });
  return p as unknown as ReportPackage;
}

/** Decodes the `pkg` fragment value: base64url (or base64) of UTF-8 JSON. */
export function decodePackageParam(value: string): unknown {
  let s = decodeURIComponent(value.trim()).replace(/\s/g, "").replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  let bin: string;
  try {
    bin = atob(s);
  } catch {
    throw new PackageError("The link's #pkg= value is not valid base64url.");
  }
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  const text = new TextDecoder().decode(bytes);
  try {
    return JSON.parse(text);
  } catch {
    throw new PackageError("The link's #pkg= value does not contain valid JSON.");
  }
}

/** base64url(JSON) — what the plugin should put after `#pkg=`. */
export function encodePackageParam(pkg: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(pkg));
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ---------------------------------------------------------------------------------------------
// Chain access
// ---------------------------------------------------------------------------------------------
export type RpcLog = { address: string; topics: string[]; data: string; logIndex?: string };
export type RpcReceipt = { status?: string; blockNumber: string; transactionHash: string; logs: RpcLog[] };
export type RpcBlock = { number?: string; timestamp: string };

export interface ChainReader {
  /** Human-readable description of the endpoint actually used (shown on the page). */
  describe(): string;
  chainId(): Promise<number>;
  getReceipt(txHash: string): Promise<RpcReceipt | null>;
  getBlock(blockNumber: string): Promise<RpcBlock | null>;
}

/** The RPC could not be reached or refused the request: the item is unverified, not disproved. */
export class RpcUnavailableError extends Error {}

// ---------------------------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------------------------
export type Status = "pass" | "fail" | "error" | "info";
export type Detail = { label: string; value: string; mono?: boolean };
export type Check = { id: string; title: string; status: Status; summary: string; details: Detail[] };
export type Verification = {
  kind: DisclosurePackage["kind"];
  ok: boolean;
  headline: string;
  scope?: string;
  checks: Check[];
  counts: { pass: number; fail: number; error: number };
  rpc: string;
};

export type VerifyOptions = { officialPools?: Record<number, string[]> };

// ---------------------------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------------------------
export function formatUsdc(atomic: bigint): string {
  const neg = atomic < 0n;
  const v = neg ? -atomic : atomic;
  const unit = 10n ** BigInt(USDC_DECIMALS);
  let frac = (v % unit).toString().padStart(USDC_DECIMALS, "0").replace(/0+$/, "");
  if (frac.length < 2) frac = frac.padEnd(2, "0");
  const whole = (v / unit).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  return `${neg ? "-" : ""}${whole}.${frac}`;
}
export const short = (hex: string, head = 6, tail = 4) => (hex.length > head + tail + 1 ? `${hex.slice(0, head)}…${hex.slice(-tail)}` : hex);
export const eqAddr = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();
const big = (v: string | number | bigint) => BigInt(v);
const isoTime = (sec: number) => new Date(sec * 1000).toISOString().replace(".000Z", "Z").replace("T", " ").replace("Z", " UTC");
const hex32 = (v: bigint) => `0x${v.toString(16).padStart(64, "0")}`;

/** Accepts unix seconds, unix milliseconds, numeric strings and ISO dates. Returns unix seconds or null. */
export function parseTime(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v > 1e12 ? Math.floor(v / 1000) : Math.floor(v);
  if (typeof v === "string" && v.trim()) {
    if (/^\d+$/.test(v.trim())) return parseTime(Number(v.trim()));
    const ms = Date.parse(v);
    return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
  }
  return null;
}

const MEMO_FIELDS = ["kind", "counterparty", "amount", "fee", "time", "host"] as const;
export function memoDetails(memo: Memo | undefined): Detail[] {
  if (!memo) return [];
  const out: Detail[] = [];
  const keys = [...MEMO_FIELDS.filter((k) => k in memo), ...Object.keys(memo).filter((k) => !(MEMO_FIELDS as readonly string[]).includes(k))];
  for (const k of keys) {
    const raw = memo[k];
    if (raw === undefined || raw === null) continue;
    let value = typeof raw === "string" ? raw : JSON.stringify(raw);
    if ((k === "amount" || k === "fee") && /^\d+$/.test(String(raw))) value = `${formatUsdc(BigInt(String(raw)))} USDC`;
    if (k === "time") {
      const t = parseTime(raw);
      if (t !== null) value = isoTime(t);
    }
    out.push({ label: `memo.${k} (not on-chain)`, value: value.slice(0, 300) });
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Log decoding
// ---------------------------------------------------------------------------------------------
type Decoded =
  | { i: number; kind: "nullifier"; nullifier: bigint }
  | { i: number; kind: "commitment"; commitment: bigint; leafIndex: number; encryptedOutput: Hex }
  | { i: number; kind: "deposit"; depositor: string; commitment: bigint; label: bigint; amount: bigint; leafIndex: number }
  | { i: number; kind: "transacted"; relayer: string; recipient: string; publicOut: bigint; fee: bigint }
  | { i: number; kind: "usdc"; from: string; to: string; value: bigint };

export function decodeReceiptLogs(receipt: RpcReceipt, pool: string, usdc: string | undefined): Decoded[] {
  const out: Decoded[] = [];
  receipt.logs.forEach((log, i) => {
    const fromPool = eqAddr(log.address, pool);
    const fromUsdc = !!usdc && eqAddr(log.address, usdc);
    if (!fromPool && !fromUsdc) return;
    try {
      const topics = log.topics as [Hex, ...Hex[]];
      if (fromPool) {
        const ev = decodeEventLog({ abi: ghostPoolEvents, data: log.data as Hex, topics });
        const a = ev.args as Record<string, unknown>;
        if (ev.eventName === "NewNullifier") out.push({ i, kind: "nullifier", nullifier: a.nullifier as bigint });
        else if (ev.eventName === "NewCommitment")
          out.push({ i, kind: "commitment", commitment: a.commitment as bigint, leafIndex: Number(a.leafIndex), encryptedOutput: a.encryptedOutput as Hex });
        else if (ev.eventName === "Deposited")
          out.push({ i, kind: "deposit", depositor: a.depositor as string, commitment: a.commitment as bigint, label: a.label as bigint, amount: a.amount as bigint, leafIndex: Number(a.leafIndex) });
        else if (ev.eventName === "Transacted")
          out.push({ i, kind: "transacted", relayer: a.relayer as string, recipient: a.recipient as string, publicOut: a.publicOut as bigint, fee: a.fee as bigint });
      } else {
        const ev = decodeEventLog({ abi: erc20TransferEvent, data: log.data as Hex, topics });
        const a = ev.args as Record<string, unknown>;
        out.push({ i, kind: "usdc", from: a.from as string, to: a.to as string, value: a.value as bigint });
      }
    } catch {
      // Other events of the pool (AspRootUpdated, …) or of USDC (Approval, …): not relevant.
    }
  });
  return out;
}

// ---------------------------------------------------------------------------------------------
// Check helpers
// ---------------------------------------------------------------------------------------------
type Fetched<T> = { ok: true; value: T } | { ok: false; error: string };
async function attempt<T>(fn: () => Promise<T>): Promise<Fetched<T>> {
  try {
    return { ok: true, value: await fn() };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { ok: false, error: e instanceof RpcUnavailableError ? msg : `RPC unreachable: ${msg}` };
  }
}
const rpcErrorCheck = (id: string, title: string, error: string, details: Detail[] = []): Check => ({
  id, title, status: "error", summary: `Could not verify — ${error}`, details,
});

function countChecks(checks: Check[]) {
  return {
    pass: checks.filter((c) => c.status === "pass").length,
    fail: checks.filter((c) => c.status === "fail").length,
    error: checks.filter((c) => c.status === "error").length,
  };
}

function networkCheck(chainId: number, reported: Fetched<number>, rpc: string): Check {
  const name = CHAIN_NAMES[chainId] ?? `chain ${chainId}`;
  const details: Detail[] = [{ label: "RPC endpoint", value: rpc, mono: true }, { label: "Package chainId", value: String(chainId) }];
  if (!reported.ok) return rpcErrorCheck("network", "Network", reported.error, details);
  details.push({ label: "RPC chainId", value: String(reported.value) });
  if (reported.value !== chainId)
    return { id: "network", title: "Network", status: "fail", summary: `The RPC is on chain ${reported.value}, but the package is for chain ${chainId}.`, details };
  return { id: "network", title: "Network", status: "pass", summary: `The RPC node reports ${name} (chain ${chainId}), as the package states.`, details };
}

function poolCheck(chainId: number, pool: string, opts: VerifyOptions): Check {
  const pools = { ...OFFICIAL_POOLS, ...(opts.officialPools ?? {}) };
  const known = (pools[chainId] ?? []).some((p) => eqAddr(p, pool));
  const details: Detail[] = [
    { label: "Pool in package", value: pool, mono: true },
    { label: "Official pools on this chain", value: (pools[chainId] ?? []).join(", ") || "none known" },
  ];
  return known
    ? { id: "pool", title: "Official pool", status: "pass", summary: `${short(getAddress(pool))} is the official Ghost Mode pool contract.`, details }
    : { id: "pool", title: "Official pool", status: "fail", summary: `${short(pool)} is not a known Ghost Mode pool; events from an unknown contract prove nothing.`, details };
}

// ---------------------------------------------------------------------------------------------
// Receipt verification
// ---------------------------------------------------------------------------------------------
export async function verifyReceipt(pkg: ReceiptPackage, reader: ChainReader, opts: VerifyOptions = {}): Promise<Verification> {
  const checks: Check[] = [];
  const m = pkg.typedData.message;
  const d = pkg.typedData.domain;
  const usdc = USDC_BY_CHAIN[pkg.chainId];
  const n0 = big(pkg.nullifiers[0]), n1 = big(pkg.nullifiers[1]);
  const c0 = big(pkg.outCommitments[0]), c1 = big(pkg.outCommitments[1]);
  const privateAmount = big(m.privateAmount), publicAmount = big(m.publicAmount), fee = big(m.fee), deadline = big(m.deadline);
  const amount = privateAmount + publicAmount;

  const chain = await attempt(() => reader.chainId());
  checks.push(networkCheck(pkg.chainId, chain, reader.describe()));
  checks.push(poolCheck(pkg.chainId, pkg.pool, opts));

  // 1. Signature
  {
    const details: Detail[] = [{ label: "Claimed signer (PayBox wallet)", value: pkg.signer, mono: true }];
    const schema = pkg.typedData.types.GhostSpend;
    const schemaOk = pkg.typedData.primaryType === "GhostSpend" && Array.isArray(schema) && schema.length === GHOST_SPEND_TYPE.length &&
      schema.every((f, i) => f?.name === GHOST_SPEND_TYPE[i]!.name && f?.type === GHOST_SPEND_TYPE[i]!.type);
    const domainKeysOk = Object.keys(d).every((k) => ["name", "version", "chainId", "verifyingContract"].includes(k));
    let check: Check;
    if (!schemaOk || !domainKeysOk) {
      check = { id: "signature", title: "Signature", status: "fail", summary: "The typed data is not a GhostSpend v1 structure.", details };
    } else {
      try {
        const recovered = await recoverTypedDataAddress({
          domain: { name: String(d.name), version: String(d.version), chainId: big(d.chainId), verifyingContract: getAddress(d.verifyingContract) },
          types: { GhostSpend: GHOST_SPEND_TYPE },
          primaryType: "GhostSpend",
          message: {
            intent: m.intent as Hex, token: getAddress(m.token), privateAmount, privateRecipient: m.privateRecipient as Hex,
            publicAmount, publicRecipient: getAddress(m.publicRecipient), fee, deadline,
          },
          signature: pkg.signature as Hex,
        });
        details.push({ label: "Recovered EIP-712 signer", value: recovered, mono: true });
        check = eqAddr(recovered, pkg.signer)
          ? { id: "signature", title: "Signature", status: "pass", summary: `Signed by PayBox wallet ${short(recovered)} (EIP-712 GhostSpend).`, details }
          : { id: "signature", title: "Signature", status: "fail", summary: `Mismatch: the signature was made by ${short(recovered)}, not ${short(pkg.signer)}.`, details };
      } catch (e) {
        details.push({ label: "Error", value: e instanceof Error ? e.message.split("\n")[0]! : String(e) });
        check = { id: "signature", title: "Signature", status: "fail", summary: "The signature is malformed and cannot be recovered.", details };
      }
    }
    checks.push(check);
  }

  // 2. Domain
  {
    const problems: string[] = [];
    if (d.name !== "GhostMode" || String(d.version) !== "1") problems.push(`domain is ${JSON.stringify(d.name)} v${d.version}, expected "GhostMode" v1`);
    if (!eqAddr(d.verifyingContract, pkg.pool)) problems.push(`verifyingContract ${short(d.verifyingContract)} is not the pool ${short(pkg.pool)}`);
    if (Number(d.chainId) !== pkg.chainId) problems.push(`domain chainId ${d.chainId} differs from package chainId ${pkg.chainId}`);
    if (!usdc) problems.push(`no canonical USDC is known on chain ${pkg.chainId}`);
    else if (!eqAddr(m.token, usdc)) problems.push(`token ${short(m.token)} is not USDC (${short(usdc)})`);
    checks.push({
      id: "domain", title: "Domain", status: problems.length ? "fail" : "pass",
      summary: problems.length ? `Mismatch: ${problems.join("; ")}.` : "Signed for the Ghost Mode pool on this chain, token USDC.",
      details: [
        { label: "Domain", value: `${d.name} v${d.version}, chainId ${d.chainId}` },
        { label: "verifyingContract", value: d.verifyingContract, mono: true },
        { label: "Token", value: m.token, mono: true },
        { label: "USDC on this chain", value: usdc ?? "unknown", mono: true },
      ],
    });
  }

  // 3. Transaction
  const rec = await attempt(() => reader.getReceipt(pkg.txHash));
  const txDetails: Detail[] = [{ label: "Transaction", value: pkg.txHash, mono: true }];
  let logs: Decoded[] = [];
  let receipt: RpcReceipt | null = null;
  if (!rec.ok) {
    checks.push(rpcErrorCheck("transaction", "Transaction", rec.error, txDetails));
  } else if (!rec.value) {
    checks.push({ id: "transaction", title: "Transaction", status: "fail", summary: `Transaction ${short(pkg.txHash)} was not found on chain ${pkg.chainId}.`, details: txDetails });
  } else {
    receipt = rec.value;
    logs = decodeReceiptLogs(receipt, pkg.pool, usdc);
    const nulls = logs.filter((l) => l.kind === "nullifier").map((l) => (l as { nullifier: bigint }).nullifier);
    const comms = logs.filter((l) => l.kind === "commitment").map((l) => (l as { commitment: bigint }).commitment);
    txDetails.push({ label: "Block", value: String(BigInt(receipt.blockNumber)) });
    txDetails.push({ label: "Status", value: receipt.status === "0x1" ? "success" : `failed (${receipt.status ?? "unknown"})` });
    txDetails.push({ label: "Pool nullifiers in tx", value: nulls.map((n) => short(hex32(n), 10, 6)).join(", ") || "none" });
    txDetails.push({ label: "Pool commitments in tx", value: comms.map((c) => short(hex32(c), 10, 6)).join(", ") || "none" });
    const problems: string[] = [];
    if (receipt.status !== "0x1") problems.push("the transaction reverted");
    if (!nulls.includes(n0)) problems.push("nullifier 0 not spent in this tx");
    if (!nulls.includes(n1)) problems.push("nullifier 1 not spent in this tx");
    if (!comms.includes(c0)) problems.push("output commitment 0 not created in this tx");
    if (!comms.includes(c1)) problems.push("output commitment 1 not created in this tx");
    checks.push({
      id: "transaction", title: "Transaction", status: problems.length ? "fail" : "pass",
      summary: problems.length ? `Mismatch: ${problems.join("; ")}.` : `Succeeded in block ${BigInt(receipt.blockNumber)}; the pool spent both nullifiers and created both outputs.`,
      details: txDetails,
    });
  }

  // Locate this spend's events: NewCommitment(c1) and the first Transacted after it.
  const c0Log = logs.find((l) => l.kind === "commitment" && l.commitment === c0) as Extract<Decoded, { kind: "commitment" }> | undefined;
  const c1Log = logs.find((l) => l.kind === "commitment" && l.commitment === c1 && (!c0Log || l.i > c0Log.i)) as Extract<Decoded, { kind: "commitment" }> | undefined;
  const txLog = c1Log ? (logs.find((l) => l.kind === "transacted" && l.i > c1Log.i) as Extract<Decoded, { kind: "transacted" }> | undefined) : undefined;
  const transfers = c1Log && txLog ? (logs.filter((l) => l.kind === "usdc" && l.i > c1Log.i && l.i < txLog.i) as Extract<Decoded, { kind: "usdc" }>[]) : [];

  // 4. Intent binding
  if (!rec.ok) {
    checks.push(rpcErrorCheck("intent", "Intent binding", rec.error));
  } else if (!c0Log || !c1Log || !txLog) {
    checks.push({ id: "intent", title: "Intent binding", status: "fail", summary: "The transaction does not contain this spend's NewCommitment and Transacted events.", details: [] });
  } else {
    const encoded = encodeAbiParameters([{ type: "address" }, { type: "bytes" }, { type: "bytes" }], [getAddress(txLog.relayer), c0Log.encryptedOutput, c1Log.encryptedOutput]);
    const extDataHash = BigInt(keccak256(encoded)) % FIELD_SIZE;
    const intent = P5(n0, n1, c0, c1, extDataHash);
    const signed = BigInt(m.intent);
    const details: Detail[] = [
      { label: "Relayer (from Transacted)", value: txLog.relayer, mono: true },
      { label: "extDataHash", value: extDataHash.toString(), mono: true },
      { label: "Recomputed intent P5(n0, n1, c0, c1, extDataHash)", value: hex32(intent), mono: true },
      { label: "Signed intent", value: m.intent, mono: true },
    ];
    checks.push(intent === signed
      ? { id: "intent", title: "Intent binding", status: "pass", summary: "The signed intent commits to exactly this transaction's nullifiers, outputs and encrypted notes.", details }
      : { id: "intent", title: "Intent binding", status: "fail", summary: "Mismatch: the signed intent does not match this transaction's spend.", details });
  }

  // 5. Payout
  const toPublic = publicAmount > 0n;
  const toPrivate = privateAmount > 0n;
  if (!rec.ok) {
    checks.push(rpcErrorCheck("payout", "Payout", rec.error));
  } else if (!txLog) {
    checks.push({ id: "payout", title: "Payout", status: "fail", summary: "No Transacted event for this spend in the transaction.", details: [] });
  } else {
    const problems: string[] = [];
    const details: Detail[] = [
      { label: "Recipient (on-chain)", value: txLog.recipient, mono: true },
      { label: "publicOut / fee (on-chain)", value: `${formatUsdc(txLog.publicOut)} / ${formatUsdc(txLog.fee)} USDC` },
      { label: "Signed public amount / hidden amount / fee", value: `${formatUsdc(publicAmount)} / ${formatUsdc(privateAmount)} / ${formatUsdc(fee)} USDC` },
    ];
    if (!eqAddr(txLog.recipient, m.publicRecipient)) problems.push(`recipient ${short(txLog.recipient)} differs from signed ${short(m.publicRecipient)}`);
    if (txLog.publicOut - txLog.fee !== publicAmount) problems.push(`paid ${formatUsdc(txLog.publicOut - txLog.fee)} USDC publicly, signed ${formatUsdc(publicAmount)}`);
    if (txLog.fee !== fee) problems.push(`fee ${formatUsdc(txLog.fee)} differs from signed ${formatUsdc(fee)}`);
    const hasTransfer = (to: string, value: bigint) => transfers.some((t) => eqAddr(t.from, pkg.pool) && eqAddr(t.to, to) && t.value === value);
    if (fee > 0n && txLog.fee === fee && !hasTransfer(txLog.relayer, fee)) problems.push("no USDC fee transfer to the relayer");
    const parts: string[] = [];
    if (toPublic) {
      if (txLog.publicOut - txLog.fee === publicAmount && !hasTransfer(m.publicRecipient, publicAmount)) problems.push("no matching USDC transfer from the pool to the recipient");
      parts.push(`${formatUsdc(publicAmount)} USDC sent publicly to ${short(getAddress(m.publicRecipient))}`);
    } else if (!eqAddr(m.publicRecipient, ZERO_ADDRESS)) problems.push("a public recipient is signed without a public amount");
    if (toPrivate) {
      if (BigInt(m.privateRecipient) === 0n) problems.push("hidden amount without a ghost recipient tag");
      parts.push(`${formatUsdc(privateAmount)} USDC sent privately to ghost recipient ${short(m.privateRecipient, 10, 6)}`);
      details.push({ label: "Ghost recipient tag", value: m.privateRecipient, mono: true });
    } else if (BigInt(m.privateRecipient) !== 0n) problems.push("a ghost recipient is signed without a hidden amount");
    if (!toPublic && !toPrivate) problems.push("nothing was paid");
    const summary = `${parts.join(" and ")} (fee ${formatUsdc(fee)} USDC to relayer ${short(txLog.relayer)}).`;
    details.push({ label: "USDC transfers by the pool", value: transfers.map((t) => `${formatUsdc(t.value)} → ${short(t.to)}`).join(", ") || "none" });
    checks.push({ id: "payout", title: "Payout", status: problems.length ? "fail" : "pass", summary: problems.length ? `Mismatch: ${problems.join("; ")}.` : summary, details });
  }

  // 6. Time
  if (!rec.ok) {
    checks.push(rpcErrorCheck("time", "Time", rec.error));
  } else if (!receipt) {
    checks.push({ id: "time", title: "Time", status: "fail", summary: "No transaction, so no block time.", details: [] });
  } else {
    const blk = await attempt(() => reader.getBlock(receipt!.blockNumber));
    if (!blk.ok) checks.push(rpcErrorCheck("time", "Time", blk.error));
    else if (!blk.value) checks.push({ id: "time", title: "Time", status: "fail", summary: `Block ${BigInt(receipt.blockNumber)} not found.`, details: [] });
    else {
      const ts = Number(BigInt(blk.value.timestamp));
      const okTime = BigInt(ts) <= deadline;
      const details: Detail[] = [
        { label: "Block time", value: isoTime(ts) },
        { label: "Signature deadline", value: deadline < 10n ** 12n ? isoTime(Number(deadline)) : deadline.toString() },
      ];
      checks.push(okTime
        ? { id: "time", title: "Time", status: "pass", summary: `Included on ${isoTime(ts)}, before the signed deadline.`, details }
        : { id: "time", title: "Time", status: "fail", summary: `Mismatch: included on ${isoTime(ts)}, after the signed deadline.`, details });
    }
  }

  // Memo (informational)
  const memo = memoDetails(pkg.memo);
  if (memo.length)
    checks.push({ id: "memo", title: "Memo", status: "info", summary: "Payer's own notes, stored in their encrypted change note. Not verified on-chain.", details: memo });

  const counts = countChecks(checks);
  const ok = counts.fail === 0 && counts.error === 0;
  let headline: string;
  if (ok) {
    const where = [toPublic ? `to ${short(getAddress(m.publicRecipient))}` : "", toPrivate ? `privately to ghost recipient ${short(m.privateRecipient, 10, 6)}` : ""].filter(Boolean).join(" and ");
    headline = `${short(getAddress(pkg.signer))} paid ${formatUsdc(amount)} USDC ${where} (fee ${formatUsdc(fee)}) in tx ${short(pkg.txHash, 10, 6)}, authorised by their PayBox wallet; the zero-knowledge proof bound this signature to exactly these outputs.`;
  } else if (counts.fail === 0) {
    headline = `Could not finish: ${counts.error} check(s) need chain data the RPC did not return. Nothing contradicts the receipt yet; try again later.`;
  } else {
    headline = `Not verified: ${counts.fail} check(s) failed. Do not rely on this receipt.`;
  }
  return { kind: "ghost-receipt", ok, headline, checks, counts, rpc: reader.describe() };
}

// ---------------------------------------------------------------------------------------------
// Report verification
// ---------------------------------------------------------------------------------------------
export function pkHashOfPubKey(pub64: Uint8Array): bigint {
  const limb = (from: number) => BigInt(`0x${Array.from(pub64.slice(from, from + 16), (b) => b.toString(16).padStart(2, "0")).join("")}`);
  return P4(limb(0), limb(16), limb(32), limb(48));
}
const hexToU8 = (hex: string) => Uint8Array.from(hex.replace(/^0x/, "").match(/../g) ?? [], (b) => parseInt(b, 16));

export async function verifyReport(pkg: ReportPackage, reader: ChainReader, opts: VerifyOptions = {}): Promise<Verification> {
  const checks: Check[] = [];
  const usdc = USDC_BY_CHAIN[pkg.chainId];
  const chain = await attempt(() => reader.chainId());
  checks.push(networkCheck(pkg.chainId, chain, reader.describe()));
  checks.push(poolCheck(pkg.chainId, pkg.pool, opts));
  checks.push(usdc && eqAddr(pkg.token, usdc)
    ? { id: "token", title: "Token", status: "pass", summary: "Notes are denominated in USDC.", details: [{ label: "Token", value: pkg.token, mono: true }] }
    : { id: "token", title: "Token", status: "fail", summary: `Token ${short(pkg.token)} is not canonical USDC on chain ${pkg.chainId}.`, details: [{ label: "Token", value: pkg.token, mono: true }] });

  // 1. Owner binding
  const pubHex = pkg.pubKey.length === 2 + 130 ? `0x${pkg.pubKey.slice(4)}` : pkg.pubKey;
  const pub = hexToU8(pubHex);
  const pkHash = pkHashOfPubKey(pub);
  const nkHash = big(pkg.nkHash);
  const ownerTag = big(pkg.ownerTag);
  const derivedTag = P2(pkHash, nkHash);
  const derivedAddr = getAddress(`0x${keccak256(pubHex as Hex).slice(-40)}`);
  {
    const problems: string[] = [];
    if (derivedTag !== ownerTag) problems.push("ownerTag ≠ P2(pkHash(pubKey), nkHash)");
    if (!eqAddr(derivedAddr, pkg.walletAddress)) problems.push(`pubKey belongs to ${short(derivedAddr)}, not ${short(pkg.walletAddress)}`);
    checks.push({
      id: "owner", title: "Owner binding", status: problems.length ? "fail" : "pass",
      summary: problems.length ? `Mismatch: ${problems.join("; ")}.` : `The notes' owner tag is derived from PayBox wallet ${short(derivedAddr)}'s public key.`,
      details: [
        { label: "Wallet address", value: pkg.walletAddress, mono: true },
        { label: "Address derived from pubKey", value: derivedAddr, mono: true },
        { label: "pkHash = P4(x_hi, x_lo, y_hi, y_lo)", value: pkHash.toString(), mono: true },
        { label: "ownerTag (package)", value: pkg.ownerTag, mono: true },
        { label: "P2(pkHash, nkHash)", value: derivedTag.toString(), mono: true },
      ],
    });
  }

  // 2. Notes
  const asset = BigInt(pkg.token);
  const from = parseTime(pkg.period?.from), to = parseTime(pkg.period?.to);
  const totals = { deposit: 0n, transfer: 0n, depositN: 0, transferN: 0 };
  let verifiedNotes = 0;
  for (const note of pkg.notes) {
    const amount = big(note.amount);
    const title = `Note #${note.leafIndex} · ${note.source} · ${formatUsdc(amount)} USDC`;
    const id = `note-${note.leafIndex}-${note.txHash.slice(2, 10)}`;
    totals[note.source] += amount;
    totals[note.source === "deposit" ? "depositN" : "transferN"] += 1;
    const commitment = big(note.commitment);
    const recomputed = P4(asset, amount, big(note.label), P2(ownerTag, big(note.blinding)));
    const details: Detail[] = [
      { label: "Transaction", value: note.txHash, mono: true },
      { label: "Commitment", value: note.commitment, mono: true },
      { label: "P4(token, amount, label, P2(ownerTag, blinding))", value: recomputed.toString(), mono: true },
    ];
    const problems: string[] = [];
    if (recomputed !== commitment) problems.push("commitment does not open to this amount/owner");
    const rec = await attempt(() => reader.getReceipt(note.txHash));
    if (!rec.ok) {
      checks.push(rpcErrorCheck(id, title, rec.error, details));
      continue;
    }
    if (!rec.value) {
      problems.push(`transaction not found on chain ${pkg.chainId}`);
    } else {
      const receipt = rec.value;
      const logs = decodeReceiptLogs(receipt, pkg.pool, usdc);
      if (receipt.status !== "0x1") problems.push("the transaction reverted");
      const created = logs.find((l) => l.kind === "commitment" && l.commitment === commitment) as Extract<Decoded, { kind: "commitment" }> | undefined;
      if (!created) problems.push("no NewCommitment for this commitment in the transaction");
      else if (created.leafIndex !== note.leafIndex) problems.push(`created at leaf ${created.leafIndex}, not ${note.leafIndex}`);
      if (note.source === "deposit") {
        const dep = logs.find((l) => l.kind === "deposit" && l.commitment === commitment) as Extract<Decoded, { kind: "deposit" }> | undefined;
        if (!dep) problems.push("no Deposited event for this commitment");
        else {
          if (dep.amount !== amount) problems.push(`deposited ${formatUsdc(dep.amount)} USDC, not ${formatUsdc(amount)}`);
          if (dep.label !== big(note.label)) problems.push("deposit label differs");
          details.push({ label: "Depositor", value: `${dep.depositor}${eqAddr(dep.depositor, pkg.walletAddress) ? " (this wallet)" : " (another address: relayer refund or authorised deposit)"}`, mono: true });
        }
      }
      const blk = await attempt(() => reader.getBlock(receipt.blockNumber));
      if (blk.ok && blk.value) {
        const ts = Number(BigInt(blk.value.timestamp));
        details.push({ label: "Block time", value: isoTime(ts) });
        if ((from !== null && ts < from) || (to !== null && ts > to)) problems.push("outside the stated period");
      } else {
        details.push({ label: "Block time", value: blk.ok ? "block not found" : blk.error });
      }
    }
    if (note.time !== undefined) {
      const t = parseTime(note.time);
      details.push({ label: "time (package)", value: t !== null ? isoTime(t) : String(note.time) });
    }
    details.push(...memoDetails(note.memo));
    if (!problems.length) verifiedNotes++;
    checks.push({
      id, title, status: problems.length ? "fail" : "pass",
      summary: problems.length ? `Mismatch: ${problems.join("; ")}.` : `On-chain at leaf ${note.leafIndex}; opens to ${formatUsdc(amount)} USDC owned by this wallet.`,
      details,
    });
  }

  // 3. Totals
  const total = totals.deposit + totals.transfer;
  const periodText = `${from !== null ? isoTime(from) : String(pkg.period?.from)} → ${to !== null ? isoTime(to) : String(pkg.period?.to)}`;
  checks.push({
    id: "totals", title: "Totals", status: "info",
    summary: `${formatUsdc(total)} USDC in ${pkg.notes.length} note(s): deposits ${formatUsdc(totals.deposit)}, transfers and change ${formatUsdc(totals.transfer)}.`,
    details: [
      { label: "Period", value: periodText },
      { label: `Deposits (${totals.depositN})`, value: `${formatUsdc(totals.deposit)} USDC` },
      { label: `Transfers received (${totals.transferN})`, value: `${formatUsdc(totals.transfer)} USDC` },
      { label: "Notes verified", value: `${verifiedNotes} of ${pkg.notes.length}` },
    ],
  });

  const counts = countChecks(checks);
  const ok = counts.fail === 0 && counts.error === 0;
  const headline = ok
    ? `${pkg.notes.length} verified shielded note(s) totalling ${formatUsdc(total)} USDC belong to PayBox wallet ${short(getAddress(pkg.walletAddress))} (deposits ${formatUsdc(totals.deposit)}, transfers and change ${formatUsdc(totals.transfer)}), period ${periodText}.`
    : counts.fail === 0
      ? `Could not finish: ${counts.error} check(s) need chain data the RPC did not return. Nothing contradicts the report yet; try again later.`
      : `Not verified: ${counts.fail} check(s) failed. Do not rely on this report.`;
  return {
    kind: "ghost-report", ok, headline, checks, counts, rpc: reader.describe(),
    scope: "This package proves only the listed notes in the stated period; it reveals nothing else.",
  };
}

export function verifyPackage(pkg: DisclosurePackage, reader: ChainReader, opts: VerifyOptions = {}): Promise<Verification> {
  return pkg.kind === "ghost-receipt" ? verifyReceipt(pkg, reader, opts) : verifyReport(pkg, reader, opts);
}
