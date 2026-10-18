// Single-signature, gasless shield (GhostPool v2 `depositWithAuthorization`). The user signs one
// EIP-3009 ReceiveWithAuthorization in PayBox; the relayer submits it and is repaid a USDC fee.
// The authorization nonce binds the note (precommitment + ciphertext) and the fee, so the relayer
// cannot change what gets deposited, and the pool is the only party that can redeem it.
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { encodeAbiParameters, getAddress, hashTypedData, isAddress, keccak256, parseAbi, parseSignature, recoverAddress, type Hex } from "viem";
import { config, SERVICE_ROOT } from "./config.js";
import { publicClient, relayerAccount, sync, walletClient, withRelayerLock } from "./indexer.js";

const FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const MAX_DEPOSIT = 100_000_000n;

const poolV2Abi = parseAbi([
  "function depositWithAuthorization(address from, uint256 value, uint256 fee, uint256 validAfter, uint256 validBefore, uint256 precommitment, bytes encryptedNote, uint8 v, bytes32 r, bytes32 s) returns (uint256 commitment, uint32 leafIndex)",
  "function authorizationNonce(uint256 precommitment, bytes encryptedNote, uint256 fee) view returns (bytes32)",
]);
const tokenMeta = parseAbi(["function name() view returns (string)", "function version() view returns (string)"]);

export type ShieldPackage = {
  from: Hex; amount: string; fee: string; value: string; validAfter: string; validBefore: string;
  precommitment: string; encryptedNote: Hex; nonce: Hex;
};
type Prepared = { id: string; pkg: ShieldPackage; typedData: ReturnType<typeof buildTypedData>; expiresAt: number };
type ShieldJob = {
  id: string; status: "queued" | "relaying" | "done" | "failed"; createdAt: number; updatedAt: number;
  from: Hex; amount: string; fee: string; txHash?: Hex; error?: string;
};

const prepared = new Map<string, Prepared>();
const jobs = new Map<string, ShieldJob>();
const DATA_DIR = process.env.DATA_DIR ?? resolve(SERVICE_ROOT, "data");
const storeFile = resolve(DATA_DIR, "shield-state.json");

function save() {
  try {
    mkdirSync(DATA_DIR, { recursive: true });
    const tmp = `${storeFile}.tmp`;
    writeFileSync(tmp, JSON.stringify({ prepared: [...prepared.values()], jobs: [...jobs.values()] }));
    renameSync(tmp, storeFile);
  } catch (err) {
    console.error(`[shield] persist failed: ${(err as Error).message}`);
  }
}
if (existsSync(storeFile)) {
  try {
    const data = JSON.parse(readFileSync(storeFile, "utf8"));
    for (const p of data.prepared ?? []) if (p.expiresAt > Date.now()) prepared.set(p.id, p);
    for (const j of data.jobs ?? []) {
      if (j.status === "queued" || j.status === "relaying") Object.assign(j, { status: "failed", error: "service restarted during processing; check ghost_balance" });
      jobs.set(j.id, j);
    }
  } catch { /* start fresh */ }
}

let usdcDomain: { name: string; version: string } | undefined;
async function getUsdcDomain() {
  if (!usdcDomain) {
    const [name, version] = await Promise.all([
      publicClient.readContract({ address: config.token, abi: tokenMeta, functionName: "name" }),
      publicClient.readContract({ address: config.token, abi: tokenMeta, functionName: "version" }),
    ]);
    usdcDomain = { name, version };
  }
  return usdcDomain;
}

let supported: boolean | undefined;
export async function poolSupportsAuthorization(): Promise<boolean> {
  if (supported === undefined && config.pool) {
    try {
      await publicClient.readContract({ address: config.pool, abi: poolV2Abi, functionName: "authorizationNonce", args: [1n, "0x", 0n] });
      supported = true;
    } catch {
      supported = false;
    }
  }
  return supported ?? false;
}

async function shieldFee(): Promise<bigint> {
  try {
    const fees: any = await import("./fees" + ".js");
    return BigInt(fees.relayerFees().shield);
  } catch {
    return config.relayerFee;
  }
}

async function sanctioned(address: string): Promise<boolean> {
  try {
    const ofac: any = await import("./ofac" + ".js");
    if (ofac.isSanctioned(address)) return true;
  } catch { /* list not available */ }
  return config.aspDenylist.has(address.toLowerCase());
}

export function authorizationNonce(precommitment: bigint, encryptedNote: Hex, fee: bigint): Hex {
  return keccak256(encodeAbiParameters(
    [{ type: "address" }, { type: "uint256" }, { type: "bytes32" }, { type: "uint256" }],
    [config.pool, precommitment, keccak256(encryptedNote), fee],
  ));
}

function buildTypedData(pkg: ShieldPackage, domain: { name: string; version: string }) {
  return {
    domain: { name: domain.name, version: domain.version, chainId: config.chainId, verifyingContract: getAddress(config.token) },
    types: {
      EIP712Domain: [
        { name: "name", type: "string" }, { name: "version", type: "string" },
        { name: "chainId", type: "uint256" }, { name: "verifyingContract", type: "address" },
      ],
      ReceiveWithAuthorization: [
        { name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" },
        { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" },
      ],
    },
    primaryType: "ReceiveWithAuthorization" as const,
    message: { from: getAddress(pkg.from), to: getAddress(config.pool), value: pkg.value, validAfter: pkg.validAfter, validBefore: pkg.validBefore, nonce: pkg.nonce },
  };
}

export async function shieldInfo() {
  const domain = await getUsdcDomain().catch(() => ({ name: "USD Coin", version: "2" }));
  return {
    chainId: config.chainId, pool: config.pool, token: config.token, relayer: relayerAccount?.address ?? null,
    fee: (await shieldFee()).toString(), usdcName: domain.name, usdcVersion: domain.version,
    supported: await poolSupportsAuthorization(), maxDeposit: MAX_DEPOSIT.toString(),
  };
}

export async function shieldPrepare(body: any) {
  if (!(await poolSupportsAuthorization())) throw new Error("This pool has no single-signature deposits; use ghost_shield approve/deposit.");
  const p = body?.package as ShieldPackage;
  if (!p || !isAddress(p.from)) throw new Error("Need a shield package with a valid 'from' address.");
  const amount = BigInt(p.amount), fee = BigInt(p.fee), value = BigInt(p.value);
  const precommitment = BigInt(p.precommitment);
  const now = Math.floor(Date.now() / 1000);
  if (amount <= 0n || amount > MAX_DEPOSIT) throw new Error("Shield amount must be between 0.000001 and 100 USDC.");
  if (value !== amount + fee) throw new Error("value must equal amount + fee.");
  const current = await shieldFee();
  if (fee * 5n < current * 4n) throw new Error(`Relayer fee too low; current shield fee is ${current}.`);
  if (precommitment >= FIELD_SIZE) throw new Error("precommitment out of range.");
  if (!/^0x[0-9a-fA-F]*$/.test(p.encryptedNote) || p.encryptedNote.length > 2 + 2 * 1024) throw new Error("Bad encrypted note.");
  if (BigInt(p.validAfter) !== 0n || Number(p.validBefore) < now + 300 || Number(p.validBefore) > now + 7200) throw new Error("Authorization window must be 5 minutes to 2 hours.");
  if (authorizationNonce(precommitment, p.encryptedNote, fee).toLowerCase() !== p.nonce.toLowerCase()) throw new Error("Authorization nonce does not bind this note and fee.");
  if (await sanctioned(p.from)) throw new Error("This address is on the OFAC sanctions list; Ghost Mode does not accept deposits from it.");
  const typedData = buildTypedData(p, await getUsdcDomain());
  const entry: Prepared = { id: `shp_${randomBytes(12).toString("hex")}`, pkg: p, typedData, expiresAt: Number(p.validBefore) * 1000 };
  prepared.set(entry.id, entry);
  save();
  return { prepare_id: entry.id, expires_at: new Date(entry.expiresAt).toISOString(), typedData };
}

/** USDC rejects high-s signatures; (r, n - s) with the flipped v is the same authorization. */
function normalizedVrs(signature: Hex) {
  const sig = parseSignature(signature);
  let s = BigInt(sig.s);
  let v = Number(sig.v ?? BigInt(27 + (sig.yParity ?? 0)));
  if (v < 27) v += 27;
  if (s > SECP256K1_N / 2n) { s = SECP256K1_N - s; v = v === 27 ? 28 : 27; }
  return { v, r: sig.r, s: `0x${s.toString(16).padStart(64, "0")}` as Hex };
}

export async function shieldSubmit(body: any) {
  const p = prepared.get(String(body?.prepare_id));
  if (!p) throw new Error("Unknown or expired shield prepare_id. Run ghost_shield_authorize again.");
  if (!/^0x[0-9a-fA-F]{128,130}$/.test(body?.signature ?? "")) throw new Error("Need a 65-byte hex signature.");
  const { EIP712Domain: _d, ...types } = p.typedData.types;
  const digest = hashTypedData({ ...p.typedData, types } as never);
  const signer = await recoverAddress({ hash: digest, signature: body.signature as Hex });
  if (signer.toLowerCase() !== p.pkg.from.toLowerCase()) throw new Error("Signature is not from the shielding wallet, or the authorization was altered.");
  if (await sanctioned(p.pkg.from)) throw new Error("This address is on the OFAC sanctions list.");
  prepared.delete(p.id);
  const job: ShieldJob = { id: `sjob_${randomBytes(12).toString("hex")}`, status: "queued", createdAt: Date.now(), updatedAt: Date.now(), from: p.pkg.from, amount: p.pkg.amount, fee: p.pkg.fee };
  jobs.set(job.id, job);
  save();
  void run(job, p, body.signature as Hex);
  return { job_id: job.id };
}

async function run(job: ShieldJob, p: Prepared, signature: Hex) {
  const set = (status: ShieldJob["status"], extra: Partial<ShieldJob> = {}) => { Object.assign(job, extra, { status, updatedAt: Date.now() }); save(); };
  try {
    if (!walletClient || !relayerAccount) throw new Error("Relayer wallet not configured.");
    set("relaying");
    const { v, r, s } = normalizedVrs(signature);
    const pkg = p.pkg;
    const wallet = walletClient;
    const receipt = await withRelayerLock(async () => {
      const { request } = await publicClient.simulateContract({
        account: relayerAccount, address: config.pool, abi: poolV2Abi, functionName: "depositWithAuthorization",
        args: [pkg.from, BigInt(pkg.value), BigInt(pkg.fee), BigInt(pkg.validAfter), BigInt(pkg.validBefore), BigInt(pkg.precommitment), pkg.encryptedNote, v, r, s],
      });
      const hash = await wallet.writeContract(request);
      job.txHash = hash;
      return publicClient.waitForTransactionReceipt({ hash, timeout: 120_000 });
    });
    if (receipt.status !== "success") throw new Error(`depositWithAuthorization reverted in ${receipt.transactionHash}`);
    set("done", { txHash: receipt.transactionHash });
    void sync(true);
  } catch (err) {
    set("failed", { error: ((err as Error).message ?? String(err)).split("\n").slice(0, 3).join(" ").slice(0, 500) });
  }
}

export function getShieldJob(id: string) {
  return jobs.get(id);
}
