// Ghost key backup and recovery. A lost ghost key means lost access to private notes, so the
// service keeps an encrypted copy that is released only to a fresh signature from the same PayBox
// wallet. The service already sees spend witnesses while proving, so the trust model is unchanged.
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { getAddress, hashMessage, isAddress, recoverPublicKey, type Hex } from "viem";
import { publicKeyToAddress } from "viem/accounts";
import { REPO_ROOT, SERVICE_ROOT } from "./config.js";

const SECRET_FILE = resolve(REPO_ROOT, "../.secrets/backup.key");
const DATA_DIR = process.env.DATA_DIR ?? resolve(SERVICE_ROOT, "data");
const STORE = resolve(DATA_DIR, "key-backups.json");
const FRESH_MS = 15 * 60_000;

function masterKey(): Buffer {
  if (!existsSync(SECRET_FILE)) writeFileSync(SECRET_FILE, randomBytes(32).toString("hex"), { mode: 0o600 });
  return Buffer.from(readFileSync(SECRET_FILE, "utf8").trim(), "hex");
}

type Entry = { iv: string; ct: string; tag: string; createdAt: string };
let backups: Record<string, Entry[]> = existsSync(STORE) ? JSON.parse(readFileSync(STORE, "utf8")) : {};

function persist() {
  mkdirSync(DATA_DIR, { recursive: true });
  writeFileSync(`${STORE}.tmp`, JSON.stringify(backups));
  renameSync(`${STORE}.tmp`, STORE);
}

function seal(plain: string, wallet: string): Entry {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", masterKey(), iv);
  cipher.setAAD(Buffer.from(wallet));
  const ct = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  return { iv: iv.toString("hex"), ct: ct.toString("hex"), tag: cipher.getAuthTag().toString("hex"), createdAt: new Date().toISOString() };
}

function open(e: Entry, wallet: string): string {
  const decipher = createDecipheriv("aes-256-gcm", masterKey(), Buffer.from(e.iv, "hex"));
  decipher.setAAD(Buffer.from(wallet));
  decipher.setAuthTag(Buffer.from(e.tag, "hex"));
  return Buffer.concat([decipher.update(Buffer.from(e.ct, "hex")), decipher.final()]).toString("utf8");
}

/** Accepts `<prefix>…\nIssued: <ISO>` messages signed within the last 15 minutes; returns the signer address. */
async function verifyFresh(message: string, signature: Hex, prefix: string): Promise<{ address: string; pubKey: Hex }> {
  if (!message.startsWith(prefix)) throw new Error("Unexpected message.");
  const issued = /\nIssued: (\S+)$/.exec(message)?.[1];
  const age = issued ? Date.now() - Date.parse(issued) : NaN;
  if (!(age >= -60_000 && age <= FRESH_MS)) throw new Error("Signed message expired; sign a fresh one.");
  const pubKey = await recoverPublicKey({ hash: hashMessage(message), signature });
  return { address: publicKeyToAddress(pubKey), pubKey };
}

export async function backupKey(body: any) {
  const ghostKey = String(body?.ghost_key ?? "");
  const m = /^ghk1_[0-9a-f]{64}_([0-9a-f]{128})$/.exec(ghostKey);
  if (!m) throw new Error("Invalid ghost key.");
  const { address, pubKey } = await verifyFresh(String(body?.message ?? ""), body?.signature as Hex, "Ghost Mode setup");
  if (pubKey.slice(4).toLowerCase() !== m[1]) throw new Error("The ghost key is not bound to the wallet that signed.");
  const wallet = getAddress(address).toLowerCase();
  const list = backups[wallet] ?? [];
  if (!list.some((e) => open(e, wallet) === ghostKey)) list.push(seal(ghostKey, wallet));
  backups[wallet] = list.slice(-10);
  persist();
  return { backed_up: true, keys_for_wallet: backups[wallet]!.length };
}

export async function recoverKeys(body: any) {
  if (!isAddress(String(body?.address ?? ""))) throw new Error("Need the wallet address.");
  const wallet = getAddress(body.address).toLowerCase();
  const { address } = await verifyFresh(String(body?.message ?? ""), body?.signature as Hex, `Ghost Mode key recovery\nAddress: ${getAddress(body.address)}`);
  if (address.toLowerCase() !== wallet) throw new Error("Recovery challenge was not signed by this wallet.");
  const list = backups[wallet] ?? [];
  return { ghost_keys: list.map((e) => open(e, wallet)), created_at: list.map((e) => e.createdAt) };
}
