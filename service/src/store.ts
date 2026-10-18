// Durable state for prepared spends and jobs: data/state.json (config.stateFile).
// Writes are debounced (~200 ms) and atomic (temp file + rename); bigints are stored as strings.
// Prepared spends carry full circuit witnesses (incl. nk) and jobs carry signer<->nullifier receipts,
// so when a relayer key is configured the payload is encrypted at rest with AES-256-GCM under a key
// derived from it (protects backups / accidental commits of the file; not a defence against host compromise).
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { config } from "./config.js";

export type PersistedState = { prepared: unknown[]; jobs: unknown[] };

const FORMAT = "ghost-state-v1";
const key = config.relayerKey ? createHash("sha256").update("ghost-mode:state-file:v1").update(config.relayerKey.toLowerCase()).digest() : undefined;

const toJson = (value: unknown) => JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? v.toString() : v));

function encode(state: PersistedState): string {
  const plain = toJson(state);
  if (!key) return JSON.stringify({ format: FORMAT, enc: "none", state: JSON.parse(plain) });
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const data = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  return JSON.stringify({ format: FORMAT, enc: "aes-256-gcm", iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), data: data.toString("base64") });
}

function decode(text: string): PersistedState {
  const doc = JSON.parse(text) as { format?: string; enc?: string; state?: PersistedState; iv?: string; tag?: string; data?: string };
  if (doc.format !== FORMAT) throw new Error("unknown state file format");
  if (doc.enc === "none") return { prepared: doc.state?.prepared ?? [], jobs: doc.state?.jobs ?? [] };
  if (doc.enc !== "aes-256-gcm" || !key) throw new Error("state file is encrypted with a relayer key that is not configured");
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(doc.iv!, "base64"));
  decipher.setAuthTag(Buffer.from(doc.tag!, "base64"));
  const plain = Buffer.concat([decipher.update(Buffer.from(doc.data!, "base64")), decipher.final()]).toString("utf8");
  const state = JSON.parse(plain) as PersistedState;
  return { prepared: state.prepared ?? [], jobs: state.jobs ?? [] };
}

export function loadState(file = config.stateFile): PersistedState {
  if (!existsSync(file)) return { prepared: [], jobs: [] };
  try {
    return decode(readFileSync(file, "utf8"));
  } catch (err) {
    // Keep the unreadable file for inspection instead of overwriting it on the next save.
    const aside = `${file}.unreadable-${Date.now()}`;
    try { renameSync(file, aside); } catch { /* ignore */ }
    console.error(`[store] could not load ${file} (${(err as Error).message.split("\n")[0]}); moved aside, starting empty`);
    return { prepared: [], jobs: [] };
  }
}

function writeAtomic(file: string, text: string) {
  mkdirSync(dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, text, { mode: 0o600 });
  try {
    renameSync(tmp, file);
  } catch {
    // Windows can refuse to replace a file another process (AV, indexer) holds open: fall back to copy.
    copyFileSync(tmp, file);
    try { unlinkSync(tmp); } catch { /* ignore */ }
  }
}

let snapshotFn: (() => PersistedState) | undefined;
let timer: ReturnType<typeof setTimeout> | undefined;

function flush(file = config.stateFile) {
  timer = undefined;
  if (!snapshotFn) return;
  try {
    writeAtomic(file, encode(snapshotFn()));
  } catch (err) {
    console.error(`[store] save failed: ${(err as Error).message.split("\n")[0]}`);
  }
}

/** Registers the snapshot source; saves are scheduled with scheduleSave(). */
export function bindStore(snapshot: () => PersistedState) {
  snapshotFn = snapshot;
  process.once("exit", () => { if (timer) { clearTimeout(timer); flush(); } });
}

export function scheduleSave(delayMs = 200) {
  if (timer || !snapshotFn) return;
  timer = setTimeout(() => flush(), delayMs);
}

export function saveNow() {
  if (timer) clearTimeout(timer);
  flush();
}
