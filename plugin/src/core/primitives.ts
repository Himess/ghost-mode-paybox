// Shared Ghost Mode primitives: field math, Poseidon, keys, notes, Merkle trees,
// note encryption and the EIP-712 spend intent. Used by the plugin and the service.
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { x25519 } from "@noble/curves/ed25519";
import { poseidon1 } from "poseidon-lite/poseidon1";
import { poseidon2 } from "poseidon-lite/poseidon2";
import { poseidon3 } from "poseidon-lite/poseidon3";
import { poseidon4 } from "poseidon-lite/poseidon4";
import { poseidon5 } from "poseidon-lite/poseidon5";
import { bytesToHex, concat, encodeAbiParameters, hashDomain, hexToBytes, keccak256, toBytes, type Hex } from "viem";

export const FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const TREE_DEPTH = 16;
export const ASP_DEPTH = 16;

export const H1 = (a: bigint) => poseidon1([a]);
export const H2 = (a: bigint, b: bigint) => poseidon2([a, b]);
export const H3 = (a: bigint, b: bigint, c: bigint) => poseidon3([a, b, c]);
export const H4 = (a: bigint, b: bigint, c: bigint, d: bigint) => poseidon4([a, b, c, d]);
export const H5 = (a: bigint, b: bigint, c: bigint, d: bigint, e: bigint) => poseidon5([a, b, c, d, e]);

export const toHex32 = (value: bigint): Hex => `0x${value.toString(16).padStart(64, "0")}`;
export const randomField = (): bigint => BigInt(bytesToHex(randomBytes(31)));
const sha256 = (...parts: Uint8Array[]) => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
};

// ---------------------------------------------------------------------------
// Keys. The ghost key holds only privacy material (nk + viewing key seed) plus
// the PayBox wallet's public key. Spending always needs a fresh PayBox signature.
// ---------------------------------------------------------------------------
export type GhostKeys = {
  seed: Uint8Array;
  pubKey: Uint8Array; // 64-byte uncompressed secp256k1 key without the 0x04 prefix
  nk: bigint;
  viewPriv: Uint8Array;
  viewPub: Uint8Array;
  pkHash: bigint;
  ownerTag: bigint;
};

const GHOST_KEY_RE = /^ghk1_([0-9a-f]{64})_([0-9a-f]{128})$/;

export function formatGhostKey(seed: Uint8Array, pubKey: Uint8Array): string {
  return `ghk1_${Buffer.from(seed).toString("hex")}_${Buffer.from(pubKey).toString("hex")}`;
}

export function pkHashOf(pubKey: Uint8Array): bigint {
  const limb = (from: number) => BigInt(bytesToHex(pubKey.slice(from, from + 16)));
  return H4(limb(0), limb(16), limb(32), limb(48));
}

export function parseGhostKey(ghostKey: string): GhostKeys {
  const m = GHOST_KEY_RE.exec(ghostKey.trim().toLowerCase());
  if (!m) throw new Error("Invalid ghost key. Expected the ghk1_… string returned by ghost_setup.");
  const seed = hexToBytes(`0x${m[1]}`);
  const pubKey = hexToBytes(`0x${m[2]}`);
  const nk = BigInt(keccak256(concat([seed, toBytes("ghost-mode:nk")]))) % FIELD_SIZE;
  const viewPriv = sha256(seed, toBytes("ghost-mode:ivk"));
  const viewPub = x25519.getPublicKey(viewPriv);
  const pkHash = pkHashOf(pubKey);
  const ownerTag = H2(pkHash, H1(nk));
  return { seed, pubKey, nk, viewPriv, viewPub, pkHash, ownerTag };
}

export function ghostAddress(keys: Pick<GhostKeys, "ownerTag" | "viewPub">): string {
  const payload = concat([hexToBytes(toHex32(keys.ownerTag)), keys.viewPub]);
  const checksum = keccak256(payload).slice(2, 10);
  return `ghost:${bytesToHex(payload).slice(2)}${checksum}`;
}

export function parseGhostAddress(address: string): { ownerTag: bigint; viewPub: Uint8Array } {
  const m = /^ghost:([0-9a-f]{128})([0-9a-f]{8})$/.exec(address.trim().toLowerCase());
  if (!m) throw new Error("Invalid ghost address. Expected ghost:<136 hex chars>.");
  const payload = hexToBytes(`0x${m[1]}`);
  if (keccak256(payload).slice(2, 10) !== m[2]) throw new Error("Ghost address checksum mismatch.");
  const ownerTag = BigInt(bytesToHex(payload.slice(0, 32)));
  if (ownerTag >= FIELD_SIZE) throw new Error("Ghost address owner tag out of range.");
  return { ownerTag, viewPub: payload.slice(32) };
}

// ---------------------------------------------------------------------------
// Notes
// ---------------------------------------------------------------------------
export type Note = { asset: bigint; amount: bigint; ownerTag: bigint; blinding: bigint; label: bigint };
export const precommitmentOf = (ownerTag: bigint, blinding: bigint) => H2(ownerTag, blinding);
export const commitmentOf = (n: Note) => H4(n.asset, n.amount, n.label, precommitmentOf(n.ownerTag, n.blinding));
export const nullifierOf = (commitment: bigint, leafIndex: number, nk: bigint) => H3(commitment, BigInt(leafIndex), nk);

// ---------------------------------------------------------------------------
// Merkle tree (Poseidon, zero leaf = 0), identical to GhostPool's on-chain tree.
// ---------------------------------------------------------------------------
const zeroCache: bigint[] = [];
export function zeroAt(level: number): bigint {
  if (!zeroCache.length) {
    zeroCache.push(0n);
    for (let i = 0; i < 32; i++) zeroCache.push(H2(zeroCache[i]!, zeroCache[i]!));
  }
  return zeroCache[level]!;
}

export class MerkleTree {
  private layers: bigint[][];
  constructor(readonly depth: number, leaves: bigint[]) {
    if (leaves.length > 2 ** depth) throw new Error("Merkle tree is full.");
    this.layers = [leaves.slice()];
    for (let level = 0; level < depth; level++) {
      const below = this.layers[level]!;
      const above: bigint[] = [];
      for (let i = 0; i < below.length; i += 2) above.push(H2(below[i]!, below[i + 1] ?? zeroAt(level)));
      this.layers.push(above);
    }
  }
  get root(): bigint {
    return this.layers[this.depth]![0] ?? zeroAt(this.depth);
  }
  path(index: number): bigint[] {
    if (index < 0 || index >= this.layers[0]!.length) throw new Error(`Leaf ${index} not in tree.`);
    const out: bigint[] = [];
    let i = index;
    for (let level = 0; level < this.depth; level++) {
      out.push(this.layers[level]![i ^ 1] ?? zeroAt(level));
      i >>= 1;
    }
    return out;
  }
  indexOf(leaf: bigint): number {
    return this.layers[0]!.indexOf(leaf);
  }
}

// ---------------------------------------------------------------------------
// Note encryption: X25519 + AES-256-GCM.
// Layout: 0x01 | ephPub(32) | iv(12) | ct(72 = amount 8 | blinding 32 | label 32) | tag(16) = 133 bytes.
// Deposits encrypt label 0: the pool assigns the label, read it from the Deposited event.
// ---------------------------------------------------------------------------
// Version 2 appends a self-encrypted memo (UTF-8 JSON, <= 512 bytes) after the label:
// 0x02 | ephPub(32) | iv(12) | ct(72 + memo) | tag(16). Spends put the payment details in the
// change note's memo, so the full history is recoverable from the chain and the ghost key alone.
export const MAX_MEMO_BYTES = 512;

export function encryptNote(recipientViewPub: Uint8Array, amount: bigint, blinding: bigint, label: bigint, memo?: object): Hex {
  const ephPriv = randomBytes(32);
  const ephPub = x25519.getPublicKey(ephPriv);
  const shared = x25519.getSharedSecret(ephPriv, recipientViewPub);
  const key = sha256(toBytes("ghost-mode:note"), shared, ephPub, recipientViewPub);
  const iv = randomBytes(12);
  const memoBytes = memo ? new TextEncoder().encode(JSON.stringify(memo)) : new Uint8Array();
  if (memoBytes.length > MAX_MEMO_BYTES) throw new Error("Note memo too long.");
  const plain = concat([
    hexToBytes(`0x${amount.toString(16).padStart(16, "0")}`), hexToBytes(toHex32(blinding)), hexToBytes(toHex32(label)), memoBytes,
  ]);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
  return bytesToHex(concat([new Uint8Array([memo ? 2 : 1]), ephPub, iv, ct, cipher.getAuthTag()]));
}

export type DecryptedNote = { amount: bigint; blinding: bigint; label: bigint; memo?: Record<string, unknown> };

export function decryptNote(viewPriv: Uint8Array, viewPub: Uint8Array, data: Hex): DecryptedNote | null {
  if (!data || data.length < 2 + 133 * 2 || data.length > 2 + (133 + MAX_MEMO_BYTES) * 2) return null;
  const bytes = hexToBytes(data);
  if (!(bytes[0] === 1 && bytes.length === 133) && bytes[0] !== 2) return null;
  const ephPub = bytes.slice(1, 33);
  const iv = bytes.slice(33, 45);
  const ct = bytes.slice(45, bytes.length - 16);
  const tag = bytes.slice(bytes.length - 16);
  try {
    const shared = x25519.getSharedSecret(viewPriv, ephPub);
    const key = sha256(toBytes("ghost-mode:note"), shared, ephPub, viewPub);
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
    const word = (from: number, to: number) => BigInt(`0x${plain.subarray(from, to).toString("hex")}`);
    const note: DecryptedNote = { amount: word(0, 8), blinding: word(8, 40), label: word(40, 72) };
    if (plain.length > 72) {
      try { note.memo = JSON.parse(plain.subarray(72).toString("utf8")); } catch { /* ignore malformed memo */ }
    }
    return note;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// EIP-712 spend intent signed by the PayBox wallet and verified in the circuit.
// ---------------------------------------------------------------------------
export const SPEND_TYPES = {
  // v1.1: hidden flow and public flow are shown separately on the PayBox approval screen.
  GhostSpend: [
    { name: "intent", type: "bytes32" },
    { name: "token", type: "address" },
    { name: "privateAmount", type: "uint256" },
    { name: "privateRecipient", type: "bytes32" },
    { name: "publicAmount", type: "uint256" },
    { name: "publicRecipient", type: "address" },
    { name: "fee", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
} as const;

export const EIP712_DOMAIN_TYPE = [
  { name: "name", type: "string" },
  { name: "version", type: "string" },
  { name: "chainId", type: "uint256" },
  { name: "verifyingContract", type: "address" },
] as const;

export function ghostDomain(chainId: number, pool: Hex) {
  return { name: "GhostMode", version: "1", chainId, verifyingContract: pool } as const;
}

export function domainSeparatorOf(chainId: number, pool: Hex): bigint {
  const domain = { ...ghostDomain(chainId, pool), chainId: BigInt(chainId) };
  return BigInt(hashDomain({ domain, types: { EIP712Domain: EIP712_DOMAIN_TYPE } }));
}

export function extDataHashOf(relayer: Hex, enc0: Hex, enc1: Hex): bigint {
  const encoded = encodeAbiParameters([{ type: "address" }, { type: "bytes" }, { type: "bytes" }], [relayer, enc0, enc1]);
  return BigInt(keccak256(encoded)) % FIELD_SIZE;
}

export const intentOf = (n0: bigint, n1: bigint, c0: bigint, c1: bigint, extDataHash: bigint) => H5(n0, n1, c0, c1, extDataHash);
