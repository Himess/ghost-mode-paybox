// Note scanning and spend construction. Produces every circuit input except the
// PayBox signature, plus the EIP-712 typed data the PayBox wallet must sign.
import { bytesToHex, compactSignatureToSignature, getAddress, hexToBytes, parseCompactSignature, parseSignature, serializeSignature, zeroAddress, type Hex } from "viem";
import {
  ASP_DEPTH, EIP712_DOMAIN_TYPE, H2, MerkleTree, SPEND_TYPES, TREE_DEPTH, commitmentOf, decryptNote, domainSeparatorOf,
  encryptNote, extDataHashOf, ghostDomain, intentOf, nullifierOf, randomField, toHex32, zeroAt, type GhostKeys,
} from "./primitives.js";

/** v1.1 change blinding: Poseidon2(nk, nullifier0), enforced by the circuit. */
export const changeBlindingOf = (nk: bigint, nullifier0: bigint) => H2(nk, nullifier0);

export type PoolState = {
  chainId: number;
  pool: Hex;
  token: Hex;
  relayer: Hex;
  relayerFee: bigint;
  root: bigint;
  leaves: { index: number; commitment: bigint; encrypted: Hex; blockTime: number; txHash: Hex }[];
  deposits: { leafIndex: number; label: bigint; amount: bigint; depositor: Hex; blockTime: number; txHash: Hex }[];
  nullifiers: Set<string>;
  asp: { root: bigint; labels: bigint[] };
  /** Tags H2(nullifier, nk) of signed spends the relayer has not sent yet (raw nullifiers stay private until relay). */
  pending?: Set<string>;
};

export type OwnedNote = {
  leafIndex: number;
  commitment: bigint;
  amount: bigint;
  blinding: bigint;
  label: bigint;
  nullifier: bigint;
  spent: boolean;
  /** Signed and scheduled for relay (random delay); not spendable again. */
  pending: boolean;
  approved: boolean;
  blockTime: number;
  txHash: Hex;
  source: "deposit" | "transfer";
  memo?: Record<string, unknown>;
};

export function scanNotes(keys: GhostKeys, state: PoolState): OwnedNote[] {
  const asset = BigInt(state.token);
  const depositByLeaf = new Map(state.deposits.map((d) => [d.leafIndex, d]));
  const approved = new Set(state.asp.labels.map((l) => l.toString()));
  const notes: OwnedNote[] = [];
  for (const leaf of state.leaves) {
    const dec = decryptNote(keys.viewPriv, keys.viewPub, leaf.encrypted);
    if (!dec) continue;
    const deposit = depositByLeaf.get(leaf.index);
    const label = dec.label === 0n && deposit ? deposit.label : dec.label;
    const note = { asset, amount: dec.amount, ownerTag: keys.ownerTag, blinding: dec.blinding, label };
    if (commitmentOf(note) !== leaf.commitment) continue; // not ours, or malformed
    const nullifier = nullifierOf(leaf.commitment, leaf.index, keys.nk);
    notes.push({
      leafIndex: leaf.index, commitment: leaf.commitment, amount: dec.amount, blinding: dec.blinding, label, nullifier,
      spent: state.nullifiers.has(nullifier.toString()), pending: state.pending?.has(H2(nullifier, keys.nk).toString()) ?? false,
      approved: approved.has(label.toString()),
      blockTime: leaf.blockTime, txHash: leaf.txHash, source: deposit ? "deposit" : "transfer",
      ...(dec.memo ? { memo: dec.memo } : {}),
    });
  }
  return notes;
}

export type SpendKind = "send_ghost" | "pay_address" | "unshield" | "pay_x402";

export type SpendRequest = {
  keys: GhostKeys;
  state: PoolState;
  notes: OwnedNote[];
  kind: SpendKind;
  amount: bigint;
  recipientAddress?: Hex;
  recipientGhost?: { ownerTag: bigint; viewPub: Uint8Array };
  deadline: number;
  /** Extra memo fields (e.g. the x402 host) stored, encrypted to the sender, in the change note. */
  memoExtra?: Record<string, string>;
};

export type SpendPackage = ReturnType<typeof buildSpend>;

const str = (v: bigint | number) => v.toString();

function pickInputs(notes: OwnedNote[], needed: bigint): OwnedNote[] {
  const usable = notes.filter((n) => !n.spent && !n.pending && n.approved && n.amount > 0n).sort((a, b) => (a.amount < b.amount ? -1 : 1));
  const single = usable.find((n) => n.amount >= needed);
  if (single) return [single];
  let best: OwnedNote[] | undefined;
  for (let i = 0; i < usable.length; i++) {
    for (let j = i + 1; j < usable.length; j++) {
      const a = usable[i]!, b = usable[j]!;
      if (a.label !== b.label || a.amount + b.amount < needed) continue;
      if (!best || a.amount + b.amount < best[0]!.amount + best[1]!.amount) best = [a, b];
    }
  }
  if (best) return best;
  const total = usable.reduce((s, n) => s + n.amount, 0n);
  throw new Error(
    `Insufficient spendable ghost balance: need ${needed} atomic units including the relayer fee, have ${total} across ${usable.length} approved note(s). ` +
      "A spend can combine at most two notes from the same deposit lineage.",
  );
}

export function buildSpend(req: SpendRequest) {
  const { keys, state, kind, amount } = req;
  if (amount <= 0n) throw new Error("Amount must be positive.");
  const fee = state.relayerFee;
  const asset = BigInt(state.token);
  const ghostTransfer = kind === "send_ghost";
  if (ghostTransfer && !req.recipientGhost) throw new Error("send_ghost needs a ghost address recipient.");
  if (!ghostTransfer && !req.recipientAddress) throw new Error(`${kind} needs an EVM recipient address.`);

  const inputs = pickInputs(req.notes, amount + fee);
  const label = inputs[0]!.label;
  const sumIn = inputs.reduce((s, n) => s + n.amount, 0n);
  const change = sumIn - amount - fee;

  // Inputs (pad with a zero-value dummy note).
  const tree = new MerkleTree(TREE_DEPTH, state.leaves.map((l) => l.commitment));
  if (tree.root !== state.root) throw new Error("Indexer root mismatch; retry in a few seconds.");
  const aspTree = new MerkleTree(ASP_DEPTH, state.asp.labels);
  if (aspTree.root !== state.asp.root) throw new Error("ASP root mismatch; the association set is updating, retry shortly.");
  const zeroPath = (depth: number) => Array.from({ length: depth }, (_, i) => zeroAt(i));

  const ins = inputs.map((n) => ({
    amount: n.amount, blinding: n.blinding, label: n.label, index: n.leafIndex, nullifier: n.nullifier,
    path: tree.path(n.leafIndex), aspIndex: state.asp.labels.findIndex((l) => l === n.label),
  }));
  if (ins.length === 1) {
    const blinding = randomField();
    const commitment = commitmentOf({ asset, amount: 0n, ownerTag: keys.ownerTag, blinding, label });
    ins.push({ amount: 0n, blinding, label, index: 0, nullifier: nullifierOf(commitment, 0, keys.nk), path: zeroPath(TREE_DEPTH), aspIndex: -1 });
  }
  const aspPaths = ins.map((i) => (i.aspIndex >= 0 ? aspTree.path(i.aspIndex) : zeroPath(ASP_DEPTH)));

  // Outputs: [recipient note or zero note, change note].
  const out0 = ghostTransfer
    ? { amount, ownerTag: req.recipientGhost!.ownerTag, blinding: randomField() }
    : { amount: 0n, ownerTag: keys.ownerTag, blinding: randomField() };
  // v1.1: the change blinding is derived from nk and the first nullifier (enforced in the circuit).
  const out1 = { amount: change, ownerTag: keys.ownerTag, blinding: changeBlindingOf(keys.nk, ins[0]!.nullifier) };
  const c0 = commitmentOf({ asset, label, ...out0 });
  const c1 = commitmentOf({ asset, label, ...out1 });
  const enc0: Hex = ghostTransfer ? encryptNote(req.recipientGhost!.viewPub, out0.amount, out0.blinding, label) : "0x";
  // The change note is always emitted (even for zero change) because it carries the sender's own
  // encrypted record of this payment; history is recoverable from the chain plus the ghost key.
  const memo = {
    v: 1, k: kind, a: amount.toString(), f: fee.toString(), t: Math.floor(Date.now() / 1000),
    to: ghostTransfer ? `ghost:${toHex32(req.recipientGhost!.ownerTag).slice(2, 14)}` : getAddress(req.recipientAddress!),
    ...(req.memoExtra ?? {}),
  };
  const enc1: Hex = encryptNote(keys.viewPub, out1.amount, out1.blinding, label, memo);

  const recipient: Hex = ghostTransfer ? zeroAddress : getAddress(req.recipientAddress!);
  const publicOut = ghostTransfer ? fee : amount + fee;
  const extDataHash = extDataHashOf(state.relayer, enc0, enc1);
  const intent = intentOf(ins[0]!.nullifier, ins[1]!.nullifier, c0, c1, extDataHash);
  const ds = domainSeparatorOf(state.chainId, state.pool);
  const mask128 = (1n << 128n) - 1n;

  const message = {
    intent: toHex32(intent),
    token: getAddress(state.token),
    privateAmount: str(out0.amount),
    privateRecipient: out0.amount > 0n ? toHex32(out0.ownerTag) : toHex32(0n),
    publicAmount: str(publicOut - fee),
    publicRecipient: recipient,
    fee: str(fee),
    deadline: str(req.deadline),
  };
  const typedData = {
    domain: ghostDomain(state.chainId, state.pool),
    types: { EIP712Domain: EIP712_DOMAIN_TYPE, ...SPEND_TYPES },
    primaryType: "GhostSpend" as const,
    message,
  };

  const pub = keys.pubKey;
  const circuitInputs = {
    root: str(state.root),
    asp_root: str(state.asp.root),
    nullifiers: ins.map((i) => str(i.nullifier)),
    out_commitments: [str(c0), str(c1)],
    public_out: str(publicOut),
    ext_data_hash: str(extDataHash),
    asset: str(asset),
    recipient: str(BigInt(recipient)),
    fee: str(fee),
    deadline: str(req.deadline),
    domain_hi: str(ds >> 128n),
    domain_lo: str(ds & mask128),
    in_amounts: ins.map((i) => str(i.amount)),
    in_blindings: ins.map((i) => str(i.blinding)),
    in_labels: ins.map((i) => str(i.label)),
    in_indices: ins.map((i) => str(i.index)),
    in_paths: ins.map((i) => i.path.map(str)),
    asp_indices: ins.map((i) => str(Math.max(i.aspIndex, 0))),
    asp_paths: aspPaths.map((p) => p.map(str)),
    nk: str(keys.nk),
    pub_x: Array.from(pub.slice(0, 32), (b) => str(b)),
    pub_y: Array.from(pub.slice(32, 64), (b) => str(b)),
    out_amounts: [str(out0.amount), str(out1.amount)],
    out_owner_tags: [str(out0.ownerTag), str(out1.ownerTag)],
    out_blindings: [str(out0.blinding), str(out1.blinding)],
  };

  const tx = {
    root: str(state.root),
    aspRoot: str(state.asp.root),
    nullifiers: ins.map((i) => str(i.nullifier)),
    outCommitments: [str(c0), str(c1)],
    publicOut: str(publicOut),
    recipient,
    fee: str(fee),
    deadline: str(req.deadline),
    relayer: getAddress(state.relayer),
    encryptedOutput0: enc0,
    encryptedOutput1: enc1,
  };

  return {
    version: 1 as const,
    kind,
    chainId: state.chainId,
    pool: state.pool,
    pubKey: `0x04${Buffer.from(pub).toString("hex")}` as Hex,
    // Where the relayer re-deposits funds privately if an x402 merchant payment fails after transact.
    refundTo: { ownerTag: keys.ownerTag.toString(), viewPub: bytesToHex(keys.viewPub) },
    memo,
    circuitInputs,
    tx,
    typedData,
    summary: {
      amount: str(amount), fee: str(fee), change: str(change), inputsUsed: inputs.length,
      inputLeaves: inputs.map((n) => n.leafIndex), recipient: ghostTransfer ? "ghost" : recipient,
    },
  };
}

const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/**
 * Converts a 65-byte (r, s, v) signature into the circuit's 64-byte (r, s) array.
 * MPC signers may return high-s signatures; (r, n - s) verifies for the same key,
 * so normalise to low-s, which the in-circuit verifier expects.
 */
export function signatureToCircuit(signature: Hex): string[] {
  const length = hexToBytes(signature).length;
  if (length !== 65 && length !== 64) throw new Error("Signature must be 64 or 65 bytes.");
  const sig = length === 64 ? compactSignatureToSignature(parseCompactSignature(signature)) : parseSignature(signature);
  let s = BigInt(sig.s);
  if (s > SECP256K1_N / 2n) s = SECP256K1_N - s;
  return [...Array.from(hexToBytes(sig.r)), ...Array.from(hexToBytes(toHex32(s)))].map((b) => b.toString());
}

/**
 * Re-derives every security-relevant value of a prepared spend before it is shown for signing.
 * A package that fails here never reaches the PayBox signature step.
 */
export function validateSpend(pkg: SpendPackage, keys: GhostKeys, state: PoolState): void {
  const ci = pkg.circuitInputs;
  const t = pkg.tx;
  const fail = (why: string) => { throw new Error(`Self-check failed: ${why}. Nothing was signed.`); };
  const asset = BigInt(state.token);
  const label = BigInt(ci.in_labels[BigInt(ci.in_amounts[0]!) !== 0n ? 0 : 1]!);
  // 1. Change note returns to us and decrypts with our own ghost key.
  if (BigInt(ci.out_owner_tags[1]!) !== keys.ownerTag) fail("change is not addressed to this ghost key");
  const change = decryptNote(keys.viewPriv, keys.viewPub, t.encryptedOutput1);
  if (!change) fail("change note does not decrypt with this ghost key");
  if (change!.amount !== BigInt(ci.out_amounts[1]!) || change!.blinding !== BigInt(ci.out_blindings[1]!) || change!.label !== label) fail("change note contents mismatch");
  const c1 = commitmentOf({ asset, amount: change!.amount, ownerTag: keys.ownerTag, blinding: change!.blinding, label });
  if (c1.toString() !== t.outCommitments[1]) fail("change commitment mismatch");
  // 2. Output 0: zero for public payouts; for ghost transfers it decrypts for nobody we can check, but its commitment must match.
  const c0 = commitmentOf({ asset, amount: BigInt(ci.out_amounts[0]!), ownerTag: BigInt(ci.out_owner_tags[0]!), blinding: BigInt(ci.out_blindings[0]!), label });
  if (c0.toString() !== t.outCommitments[0]) fail("output commitment mismatch");
  const msg = pkg.typedData.message;
  if (BigInt(ci.out_blindings[1]!) !== changeBlindingOf(keys.nk, BigInt(t.nullifiers[0]!))) fail("change blinding is not derived from the ghost key");
  if (BigInt(msg.privateAmount) !== BigInt(ci.out_amounts[0]!)) fail("displayed private amount differs");
  if (BigInt(msg.publicAmount) !== BigInt(t.publicOut) - BigInt(t.fee)) fail("displayed public amount differs");
  if (getAddress(msg.publicRecipient) !== getAddress(t.recipient)) fail("displayed public recipient differs from the payout");
  if (pkg.kind !== "send_ghost") {
    if (BigInt(ci.out_amounts[0]!) !== 0n) fail("public payout carries a hidden output");
    if (BigInt(msg.privateRecipient) !== 0n) fail("public payout shows a hidden recipient");
  } else {
    if (BigInt(msg.privateRecipient) !== BigInt(ci.out_owner_tags[0]!)) fail("displayed ghost recipient differs");
    if (BigInt(msg.publicAmount) !== 0n || BigInt(msg.publicRecipient) !== 0n) fail("ghost transfer carries a public payout");
  }
  // 3. Nullifiers: distinct and unspent (dummy blinding is random, so dummies never collide).
  if (t.nullifiers[0] === t.nullifiers[1]) fail("duplicate nullifiers");
  if (state.nullifiers.has(t.nullifiers[0]!) || state.nullifiers.has(t.nullifiers[1]!)) fail("an input note is already spent");
  if (state.pending?.has(H2(BigInt(t.nullifiers[0]!), keys.nk).toString()) || state.pending?.has(H2(BigInt(t.nullifiers[1]!), keys.nk).toString())) {
    fail("an input note is already being relayed");
  }
  // 4. Binding values recomputed from the transaction fields.
  const ext = extDataHashOf(t.relayer, t.encryptedOutput0, t.encryptedOutput1);
  if (ext.toString() !== ci.ext_data_hash) fail("external data hash mismatch");
  const intent = intentOf(BigInt(t.nullifiers[0]!), BigInt(t.nullifiers[1]!), BigInt(t.outCommitments[0]!), BigInt(t.outCommitments[1]!), ext);
  if (toHex32(intent) !== msg.intent) fail("intent mismatch");
  // 5. Value conservation and the displayed amount.
  const sumIn = BigInt(ci.in_amounts[0]!) + BigInt(ci.in_amounts[1]!);
  const sumOut = BigInt(ci.out_amounts[0]!) + BigInt(ci.out_amounts[1]!) + BigInt(t.publicOut);
  if (sumIn !== sumOut) fail("value is not conserved");

}

/** Expands an EIP-2098 compact (64-byte) signature to the standard 65-byte (r, s, v) form. */
export function fullSignature(signature: string): Hex {
  const sig = signature as Hex;
  return hexToBytes(sig).length === 64 ? serializeSignature(compactSignatureToSignature(parseCompactSignature(sig))) : sig;
}
