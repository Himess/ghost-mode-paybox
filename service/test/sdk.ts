// SDK checks: change memos, pre-signature self-validation (incl. tamper cases) and a real proof
// over a spend whose change note carries a memo.
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { cpus } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { Noir } from "@noir-lang/noir_js";
import { hexToBytes, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  ASP_DEPTH, MerkleTree, TREE_DEPTH, commitmentOf, decryptNote, encryptNote, formatGhostKey, parseGhostKey, randomField,
} from "../../plugin/src/core/primitives.js";
import { buildSpend, scanNotes, signatureToCircuit, validateSpend, type PoolState } from "../../plugin/src/core/spend.js";

const here = dirname(fileURLToPath(import.meta.url));
const token = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" as Hex;
const account = privateKeyToAccount(generatePrivateKey());
const keys = parseGhostKey(formatGhostKey(randomBytes(32), hexToBytes(account.publicKey).slice(1)));
const friend = parseGhostKey(formatGhostKey(randomBytes(32), hexToBytes(privateKeyToAccount(generatePrivateKey()).publicKey).slice(1)));
const label = 4242n, amount = 50_000_000n, blinding = randomField();
const commitment = commitmentOf({ asset: BigInt(token), amount, ownerTag: keys.ownerTag, blinding, label });
const tree = new MerkleTree(TREE_DEPTH, [commitment]);
const asp = new MerkleTree(ASP_DEPTH, [label]);
const state: PoolState = {
  chainId: 8453, pool: "0x1882d5b6910c418c79ee6997179d473bc884693d", token, relayer: "0x06cb7dDa8a2E453097085629A6bBfAf33EB9d78b",
  relayerFee: 10_000n, root: tree.root,
  leaves: [{ index: 0, commitment, encrypted: encryptNote(keys.viewPub, amount, blinding, 0n, { v: 1, k: "shield" }), blockTime: 0, txHash: "0x" }],
  deposits: [{ leafIndex: 0, label, amount, depositor: account.address, blockTime: 0, txHash: "0x" }],
  nullifiers: new Set(), asp: { root: asp.root, labels: [label] },
};
let failures = 0;
const check = (name: string, ok: boolean) => { console.log(`${ok ? "ok  " : "FAIL"} ${name}`); if (!ok) failures++; };
const throws = (fn: () => void) => { try { fn(); return false; } catch { return true; } };

const notes = scanNotes(keys, state);
check("deposit note with memo is found", notes.length === 1 && notes[0]!.memo?.k === "shield");
const base = { keys, state, notes, deadline: Math.floor(Date.now() / 1000) + 1200 };
const pay = buildSpend({ ...base, kind: "pay_address", amount: 10_000_000n, recipientAddress: "0x000000000000000000000000000000000000bEEF" });
check("pay_address passes self-validation", !throws(() => validateSpend(pay, keys, state)));
const memo = decryptNote(keys.viewPriv, keys.viewPub, pay.tx.encryptedOutput1)?.memo;
check("change memo records the payment", memo?.k === "pay_address" && memo?.a === "10000000" && memo?.to === "0x000000000000000000000000000000000000bEEF");
const ghost = buildSpend({ ...base, kind: "send_ghost", amount: 20_000_000n, recipientGhost: { ownerTag: friend.ownerTag, viewPub: friend.viewPub } });
check("send_ghost passes self-validation", !throws(() => validateSpend(ghost, keys, state)));
check("recipient can decrypt the ghost transfer", decryptNote(friend.viewPriv, friend.viewPub, ghost.tx.encryptedOutput0)?.amount === 20_000_000n);
const x402 = buildSpend({ ...base, kind: "pay_x402", amount: 2_000n, recipientAddress: state.relayer, memoExtra: { h: "api.blockscout.com" } });
check("x402 memo carries the host", decryptNote(keys.viewPriv, keys.viewPub, x402.tx.encryptedOutput1)?.memo?.h === "api.blockscout.com");
check("refund target is the spender", pay.refundTo.ownerTag === keys.ownerTag.toString());
const full = buildSpend({ ...base, kind: "pay_address", amount: 49_990_000n, recipientAddress: "0x000000000000000000000000000000000000bEEF" });
check("zero-change spend still carries a memo", decryptNote(keys.viewPriv, keys.viewPub, full.tx.encryptedOutput1)?.memo?.k === "pay_address");

// Tampering: each must be caught before signing.
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const t1 = clone(pay); t1.tx.encryptedOutput1 = encryptNote(friend.viewPub, 39_990_000n, 1n, label);
check("tamper: change encrypted to someone else", throws(() => validateSpend(t1, keys, state)));
const t2 = clone(pay); t2.typedData.message.privateRecipient = `0x${"11".repeat(32)}` as Hex;
check("tamper: hidden recipient on public payout", throws(() => validateSpend(t2, keys, state)));
const t3 = clone(pay); t3.circuitInputs.out_owner_tags[1] = friend.ownerTag.toString();
check("tamper: change owner", throws(() => validateSpend(t3, keys, state)));
const t4 = clone(pay); t4.typedData.message.publicAmount = "1";
check("tamper: displayed amount", throws(() => validateSpend(t4, keys, state)));
const t5 = clone(pay); t5.tx.relayer = "0x0000000000000000000000000000000000000001";
check("tamper: relayer", throws(() => validateSpend(t5, keys, state)));
const spent = { ...state, nullifiers: new Set([notes[0]!.nullifier.toString()]) };
check("spent input rejected", throws(() => validateSpend(pay, keys, spent)));

// Real proof with a v2 (memo) change ciphertext bound into extDataHash.
const { EIP712Domain: _d, ...types } = pay.typedData.types;
const signature = await account.signTypedData({ ...pay.typedData, types } as never);
const program = JSON.parse(readFileSync(resolve(here, "../../circuits/transact/target/transact.json"), "utf8"));
const { witness } = await new Noir(program).execute({ ...pay.circuitInputs, signature: signatureToCircuit(signature) } as never);
const api = await Barretenberg.new({ threads: Math.max(1, cpus().length - 2) });
try {
  const backend = new UltraHonkBackend(program.bytecode, api);
  const proof = await backend.generateProof(witness, { verifierTarget: "evm" });
  check("proof over memo-carrying spend verifies", await backend.verifyProof(proof, { verifierTarget: "evm" }));
} finally {
  await api.destroy();
}
console.log(failures ? `${failures} FAILED` : "SDK CHECKS PASSED");
process.exit(failures ? 1 : 0);
