// End-to-end circuit check: builds a real spend with the shared SDK, signs the
// EIP-712 intent with a secp256k1 key (stand-in for a PayBox wallet), executes
// the Noir program, proves with UltraHonk (EVM/ZK target) and verifies.
import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { cpus } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { Noir } from "@noir-lang/noir_js";
import { bytesToHex, hexToBytes, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  ASP_DEPTH, MerkleTree, TREE_DEPTH, commitmentOf, encryptNote, formatGhostKey, parseGhostKey, randomField,
} from "../../plugin/src/core/primitives.js";
import { buildSpend, scanNotes, signatureToCircuit, type PoolState } from "../../plugin/src/core/spend.js";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
const pool = (process.env.POOL ?? "0x000000000000000000000000000000000000dEaD") as Hex;
const token = (process.env.TOKEN ?? "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913") as Hex;
const chainId = Number(process.env.CHAIN_ID ?? 8453);

const account = privateKeyToAccount(generatePrivateKey());
const keys = parseGhostKey(formatGhostKey(randomBytes(32), hexToBytes(account.publicKey).slice(1)));

const label = 987654321n;
const amount = 50_000_000n;
const blinding = randomField();
const commitment = commitmentOf({ asset: BigInt(token), amount, ownerTag: keys.ownerTag, blinding, label });
const tree = new MerkleTree(TREE_DEPTH, [commitment]);
const asp = new MerkleTree(ASP_DEPTH, [label]);
const state: PoolState = {
  chainId, pool, token, relayer: "0x1111111111111111111111111111111111111111", relayerFee: 10_000n, root: tree.root,
  leaves: [{ index: 0, commitment, encrypted: encryptNote(keys.viewPub, amount, blinding, 0n), blockTime: 0, txHash: "0x" }],
  deposits: [{ leafIndex: 0, label, amount, depositor: account.address, blockTime: 0, txHash: "0x" }],
  nullifiers: new Set(),
  asp: { root: asp.root, labels: [label] },
};

const notes = scanNotes(keys, state);
if (notes.length !== 1) throw new Error(`expected 1 owned note, found ${notes.length}`);
const kind = (process.env.KIND ?? "pay_address") as "pay_address" | "send_ghost";
const pkg = buildSpend({
  keys, state, notes, kind, amount: 20_000_000n,
  recipientAddress: "0x2222222222222222222222222222222222222222",
  recipientGhost: { ownerTag: keys.ownerTag, viewPub: keys.viewPub },
  deadline: Math.floor(Date.now() / 1000) + 3600,
});
const { EIP712Domain: _omit, ...types } = pkg.typedData.types;
const signature = await account.signTypedData({ ...pkg.typedData, types } as never);
const inputs = { ...pkg.circuitInputs, signature: signatureToCircuit(signature) };

const program = JSON.parse(readFileSync(resolve(root, "circuits/transact/target/transact.json"), "utf8"));
const t0 = Date.now();
const { witness } = await new Noir(program).execute(inputs);
const t1 = Date.now();
const api = await Barretenberg.new({ threads: cpus().length });
try {
  const backend = new UltraHonkBackend(program.bytecode, api);
  const proof = await backend.generateProof(witness, { verifierTarget: "evm" });
  const t2 = Date.now();
  const ok = await backend.verifyProof(proof, { verifierTarget: "evm" });
  console.log(JSON.stringify({ witnessMs: t1 - t0, proveMs: t2 - t1, verified: ok, proofBytes: proof.proof.length, publicInputs: proof.publicInputs.length }));
  mkdirSync(resolve(here, "fixtures"), { recursive: true });
  writeFileSync(resolve(here, "fixtures/proof.json"), JSON.stringify({
    pool, token, chainId, proof: bytesToHex(proof.proof), publicInputs: proof.publicInputs, tx: pkg.tx, typedData: pkg.typedData,
  }, null, 2));
} finally {
  await api.destroy();
}
