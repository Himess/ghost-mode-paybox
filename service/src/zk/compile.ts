// Compiles the Noir `transact` circuit with noir_wasm, then derives the EVM
// (keccak, zero-knowledge) verification key and Solidity verifier with bb.js.
import { mkdirSync, writeFileSync } from "node:fs";
import { cpus } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { compileNoir } from "./noirFs.js";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../../..");
const circuitDir = resolve(root, "circuits/transact");
const targetDir = resolve(circuitDir, "target");

const started = Date.now();
const { program } = await compileNoir(resolve(root, "circuits"), "transact");
mkdirSync(targetDir, { recursive: true });
writeFileSync(resolve(targetDir, "transact.json"), JSON.stringify(program));
console.error(`compiled in ${Date.now() - started} ms; bytecode ${program.bytecode.length} b64 chars`);

const api = await Barretenberg.new({ threads: cpus().length });
try {
  const backend = new UltraHonkBackend(program.bytecode, api);
  const vk = await backend.getVerificationKey({ verifierTarget: "evm" });
  writeFileSync(resolve(targetDir, "vk.bin"), vk);
  const solidity = await backend.getSolidityVerifier(vk, { verifierTarget: "evm" });
  const out = resolve(root, "contracts/src/HonkVerifier.sol");
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, solidity);
  console.error(`vk ${vk.length} bytes; verifier written to ${out} (${solidity.length} chars) in ${Date.now() - started} ms`);
} finally {
  await api.destroy();
}
