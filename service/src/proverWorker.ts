// Runs Noir witness generation and UltraHonk proving off the main thread so the
// HTTP API stays responsive while a proof is being built.
import { readFileSync } from "node:fs";
import { cpus } from "node:os";
import { parentPort, workerData } from "node:worker_threads";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { Noir } from "@noir-lang/noir_js";

const program = JSON.parse(readFileSync(workerData.circuitPath as string, "utf8"));
const noir = new Noir(program);
const backend = Barretenberg.new({ threads: Math.max(1, cpus().length - 2) }).then((api) => new UltraHonkBackend(program.bytecode, api));

parentPort!.on("message", async (msg: { id: number; inputs: Record<string, unknown> }) => {
  try {
    const t0 = Date.now();
    const { witness } = await noir.execute(msg.inputs as never);
    const t1 = Date.now();
    const data = await (await backend).generateProof(witness, { verifierTarget: "evm" });
    parentPort!.postMessage({ id: msg.id, ok: true, proof: Buffer.from(data.proof).toString("hex"), publicInputs: data.publicInputs, witnessMs: t1 - t0, proveMs: Date.now() - t1 });
  } catch (err) {
    parentPort!.postMessage({ id: msg.id, ok: false, error: (err as Error).message ?? String(err) });
  }
});
parentPort!.postMessage({ ready: true });
