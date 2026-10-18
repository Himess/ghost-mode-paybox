// UltraHonk prover (bb.js, EVM/ZK target) in a worker thread. Proofs run one at a time on all cores.
import { Worker } from "node:worker_threads";
import type { Hex } from "viem";
import { config } from "./config.js";

type Result = { proof: Hex; publicInputs: string[]; witnessMs: number; proveMs: number };
let worker: Worker | undefined;
let nextId = 1;
const waiting = new Map<number, { resolve: (r: Result) => void; reject: (e: Error) => void }>();
let queue: Promise<unknown> = Promise.resolve();

function getWorker(): Worker {
  if (worker) return worker;
  worker = new Worker(new URL("./proverWorker.ts", import.meta.url), {
    workerData: { circuitPath: config.circuitPath },
    execArgv: ["--import", "tsx"],
  });
  worker.on("message", (msg: any) => {
    if (msg.ready) return;
    const w = waiting.get(msg.id);
    if (!w) return;
    waiting.delete(msg.id);
    if (msg.ok) w.resolve({ proof: `0x${msg.proof}`, publicInputs: msg.publicInputs, witnessMs: msg.witnessMs, proveMs: msg.proveMs });
    else w.reject(new Error(msg.error));
  });
  worker.on("error", (err) => {
    for (const w of waiting.values()) w.reject(err);
    waiting.clear();
    worker = undefined;
  });
  return worker;
}

export function warmProver() {
  getWorker();
}

export function prove(inputs: Record<string, unknown>): Promise<Result> {
  const run = () => new Promise<Result>((resolve, reject) => {
    const id = nextId++;
    waiting.set(id, { resolve, reject });
    getWorker().postMessage({ id, inputs });
  });
  const result = queue.then(run, run);
  queue = result.catch(() => undefined);
  return result;
}
