// End-to-end test that drives the BUILT plugin bundle over MCP stdio (one fresh
// process per call, like PayBox), executes its proposals with a local wallet that
// stands in for PayBox, and checks balances on-chain.
// Env: RPC_URL, SERVICE_URL, USER_KEY, AYSE_KEY, TOKEN (optional), CHAIN_ID (optional)
import { spawn } from "node:child_process";
import { dirname, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { createPublicClient, createWalletClient, defineChain, http, parseAbi, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const here = dirname(fileURLToPath(import.meta.url));
const bundle = resolve(here, "../../plugin/dist/plugin.mjs");
const rpc = process.env.RPC_URL ?? "http://127.0.0.1:8545";
const chainId = Number(process.env.CHAIN_ID ?? 31337);
const chain = defineChain({ id: chainId, name: "e2e", nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 }, rpcUrls: { default: { http: [rpc] } } });
const pub = createPublicClient({ chain, transport: http(rpc) });
const user = privateKeyToAccount(process.env.USER_KEY as Hex);
const ayse = privateKeyToAccount(process.env.AYSE_KEY as Hex);
const erc20 = parseAbi(["function balanceOf(address) view returns (uint256)"]);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function tool(name: string, args: Record<string, unknown>): Promise<any> {
  const child = spawn(process.execPath, [bundle], { env: { ...process.env, GHOST_SERVICE_URL: process.env.SERVICE_URL }, stdio: ["pipe", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (d) => (stderr += d));
  child.stdin.write(`${JSON.stringify({
    jsonrpc: "2.0", id: 2, method: "tools/call",
    params: { name, arguments: args, _meta: {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientInfo": { name: "ghost-e2e", version: "1" },
      "io.modelcontextprotocol/clientCapabilities": {},
    } },
  })}\n`);
  const started = Date.now();
  const lines = createInterface({ input: child.stdout });
  for await (const line of lines) {
    const msg = JSON.parse(line);
    if (msg.id !== 2) continue;
    child.kill();
    const ms = Date.now() - started;
    if (msg.error) throw new Error(`${name}: JSON-RPC error ${JSON.stringify(msg.error)}`);
    if (msg.result.isError) throw new Error(`${name}: ${msg.result.content?.[0]?.text}`);
    console.log(`  ${name} ok (${ms} ms): ${msg.result.content?.[0]?.text?.slice(0, 160)}`);
    if (ms > 10_000) throw new Error(`${name} exceeded the 10 s PayBox budget (${ms} ms)`);
    return msg.result.structuredContent;
  }
  throw new Error(`${name}: no response. stderr: ${stderr.slice(0, 500)}`);
}

async function execute(account: typeof user, proposal: any) {
  const p = proposal["io.paybox/transactionProposal"];
  const wallet = createWalletClient({ account, chain, transport: http(rpc) });
  const hash = await wallet.sendTransaction({ to: p.transaction.to, data: p.transaction.data, value: BigInt(p.transaction.value) });
  const receipt = await pub.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error(`proposal tx reverted: ${hash}`);
  return hash;
}

async function setup(account: typeof user) {
  const step1 = await tool("ghost_setup", {});
  const signature = await account.signMessage({ message: step1.sign_request.message });
  return tool("ghost_setup", { message: step1.sign_request.message, signature });
}

async function spend(account: typeof user, args: Record<string, unknown>) {
  const prepared = await tool("ghost_prepare", args);
  const { EIP712Domain: _d, ...types } = prepared.sign_request.typedData.types;
  const signature = await account.signTypedData({ ...prepared.sign_request.typedData, types } as never);
  const { job_id } = await tool("ghost_submit", { prepare_id: prepared.prepare_id, signature });
  for (;;) {
    await sleep(2_000);
    const job = await tool("ghost_job", { job_id });
    if (job.status === "done") return { job, job_id, prepared };
    if (job.status === "failed") throw new Error(`job failed: ${job.error}`);
  }
}

async function waitSpendable(ghostKey: string, min: string) {
  for (let i = 0; i < 40; i++) {
    const bal = await tool("ghost_balance", { ghost_key: ghostKey });
    if (Number(bal.spendable_usdc) >= Number(min)) return bal;
    await sleep(3_000);
  }
  throw new Error("note never became spendable");
}

const info = await (await fetch(`${process.env.SERVICE_URL}/v1/info`)).json();
const token = info.token as Hex;
console.log("1. setup ghost identities");
const me = await setup(user);
const her = await setup(ayse);
if (!me.backed_up) throw new Error("ghost key was not backed up");
console.log("1b. recover the ghost key from the encrypted backup with a fresh signature");
const r1 = await tool("ghost_recover", { address: user.address });
const r2 = await tool("ghost_recover", { address: user.address, message: r1.sign_request.message, signature: await user.signMessage({ message: r1.sign_request.message }) });
if (!r2.ghost_keys.includes(me.ghost_key)) throw new Error("recovery did not return the ghost key");
const wrong = await tool("ghost_recover", { address: user.address }).then(async (c) =>
  tool("ghost_recover", { address: user.address, message: c.sign_request.message, signature: await ayse.signMessage({ message: c.sign_request.message }) }).then(() => "accepted", () => "rejected"));
if (wrong !== "rejected") throw new Error("recovery accepted another wallet's signature");
const shieldInfo = await (await fetch(`${process.env.SERVICE_URL}/v1/shield/info`)).json();
if (shieldInfo.supported) {
  console.log(`2. shield 50 USDC with ONE signature (EIP-3009, relayer pays gas; fee ${shieldInfo.fee})`);
  const ethBefore = await pub.getBalance({ address: user.address });
  const auth = await tool("ghost_shield_authorize", { ghost_key: me.ghost_key, amount_usdc: "50" });
  console.log("   human_summary:", auth.human_summary);
  const { EIP712Domain: _d2, ...types2 } = auth.sign_request.typedData.types;
  const sig = await user.signTypedData({ ...auth.sign_request.typedData, types: types2 } as never);
  const { job_id } = await tool("ghost_submit", { prepare_id: auth.prepare_id, signature: sig });
  for (;;) {
    await sleep(1_500);
    const job = await tool("ghost_job", { job_id });
    if (job.status === "done") break;
    if (job.status === "failed") throw new Error(`shield failed: ${job.error}`);
  }
  const ethAfter = await pub.getBalance({ address: user.address });
  if (ethAfter !== ethBefore) throw new Error("user paid gas for the one-signature shield");
  console.log("   user ETH unchanged: shield was gasless for the user");
} else {
  console.log("2. shield 50 USDC (approve + deposit)");
  await execute(user, await tool("ghost_shield", { ghost_key: me.ghost_key, amount_usdc: "50", step: "approve" }));
  await execute(user, await tool("ghost_shield", { ghost_key: me.ghost_key, amount_usdc: "50", step: "deposit" }));
}
await waitSpendable(me.ghost_key, "50");
console.log("3. private ghost-to-ghost transfer: 20 USDC to Ayse");
const t1 = await spend(user, { ghost_key: me.ghost_key, action: "send_ghost", amount_usdc: "20", to: her.ghost_address });
console.log("   timings", JSON.stringify(t1.job.timings_ms), t1.job.tx_hash);
const herBal = await waitSpendable(her.ghost_key, "20");
console.log(`   Ayse private balance ${herBal.spendable_usdc}`);
console.log("4. pay an address privately: 10 USDC");
const recipient = "0x000000000000000000000000000000000000bEEF";
const before = await pub.readContract({ address: token, abi: erc20, functionName: "balanceOf", args: [recipient] });
const t2 = await spend(user, { ghost_key: me.ghost_key, action: "pay_address", amount_usdc: "10", to: recipient });
const after = await pub.readContract({ address: token, abi: erc20, functionName: "balanceOf", args: [recipient] });
if (after - before !== 10_000_000n) throw new Error(`recipient got ${after - before}`);
console.log(`   recipient +${after - before} atomic USDC`);
console.log("5. receipt");
const receipt = await tool("ghost_receipt", { job_id: t2.job_id });
if (receipt.signer.toLowerCase() !== user.address.toLowerCase()) throw new Error("receipt signer mismatch");
if (!String(receipt.verify_url).includes("/verify#pkg=")) throw new Error("receipt has no verify_url");
console.log("   receipt verify_url:", String(receipt.verify_url).slice(0, 90) + "…");
const report = await tool("ghost_report", { ghost_key: me.ghost_key });
const sent = report.outgoing.find((o: any) => o.kind === "pay_address" && o.to.toLowerCase() === recipient.toLowerCase());
if (!sent || sent.amount_usdc !== "10.0") throw new Error("report is missing the memo record of the 10 USDC payment");
if (!report.outgoing.find((o: any) => o.kind === "send_ghost")) throw new Error("report is missing the ghost transfer memo");
console.log(`   report: ${report.notes.length} notes, ${report.outgoing.length} outgoing records from memos, paid out ${report.totals.paid_out_usdc} USDC`);
process.env.E2E_REPORT_URL = report.verify_url;
process.env.E2E_RECEIPT_URL = receipt.verify_url;
console.log("6. Ayse unshields 5 USDC to her wallet");
const prepD = await tool("ghost_prepare", { ghost_key: her.ghost_key, action: "unshield", amount_usdc: "5", to: ayse.address, delay_minutes: 1 });
const { EIP712Domain: _d3, ...types3 } = prepD.sign_request.typedData.types;
const subD = await tool("ghost_submit", { prepare_id: prepD.prepare_id, signature: await ayse.signTypedData({ ...prepD.sign_request.typedData, types: types3 } as never) });
const balD = await tool("ghost_balance", { ghost_key: her.ghost_key });
if (!balD.notes.some((n: any) => n.status === "pending_relay")) throw new Error("scheduled note is not shown as pending_relay");
if (balD.spendable_usdc !== "0.0") throw new Error(`a scheduled note is still spendable: ${balD.spendable_usdc}`);
console.log("   while scheduled: the note shows as pending_relay and is not spendable");
for (;;) {
  await sleep(3_000);
  const j = await tool("ghost_job", { job_id: subD.job_id });
  if (j.status === "done") { console.log(`   delayed unshield relayed at a random time: ${j.tx_hash}`); break; }
  if (j.status === "failed") throw new Error(`delayed unshield failed: ${j.error}`);
}
const mine = await tool("ghost_balance", { ghost_key: me.ghost_key });
const hers = await tool("ghost_balance", { ghost_key: her.ghost_key });
console.log("VERIFY_URLS", JSON.stringify({ receipt: process.env.E2E_RECEIPT_URL, report: process.env.E2E_REPORT_URL }));
console.log(`E2E PASSED. me=${mine.spendable_usdc} USDC private, ayse=${hers.spendable_usdc} USDC private`);
