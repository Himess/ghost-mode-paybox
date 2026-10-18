import { randomBytes } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { encodeAbiParameters, encodeFunctionData, getAddress, hashMessage, hexToBytes, isAddress, keccak256, parseAbi, recoverMessageAddress, recoverPublicKey, type Hex } from "viem";
import { publicKeyToAddress } from "viem/accounts";
import * as z from "zod/v4";
import { atomicAmount, evmOutputSchema, proposeEvm } from "./paybox.js";
import {
  decryptNote, encryptNote, formatGhostKey, ghostAddress, H1, parseGhostAddress, parseGhostKey, precommitmentOf, randomField, type GhostKeys,
} from "./core/primitives.js";
import { buildSpend, fullSignature, scanNotes, validateSpend, type SpendKind } from "./core/spend.js";
import { assessSpend, formatUsdc, shieldAdvice } from "./ghost/operator.js";
import * as service from "./ghost/service.js";

const PROTOCOL_VERSION = "2026-07-28";
const MAX_DEPOSIT = 100_000_000n; // 100 USDC, mirrors the pool cap
const SETUP_PREFIX = "Ghost Mode setup";
const SCAN_PREFIX = "Ghost Mode exposure scan";

// 65-byte (r, s, v) or 64-byte compact (EIP-2098) signature, as returned by PayBox request_wallet_sign.
const hex65 = z.string().regex(/^0x(?:[0-9a-fA-F]{130}|[0-9a-fA-F]{128})$/, "hex signature (65 or 64 bytes) from PayBox request_wallet_sign");
const ghostKeyField = z.string().min(20).max(260).describe("The ghk1_… ghost key from ghost_setup (store it as a PayBox Secret).");
const usdcAmount = z.string().regex(/^(0|[1-9][0-9]{0,8})(\.[0-9]{1,6})?$/, "decimal USDC amount, e.g. 20 or 0.5");
const poolAbi = parseAbi(["function deposit(uint256 amount, uint256 precommitment, bytes encryptedNote)"]);
const erc20 = parseAbi(["function approve(address spender, uint256 amount) returns (bool)"]);

const text = (t: string) => [{ type: "text" as const, text: t }];
const fail = (err: unknown) => ({ isError: true, content: text(`Ghost Mode: ${(err as Error)?.message ?? String(err)}`) });
const usdc = (v: bigint) => formatUsdc(v);
const explorer = (hash: string) => `https://basescan.org/tx/${hash}`;
const signRequest = (message: string) => ({ op: "message" as const, message });
const short = (a: string) => `${a.slice(0, 6)}…${a.slice(-4)}`;
const clock = (iso: string) => `${iso.slice(11, 16)} UTC`;
const walletOf = (keys: GhostKeys) => publicKeyToAddress(`0x04${Buffer.from(keys.pubKey).toString("hex")}`);
const signStep = (wallet: string, prepareId: string, confirm: boolean) =>
  `Show human_summary to the user${confirm ? " together with the high-risk warnings and get explicit confirmation" : ""}. Then call PayBox ` +
  `request_wallet_sign with {credential_id: <the EVM wallet credential whose address is ${wallet}>, intent: {op: "typedData", ` +
  `typedData: sign_request.typedData}}. If it returns pending_approval, show approval_url and poll get_request until success. ` +
  `Then call ghost_submit with {prepare_id: "${prepareId}", signature: <output.signature>} and poll ghost_job.`;

/** Plain-language list of what the exposure report shows that Ghost Mode payments would not reveal. */
function wouldHide(report: any): string[] {
  const out: string[] = [];
  const x = report?.x402Footprint;
  if (x?.authorizationCount > 0) out.push(`Your ${x.authorizationCount} x402 API payments would be paid by the Ghost relayer, so merchants and observers would not see your wallet.`);
  const top = Array.isArray(report?.topCounterparties) ? report.topCounterparties : [];
  if (top.length) out.push(`Who you pay (${top.length} top counterparties, e.g. ${short(String(top[0]?.address ?? ""))}) and how much would not be linked to your address.`);
  if (Array.isArray(report?.recurring) && report.recurring.length) out.push(`Recurring payment patterns (${report.recurring.length}) would not be attributable to you.`);
  if (report?.activityClock?.offsetLabel) out.push(`Your spending would no longer reveal your active hours (time zone guess ${report.activityClock.offsetLabel}).`);
  out.push("Your spending balance would sit in the shared pool instead of on your public address; only the deposit itself stays public.");
  return out;
}

const typedDataSchema = z.object({
  domain: z.object({ name: z.string(), version: z.string(), chainId: z.number(), verifyingContract: z.string() }),
  types: z.record(z.string(), z.array(z.object({ name: z.string(), type: z.string() }))),
  primaryType: z.string(),
  message: z.record(z.string(), z.string()),
});
const warningSchema = z.object({ severity: z.enum(["high", "medium", "low"]), code: z.string(), message: z.string() });

function createServer() {
  const server = new McpServer(
    { name: "ghost-mode", version: "0.1.0" },
    {
      supportedProtocolVersions: [PROTOCOL_VERSION],
      instructions:
        "Ghost Mode gives a PayBox user a private USDC balance on Base. Every private spend is authorised by ONE PayBox " +
        "wallet signature that is verified inside a zero-knowledge proof; the key never leaves PayBox. Flow: ghost_setup once " +
        "(store the ghost key as a PayBox Secret; losing it loses access to the private notes) -> ghost_shield_authorize (one " +
        "signature, no ETH; fallback ghost_shield approve then deposit) -> ghost_balance -> ghost_prepare -> PayBox " +
        "request_wallet_sign with the returned typedData -> ghost_submit -> poll ghost_job until done. Always show human_summary " +
        "and privacy warnings to the user before asking for a signature; for withdrawals flagged for timing, offer delay_minutes. " +
        "If the user lost the ghost key, use ghost_recover (fresh PayBox signature). Never re-run ghost_prepare or ghost_submit to " +
        "finish an operation; poll ghost_job.",
    },
  );

  // ---------------------------------------------------------------- setup
  server.registerTool(
    "ghost_setup",
    {
      title: "Set up Ghost Mode",
      description:
        "Creates the user's ghost key and ghost address. Step 1: call with no arguments; it returns a message. Ask PayBox " +
        "request_wallet_sign to sign it with intent {op:'message', message} (EVM wallet), poll get_request for the signature. " +
        "Step 2: call again with {message, signature}. The signature only reveals the wallet's public key; it cannot move funds. " +
        "Check that wallet_address equals the PayBox wallet that signed. Tell the user to save the returned ghost_key as a " +
        "PayBox Secret named 'Ghost key' and never share it publicly.",
      inputSchema: z.object({ message: z.string().max(400).optional(), signature: hex65.optional() }).strict(),
      outputSchema: z.object({
        step: z.enum(["sign", "done"]),
        sign_request: z.object({ op: z.literal("message"), message: z.string() }).optional(),
        ghost_key: z.string().optional(),
        ghost_address: z.string().optional(),
        wallet_address: z.string().optional(),
        backed_up: z.boolean().optional(),
        instructions: z.string(),
      }).strict(),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    async ({ message, signature }) => {
      try {
        if (signature) signature = fullSignature(signature);
        if (!signature) {
          const msg = `${SETUP_PREFIX}\n\nSign to bind Ghost Mode to this PayBox wallet. This reveals only your public key and cannot move funds.\n\nNonce: ${randomBytes(12).toString("hex")}\nIssued: ${new Date().toISOString().replace(/\.\d{3}Z$/, "Z")}`;
          return {
            content: text("Ask PayBox to sign this message (request_wallet_sign, op 'message'), then call ghost_setup again with the message and signature."),
            structuredContent: { step: "sign" as const, sign_request: signRequest(msg), instructions: "Sign the message with the user's PayBox EVM wallet, then call ghost_setup with {message, signature}." },
          };
        }
        if (!message?.startsWith(SETUP_PREFIX)) throw new Error("Pass back the exact setup message that was signed.");
        const pub = await recoverPublicKey({ hash: hashMessage(message), signature: signature as Hex });
        const pubKey = hexToBytes(pub).slice(1);
        const ghostKey = formatGhostKey(randomBytes(32), pubKey);
        const keys = parseGhostKey(ghostKey);
        const address = ghostAddress(keys);
        const wallet = publicKeyToAddress(pub);
        // Encrypted backup on the Ghost service, released only to a fresh signature from this wallet (ghost_recover).
        const backedUp = await service.backupKey({ ghost_key: ghostKey, message, signature: signature as Hex }).then((r) => r.backed_up, () => false);
        return {
          content: text(`Ghost Mode is ready for ${wallet}. Ghost address (shareable): ${address}. Save the ghost key as a PayBox Secret named "Ghost key"; it is needed to see and spend private notes, and losing it loses access to them${backedUp ? " (an encrypted backup is recoverable with ghost_recover and a fresh signature from this wallet)" : ""}. Leaking it reveals your private history but cannot move funds without your PayBox signature.`),
          structuredContent: {
            step: "done" as const, ghost_key: ghostKey, ghost_address: address, wallet_address: wallet, backed_up: backedUp,
            instructions: backedUp
              ? "Store ghost_key as a PayBox Secret ('Ghost key'). An encrypted backup is also kept by the Ghost service and released only to a fresh signature from this wallet (ghost_recover). Share only ghost_address. Next: ghost_shield_authorize."
              : "Store ghost_key as a PayBox Secret ('Ghost key'); the service backup failed, so this is the only copy. Share only ghost_address. Next: ghost_shield_authorize.",
          },
        };
      } catch (err) {
        return fail(err);
      }
    },
  );

  server.registerTool(
    "ghost_address",
    {
      title: "Show ghost address",
      description: "Returns the shareable ghost address (others use it with ghost_prepare action send_ghost) and the bound PayBox wallet address.",
      inputSchema: z.object({ ghost_key: ghostKeyField }).strict(),
      outputSchema: z.object({ ghost_address: z.string(), wallet_address: z.string() }).strict(),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ ghost_key }) => {
      try {
        const keys = parseGhostKey(ghost_key);
        const wallet = publicKeyToAddress(`0x04${Buffer.from(keys.pubKey).toString("hex")}`);
        const address = ghostAddress(keys);
        return { content: text(`Ghost address: ${address}`), structuredContent: { ghost_address: address, wallet_address: wallet } };
      } catch (err) {
        return fail(err);
      }
    },
  );

  server.registerTool(
    "ghost_recover",
    {
      title: "Recover a lost ghost key",
      description:
        "Recovers the ghost key(s) bound to a PayBox wallet from the Ghost service's encrypted backup. Step 1: call with {address}; " +
        "sign the returned message with PayBox request_wallet_sign {op:'message'} using that wallet. Step 2: call with " +
        "{address, message, signature}. Store the recovered key as a PayBox Secret again.",
      inputSchema: z.object({ address: z.string().regex(/^0x[0-9a-fA-F]{40}$/), message: z.string().max(300).optional(), signature: hex65.optional() }).strict(),
      outputSchema: z.object({
        step: z.enum(["sign", "done"]),
        sign_request: z.object({ op: z.literal("message"), message: z.string() }).optional(),
        ghost_keys: z.array(z.string()).optional(),
        instructions: z.string(),
      }).strict(),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ address, message, signature }) => {
      try {
        if (signature) signature = fullSignature(signature);
        const wallet = getAddress(address);
        if (!signature || !message) {
          const msg = `Ghost Mode key recovery\nAddress: ${wallet}\nIssued: ${new Date().toISOString().replace(/\.\d{3}Z$/, "Z")}`;
          return {
            content: text("Sign this recovery challenge with the same PayBox wallet, then call ghost_recover again with message and signature."),
            structuredContent: { step: "sign" as const, sign_request: signRequest(msg), instructions: "Sign with request_wallet_sign {op:'message'}, then call ghost_recover with {address, message, signature}." },
          };
        }
        const { ghost_keys } = await service.recoverKeys({ address: wallet, message, signature: signature as Hex });
        if (!ghost_keys.length) throw new Error("No backup exists for this wallet.");
        return {
          content: text(`Recovered ${ghost_keys.length} ghost key(s) for ${wallet}. Store the latest one as a PayBox Secret named "Ghost key".`),
          structuredContent: { step: "done" as const, ghost_keys, instructions: "The last key is the most recent. Store it as a PayBox Secret; run ghost_balance with each key to see its notes." },
        };
      } catch (err) {
        return fail(err);
      }
    },
  );

  // ---------------------------------------------------------------- shield
  server.registerTool(
    "ghost_shield",
    {
      title: "Shield USDC into Ghost Mode",
      description:
        "Fallback shield when ghost_shield_authorize is unavailable or PayBox will not sign it. Proposes moving USDC from the " +
        "user's PayBox wallet on Base into the Ghost pool as two transactions (the wallet needs ETH for gas): step 'approve' " +
        "(USDC allowance for the pool), wait until PayBox confirms it, then step 'deposit'. The deposit is public; everything after " +
        "it is private. Max 100 USDC per deposit (experimental, capped pool). Prefer round amounts.",
      inputSchema: z.object({ ghost_key: ghostKeyField, amount_usdc: usdcAmount, step: z.enum(["approve", "deposit"]) }).strict(),
      outputSchema: evmOutputSchema,
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    async ({ ghost_key, amount_usdc, step }) => {
      try {
        const keys = parseGhostKey(ghost_key);
        const amount = BigInt(atomicAmount(amount_usdc, 6));
        if (amount <= 0n || amount > MAX_DEPOSIT) throw new Error("Deposit must be between 0.000001 and 100 USDC.");
        const info = await service.getInfo();
        const chain = `eip155:${info.chainId}`;
        const advice = shieldAdvice(amount).map((w) => w.message).join(" ");
        if (step === "approve") {
          const proposal = proposeEvm({ chain, to: info.token, data: encodeFunctionData({ abi: erc20, functionName: "approve", args: [info.pool, amount] }) });
          return { ...proposal, content: text(`Proposed USDC approval of ${usdc(amount)} for the Ghost pool ${info.pool}. After PayBox confirms it, call ghost_shield with step "deposit". ${advice}`.trim()) };
        }
        const blinding = randomField();
        const data = encodeFunctionData({
          abi: poolAbi, functionName: "deposit",
          args: [amount, precommitmentOf(keys.ownerTag, blinding), encryptNote(keys.viewPub, amount, blinding, 0n)],
        });
        const proposal = proposeEvm({ chain, to: info.pool, data });
        return { ...proposal, content: text(`Proposed a ${usdc(amount)} USDC deposit into Ghost Mode. The note is encrypted to your ghost key; it becomes spendable once the association set approves it (usually under a minute). ${advice}`.trim()) };
      } catch (err) {
        return fail(err);
      }
    },
  );

  // ---------------------------------------------------------------- balance
  server.registerTool(
    "ghost_balance",
    {
      title: "Private balance",
      description: "Decrypts the user's private notes locally with the ghost key and returns the private USDC balance. Read-only.",
      inputSchema: z.object({ ghost_key: ghostKeyField }).strict(),
      outputSchema: z.object({
        ghost_address: z.string(),
        spendable_usdc: z.string(),
        pending_approval_usdc: z.string(),
        notes: z.array(z.object({
          leaf_index: z.number(), amount_usdc: z.string(), status: z.enum(["spendable", "pending_asp", "pending_relay", "spent"]),
          source: z.enum(["deposit", "transfer"]), age_minutes: z.number(), tx_hash: z.string(),
        })),
        pool: z.object({ deposits: z.number(), distinct_depositors: z.number(), notes_in_tree: z.number(), address: z.string() }),
      }).strict(),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ ghost_key }) => {
      try {
        const keys = parseGhostKey(ghost_key);
        const state = await service.getState();
        const notes = scanNotes(keys, state);
        const now = Math.floor(Date.now() / 1000);
        const live = notes.filter((n) => !n.spent && !n.pending && n.amount > 0n);
        const relaying = notes.filter((n) => n.pending && !n.spent).reduce((s, n) => s + n.amount, 0n);
        const spendable = live.filter((n) => n.approved).reduce((s, n) => s + n.amount, 0n);
        const pending = live.filter((n) => !n.approved).reduce((s, n) => s + n.amount, 0n);
        const out = {
          ghost_address: ghostAddress(keys),
          spendable_usdc: usdc(spendable),
          pending_approval_usdc: usdc(pending),
          notes: notes.filter((n) => n.amount > 0n).slice(-40).map((n) => ({
            leaf_index: n.leafIndex, amount_usdc: usdc(n.amount),
            status: n.spent ? "spent" as const : n.pending ? "pending_relay" as const : n.approved ? "spendable" as const : "pending_asp" as const,
            source: n.source, age_minutes: Math.max(0, Math.round((now - n.blockTime) / 60)), tx_hash: n.txHash,
          })),
          pool: {
            deposits: state.deposits.length,
            distinct_depositors: new Set(state.deposits.map((d) => d.depositor.toLowerCase())).size,
            notes_in_tree: state.leaves.length,
            address: state.pool,
          },
        };
        return { content: text(`Private balance: ${out.spendable_usdc} USDC spendable${pending ? `, ${out.pending_approval_usdc} USDC awaiting association-set approval` : ""}${relaying ? `, ${usdc(relaying)} USDC in a scheduled withdrawal` : ""}.`), structuredContent: out };
      } catch (err) {
        return fail(err);
      }
    },
  );

  // ---------------------------------------------------------------- shield (one signature)
  server.registerTool(
    "ghost_shield_authorize",
    {
      title: "Shield USDC with one signature",
      description:
        "Preferred way to move USDC from the user's PayBox wallet into Ghost Mode: ONE PayBox typed-data signature (EIP-3009 " +
        "ReceiveWithAuthorization on Base USDC) and no ETH needed; the Ghost relayer submits it and keeps a small USDC fee. " +
        "Show human_summary to the user first. Then call PayBox request_wallet_sign with intent {op:'typedData', typedData: " +
        "sign_request.typedData} using the EVM wallet whose address is wallet_address, poll get_request, then ghost_submit " +
        "(prepare_id, signature) and poll ghost_job. If PayBox refuses to sign it, fall back to ghost_shield (approve, then deposit).",
      inputSchema: z.object({ ghost_key: ghostKeyField, amount_usdc: usdcAmount }).strict(),
      outputSchema: z.object({
        prepare_id: z.string(),
        human_summary: z.string(),
        wallet_address: z.string(),
        amount_usdc: z.string(),
        fee_usdc: z.string(),
        total_authorized_usdc: z.string(),
        expires_at: z.string(),
        sign_request: z.object({ op: z.literal("typedData"), typedData: typedDataSchema }),
        warnings: z.array(warningSchema),
        next_step: z.string(),
      }).strict(),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    async ({ ghost_key, amount_usdc }) => {
      try {
        const keys = parseGhostKey(ghost_key);
        const amount = BigInt(atomicAmount(amount_usdc, 6));
        if (amount <= 0n || amount > MAX_DEPOSIT) throw new Error("Deposit must be between 0.000001 and 100 USDC.");
        const info = await service.shieldInfo();
        if (!info.supported) throw new Error("This Ghost pool has no single-signature deposits; use ghost_shield (approve, then deposit).");
        const fee = BigInt(info.fee);
        const value = amount + fee;
        const now = Math.floor(Date.now() / 1000);
        const wallet = walletOf(keys);
        const blinding = randomField();
        const precommitment = precommitmentOf(keys.ownerTag, blinding);
        const encryptedNote = encryptNote(keys.viewPub, amount, blinding, 0n, { v: 1, k: "shield", a: amount.toString(), f: fee.toString(), t: now });
        const self = decryptNote(keys.viewPriv, keys.viewPub, encryptedNote);
        if (!self || self.amount !== amount || self.blinding !== blinding) throw new Error("Self-check failed: deposit note does not decrypt. Nothing was signed.");
        const nonce = keccak256(encodeAbiParameters(
          [{ type: "address" }, { type: "uint256" }, { type: "bytes32" }, { type: "uint256" }],
          [info.pool, precommitment, keccak256(encryptedNote), fee],
        ));
        const pkg = {
          from: wallet, amount: amount.toString(), fee: fee.toString(), value: value.toString(), validAfter: "0",
          validBefore: String(now + 30 * 60), precommitment: precommitment.toString(), encryptedNote, nonce,
        };
        const prepared = await service.shieldPrepare(pkg);
        const m = prepared.typedData?.message ?? {};
        if (getAddress(m.from) !== wallet || getAddress(m.to) !== getAddress(info.pool) || String(m.value) !== pkg.value || String(m.nonce).toLowerCase() !== nonce.toLowerCase()
          || getAddress(prepared.typedData.domain.verifyingContract) !== getAddress(info.token)) {
          throw new Error("Self-check failed: the service returned a different authorization. Nothing was signed.");
        }
        const human = `Shield ${usdc(amount)} USDC from ${short(wallet)} into Ghost Mode · relayer fee ${usdc(fee)} USDC (you authorize ${usdc(value)} USDC to the Ghost pool ${short(info.pool)}) · no ETH needed · valid until ${clock(prepared.expires_at)}`;
        const out = {
          prepare_id: prepared.prepare_id, human_summary: human, wallet_address: wallet,
          amount_usdc: usdc(amount), fee_usdc: usdc(fee), total_authorized_usdc: usdc(value), expires_at: prepared.expires_at,
          sign_request: { op: "typedData" as const, typedData: prepared.typedData },
          warnings: shieldAdvice(amount),
          next_step: signStep(wallet, prepared.prepare_id, false),
        };
        return { content: text(`${human}. Show this to the user, then get one PayBox typed-data signature and call ghost_submit.`), structuredContent: out };
      } catch (err) {
        return fail(err);
      }
    },
  );

  // ---------------------------------------------------------------- prepare
  server.registerTool(
    "ghost_prepare",
    {
      title: "Prepare a private payment",
      description:
        "Builds a private spend from the ghost balance and returns typed data for ONE PayBox signature. Actions: " +
        "'send_ghost' (to = a ghost:… address; amount and recipient stay hidden on-chain), 'pay_address' or 'unshield' (to = 0x " +
        "address; the sender stays hidden), 'pay_x402' (url of an x402 endpoint on Base; the Ghost relayer pays the merchant and " +
        "the response comes back via ghost_job). RULES: show human_summary and any warnings to the user before asking for the " +
        "signature; if risk is 'high', get explicit confirmation first. Then follow next_step exactly: PayBox request_wallet_sign " +
        "with intent {op:'typedData', typedData: sign_request.typedData} using the EVM wallet whose address is wallet_address, poll " +
        "get_request, then ghost_submit(prepare_id, signature) and poll ghost_job. Every package is self-checked before it is returned.",
      inputSchema: z.object({
        ghost_key: ghostKeyField,
        action: z.enum(["send_ghost", "pay_address", "unshield", "pay_x402"]),
        amount_usdc: usdcAmount.optional().describe("Required except for pay_x402, where the endpoint sets the price."),
        to: z.string().max(200).optional().describe("ghost:… address for send_ghost; 0x address for pay_address/unshield."),
        url: z.url().max(2048).optional().describe("x402 endpoint (https) for pay_x402."),
        method: z.enum(["GET", "POST"]).optional(),
        body: z.record(z.string(), z.unknown()).optional().describe("JSON body for POST x402 requests."),
        delay_minutes: z.number().int().min(0).max(30).optional()
          .describe("unshield/pay_address only: relay at a uniformly random time within this many minutes to break timing correlation (recommended when the privacy check warns about timing)."),
      }).strict(),
      outputSchema: z.object({
        prepare_id: z.string(),
        risk: z.enum(["low", "medium", "high"]),
        warnings: z.array(warningSchema),
        human_summary: z.string(),
        wallet_address: z.string(),
        summary: z.object({
          action: z.string(), amount_usdc: z.string(), fee_usdc: z.string(), change_usdc: z.string(), recipient: z.string(),
          anonymity_set: z.number(), expires_at: z.string(),
        }),
        sign_request: z.object({ op: z.literal("typedData"), typedData: typedDataSchema }),
        next_step: z.string(),
      }).strict(),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    async (args) => {
      try {
        const keys = parseGhostKey(args.ghost_key);
        const kind = args.action as SpendKind;
        const state = await service.getState();
        const notes = scanNotes(keys, state);
        let amount: bigint;
        let recipientAddress: Hex | undefined;
        let recipientGhost: ReturnType<typeof parseGhostAddress> | undefined;
        let x402: { url: string; method: "GET" | "POST"; body?: unknown } | undefined;
        if (kind === "pay_x402") {
          if (!args.url) throw new Error("pay_x402 needs url.");
          x402 = { url: args.url, method: args.method ?? "GET", ...(args.method === "POST" ? { body: args.body ?? {} } : {}) };
          const quote = await service.quoteX402(x402);
          if (quote.free || !quote.price) throw new Error(`That endpoint did not ask for payment (HTTP ${quote.status ?? "?"}).`);
          amount = BigInt(quote.price);
          recipientAddress = state.relayer;
        } else {
          if (!args.amount_usdc) throw new Error(`${kind} needs amount_usdc.`);
          if (!args.to) throw new Error(`${kind} needs a recipient in 'to'.`);
          amount = BigInt(atomicAmount(args.amount_usdc, 6));
          if (kind === "send_ghost") recipientGhost = parseGhostAddress(args.to);
          else if (isAddress(args.to)) recipientAddress = getAddress(args.to);
          else throw new Error("'to' must be a 0x address for pay_address/unshield.");
        }
        const now = Math.floor(Date.now() / 1000);
        const assessment = assessSpend({ kind, amount, recipient: recipientAddress, state, notes, now });
        const memoExtra = x402 ? { h: new URL(x402.url).host } : undefined;
        const delayMinutes = args.delay_minutes ?? 0;
        if (delayMinutes > 0 && kind !== "unshield" && kind !== "pay_address") throw new Error("delay_minutes applies only to unshield and pay_address.");
        const pkg = buildSpend({ keys, state, notes, kind, amount, recipientAddress, recipientGhost, deadline: now + 20 * 60 + delayMinutes * 60, memoExtra });
        validateSpend(pkg, keys, state);
        const prepared = await service.prepare({ package: pkg, x402, ...(delayMinutes > 0 ? { delaySeconds: delayMinutes * 60 } : {}) });
        const wallet = walletOf(keys);
        const fee = state.relayerFee;
        const exp = clock(prepared.expires_at);
        const human =
          kind === "send_ghost" ? `Send ${usdc(amount)} USDC privately → ${args.to!.slice(0, 16)}… · fee ${usdc(fee)} USDC · amount and recipient hidden on-chain · expires ${exp}`
          : kind === "pay_x402" ? `Pay ${usdc(amount)} USDC for ${new URL(x402!.url).host}${new URL(x402!.url).pathname} via Ghost relayer ${short(state.relayer)} (the merchant sees the relayer, not you) · fee ${usdc(fee)} USDC · expires ${exp}`
          : kind === "unshield" ? `Withdraw ${usdc(amount)} USDC → ${short(recipientAddress!)} · fee ${usdc(fee)} USDC · hidden recipient: none · expires ${exp}`
          : `Pay ${usdc(amount)} USDC → ${short(recipientAddress!)} · fee ${usdc(fee)} USDC · sender hidden · hidden recipient: none · expires ${exp}`;
        const humanWithDelay = delayMinutes > 0 ? `${human} · relayed at a random time within ${delayMinutes} min` : human;
        const out = {
          prepare_id: prepared.prepare_id,
          risk: assessment.risk,
          warnings: assessment.warnings,
          human_summary: humanWithDelay,
          wallet_address: wallet,
          summary: {
            action: kind, amount_usdc: usdc(amount), fee_usdc: usdc(fee), change_usdc: usdc(BigInt(pkg.summary.change)),
            recipient: kind === "send_ghost" ? args.to! : kind === "pay_x402" ? `${args.url} (via Ghost relayer ${state.relayer})` : recipientAddress!,
            anonymity_set: assessment.anonymitySet, expires_at: prepared.expires_at,
          },
          sign_request: { op: "typedData" as const, typedData: { ...pkg.typedData, types: pkg.typedData.types as unknown as Record<string, { name: string; type: string }[]> } },
          next_step: signStep(wallet, prepared.prepare_id, assessment.risk === "high"),
        };
        const warn = assessment.warnings.length ? ` Privacy check (${assessment.risk}): ${assessment.warnings.map((w) => w.message).join(" ")}` : " Privacy check: low risk.";
        return { content: text(`${human}.${warn} Show this to the user, then get one PayBox typed-data signature and call ghost_submit.`), structuredContent: out };
      } catch (err) {
        return fail(err);
      }
    },
  );

  // ---------------------------------------------------------------- submit / job
  server.registerTool(
    "ghost_submit",
    {
      title: "Submit a signed Ghost operation",
      description:
        "Hands the PayBox signature for a prepared spend (prep_…) or a one-signature shield (shp_…) to the Ghost service. Spends " +
        "are checked against the ghost key's wallet, proven in zero knowledge (~10 s) and relayed on Base; shields are relayed " +
        "directly. Returns job_id; poll ghost_job. Call once per prepare_id.",
      inputSchema: z.object({ prepare_id: z.string().regex(/^(prep|shp)_[0-9a-f]{24}$/), signature: hex65 }).strict(),
      outputSchema: z.object({ job_id: z.string(), status: z.literal("queued"), next_step: z.string() }).strict(),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    async ({ prepare_id, signature }) => {
      try {
        signature = fullSignature(signature);
        const { job_id } = prepare_id.startsWith("shp_")
          ? await service.shieldSubmit({ prepare_id, signature: signature as Hex })
          : await service.submit({ prepare_id, signature: signature as Hex });
        return {
          content: text(`Submitted (job ${job_id}). Poll ghost_job every few seconds.`),
          structuredContent: { job_id, status: "queued" as const, next_step: `Poll ghost_job with job_id ${job_id} until status is done, failed, refunded or requote_needed.` },
        };
      } catch (err) {
        return fail(err);
      }
    },
  );

  server.registerTool(
    "ghost_job",
    {
      title: "Ghost operation status",
      description:
        "Returns the status of a submitted operation: queued, proving, relaying, paying (x402), done, failed, refunded (x402 merchant " +
        "failed; the relayer re-deposited the price to your ghost balance; refunding while in progress) or requote_needed (price changed; nothing was spent). " +
        "Includes the Base transaction and, for x402, the paid response body and settlement transaction.",
      inputSchema: z.object({ job_id: z.string().regex(/^(job|sjob)_[0-9a-f]{24}$/) }).strict(),
      outputSchema: z.object({
        job_id: z.string(),
        status: z.enum(["queued", "scheduled", "proving", "requote_needed", "relaying", "paying", "refunding", "refunded", "done", "failed"]),
        scheduled_for: z.string().optional(),
        action: z.string(),
        tx_hash: z.string().optional(),
        explorer_url: z.string().optional(),
        refund_tx_hash: z.string().optional(),
        error: z.string().optional(),
        timings_ms: z.record(z.string(), z.number()),
        x402: z.object({
          status: z.number(), content_type: z.string(), body: z.string(), pay_to: z.string(), price_usdc: z.string(), settlement_tx: z.string().optional(), error: z.string().optional(),
        }).optional(),
      }).strict(),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ job_id }) => {
      try {
        const shield = job_id.startsWith("sjob_");
        const job = shield ? await service.getShieldJob(job_id) : await service.getJob(job_id);
        const out = {
          job_id, status: job.status, action: shield ? "shield" : String(job.kind), timings_ms: job.timings ?? {},
          ...(job.txHash ? { tx_hash: job.txHash, explorer_url: explorer(job.txHash) } : {}),
          ...(job.refundTxHash ? { refund_tx_hash: String(job.refundTxHash) } : {}),
          ...(job.scheduledFor ? { scheduled_for: String(job.scheduledFor) } : {}),
          ...(job.error ? { error: String(job.error) } : {}),
          ...(job.x402 ? { x402: {
            status: Number(job.x402.status ?? 0), content_type: String(job.x402.contentType ?? ""),
            body: String(job.x402.body ?? "").slice(0, 24_000), pay_to: String(job.x402.payTo ?? ""), price_usdc: usdc(BigInt(job.x402.price ?? 0)),
            ...(job.x402.settlementTx ? { settlement_tx: String(job.x402.settlementTx) } : {}),
            ...(job.x402.error ? { error: String(job.x402.error).slice(0, 500) } : {}),
          } } : {}),
        };
        const msg =
          job.status === "done" ? (shield
            ? `Shielded ${usdc(BigInt(job.amount))} USDC in ${job.txHash}. It becomes spendable once the association set approves it (seconds).`
            : `Done. Base transaction ${job.txHash}; on-chain it shows only the Ghost pool and relayer.${job.x402 ? ` Merchant answered HTTP ${job.x402.status}.` : ""}`)
          : job.status === "scheduled" ? `Scheduled: the relayer will submit at a random time (by ${String(job.scheduledFor ?? "").slice(11, 16)} UTC) to break timing correlation. Poll ghost_job later.`
          : job.status === "refunding" ? "The merchant payment failed; the relayer is cancelling its authorization and refunding the price to your ghost balance."
          : job.status === "refunded" ? `The merchant payment failed after the pool paid the relayer; the relayer re-deposited the price privately to your ghost balance (${job.refundTxHash}).`
          : job.status === "requote_needed" ? `The merchant's price changed before relaying; nothing was spent. Run ghost_prepare again. ${job.error ?? ""}`.trim()
          : job.status === "failed" ? `Failed: ${job.error}. Check ghost_balance before trying again.` : `Status: ${job.status}.`;
        return { content: text(msg), structuredContent: out };
      } catch (err) {
        return fail(err);
      }
    },
  );

  // ---------------------------------------------------------------- exposure
  server.registerTool(
    "ghost_exposure",
    {
      title: "What is my wallet leaking?",
      description:
        "Scans the PUBLIC Base footprint of the user's own PayBox wallet: counterparties, x402 payments, recurring payments, " +
        "activity clock (time zone), amount fingerprints, balances, with a privacy score. Only for the user's own wallet: step 1 " +
        "call with {address} to get a challenge, sign it with PayBox request_wallet_sign {op:'message'}, step 2 call with " +
        "{address, message, signature}.",
      inputSchema: z.object({
        address: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
        message: z.string().max(300).optional(),
        signature: hex65.optional(),
      }).strict(),
      outputSchema: z.object({
        step: z.enum(["sign", "done"]),
        sign_request: z.object({ op: z.literal("message"), message: z.string() }).optional(),
        report: z.record(z.string(), z.unknown()).optional(),
        ghost_mode_would_hide: z.array(z.string()).optional(),
      }).strict(),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ address, message, signature }) => {
      try {
        if (signature) signature = fullSignature(signature);
        const wallet = getAddress(address);
        if (!signature) {
          const msg = `${SCAN_PREFIX}\nAddress: ${wallet}\nIssued: ${new Date().toISOString().replace(/\.\d{3}Z$/, "Z")}`;
          return { content: text("Sign this challenge with the same PayBox wallet to prove it is yours, then call ghost_exposure again with message and signature."), structuredContent: { step: "sign" as const, sign_request: signRequest(msg) } };
        }
        const m = new RegExp(`^${SCAN_PREFIX}\\nAddress: (0x[0-9a-fA-F]{40})\\nIssued: (\\S+)$`).exec(message ?? "");
        if (!m || m[1]!.toLowerCase() !== wallet.toLowerCase()) throw new Error("Pass back the exact challenge message for this address.");
        const age = Date.now() - Date.parse(m[2]!);
        if (!(age >= -60_000 && age <= 15 * 60_000)) throw new Error("Challenge expired; request a new one.");
        const signer = await recoverMessageAddress({ message: message!, signature: signature as Hex });
        if (signer.toLowerCase() !== wallet.toLowerCase()) throw new Error("Signature is not from this address; exposure scans are limited to the user's own wallet.");
        const report = await service.exposure(wallet, message!, signature as Hex);
        const score = typeof report?.privacyScore === "number" ? ` Privacy score: ${report.privacyScore}/100.` : "";
        const hide = wouldHide(report);
        return {
          content: text(`Exposure report for ${wallet}.${score} Everything listed is public and permanent on Base. With Ghost Mode: ${hide.join(" ")}`),
          structuredContent: { step: "done" as const, report, ghost_mode_would_hide: hide },
        };
      } catch (err) {
        return fail(err);
      }
    },
  );

  // ---------------------------------------------------------------- report
  server.registerTool(
    "ghost_report",
    {
      title: "Disclosure report",
      description:
        "Builds a scoped disclosure package for an accountant or auditor and a verify_url that checks it in the browser against " +
        "Base: openings of the user's private notes in a date range (anyone can recompute each commitment and find it on-chain) " +
        "plus the user's own encrypted record of outgoing payments. Notes outside the range stay private. Confirm with the user " +
        "before sharing; pair important outgoing payments with ghost_receipt (PayBox-signed proof).",
      inputSchema: z.object({
        ghost_key: ghostKeyField,
        from: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional().describe("Start date (UTC, inclusive), e.g. 2026-10-01"),
        to: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional().describe("End date (UTC, inclusive), e.g. 2026-10-31"),
      }).strict(),
      outputSchema: z.object({
        wallet_address: z.string(), ghost_address: z.string(), chain: z.string(), pool: z.string(), token: z.string(),
        period: z.object({ from: z.string(), to: z.string() }),
        totals: z.object({ deposited_usdc: z.string(), received_usdc: z.string(), paid_out_usdc: z.string(), still_private_unspent_usdc: z.string() }),
        notes: z.array(z.object({
          leaf_index: z.number(), time: z.string(), source: z.string(), amount_usdc: z.string(), spent: z.boolean(),
          commitment: z.string(), opening: z.object({ asset: z.string(), amount: z.string(), label: z.string(), owner_tag: z.string(), blinding: z.string() }),
          tx_hash: z.string(),
        })),
        outgoing: z.array(z.object({
          time: z.string(), kind: z.string(), to: z.string(), amount_usdc: z.string(), fee_usdc: z.string(), host: z.string().optional(), tx_hash: z.string(),
        })),
        verify_url: z.string(),
        verify: z.array(z.string()),
      }).strict(),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ ghost_key, from, to }) => {
      try {
        const keys = parseGhostKey(ghost_key);
        const state = await service.getState();
        const start = from ? Date.parse(`${from}T00:00:00Z`) / 1000 : 0;
        const end = to ? Date.parse(`${to}T23:59:59Z`) / 1000 : Number.MAX_SAFE_INTEGER;
        const inRange = scanNotes(keys, state).filter((n) => n.blockTime >= start && n.blockTime <= end);
        const notes = inRange.filter((n) => n.amount > 0n || n.memo).slice(-40);
        const valued = notes.filter((n) => n.amount > 0n);
        const sum = (xs: typeof notes) => xs.reduce((s, n) => s + n.amount, 0n);
        // Outgoing payments come from the sender's own memo inside each change note.
        const outgoing = notes.filter((n) => n.memo && n.memo.k && n.memo.k !== "shield").map((n) => {
          const memo = n.memo as Record<string, string>;
          return {
            time: new Date(Number(memo.t ?? n.blockTime) * 1000).toISOString(), kind: String(memo.k), to: String(memo.to ?? ""),
            amount_usdc: usdc(BigInt(memo.a ?? 0)), fee_usdc: usdc(BigInt(memo.f ?? 0)), ...(memo.h ? { host: String(memo.h) } : {}), tx_hash: n.txHash,
          };
        });
        const paidOut = outgoing.reduce((s, o) => s + BigInt(atomicAmount(o.amount_usdc, 6)), 0n);
        const asset = BigInt(state.token).toString();
        const wallet = walletOf(keys);
        const pkg = {
          kind: "ghost-report", version: 1, chainId: state.chainId, pool: state.pool, token: state.token, walletAddress: wallet,
          pubKey: `0x${Buffer.from(keys.pubKey).toString("hex")}`, nkHash: H1(keys.nk).toString(), ownerTag: keys.ownerTag.toString(),
          // ISO timestamps: the verification page checks every note's block time against this window.
          period: {
            from: new Date(start * 1000).toISOString(),
            to: (end === Number.MAX_SAFE_INTEGER ? new Date() : new Date(end * 1000)).toISOString(),
          },
          notes: notes.map((n) => ({
            leafIndex: n.leafIndex, txHash: n.txHash, commitment: n.commitment.toString(), amount: n.amount.toString(),
            blinding: n.blinding.toString(), label: n.label.toString(), source: n.source, time: n.blockTime, ...(n.memo ? { memo: n.memo } : {}),
          })),
        };
        const out = {
          wallet_address: wallet, ghost_address: ghostAddress(keys), chain: `eip155:${state.chainId}`, pool: state.pool, token: state.token,
          period: pkg.period,
          totals: {
            deposited_usdc: usdc(sum(valued.filter((n) => n.source === "deposit"))),
            received_usdc: usdc(sum(valued.filter((n) => n.source === "transfer"))),
            paid_out_usdc: usdc(paidOut),
            still_private_unspent_usdc: usdc(sum(valued.filter((n) => !n.spent))),
          },
          notes: notes.map((n) => ({
            leaf_index: n.leafIndex, time: new Date(n.blockTime * 1000).toISOString(), source: n.source, amount_usdc: usdc(n.amount),
            spent: n.spent, commitment: n.commitment.toString(), tx_hash: n.txHash,
            opening: { asset, amount: n.amount.toString(), label: n.label.toString(), owner_tag: keys.ownerTag.toString(), blinding: n.blinding.toString() },
          })),
          outgoing,
          verify_url: service.verifyUrl(pkg),
          verify: [
            "Open verify_url: the page recomputes every commitment with Poseidon, finds it in the pool's NewCommitment events on Base and ties the owner tag to the PayBox wallet's public key.",
            "Outgoing payment records come from the user's own encrypted change notes; prove an individual payment with ghost_receipt.",
            "The package reveals only the listed notes; the nullifier key is never included.",
          ],
        };
        return { content: text(`Disclosure package for ${out.period.from} to ${out.period.to}: ${notes.length} note(s), ${outgoing.length} outgoing payment(s). Verification link: ${out.verify_url.slice(0, 80)}… It reveals only these notes; share it only with the intended auditor.`), structuredContent: out };
      } catch (err) {
        return fail(err);
      }
    },
  );

  // ---------------------------------------------------------------- receipt
  server.registerTool(
    "ghost_receipt",
    {
      title: "Payment receipt",
      description:
        "Produces a verifiable receipt for one completed private payment: the PayBox-signed intent, the signer address, the " +
        "on-chain transaction and a verify_url that checks it in the browser against Base. Give it to an accountant or " +
        "merchant; it discloses only this payment.",
      inputSchema: z.object({ job_id: z.string().regex(/^job_[0-9a-f]{24}$/) }).strict(),
      outputSchema: z.object({
        tx_hash: z.string(), explorer_url: z.string(), chain: z.string(), pool: z.string(), signer: z.string(),
        signature: z.string(), typed_data: typedDataSchema, nullifiers: z.array(z.string()), out_commitments: z.array(z.string()),
        x402_settlement_tx: z.string().optional(),
        verify_url: z.string(),
        verify: z.array(z.string()),
      }).strict(),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ job_id }) => {
      try {
        const job = await service.getJob(job_id);
        if (!["done", "refunded"].includes(job.status) || !job.receipt?.typedData) throw new Error(`Job is ${job.status}; receipts exist only for completed payments.`);
        const { typedData, signature, nullifiers, outCommitments } = job.receipt;
        const pkg = {
          kind: "ghost-receipt", version: 1, chainId: typedData.domain.chainId, pool: typedData.domain.verifyingContract, txHash: job.txHash,
          signer: job.receipt.signer, signature, typedData, nullifiers, outCommitments,
        };
        const out = {
          tx_hash: job.txHash, explorer_url: explorer(job.txHash), chain: `eip155:${typedData.domain.chainId}`, pool: typedData.domain.verifyingContract,
          signer: job.receipt.signer, signature, typed_data: typedData, nullifiers, out_commitments: outCommitments,
          ...(job.x402?.settlementTx ? { x402_settlement_tx: String(job.x402.settlementTx) } : {}),
          verify_url: service.verifyUrl(pkg),
          verify: [
            "Open verify_url: it recovers the EIP-712 signer (the payer's PayBox wallet), checks the nullifiers and commitments in the Base transaction and recomputes the signed intent from the on-chain data.",
            "The zero-knowledge proof verified on-chain bound this signature to exactly these amounts and recipients.",
          ],
        };
        const m = typedData.message;
        const paid = BigInt(m.publicAmount ?? 0) > 0n ? `${usdc(BigInt(m.publicAmount))} USDC to ${m.publicRecipient}` : `${usdc(BigInt(m.privateAmount ?? 0))} USDC to a hidden ghost recipient`;
        return { content: text(`Receipt for ${paid}, signed by ${job.receipt.signer}, executed in ${job.txHash}. Verification link: ${out.verify_url.slice(0, 80)}…`), structuredContent: out };
      } catch (err) {
        return fail(err);
      }
    },
  );

  return server;
}

serveStdio(createServer, { legacy: "reject" });
