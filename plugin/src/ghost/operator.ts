// Privacy operator: rule-based linkability checks the agent surfaces before a spend.
import type { Hex } from "viem";
import type { OwnedNote, PoolState, SpendKind } from "../core/spend.js";

export type Warning = { severity: "high" | "medium" | "low"; code: string; message: string };
const USDC = 1_000_000n;
const fmt = (v: bigint) => `${v / USDC}.${(v % USDC).toString().padStart(6, "0").replace(/0+$/, "") || "0"}`;

export function assessSpend(input: {
  kind: SpendKind; amount: bigint; recipient?: Hex; state: PoolState; notes: OwnedNote[]; now: number;
}): { risk: "low" | "medium" | "high"; anonymitySet: number; warnings: Warning[] } {
  const { kind, amount, state, notes, now } = input;
  const warnings: Warning[] = [];
  const depositors = new Set(state.deposits.map((d) => d.depositor.toLowerCase()));
  const anonymitySet = depositors.size;
  const publicExit = kind !== "send_ghost";

  if (anonymitySet < 5) {
    warnings.push({ severity: "medium", code: "small_anonymity_set", message: `Only ${anonymitySet} distinct depositor(s) in the pool so far; observers can narrow down who is spending.` });
  }
  if (publicExit) {
    const recent = state.deposits.filter((d) => now - d.blockTime < 86_400);
    const close = recent.find((d) => {
      const diff = d.amount > amount ? d.amount - amount : amount - d.amount;
      return diff * 100n <= d.amount; // within 1%
    });
    if (close) {
      warnings.push({ severity: "high", code: "amount_matches_deposit", message: `${fmt(amount)} USDC is within 1% of a deposit made ${Math.round((now - close.blockTime) / 60)} min ago. Withdrawing the same amount links the two. Split it or wait.` });
    }
    const myDeposits = notes.filter((n) => n.source === "deposit");
    const freshest = myDeposits.reduce((m, n) => Math.max(m, n.blockTime), 0);
    if (freshest && now - freshest < 1_800) {
      warnings.push({ severity: "medium", code: "timing_correlation", message: `Your last deposit was ${Math.round((now - freshest) / 60)} min ago. Exiting soon after shielding makes timing analysis easy; wait, or set delay_minutes so the relayer submits at a random later time.` });
    }
    if (input.recipient && state.deposits.some((d) => d.depositor.toLowerCase() === input.recipient!.toLowerCase())) {
      warnings.push({ severity: "high", code: "recipient_is_depositor", message: "The recipient address has deposited into this pool before; paying it from the pool can link your activity to that address." });
    }
    if (amount % USDC !== 0n) {
      warnings.push({ severity: "low", code: "non_round_amount", message: `${fmt(amount)} USDC is a distinctive amount. Round amounts blend in better.` });
    }
  }
  const risk = warnings.some((w) => w.severity === "high") ? "high" : warnings.some((w) => w.severity === "medium") ? "medium" : "low";
  return { risk, anonymitySet, warnings };
}

export function shieldAdvice(amount: bigint): Warning[] {
  if (amount % (5n * USDC) === 0n) return [];
  const rounded = ((amount + 5n * USDC - 1n) / (5n * USDC)) * 5n * USDC;
  return [{ severity: "low", code: "round_deposit", message: `Deposits are public. ${fmt(amount)} USDC is easy to match later; consider ${fmt(rounded)} USDC instead.` }];
}

export { fmt as formatUsdc };
