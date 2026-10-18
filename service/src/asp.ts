// Association Set Provider: screens deposits and publishes the approved-label root.
// Hackathon policy: approve every deposit whose depositor is not on the denylist, after ASP_DELAY_SECONDS.
// The denylist (config.aspDenylist) is ASP_DENYLIST merged with the vendored OFAC SDN Ethereum list
// (ofac.ts), so sanctioned depositors are never approved. Unapproved deposits can never be spent privately.
import { ghostPoolAbi } from "./abi.js";
import { config } from "./config.js";
import { isSanctioned } from "./ofac.js";
import { approvedLabels, aspTreeFor, publicClient, state, walletClient, withRelayerLock } from "./indexer.js";

let pending = false;
let lastSanctioned = 0;

export async function refreshAsp() {
  const labels = approvedLabels();
  const sanctioned = state.deposits.filter((d) => isSanctioned(d.depositor)).length;
  if (sanctioned !== lastSanctioned) {
    lastSanctioned = sanctioned;
    console.error(`[asp] ${sanctioned} deposit(s) from OFAC-sanctioned addresses excluded from the association set`);
  }
  const tree = aspTreeFor(labels);
  if (state.onchainAspRoot === tree.root) {
    state.publishedAsp = { root: tree.root, labels };
    return;
  }
  // Keep serving the last list that matches the on-chain root while an update is pending.
  if (state.publishedAsp.root !== state.onchainAspRoot) {
    for (let n = labels.length; n >= 0; n--) {
      const candidate = labels.slice(0, n);
      if (aspTreeFor(candidate).root === state.onchainAspRoot) { state.publishedAsp = { root: state.onchainAspRoot, labels: candidate }; break; }
    }
  }
  const wallet = walletClient;
  if (pending || !wallet || labels.length === 0) return;
  pending = true;
  try {
    const { hash, receipt } = await withRelayerLock(async () => {
      const hash = await wallet.writeContract({ address: config.pool, abi: ghostPoolAbi, functionName: "setAspRoot", args: [tree.root] });
      return { hash, receipt: await publicClient.waitForTransactionReceipt({ hash, timeout: 60_000 }) };
    });
    if (receipt.status === "success") {
      state.onchainAspRoot = tree.root;
      state.publishedAsp = { root: tree.root, labels };
      console.error(`[asp] published root for ${labels.length} approved deposit(s): ${hash}`);
    }
  } catch (err) {
    console.error(`[asp] update failed: ${(err as Error).message.split("\n")[0]}`);
  } finally {
    pending = false;
  }
}
