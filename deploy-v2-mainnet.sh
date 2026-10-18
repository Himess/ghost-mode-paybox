#!/usr/bin/env bash
# Deploys GhostPool v2 (one-signature shield, pause = deposits only) to Base mainnet, reusing the
# live HonkVerifier and Poseidon libraries, then points service/.env at the new pool.
# The relayer key is read from ../.secrets/relayer.key and never printed.
set -euo pipefail
source /c/Users/USER/Desktop/paybox/.toolchain/env.sh
ROOT=/c/Users/USER/Desktop/paybox/ghost-mode
RPC=${RPC_URL:-https://mainnet.base.org}
cd "$ROOT/contracts"
VERIFIER=0x519a6d1022586ca29071e6d8c7a92180d5397d4f forge script script/DeployV2.s.sol --rpc-url "$RPC" --broadcast --slow \
  --libraries src/poseidon/PoseidonT3.sol:PoseidonT3:0xa6e3d33abef457db3a2f1504c91eee1a77375891 \
  --libraries src/poseidon/PoseidonT5.sol:PoseidonT5:0x95d619151c18632fd0e6271d8376a44da2a2290e \
  --private-key "$(cat /c/Users/USER/Desktop/paybox/.secrets/relayer.key)" > "$ROOT/deploy-v2.log" 2>&1 || { tail -25 "$ROOT/deploy-v2.log"; exit 1; }
grep -E "GhostPool|Owner|owner|Verifier" "$ROOT/deploy-v2.log" | head
POOL=$(grep -oE "GhostPoolV2: 0x[0-9a-fA-F]{40}" "$ROOT/deploy-v2.log" | awk '{print $2}')
BLOCK=$(node -e '
const r = require(process.argv[1]);
const rec = r.receipts.find((x) => x.contractAddress && x.contractAddress.toLowerCase() === process.argv[2].toLowerCase());
console.log(parseInt(rec.blockNumber));' "$ROOT/contracts/broadcast/DeployV2.s.sol/8453/run-latest.json" "$POOL")
node -e '
const fs = require("fs"); const f = process.argv[1];
let s = fs.readFileSync(f, "utf8");
s = s.replace(/^POOL_ADDRESS=.*$/m, "POOL_ADDRESS=" + process.argv[2]).replace(/^POOL_DEPLOY_BLOCK=.*$/m, "POOL_DEPLOY_BLOCK=" + process.argv[3]);
fs.writeFileSync(f, s);' "$ROOT/service/.env" "$POOL" "$BLOCK"
echo "GhostPool v2 $POOL at block $BLOCK written to service/.env"
