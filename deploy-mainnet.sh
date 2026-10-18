#!/usr/bin/env bash
# Deploys HonkVerifier + GhostPool (and linked libraries) to Base mainnet with the relayer key,
# then writes service/.env. The key is read from ../.secrets/relayer.key and never printed.
set -euo pipefail
source /c/Users/USER/Desktop/paybox/.toolchain/env.sh
ROOT=/c/Users/USER/Desktop/paybox/ghost-mode
RPC=${RPC_URL:-https://base-rpc.publicnode.com}
cd "$ROOT/contracts"
forge script script/Deploy.s.sol --rpc-url "$RPC" --broadcast --slow \
  --private-key "$(cat /c/Users/USER/Desktop/paybox/.secrets/relayer.key)" > "$ROOT/deploy.log" 2>&1 || { tail -20 "$ROOT/deploy.log"; exit 1; }
grep -E "Deployer|Token:|HonkVerifier:|GhostPool:" "$ROOT/deploy.log"
POOL=$(grep -oE "GhostPool: 0x[0-9a-fA-F]{40}" "$ROOT/deploy.log" | awk '{print $2}')
BLOCK=$(node -e '
const r = require(process.argv[1]);
const rec = r.receipts.find((x) => x.contractAddress && x.contractAddress.toLowerCase() === process.argv[2].toLowerCase());
console.log(parseInt(rec.blockNumber));' "$ROOT/contracts/broadcast/Deploy.s.sol/8453/run-latest.json" "$POOL")
cat > "$ROOT/service/.env" <<EOF
CHAIN_ID=8453
RPC_URL=$RPC
POOL_ADDRESS=$POOL
POOL_DEPLOY_BLOCK=$BLOCK
TOKEN=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
RELAYER_FEE=10000
ASP_DELAY_SECONDS=0
X402_MAX_AMOUNT=1000000
LOG_CHUNK=10000
PORT=8787
EOF
echo "POOL_ADDRESS=$POOL POOL_DEPLOY_BLOCK=$BLOCK written to service/.env"
