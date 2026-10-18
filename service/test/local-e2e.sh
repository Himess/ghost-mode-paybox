#!/usr/bin/env bash
# Local end-to-end run: anvil + MockUSDC + HonkVerifier/GhostPool + Ghost service + the built plugin bundle.
# Uses anvil's well-known public test keys only.
set -euo pipefail
source /c/Users/USER/Desktop/paybox/.toolchain/env.sh
ROOT=/c/Users/USER/Desktop/paybox/ghost-mode
RPC=http://127.0.0.1:8545
PORT=8788
K0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80   # deployer + relayer + ASP operator
K1=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d   # user (stands in for the PayBox wallet)
K2=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a   # Ayse
USER_ADDR=0x70997970C51812dc3A010C7d01b50e0d17dc79C8

free_port() { for pid in $(netstat -ano | grep LISTENING | grep -E "[:.]$1\s" | awk '{print $NF}' | sort -u); do taskkill //F //T //PID "$pid" >/dev/null 2>&1 || true; done; }
cleanup() { kill ${ANVIL_PID:-} ${SVC_PID:-} 2>/dev/null || true; free_port 8545; free_port $PORT; }
free_port 8545; free_port $PORT
if [ -z "${KEEP:-}" ]; then trap cleanup EXIT; fi

anvil --silent --port 8545 > /dev/null 2>&1 &
ANVIL_PID=$!
for i in $(seq 1 30); do cast block-number --rpc-url $RPC >/dev/null 2>&1 && break; sleep 0.5; done

cd "$ROOT/contracts"
USDC=$(forge create test/mocks/MockUSDC.sol:MockUSDC --rpc-url $RPC --private-key $K0 --broadcast 2>/dev/null | grep -oE "Deployed to: 0x[0-9a-fA-F]{40}" | awk '{print $3}')
echo "MockUSDC $USDC"
cast send "$USDC" "mint(address,uint256)" $USER_ADDR 1000000000 --rpc-url $RPC --private-key $K0 >/dev/null
POOL=$(TOKEN=$USDC forge script script/Deploy.s.sol --rpc-url $RPC --broadcast --private-key $K0 2>/dev/null | grep -oE "GhostPool: 0x[0-9a-fA-F]{40}" | awk '{print $2}')
echo "GhostPool $POOL"

cd "$ROOT/service"
TESTDATA=$(mktemp -d)
CIRCUIT_PATH=$ROOT/circuits/transact/target/transact.json DATA_DIR=$TESTDATA STATE_FILE=$TESTDATA/state.json POOL_ADDRESS=$POOL POOL_DEPLOY_BLOCK=0 RPC_URL=$RPC CHAIN_ID=31337 RELAYER_PRIVATE_KEY=$K0 TOKEN=$USDC PORT=$PORT \
  npx tsx src/server.ts > "$ROOT/service/test/local-service.log" 2>&1 &
SVC_PID=$!
for i in $(seq 1 60); do curl -sf http://127.0.0.1:$PORT/health >/dev/null && break; sleep 0.5; done

SERVICE_URL=http://127.0.0.1:$PORT USER_KEY=$K1 AYSE_KEY=$K2 RPC_URL=$RPC CHAIN_ID=31337 npx tsx test/e2e.ts
