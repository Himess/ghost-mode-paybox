#!/usr/bin/env bash
# Starts the Ghost service (Base mainnet) and a Cloudflare quick tunnel, then prints the public URL.
set -euo pipefail
source /c/Users/USER/Desktop/paybox/.toolchain/env.sh
ROOT=/c/Users/USER/Desktop/paybox/ghost-mode
cd "$ROOT/service"
npx tsx src/server.ts > "$ROOT/service/service.log" 2>&1 &
echo "service pid $!"
for i in $(seq 1 60); do curl -sf http://127.0.0.1:8787/health >/dev/null && break; sleep 0.5; done
/c/Users/USER/Desktop/paybox/.toolchain/cloudflared.exe tunnel --no-autoupdate --url http://127.0.0.1:8787 > "$ROOT/service/tunnel.log" 2>&1 &
echo "tunnel pid $!"
for i in $(seq 1 60); do URL=$(grep -oE "https://[a-z0-9-]+\.trycloudflare\.com" "$ROOT/service/tunnel.log" | head -1 || true); [ -n "$URL" ] && break; sleep 1; done
echo "GHOST_SERVICE_URL=$URL"
