#!/usr/bin/env bash
# Boots a throwaway Hardhat chain, deploys the registry, runs the end-to-end demo.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
DELAY="${RECOVERY_DELAY_SECONDS:-30}"

if curl -s -m 1 -X POST -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' "$RPC_URL" >/dev/null; then
  echo "port 8545 already serving JSON-RPC; using it as-is"
  STARTED=0
else
  echo "starting hardhat node on 8545…"
  (cd "$ROOT/packages/contracts" && npx hardhat node >"$ROOT/.chain.log" 2>&1) &
  CHAIN_PID=$!
  STARTED=1
  for _ in $(seq 1 60); do
    if curl -s -m 1 -X POST -H 'content-type: application/json' \
      --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' "$RPC_URL" >/dev/null; then
      break
    fi
    sleep 0.5
  done
fi

cleanup() {
  if [ "${STARTED:-0}" = "1" ]; then
    kill "$CHAIN_PID" 2>/dev/null || true
    wait "$CHAIN_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "deploying registry (recovery delay ${DELAY}s)…"
DEPLOYMENT="$(cd "$ROOT/packages/contracts" && RECOVERY_DELAY_SECONDS="$DELAY" npx hardhat run scripts/deploy.ts --network localhost | tail -n 1)"
CONTRACT_ADDRESS="$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).address)' "$DEPLOYMENT")"
echo "registry at $CONTRACT_ADDRESS"

cd "$ROOT"
RPC_URL="$RPC_URL" CONTRACT_ADDRESS="$CONTRACT_ADDRESS" npm run demo -w @sss/backend
