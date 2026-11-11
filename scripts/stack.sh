#!/usr/bin/env bash
# Boots the private QBFT network, PostgreSQL, deploys the registry and runs the API + console.
#
#   scripts/stack.sh boot     # network + database + contract + api + web (docker)
#   scripts/stack.sh dev      # network + database, then run API/web from source
#   scripts/stack.sh deploy   # (re)deploy the registry on the running network
#   scripts/stack.sh demo     # run the end-to-end story against the running API
#   scripts/stack.sh test     # contract, crypto and API suites
#   scripts/stack.sh down     # stop containers, keep volumes
#   scripts/stack.sh reset    # stop containers, delete volumes and generated keys
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DELAY="${RECOVERY_DELAY_SECONDS:-20}"
# Load a previous deployment (if any) so compose interpolation always resolves.
if [ -f "$ROOT/.env" ]; then set -a; . "$ROOT/.env"; set +a; fi
RPC="${RPC_URL:-http://127.0.0.1:8545}"
API="${API_URL:-http://127.0.0.1:8788}"

compose() { docker compose -f "$ROOT/docker-compose.yml" "$@"; }

rpc_up() {
  curl -sf -m 2 -X POST -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' "$RPC" >/dev/null
}

wait_rpc() {
  for _ in $(seq 1 120); do
    if rpc_up; then return 0; fi
    sleep 1
  done
  echo "QBFT network did not answer on $RPC" >&2
  compose logs --tail 40 besu1 >&2 || true
  exit 1
}

wait_api() {
  for _ in $(seq 1 90); do
    if curl -sf -m 2 "$API/api/health" >/dev/null; then return 0; fi
    sleep 1
  done
  echo "API did not answer on $API" >&2
  compose logs --tail 40 api >&2 || true
  exit 1
}

chain_only() {
  compose up -d --wait postgres besu1 besu2 besu3 besu4 >/dev/null
  wait_rpc
  echo "QBFT: chainId $(curl -s -X POST -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' "$RPC" | sed 's/.*"result":"//;s/".*//') (4 validators)"
}

deploy() {
  local out address
  out="$(cd "$ROOT/packages/contracts" && RECOVERY_DELAY_SECONDS="$DELAY" \
    npx hardhat run scripts/deploy.ts --network besu | tail -n 1)"
  address="$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).address)' "$out")"
  printf 'CONTRACT_ADDRESS=%s\nRECOVERY_DELAY_SECONDS=%s\n' "$address" "$DELAY" >"$ROOT/.env"
  echo "registry deployed at $address (timelock ${DELAY}s)"
}

case "${1:-boot}" in
  boot)
    chain_only
    deploy
    set -a; . "$ROOT/.env"; set +a
    compose up -d --build api web >/dev/null
    wait_api
    echo "console  http://127.0.0.1:8080"
    echo "api      $API/api/health"
    ;;
  dev)
    chain_only
    [ -f "$ROOT/.env" ] || deploy
    set -a; . "$ROOT/.env"; set +a
    echo "start the API:  (cd services/api && CONTRACT_ADDRESS=$CONTRACT_ADDRESS uv run python -m app.main)"
    echo "start the web:  npm run dev:web"
    ;;
  deploy)
    wait_rpc
    deploy
    ;;
  demo)
    (cd "$ROOT/services/api" && API_URL="$API" uv run python scripts/e2e_demo.py)
    ;;
  test)
    (cd "$ROOT" && npm run test -w @sss/crypto && npm run test -w @sss/contracts)
    (cd "$ROOT/services/api" && uv run pytest)
    ;;
  down)
    compose down
    ;;
  reset)
    compose down -v
    rm -rf "$ROOT/infra/besu/networkFiles" "$ROOT/infra/besu/networkFiles-private" "$ROOT/.env"
    echo "volumes and generated network files removed; run 'scripts/stack.sh generate' next"
    ;;
  generate)
    bash "$ROOT/scripts/besu-network.sh"
    ;;
  *)
    echo "usage: $0 {boot|dev|deploy|demo|test|down|reset|generate}" >&2
    exit 1
    ;;
esac
