#!/usr/bin/env bash
# Regenerates the QBFT validator set, node keys and genesis file.
#
# This rotates every validator identity: the committed genesis, the bootnode
# enodes in docker-compose.yml and the validator list all change together, and
# existing chain volumes become unreadable. Run scripts/stack.sh reset first,
# then this script, then commit the regenerated networkFiles directory.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="$ROOT/infra/besu/networkFiles"

if [ -d "$TARGET" ]; then
  echo "$TARGET already exists; delete it (scripts/stack.sh reset) before regenerating" >&2
  exit 1
fi

mkdir -p "$TARGET"
TAG="${BESU_TAG:-25.9.0}"

docker run --rm \
  -v "$ROOT/infra/besu/config:/config:ro" \
  -v "$TARGET:/networkFiles" \
  "hyperledger/besu:$TAG" \
  operator generate-blockchain-config \
  --config-file=/config/qbft-config.json \
  --to=/networkFiles \
  --private-key-file-name=key

node - "$TARGET" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const [target] = process.argv.slice(2);
const keysDir = path.join(target, 'keys');
const validators = fs.readdirSync(keysDir).sort();
const enodes = validators.map((address, index) => {
  const pub = fs.readFileSync(path.join(keysDir, address, 'key.pub'), 'utf8').trim().replace(/^0x/, '');
  return `enode://${pub}@172.28.0.${11 + index}:30303`;
});
console.log('validators:', validators.join(', '));
console.log('bootnodes for docker-compose.yml:');
console.log(enodes.join(','));
NODE

echo "generated $TARGET/genesis.json and $(find "$TARGET/keys" -maxdepth 1 -type d | tail -n +2 | wc -l | tr -d ' ') node keys"
