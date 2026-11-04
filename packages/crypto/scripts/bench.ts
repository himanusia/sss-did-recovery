/**
 * Micro-benchmark for the client-side share operations.
 * Run with: npm run bench -w @sss/crypto
 */
import {
  buildShareProof,
  combineShares,
  decodeShare,
  encodeShare,
  randomScalar,
  shareRoot,
  splitSecret,
  verifyShareProof,
} from '../src/index.js';

function measure(label: string, iterations: number, run: () => void): number {
  for (let i = 0; i < Math.min(10, iterations); i += 1) run();
  const started = performance.now();
  for (let i = 0; i < iterations; i += 1) run();
  const perOp = (performance.now() - started) / iterations;
  console.log(`${label.padEnd(38)} ${perOp.toFixed(3)} ms/op`);
  return perOp;
}

const configurations: [number, number][] = [
  [2, 3],
  [3, 5],
  [4, 7],
];

console.log('Shamir over secp256k1 — client-side operations\n');

for (const [threshold, shareCount] of configurations) {
  console.log(`\n${threshold}-of-${shareCount}`);
  let shares = splitSecret(randomScalar(), threshold, shareCount);
  const root = shareRoot(shares);

  measure('split', 500, () => {
    shares = splitSecret(randomScalar(), threshold, shareCount);
  });

  const selected = shares.slice(0, threshold);
  measure('combine (reconstruct)', 500, () => {
    combineShares(selected);
  });

  measure('commitment root', 300, () => {
    shareRoot(shares);
  });

  const proofs = shares.map((share) => buildShareProof(shares, share.index));
  measure('proof verify (per share)', 500, () => {
    verifyShareProof(proofs[0], root);
  });

  const token = encodeShare(shares[0]);
  measure('encode + decode share', 2000, () => {
    decodeShare(token);
  });
}
