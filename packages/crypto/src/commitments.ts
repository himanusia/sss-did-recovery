/**
 * Merkle commitments for a share set.
 *
 * The chain stores a single 32-byte root instead of n share hashes, keeping
 * on-chain data minimal (NFR-11, NFR-18). The client keeps the proofs and can
 * verify that a gathered share belongs to the set committed at registration.
 */
import { keccak_256 } from '@noble/hashes/sha3';
import { commitmentOf, fromHex, toHex, type Share } from './sss.js';

function hashPair(left: Uint8Array, right: Uint8Array): Uint8Array {
  const [a, b] = toHex(left) <= toHex(right) ? [left, right] : [right, left];
  const payload = new Uint8Array(64);
  payload.set(a, 0);
  payload.set(b, 32);
  return keccak_256(payload);
}

export interface ShareProof {
  index: number;
  leaf: string;
  siblings: string[];
}

export function buildShareTree(shares: Share[]): { root: Uint8Array; levels: Uint8Array[][] } {
  if (shares.length === 0) throw new Error('no shares');
  const levels: Uint8Array[][] = [shares.map(commitmentOf)];
  let current = levels[0];
  while (current.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i];
      const right = i + 1 < current.length ? current[i + 1] : left;
      next.push(hashPair(left, right));
    }
    levels.push(next);
    current = next;
  }
  return { root: current[0], levels };
}

export function shareRoot(shares: Share[]): string {
  return `0x${toHex(buildShareTree(shares).root)}`;
}

export function buildShareProof(shares: Share[], shareIndex: number): ShareProof {
  const { levels } = buildShareTree(shares);
  const position = shares.findIndex((share) => share.index === shareIndex);
  if (position === -1) throw new Error(`share ${shareIndex} not in set`);

  const siblings: string[] = [];
  let cursor = position;
  for (let level = 0; level < levels.length - 1; level += 1) {
    const nodes = levels[level];
    const sibling = cursor % 2 === 0 ? cursor + 1 : cursor - 1;
    siblings.push(toHex(nodes[sibling] ?? nodes[cursor]));
    cursor = Math.floor(cursor / 2);
  }
  return { index: shares[position].index, leaf: toHex(levels[0][position]), siblings };
}

export function verifyShareProof(proof: ShareProof, root: string): boolean {
  let cursor = fromHex(proof.leaf);
  for (const sibling of proof.siblings) cursor = hashPair(cursor, fromHex(sibling));
  return toHex(cursor) === (root.startsWith('0x') ? root.slice(2) : root);
}
