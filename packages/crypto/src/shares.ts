/**
 * Share envelopes and text encoding.
 *
 * A share leaves the client as a self-describing token so it can be handed to
 * a guardian out of band (paper, file, password manager). The envelope also
 * carries the Merkle proof against the on-chain root, letting the owner verify
 * a gathered share before using it.
 */
import { bigIntToBytes, bytesToBigInt, fromHex, toHex, type Share } from './sss.js';
import type { ShareProof } from './commitments.js';

export interface ShareEnvelope {
  version: 1;
  index: number;
  /** 32-byte big-endian share value, hex encoded. */
  value: string;
  proof: ShareProof;
  root: string;
  guardian: string;
}

const SHARE_TAG = 'sss1';

export function encodeShare(share: Share): string {
  return `${SHARE_TAG}:${share.index}:${toHex(bigIntToBytes(share.value, 32))}`;
}

export function decodeShare(token: string): Share {
  const parts = token.trim().split(':');
  if (parts.length !== 3 || parts[0] !== SHARE_TAG) throw new Error('invalid share token');
  const index = Number.parseInt(parts[1], 10);
  const value = bytesToBigInt(fromHex(parts[2]));
  if (!Number.isInteger(index) || index < 1 || index > 255) throw new Error('invalid share index');
  if (value <= 0n) throw new Error('invalid share value');
  return { index, value };
}

export function toEnvelope(share: Share, proof: ShareProof, root: string, guardian: string): ShareEnvelope {
  return {
    version: 1,
    index: share.index,
    value: `0x${toHex(bigIntToBytes(share.value, 32))}`,
    proof,
    root,
    guardian,
  };
}

export function envelopeToShare(envelope: ShareEnvelope): Share {
  if (envelope.version !== 1) throw new Error('unsupported envelope version');
  return { index: envelope.index, value: bytesToBigInt(fromHex(envelope.value)) };
}

export function encodeEnvelope(envelope: ShareEnvelope): string {
  return JSON.stringify(envelope);
}

export function decodeEnvelope(text: string): ShareEnvelope {
  const parsed = JSON.parse(text) as ShareEnvelope;
  if (parsed.version !== 1 || !parsed.proof || !parsed.root) throw new Error('invalid envelope');
  return parsed;
}
