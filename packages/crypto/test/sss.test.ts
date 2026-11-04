import { describe, expect, it } from 'vitest';
import {
  FIELD,
  buildShareProof,
  combineShares,
  commitmentOf,
  addressFromPrivateKey,
  createAuthKeyPair,
  decodeShare,
  didFromId,
  didHash,
  encodeShare,
  envelopeToShare,
  isValidDid,
  randomScalar,
  recoveryAddress,
  idFromDid,
  newDid,
  shareRoot,
  splitSecret,
  toEnvelope,
  verifyShareProof,
} from '../src/index.js';

describe('Shamir secret sharing over secp256k1', () => {
  it('reconstructs the secret from any k shares', () => {
    const secret = randomScalar();
    const shares = splitSecret(secret, 3, 5);
    const subsets = [
      [0, 1, 2],
      [0, 3, 4],
      [1, 2, 4],
      [2, 3, 4],
    ];
    for (const subset of subsets) {
      expect(combineShares(subset.map((i) => shares[i]))).toBe(secret);
    }
  });

  it('does not reconstruct with fewer than k shares', () => {
    const secret = randomScalar();
    const shares = splitSecret(secret, 3, 5);
    expect(combineShares([shares[0], shares[1]])).not.toBe(secret);
  });

  it('rejects duplicate share indices', () => {
    const shares = splitSecret(randomScalar(), 2, 3);
    expect(() => combineShares([shares[0], shares[0]])).toThrow(/duplicate/);
  });

  it('rejects malformed threshold configurations', () => {
    const secret = randomScalar();
    expect(() => splitSecret(secret, 1, 3)).toThrow(/at least 2/);
    expect(() => splitSecret(secret, 4, 3)).toThrow(/>= threshold/);
    expect(() => splitSecret(secret, 2, 256)).toThrow(/<= 255/);
    expect(() => splitSecret(0n, 2, 3)).toThrow(/out of field/);
    expect(() => splitSecret(FIELD, 2, 3)).toThrow(/out of field/);
  });

  it('derives a stable recovery address from the secret', () => {
    const secret = randomScalar();
    expect(recoveryAddress(secret)).toBe(recoveryAddress(secret));
    expect(recoveryAddress(secret)).toMatch(/^0x[0-9a-f]{40}$/);
    expect(recoveryAddress(secret === 1n ? 2n : secret - 1n)).not.toBe(recoveryAddress(secret));
  });
});

describe('share commitments', () => {
  it('builds a root that every share can prove membership against', () => {
    const shares = splitSecret(randomScalar(), 3, 5);
    const root = shareRoot(shares);
    for (const share of shares) {
      const proof = buildShareProof(shares, share.index);
      expect(proof.leaf).toBe(Buffer.from(commitmentOf(share)).toString('hex'));
      expect(verifyShareProof(proof, root)).toBe(true);
    }
  });

  it('rejects a proof against a different root', () => {
    const first = splitSecret(randomScalar(), 2, 4);
    const second = splitSecret(randomScalar(), 2, 4);
    const proof = buildShareProof(first, first[0].index);
    expect(verifyShareProof(proof, shareRoot(second))).toBe(false);
  });

  it('changes the root when a single share changes', () => {
    const shares = splitSecret(randomScalar(), 3, 5);
    const tampered = shares.map((share, i) => (i === 2 ? { ...share, value: share.value + 1n } : share));
    expect(shareRoot(tampered)).not.toBe(shareRoot(shares));
  });
});

describe('DID helpers', () => {
  it('keeps the identifier independent from the authentication key', () => {
    const did = newDid();
    expect(isValidDid(did)).toBe(true);
    expect(didFromId(idFromDid(did))).toBe(did);
    expect(didHash(did)).toMatch(/^0x[0-9a-f]{64}$/);
    expect(didHash(did)).toBe(didHash(did));

    const keys = createAuthKeyPair();
    expect(addressFromPrivateKey(keys.privateKey)).toBe(keys.address);
    expect(did).not.toContain(keys.address.slice(2));
  });

  it('rejects identifiers from another method', () => {
    expect(isValidDid('did:ethr:0x1234')).toBe(false);
    expect(() => didHash('did:ethr:0x1234')).toThrow(/invalid/);
  });
});

describe('share envelopes', () => {
  it('round-trips a share token and an envelope', () => {
    const shares = splitSecret(randomScalar(), 2, 3);
    const token = encodeShare(shares[0]);
    expect(decodeShare(token)).toEqual(shares[0]);

    const proof = buildShareProof(shares, shares[1].index);
    const envelope = toEnvelope(shares[1], proof, shareRoot(shares), 'Guardian B');
    expect(envelopeToShare(envelope)).toEqual(shares[1]);
    expect(verifyShareProof(envelope.proof, envelope.root)).toBe(true);
  });
});
