import { Wallet, getBytes } from 'ethers';
import {
  buildShareProof,
  combineShares,
  createAuthKeyPair,
  didHash,
  newDid,
  randomScalar,
  recoveryAddress,
  shareRoot,
  splitSecret,
  toEnvelope,
  verifyShareProof,
} from '@sss/crypto';
import { api, type DIDDocument, type GuardianInfo, type SealedEnvelope } from './api';
import { openSealed, sealTo, transportKeyPair, hexOf } from './sealing';

export interface IdentityRecord {
  did: string;
  didHash: string;
  /** Null once the device is marked as lost; the recovery flow then applies. */
  authPrivateKey: string | null;
  authAddress: string;
  recoveryAddress: string;
  shareRoot: string;
  threshold: number;
  shareCount: number;
  version: number;
  createdAt: number;
  registerTx: string;
}

export interface PendingRecovery {
  requestId: string;
  executeAfter: number;
  initiatedAt: number;
  initiateTx: string;
  newAuthPrivateKey: string;
  newAuthAddress: string;
  newRecoveryAddress: string;
  newShareRoot: string;
  newThreshold: number;
  newShareCount: number;
  /** Sealed envelopes for the next share set, deposited right after rotation. */
  newEnvelopes: SealedEnvelope[];
}

export interface Store {
  identity: IdentityRecord | null;
  pending: PendingRecovery | null;
}

const STORAGE_KEY = 'sss-did-demo-v2';
const LEGACY_KEY = 'sss-did-demo-v1';

export function loadStore(): Store {
  try {
    localStorage.removeItem(LEGACY_KEY);
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { identity: null, pending: null };
    const parsed = JSON.parse(raw) as Store;
    return { identity: parsed.identity ?? null, pending: parsed.pending ?? null };
  } catch {
    return { identity: null, pending: null };
  }
}

export function saveStore(store: Store): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
}

export function clearStore(): void {
  localStorage.removeItem(STORAGE_KEY);
}

export interface Material {
  recoveryAddress: string;
  shareRoot: string;
  envelopes: SealedEnvelope[];
}

/**
 * Splits the recovery secret and seals one envelope per guardian.
 *
 * The assignment is shuffled in the browser and the guardian list only contains
 * public keys, so the network stores opaque boxes: it cannot tell which share
 * index any guardian received. Plaintext shares exist only inside this function.
 */
export function createMaterial(threshold: number, shareCount: number, guardians: GuardianInfo[]): Material {
  if (guardians.length < shareCount) {
    throw new Error(`butuh ${shareCount} guardian aktif, jaringan hanya punya ${guardians.length}`);
  }
  const secret = randomScalar();
  const shares = splitSecret(secret, threshold, shareCount);
  const root = shareRoot(shares);

  const order = Array.from({ length: guardians.length }, (_, index) => index);
  for (let i = order.length - 1; i > 0; i -= 1) {
    const j = Math.floor(Math.random() * (i + 1));
    [order[i], order[j]] = [order[j], order[i]];
  }

  const envelopes = shares.map((share, position) => {
    const guardian = guardians[order[position] % guardians.length];
    const proof = buildShareProof(shares, share.index);
    const payload = toEnvelope(share, proof, root, guardian.id);
    const sealed = sealTo(new TextEncoder().encode(JSON.stringify(payload)), guardian.publicKey);
    return { guardianId: guardian.id, ciphertext: sealed };
  });

  return { recoveryAddress: recoveryAddress(secret), shareRoot: root, envelopes };
}

export type CreateStep = 'auth-key' | 'shares' | 'commitment' | 'signature' | 'relay' | 'distribute';

export async function createIdentity(
  threshold: number,
  shareCount: number,
  onStep: (step: CreateStep) => void,
): Promise<IdentityRecord> {
  onStep('auth-key');
  const auth = createAuthKeyPair();
  const did = newDid();
  const hash = didHash(did);

  onStep('shares');
  const guardians = (await api.guardians()).guardians;
  const material = createMaterial(threshold, shareCount, guardians);

  onStep('commitment');
  const payload = {
    did,
    didHash: hash,
    authKey: auth.address,
    recoveryKey: material.recoveryAddress,
    shareRoot: material.shareRoot,
    threshold,
    shareCount,
  };
  const { digest } = await api.prepareRegister(payload);

  onStep('signature');
  const wallet = new Wallet(auth.privateKey);
  const signature = await wallet.signMessage(getBytes(digest));

  onStep('relay');
  const registered = await api.register({ ...payload, signature });

  onStep('distribute');
  await api.depositShares({ did, shareRoot: material.shareRoot, envelopes: material.envelopes });

  return {
    did,
    didHash: hash,
    authPrivateKey: auth.privateKey,
    authAddress: auth.address,
    recoveryAddress: material.recoveryAddress,
    shareRoot: material.shareRoot,
    threshold,
    shareCount,
    version: 1,
    createdAt: Date.now(),
    registerTx: registered.txHash,
  };
}

export type RecoveryStep = 'request' | 'verify' | 'reconstruct' | 'signature' | 'relay' | 'distribute';

export async function beginRecovery(
  identity: IdentityRecord,
  threshold: number,
  shareCount: number,
): Promise<PendingRecovery> {
  const guardians = (await api.guardians()).guardians;
  const material = createMaterial(threshold, shareCount, guardians);
  const auth = createAuthKeyPair();
  const result = await api.initiateRecovery({
    did: identity.did,
    newAuthKey: auth.address,
    newRecoveryKey: material.recoveryAddress,
    newShareRoot: material.shareRoot,
    threshold,
    shareCount,
  });

  return {
    requestId: result.requestId,
    executeAfter: result.executeAfter,
    initiatedAt: Date.now(),
    initiateTx: result.txHash,
    newAuthPrivateKey: auth.privateKey,
    newAuthAddress: auth.address,
    newRecoveryAddress: material.recoveryAddress,
    newShareRoot: material.shareRoot,
    newThreshold: threshold,
    newShareCount: shareCount,
    newEnvelopes: material.envelopes,
  };
}

export interface RecoveryOutcome {
  document: DIDDocument;
  txHash: string;
  identity: IdentityRecord;
}

/**
 * Asks the network for k rewrapped shares, opens them with an ephemeral key,
 * checks every Merkle proof against the on-chain root, reconstructs the secret
 * locally and signs the rotation. No share or secret leaves this function.
 */
export async function completeRecovery(
  identity: IdentityRecord,
  pending: PendingRecovery,
  onStep: (step: RecoveryStep) => void,
): Promise<RecoveryOutcome> {
  onStep('request');
  const prepared = await api.prepareRecovery(identity.did);
  if (prepared.request.requestId !== pending.requestId) {
    throw new Error('request pemulihan berubah, muat ulang halaman');
  }
  const threshold = prepared.request.threshold;
  const transport = transportKeyPair();
  const bundle = await api.requestShares({
    did: identity.did,
    transportPublicKey: hexOf(transport.publicKey),
    count: threshold,
  });
  if (bundle.shares.length < threshold) {
    throw new Error(`jaringan hanya mengembalikan ${bundle.shares.length} share dari ${threshold} yang dibutuhkan`);
  }

  onStep('verify');
  const shares = bundle.shares.map((share) => {
    let envelope: { version: number; index: number; value: string; proof: Parameters<typeof verifyShareProof>[0] };
    try {
      envelope = JSON.parse(new TextDecoder().decode(openSealed(share.ciphertext, transport.privateKey)));
    } catch {
      throw new Error(`share dari ${share.label} tidak bisa dibuka dengan kunci transport ini`);
    }
    if (!verifyShareProof(envelope.proof, prepared.document.shareRoot)) {
      throw new Error(`share dari ${share.label} tidak cocok dengan commitment on-chain`);
    }
    return { index: envelope.index, value: BigInt(envelope.value) };
  });

  onStep('reconstruct');
  const secret = combineShares(shares);
  if (recoveryAddress(secret).toLowerCase() !== prepared.document.recoveryKey.toLowerCase()) {
    throw new Error('rekonstruksi gagal: secret tidak cocok dengan recovery key on-chain');
  }

  onStep('signature');
  const recoveryWallet = new Wallet(`0x${secret.toString(16).padStart(64, '0')}`);
  const signature = await recoveryWallet.signMessage(getBytes(prepared.digest));

  onStep('relay');
  const executed = await api.executeRecovery(identity.did, pending.requestId, signature);

  onStep('distribute');
  await api.depositShares({
    did: identity.did,
    shareRoot: pending.newShareRoot,
    envelopes: pending.newEnvelopes,
  });

  return {
    document: executed.document,
    txHash: executed.txHash,
    identity: {
      ...identity,
      authPrivateKey: pending.newAuthPrivateKey,
      authAddress: pending.newAuthAddress,
      recoveryAddress: pending.newRecoveryAddress,
      shareRoot: pending.newShareRoot,
      threshold: pending.newThreshold,
      shareCount: pending.newShareCount,
      version: executed.document.version,
    },
  };
}

export async function cancelRecovery(identity: IdentityRecord, pending: PendingRecovery): Promise<string> {
  if (!identity.authPrivateKey) throw new Error('kunci autentikasi tidak tersedia di perangkat ini');
  const prepared = await api.prepareCancel(identity.did);
  const wallet = new Wallet(identity.authPrivateKey);
  const signature = await wallet.signMessage(getBytes(prepared.digest));
  const result = await api.cancelRecovery(identity.did, pending.requestId, signature);
  return result.txHash;
}
