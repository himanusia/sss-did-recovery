import { Wallet, getBytes } from 'ethers';
import {
  buildShareProof,
  combineShares,
  createAuthKeyPair,
  decodeShare,
  didHash,
  encodeShare,
  newDid,
  randomScalar,
  recoveryAddress,
  shareRoot,
  splitSecret,
  toEnvelope,
  verifyShareProof,
  type ShareEnvelope,
} from '@sss/crypto';
import { api, type DIDDocument } from './api';

export interface GuardianShare {
  name: string;
  token: string;
  envelope: ShareEnvelope;
}

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
  guardians: GuardianShare[];
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
  newGuardians: GuardianShare[];
}

export interface Store {
  identity: IdentityRecord | null;
  pending: PendingRecovery | null;
}

const STORAGE_KEY = 'sss-did-demo-v1';

const DEFAULT_GUARDIANS = [
  'Laptop utama',
  'Ponsel cadangan',
  'Cloud vault',
  'Kertas cetak',
  'Rekan tepercaya',
];

export function loadStore(): Store {
  try {
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
  secret: bigint;
  recoveryAddress: string;
  shareRoot: string;
  guardians: GuardianShare[];
}

/** Generates the recovery secret and the committed share set. Client-side only. */
export function createMaterial(threshold: number, shareCount: number, names = DEFAULT_GUARDIANS): Material {
  const secret = randomScalar();
  const shares = splitSecret(secret, threshold, shareCount);
  const root = shareRoot(shares);
  const guardians = shares.map((share, position) => {
    const name = names[position] ?? `Guardian ${share.index}`;
    const proof = buildShareProof(shares, share.index);
    return {
      name,
      token: encodeShare(share),
      envelope: toEnvelope(share, proof, root, name),
    };
  });
  return { secret, recoveryAddress: recoveryAddress(secret), shareRoot: root, guardians };
}

export type CreateStep = 'auth-key' | 'shares' | 'commitment' | 'signature' | 'relay';

export async function createIdentity(
  threshold: number,
  shareCount: number,
  onStep: (step: CreateStep) => void,
  names = DEFAULT_GUARDIANS,
): Promise<IdentityRecord> {
  onStep('auth-key');
  const auth = createAuthKeyPair();
  const did = newDid();
  const hash = didHash(did);

  onStep('shares');
  const material = createMaterial(threshold, shareCount, names);

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

  return {
    did,
    didHash: hash,
    authPrivateKey: auth.privateKey,
    authAddress: auth.address,
    recoveryAddress: material.recoveryAddress,
    shareRoot: material.shareRoot,
    threshold,
    shareCount,
    guardians: material.guardians,
    version: 1,
    createdAt: Date.now(),
    registerTx: registered.txHash,
  };
}

export type RecoveryStep = 'verify' | 'reconstruct' | 'signature' | 'relay';

export async function beginRecovery(
  identity: IdentityRecord,
  threshold: number,
  shareCount: number,
): Promise<PendingRecovery> {
  const material = createMaterial(threshold, shareCount);
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
    newGuardians: material.guardians,
  };
}

export interface RecoveryOutcome {
  document: DIDDocument;
  txHash: string;
  identity: IdentityRecord;
}

/**
 * Gathers shares, verifies every one against the on-chain root, reconstructs
 * the recovery secret locally, then signs the rotation. Shares and secret never
 * leave this function.
 */
export async function completeRecovery(
  identity: IdentityRecord,
  pending: PendingRecovery,
  selected: GuardianShare[],
  onStep: (step: RecoveryStep) => void,
): Promise<RecoveryOutcome> {
  onStep('verify');
  const { document } = await api.getDid(identity.did);
  if (selected.length < document.threshold) {
    throw new Error(`butuh minimal ${document.threshold} share, baru ${selected.length} dipilih`);
  }
  for (const guardian of selected) {
    if (!verifyShareProof(guardian.envelope.proof, document.shareRoot)) {
      throw new Error(`share dari ${guardian.name} tidak cocok dengan commitment on-chain`);
    }
  }

  onStep('reconstruct');
  const secret = combineShares(selected.map((guardian) => decodeShare(guardian.token)));
  const derived = recoveryAddress(secret);
  if (derived.toLowerCase() !== document.recoveryKey.toLowerCase()) {
    throw new Error('rekonstruksi gagal: secret tidak cocok dengan recovery key on-chain');
  }

  onStep('signature');
  const prepared = await api.prepareRecovery(identity.did);
  if (prepared.request.requestId !== pending.requestId) {
    throw new Error('request pemulihan berubah, muat ulang halaman');
  }
  const recoveryWallet = new Wallet(`0x${secret.toString(16).padStart(64, '0')}`);
  const signature = await recoveryWallet.signMessage(getBytes(prepared.digest));

  onStep('relay');
  const executed = await api.executeRecovery(identity.did, pending.requestId, signature);

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
      guardians: pending.newGuardians,
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

export function downloadEnvelope(guardian: GuardianShare): void {
  const blob = new Blob([JSON.stringify(guardian.envelope, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `share-${guardian.envelope.index}-${guardian.name.replace(/\s+/g, '-').toLowerCase()}.json`;
  link.click();
  URL.revokeObjectURL(url);
}
