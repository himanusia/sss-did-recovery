import { ethers } from 'ethers';
import type {
  AuditEvent,
  DIDDocumentView,
  InitiateResult,
  RecoveryParams,
  RecoveryRequestView,
  RegisterParams,
  RegistryAdapter,
  RelayResult,
} from '../src/types.js';

const REGISTRY = '0x5FbDB2315678afecb367f032d93F642f64180aa3';
const RELAYER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';

/** In-memory registry mirroring the contract's observable behaviour. */
export class FakeRegistry implements RegistryAdapter {
  readonly chainId = 31337;
  readonly registryAddress = REGISTRY;
  readonly relayerAddress = RELAYER;
  readonly recoveryDelay = 60;

  documents = new Map<string, DIDDocumentView>();
  recoveries = new Map<string, RecoveryRequestView>();
  counters = new Map<string, number>();
  audit: AuditEvent[] = [];
  private clock = 1_700_000_000;

  async getDocument(didHash: string): Promise<DIDDocumentView | null> {
    return this.documents.get(didHash.toLowerCase()) ?? null;
  }

  async getRecovery(didHash: string): Promise<RecoveryRequestView | null> {
    return this.recoveries.get(didHash.toLowerCase()) ?? null;
  }

  async getAudit(didHash: string): Promise<AuditEvent[]> {
    return this.audit.filter((event) => event.didHash.toLowerCase() === didHash.toLowerCase());
  }

  async registerDigest(params: RegisterParams): Promise<string> {
    return ethers.keccak256(ethers.toUtf8Bytes(`register:${JSON.stringify(params)}`));
  }

  async recoveryDigest(didHash: string, request: RecoveryRequestView): Promise<string> {
    return ethers.keccak256(ethers.toUtf8Bytes(`recover:${didHash}:${request.requestId}`));
  }

  async cancelDigest(didHash: string, requestId: string): Promise<string> {
    return ethers.keccak256(ethers.toUtf8Bytes(`cancel:${didHash}:${requestId}`));
  }

  async register(params: RegisterParams, _signature: string): Promise<RelayResult> {
    const key = params.didHash.toLowerCase();
    if (this.documents.has(key)) throw new Error('AlreadyRegistered');
    this.documents.set(key, {
      didHash: params.didHash,
      authKey: ethers.getAddress(params.authKey),
      recoveryKey: ethers.getAddress(params.recoveryKey),
      shareRoot: params.shareRoot,
      threshold: params.threshold,
      shareCount: params.shareCount,
      version: 1,
      active: true,
      createdAt: this.clock,
      updatedAt: this.clock,
    });
    return { txHash: `0x${'11'.repeat(32)}` };
  }

  async initiateRecovery(params: RecoveryParams): Promise<InitiateResult> {
    const key = params.didHash.toLowerCase();
    const next = (this.counters.get(key) ?? 0) + 1;
    this.counters.set(key, next);
    this.recoveries.set(key, {
      requestId: String(next),
      newAuthKey: ethers.getAddress(params.newAuthKey),
      newRecoveryKey: ethers.getAddress(params.newRecoveryKey),
      newShareRoot: params.newShareRoot,
      threshold: params.threshold,
      shareCount: params.shareCount,
      requestedAt: this.clock,
      executeAfter: this.clock + this.recoveryDelay,
      executed: false,
      cancelled: false,
    });
    return { txHash: `0x${'22'.repeat(32)}`, requestId: String(next), executeAfter: this.clock + this.recoveryDelay };
  }

  async executeRecovery(didHash: string, requestId: string, _signature: string): Promise<RelayResult> {
    const key = didHash.toLowerCase();
    const request = this.recoveries.get(key);
    const document = this.documents.get(key);
    if (!request || !document) throw new Error('NoPendingRecovery');
    if (request.executed || request.cancelled || request.requestId !== requestId) {
      throw new Error('NoPendingRecovery');
    }
    request.executed = true;
    document.authKey = request.newAuthKey;
    document.recoveryKey = request.newRecoveryKey;
    document.shareRoot = request.newShareRoot;
    document.threshold = request.threshold;
    document.shareCount = request.shareCount;
    document.version += 1;
    document.updatedAt = this.clock;
    return { txHash: `0x${'33'.repeat(32)}` };
  }

  async cancelRecovery(didHash: string, requestId: string, _signature: string): Promise<RelayResult> {
    const request = this.recoveries.get(didHash.toLowerCase());
    if (!request || request.executed || request.cancelled || request.requestId !== requestId) {
      throw new Error('NoPendingRecovery');
    }
    request.cancelled = true;
    return { txHash: `0x${'44'.repeat(32)}` };
  }

  advance(seconds: number): void {
    this.clock += seconds;
  }
}
