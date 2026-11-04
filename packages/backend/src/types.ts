export interface DIDDocumentView {
  didHash: string;
  authKey: string;
  recoveryKey: string;
  shareRoot: string;
  threshold: number;
  shareCount: number;
  version: number;
  active: boolean;
  createdAt: number;
  updatedAt: number;
}

export interface RecoveryRequestView {
  requestId: string;
  newAuthKey: string;
  newRecoveryKey: string;
  newShareRoot: string;
  threshold: number;
  shareCount: number;
  requestedAt: number;
  executeAfter: number;
  executed: boolean;
  cancelled: boolean;
}

export type AuditEventType =
  | 'registered'
  | 'recovery-initiated'
  | 'recovery-cancelled'
  | 'recovery-executed'
  | 'key-rotated';

export interface AuditEvent {
  type: AuditEventType;
  didHash: string;
  txHash: string;
  blockNumber: number;
  logIndex: number;
  timestamp: number | null;
  data: Record<string, string | number>;
}

export interface RegisterParams {
  didHash: string;
  authKey: string;
  recoveryKey: string;
  shareRoot: string;
  threshold: number;
  shareCount: number;
}

export interface RecoveryParams {
  didHash: string;
  newAuthKey: string;
  newRecoveryKey: string;
  newShareRoot: string;
  threshold: number;
  shareCount: number;
}

export interface RelayResult {
  txHash: string;
}

export interface InitiateResult extends RelayResult {
  requestId: string;
  executeAfter: number;
}

/**
 * Everything the HTTP layer needs from the chain. Implemented twice: once by
 * ethers against the registry contract, once by an in-memory fake in tests.
 */
export interface RegistryAdapter {
  readonly chainId: number;
  readonly registryAddress: string;
  readonly relayerAddress: string;
  readonly recoveryDelay: number;

  getDocument(didHash: string): Promise<DIDDocumentView | null>;
  getRecovery(didHash: string): Promise<RecoveryRequestView | null>;
  getAudit(didHash: string): Promise<AuditEvent[]>;

  registerDigest(params: RegisterParams): Promise<string>;
  recoveryDigest(didHash: string, request: RecoveryRequestView): Promise<string>;
  cancelDigest(didHash: string, requestId: string): Promise<string>;

  register(params: RegisterParams, signature: string): Promise<RelayResult>;
  initiateRecovery(params: RecoveryParams): Promise<InitiateResult>;
  executeRecovery(didHash: string, requestId: string, signature: string): Promise<RelayResult>;
  cancelRecovery(didHash: string, requestId: string, signature: string): Promise<RelayResult>;
}

export class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly code = 'error',
  ) {
    super(message);
  }
}
