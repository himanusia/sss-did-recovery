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
} from './types.js';

export const DID_REGISTRY_ABI = [
  'function register(bytes32 didHash,address authKey,address recoveryKey,bytes32 shareRoot,uint8 threshold,uint8 shareCount,bytes signature)',
  'function initiateRecovery(bytes32 didHash,address newAuthKey,address newRecoveryKey,bytes32 newShareRoot,uint8 threshold,uint8 shareCount) returns (uint256)',
  'function executeRecovery(bytes32 didHash,uint256 requestId,bytes signature)',
  'function cancelRecovery(bytes32 didHash,uint256 requestId,bytes signature)',
  'function getDocument(bytes32 didHash) view returns (tuple(address authKey,address recoveryKey,bytes32 shareRoot,uint8 threshold,uint8 shareCount,uint64 createdAt,uint64 updatedAt,uint32 version,bool active))',
  'function getRecovery(bytes32 didHash) view returns (tuple(address newAuthKey,address newRecoveryKey,bytes32 newShareRoot,uint8 threshold,uint8 shareCount,uint64 requestedAt,uint64 executeAfter,bool executed,bool cancelled))',
  'function recoveryRequestCount(bytes32 didHash) view returns (uint256)',
  'function recoveryDelay() view returns (uint64)',
  'function registerDigest(bytes32 didHash,address authKey,address recoveryKey,bytes32 shareRoot,uint8 threshold,uint8 shareCount) view returns (bytes32)',
  'function recoveryDigest(bytes32 didHash,uint256 requestId,address newAuthKey,address newRecoveryKey,bytes32 newShareRoot,uint8 threshold,uint8 shareCount) view returns (bytes32)',
  'function cancelDigest(bytes32 didHash,uint256 requestId) view returns (bytes32)',
  'event DIDRegistered(bytes32 indexed didHash,address indexed authKey,address recoveryKey,bytes32 shareRoot,uint8 threshold,uint8 shareCount)',
  'event KeyRotated(bytes32 indexed didHash,address indexed oldAuthKey,address indexed newAuthKey,uint32 version)',
  'event RecoveryInitiated(bytes32 indexed didHash,uint256 indexed requestId,address newAuthKey,uint64 executeAfter)',
  'event RecoveryCancelled(bytes32 indexed didHash,uint256 indexed requestId)',
  'event RecoveryExecuted(bytes32 indexed didHash,uint256 indexed requestId,address indexed newAuthKey,uint32 version)',
];

export interface EthersRegistryOptions {
  rpcUrl: string;
  contractAddress: string;
  relayerPrivateKey: string;
}

/**
 * Ethers-backed registry adapter. The relayer pays gas for every state change;
 * authority always comes from an off-chain signature, never from msg.sender.
 */
export class EthersRegistryAdapter implements RegistryAdapter {
  readonly chainId: number;
  readonly registryAddress: string;
  readonly relayerAddress: string;
  readonly recoveryDelay: number;

  private readonly provider: ethers.JsonRpcProvider;
  private readonly reader: ethers.Contract;
  private readonly writer: ethers.Contract;
  private readonly blockTimestamps = new Map<number, number>();

  private constructor(
    provider: ethers.JsonRpcProvider,
    chainId: number,
    reader: ethers.Contract,
    writer: ethers.Contract,
    relayerAddress: string,
    recoveryDelay: number,
  ) {
    this.provider = provider;
    this.chainId = chainId;
    this.registryAddress = reader.target as string;
    this.relayerAddress = relayerAddress;
    this.reader = reader;
    this.writer = writer;
    this.recoveryDelay = recoveryDelay;
  }

  static async create(options: EthersRegistryOptions): Promise<EthersRegistryAdapter> {
    const provider = new ethers.JsonRpcProvider(options.rpcUrl);
    const network = await provider.getNetwork();
    if (!ethers.isAddress(options.contractAddress)) {
      throw new Error(`CONTRACT_ADDRESS is not an address: ${options.contractAddress}`);
    }
    const signer = new ethers.Wallet(options.relayerPrivateKey, provider);
    const reader = new ethers.Contract(options.contractAddress, DID_REGISTRY_ABI, provider);
    const writer = new ethers.Contract(options.contractAddress, DID_REGISTRY_ABI, signer);
    const recoveryDelay = Number(await reader.recoveryDelay());
    return new EthersRegistryAdapter(
      provider,
      Number(network.chainId),
      reader,
      writer,
      signer.address,
      recoveryDelay,
    );
  }

  async getDocument(didHash: string): Promise<DIDDocumentView | null> {
    const raw = await this.reader.getDocument(didHash);
    if (raw.authKey === ethers.ZeroAddress) return null;
    return {
      didHash,
      authKey: raw.authKey,
      recoveryKey: raw.recoveryKey,
      shareRoot: raw.shareRoot,
      threshold: Number(raw.threshold),
      shareCount: Number(raw.shareCount),
      version: Number(raw.version),
      active: Boolean(raw.active),
      createdAt: Number(raw.createdAt),
      updatedAt: Number(raw.updatedAt),
    };
  }

  async getRecovery(didHash: string): Promise<RecoveryRequestView | null> {
    const raw = await this.reader.getRecovery(didHash);
    if (Number(raw.requestedAt) === 0) return null;
    const requestId = await this.reader.recoveryRequestCount(didHash);
    return {
      requestId: (requestId as bigint).toString(),
      newAuthKey: raw.newAuthKey,
      newRecoveryKey: raw.newRecoveryKey,
      newShareRoot: raw.newShareRoot,
      threshold: Number(raw.threshold),
      shareCount: Number(raw.shareCount),
      requestedAt: Number(raw.requestedAt),
      executeAfter: Number(raw.executeAfter),
      executed: Boolean(raw.executed),
      cancelled: Boolean(raw.cancelled),
    };
  }

  async getAudit(didHash: string): Promise<AuditEvent[]> {
    const events: AuditEvent[] = [];
    const collect = async (
      name: 'DIDRegistered' | 'RecoveryInitiated' | 'RecoveryCancelled' | 'RecoveryExecuted' | 'KeyRotated',
      map: (log: ethers.EventLog) => AuditEvent,
    ) => {
      const logs = await this.reader.queryFilter(this.reader.filters[name](didHash), 0, 'latest');
      for (const log of logs) {
        if ('args' in log) events.push(map(log as ethers.EventLog));
      }
    };

    await collect('DIDRegistered', (log) => this.event(log, 'registered', {
      authKey: String(log.args.authKey),
      recoveryKey: String(log.args.recoveryKey),
      shareRoot: String(log.args.shareRoot),
      threshold: Number(log.args.threshold),
      shareCount: Number(log.args.shareCount),
    }));
    await collect('RecoveryInitiated', (log) => this.event(log, 'recovery-initiated', {
      requestId: String(log.args.requestId),
      newAuthKey: String(log.args.newAuthKey),
      executeAfter: Number(log.args.executeAfter),
    }));
    await collect('RecoveryCancelled', (log) => this.event(log, 'recovery-cancelled', {
      requestId: String(log.args.requestId),
    }));
    await collect('RecoveryExecuted', (log) => this.event(log, 'recovery-executed', {
      requestId: String(log.args.requestId),
      newAuthKey: String(log.args.newAuthKey),
      version: Number(log.args.version),
    }));
    await collect('KeyRotated', (log) => this.event(log, 'key-rotated', {
      oldAuthKey: String(log.args.oldAuthKey),
      newAuthKey: String(log.args.newAuthKey),
      version: Number(log.args.version),
    }));

    const sorted = events.sort((a, b) => a.blockNumber - b.blockNumber || a.logIndex - b.logIndex);
    for (const event of sorted) {
      event.timestamp = await this.timestampOf(event.blockNumber);
    }
    return sorted;
  }

  async registerDigest(params: RegisterParams): Promise<string> {
    return this.reader.registerDigest(
      params.didHash,
      params.authKey,
      params.recoveryKey,
      params.shareRoot,
      params.threshold,
      params.shareCount,
    );
  }

  async recoveryDigest(didHash: string, request: RecoveryRequestView): Promise<string> {
    return this.reader.recoveryDigest(
      didHash,
      request.requestId,
      request.newAuthKey,
      request.newRecoveryKey,
      request.newShareRoot,
      request.threshold,
      request.shareCount,
    );
  }

  async cancelDigest(didHash: string, requestId: string): Promise<string> {
    return this.reader.cancelDigest(didHash, requestId);
  }

  async register(params: RegisterParams, signature: string): Promise<RelayResult> {
    const tx = await this.writer.register(
      params.didHash,
      params.authKey,
      params.recoveryKey,
      params.shareRoot,
      params.threshold,
      params.shareCount,
      signature,
    );
    const receipt = await tx.wait();
    return { txHash: receipt?.hash ?? tx.hash };
  }

  async initiateRecovery(params: RecoveryParams): Promise<InitiateResult> {
    const tx = await this.writer.initiateRecovery(
      params.didHash,
      params.newAuthKey,
      params.newRecoveryKey,
      params.newShareRoot,
      params.threshold,
      params.shareCount,
    );
    const receipt = await tx.wait();
    const requestId = (await this.reader.recoveryRequestCount(params.didHash)) as bigint;
    const request = await this.getRecovery(params.didHash);
    return {
      txHash: receipt?.hash ?? tx.hash,
      requestId: requestId.toString(),
      executeAfter: request?.executeAfter ?? 0,
    };
  }

  async executeRecovery(didHash: string, requestId: string, signature: string): Promise<RelayResult> {
    const tx = await this.writer.executeRecovery(didHash, requestId, signature);
    const receipt = await tx.wait();
    return { txHash: receipt?.hash ?? tx.hash };
  }

  async cancelRecovery(didHash: string, requestId: string, signature: string): Promise<RelayResult> {
    const tx = await this.writer.cancelRecovery(didHash, requestId, signature);
    const receipt = await tx.wait();
    return { txHash: receipt?.hash ?? tx.hash };
  }

  private event(
    log: ethers.EventLog,
    type: AuditEvent['type'],
    data: AuditEvent['data'],
  ): AuditEvent {
    return {
      type,
      didHash: String(log.args.didHash),
      txHash: log.transactionHash,
      blockNumber: log.blockNumber,
      logIndex: log.index,
      timestamp: null,
      data,
    };
  }

  private async timestampOf(blockNumber: number): Promise<number | null> {
    const cached = this.blockTimestamps.get(blockNumber);
    if (cached !== undefined) return cached;
    const block = await this.provider.getBlock(blockNumber);
    if (!block) return null;
    this.blockTimestamps.set(blockNumber, block.timestamp);
    return block.timestamp;
  }
}
