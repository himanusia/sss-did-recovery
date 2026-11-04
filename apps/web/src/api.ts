export interface Health {
  ok: boolean;
  chainId: number;
  registry: string;
  relayer: string;
  recoveryDelay: number;
  apps: Record<string, string>;
  challengeTtlSeconds: number;
  sessionTtlSeconds: number;
}

export interface DIDDocument {
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

export interface RecoveryRequest {
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

export interface AuditEvent {
  type: 'registered' | 'recovery-initiated' | 'recovery-cancelled' | 'recovery-executed' | 'key-rotated';
  didHash: string;
  txHash: string;
  blockNumber: number;
  logIndex: number;
  timestamp: number | null;
  data: Record<string, string | number>;
}

export interface Challenge {
  challengeId: string;
  did: string;
  appId: string;
  appName: string;
  expiresAt: number;
  typedData: {
    domain: { name: string; version: string; chainId: number; verifyingContract: string };
    types: Record<string, { name: string; type: string }[]>;
    message: { did: string; app: string; nonce: string; issuedAt: number; expiresAt: number };
  };
}

export interface Session {
  token: string;
  did: string;
  appId: string;
  authKey: string;
  issuedAt: number;
  expiresAt: number;
}

export interface DidResponse {
  did: string;
  didHash: string;
  document: DIDDocument;
  recovery: RecoveryRequest | null;
  chainId: number;
  registry: string;
  recoveryDelay: number;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly code: string,
  ) {
    super(message);
  }
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
  });
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new ApiError(response.status, body?.error ?? response.statusText, body?.code ?? 'http_error');
  }
  return body as T;
}

export const api = {
  health: () => call<Health>('/api/health'),
  getDid: (did: string) => call<DidResponse>(`/api/did/${encodeURIComponent(did)}`),
  audit: (did: string) =>
    call<{ did: string; didHash: string; events: AuditEvent[] }>(`/api/audit/${encodeURIComponent(did)}`),

  prepareRegister: (body: {
    did: string;
    didHash: string;
    authKey: string;
    recoveryKey: string;
    shareRoot: string;
    threshold: number;
    shareCount: number;
  }) => call<{ digest: string }>('/api/identity/prepare', { method: 'POST', body: JSON.stringify(body) }),
  register: (body: {
    did: string;
    didHash: string;
    authKey: string;
    recoveryKey: string;
    shareRoot: string;
    threshold: number;
    shareCount: number;
    signature: string;
  }) => call<{ did: string; didHash: string; txHash: string }>('/api/identity/register', {
    method: 'POST',
    body: JSON.stringify(body),
  }),

  challenge: (did: string, appId: string) =>
    call<Challenge>('/api/auth/challenge', { method: 'POST', body: JSON.stringify({ did, appId }) }),
  verify: (challengeId: string, signature: string) =>
    call<{ session: Session; authKey: string; version: number }>('/api/auth/verify', {
      method: 'POST',
      body: JSON.stringify({ challengeId, signature }),
    }),
  session: (token: string) =>
    call<{ session: Session; document: DIDDocument }>('/api/auth/session', {
      headers: { Authorization: `Bearer ${token}` },
    }),
  logout: (token: string) =>
    call<{ ok: boolean }>('/api/auth/logout', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    }),

  initiateRecovery: (body: {
    did: string;
    newAuthKey: string;
    newRecoveryKey: string;
    newShareRoot: string;
    threshold: number;
    shareCount: number;
  }) =>
    call<{ txHash: string; requestId: string; executeAfter: number }>('/api/recovery/initiate', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  prepareRecovery: (did: string) =>
    call<{ request: RecoveryRequest; digest: string; readyAt: number }>('/api/recovery/prepare', {
      method: 'POST',
      body: JSON.stringify({ did }),
    }),
  executeRecovery: (did: string, requestId: string, signature: string) =>
    call<{ txHash: string; document: DIDDocument }>('/api/recovery/execute', {
      method: 'POST',
      body: JSON.stringify({ did, requestId, signature }),
    }),
  prepareCancel: (did: string) =>
    call<{ requestId: string; digest: string }>('/api/recovery/cancel/prepare', {
      method: 'POST',
      body: JSON.stringify({ did }),
    }),
  cancelRecovery: (did: string, requestId: string, signature: string) =>
    call<{ txHash: string }>('/api/recovery/cancel', {
      method: 'POST',
      body: JSON.stringify({ did, requestId, signature }),
    }),
};
