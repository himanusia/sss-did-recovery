import { ethers } from 'ethers';
import { randomBytes } from 'node:crypto';
import { HttpError, type DIDDocumentView, type RegistryAdapter } from './types.js';

export const LOGIN_TYPES = {
  Login: [
    { name: 'did', type: 'string' },
    { name: 'app', type: 'string' },
    { name: 'nonce', type: 'bytes32' },
    { name: 'issuedAt', type: 'uint64' },
    { name: 'expiresAt', type: 'uint64' },
  ],
} as const;

export interface AuthConfig {
  chainId: number;
  registryAddress: string;
  apps: Record<string, string>;
  challengeTtlSeconds: number;
  sessionTtlSeconds: number;
}

export interface ChallengeView {
  challengeId: string;
  did: string;
  appId: string;
  appName: string;
  expiresAt: number;
  typedData: {
    domain: ethers.TypedDataDomain;
    types: typeof LOGIN_TYPES;
    message: {
      did: string;
      app: string;
      nonce: string;
      issuedAt: number;
      expiresAt: number;
    };
  };
}

interface ChallengeRecord extends ChallengeView {
  didHash: string;
  consumed: boolean;
}

export interface SessionView {
  token: string;
  did: string;
  appId: string;
  authKey: string;
  issuedAt: number;
  expiresAt: number;
}

export interface VerifiedLogin {
  session: SessionView;
  authKey: string;
  version: number;
}

/** Challenge/response authentication with one-shot, domain-bound nonces. */
export class AuthService {
  private readonly challenges = new Map<string, ChallengeRecord>();
  private readonly sessions = new Map<string, SessionView>();

  constructor(
    private readonly adapter: RegistryAdapter,
    private readonly config: AuthConfig,
    private readonly now: () => number = () => Date.now(),
  ) {}

  domain(): ethers.TypedDataDomain {
    return {
      name: 'SSS DID Auth',
      version: '1',
      chainId: this.config.chainId,
      verifyingContract: this.config.registryAddress,
    };
  }

  async createChallenge(did: string, didHash: string, appId: string): Promise<ChallengeView> {
    const appName = this.config.apps[appId];
    if (!appName) throw new HttpError(400, `unknown app: ${appId}`, 'unknown_app');

    const document = await this.requireDocument(didHash);
    if (!document.active) throw new HttpError(409, 'identity is not active', 'inactive');

    this.evictExpired();

    const issuedAt = Math.floor(this.now() / 1000);
    const expiresAt = issuedAt + this.config.challengeTtlSeconds;
    const challengeId = randomBytes(16).toString('hex');
    const nonce = `0x${randomBytes(32).toString('hex')}`;

    const view: ChallengeView = {
      challengeId,
      did,
      appId,
      appName,
      expiresAt: expiresAt * 1000,
      typedData: {
        domain: this.domain(),
        types: LOGIN_TYPES,
        message: { did, app: appId, nonce, issuedAt, expiresAt },
      },
    };
    this.challenges.set(challengeId, { ...view, didHash, consumed: false });
    return view;
  }

  async verify(challengeId: string, signature: string): Promise<VerifiedLogin> {
    const challenge = this.challenges.get(challengeId);
    if (!challenge) throw new HttpError(404, 'challenge not found', 'unknown_challenge');
    if (challenge.consumed) throw new HttpError(409, 'challenge already used', 'challenge_used');
    if (challenge.expiresAt <= this.now()) {
      this.challenges.delete(challengeId);
      throw new HttpError(410, 'challenge expired', 'challenge_expired');
    }

    const document = await this.requireDocument(challenge.didHash);
    if (!document.active) throw new HttpError(409, 'identity is not active', 'inactive');

    let signer: string;
    try {
      signer = ethers.verifyTypedData(
        challenge.typedData.domain,
        challenge.typedData.types,
        challenge.typedData.message,
        signature,
      );
    } catch {
      throw new HttpError(400, 'malformed signature', 'bad_signature');
    }

    if (signer.toLowerCase() !== document.authKey.toLowerCase()) {
      throw new HttpError(401, 'signature does not match the authentication key', 'bad_signature');
    }

    challenge.consumed = true;
    this.challenges.delete(challengeId);

    const issuedAt = this.now();
    const session: SessionView = {
      token: randomBytes(32).toString('hex'),
      did: challenge.did,
      appId: challenge.appId,
      authKey: document.authKey,
      issuedAt,
      expiresAt: issuedAt + this.config.sessionTtlSeconds * 1000,
    };
    this.sessions.set(session.token, session);

    return { session, authKey: document.authKey, version: document.version };
  }

  session(token: string | undefined): SessionView {
    if (!token) throw new HttpError(401, 'missing bearer token', 'no_session');
    const session = this.sessions.get(token);
    if (!session) throw new HttpError(401, 'unknown session', 'no_session');
    if (session.expiresAt <= this.now()) {
      this.sessions.delete(token);
      throw new HttpError(401, 'session expired', 'session_expired');
    }
    return session;
  }

  async requireDocument(didHash: string): Promise<DIDDocumentView> {
    const document = await this.adapter.getDocument(didHash);
    if (!document) throw new HttpError(404, 'DID is not registered', 'not_registered');
    return document;
  }

  private evictExpired(): void {
    for (const [id, challenge] of this.challenges) {
      if (challenge.expiresAt <= this.now()) this.challenges.delete(id);
    }
  }
}
