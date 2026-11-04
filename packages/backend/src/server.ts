import express, { type NextFunction, type Request, type Response } from 'express';
import cors from 'cors';
import { z } from 'zod';
import { ethers } from 'ethers';
import { AuthService, type AuthConfig } from './auth.js';
import { HttpError, type RegistryAdapter } from './types.js';

export interface ServerConfig extends AuthConfig {
  allowedOrigin?: string;
}

const address = z
  .string()
  .refine((value) => ethers.isAddress(value), 'must be an Ethereum address')
  .transform((value) => ethers.getAddress(value));
const bytes32 = z.string().regex(/^0x[0-9a-fA-F]{64}$/, 'must be a 32-byte hex value');
const did = z.string().regex(/^did:sss:0x[0-9a-fA-F]{40}$/, 'must be a did:sss identifier');
const signature = z.string().regex(/^0x[0-9a-fA-F]{130}$/, 'must be a 65-byte signature');

const shareParams = {
  threshold: z.number().int().min(2).max(255),
  shareCount: z.number().int().min(2).max(255),
};

const registerSchema = z
  .object({
    did,
    didHash: bytes32,
    authKey: address,
    recoveryKey: address,
    shareRoot: bytes32,
    ...shareParams,
    signature,
  })
  .refine((value) => value.shareCount >= value.threshold, {
    message: 'shareCount must be >= threshold',
    path: ['shareCount'],
  });

const challengeSchema = z.object({ did, appId: z.string().min(1).max(64) });
const verifySchema = z.object({ challengeId: z.string().length(32), signature });
const didParamsSchema = z.object({ did });
const recoverySchema = z
  .object({
    did,
    newAuthKey: address,
    newRecoveryKey: address,
    newShareRoot: bytes32,
    ...shareParams,
  })
  .refine((value) => value.shareCount >= value.threshold, {
    message: 'shareCount must be >= threshold',
    path: ['shareCount'],
  });
const executeSchema = z.object({
  did,
  requestId: z.string().regex(/^\d+$/),
  signature,
});
const cancelSchema = executeSchema;

type Handler = (req: Request, res: Response, next: NextFunction) => Promise<unknown>;

function route(handler: Handler) {
  return (req: Request, res: Response, next: NextFunction) => {
    handler(req, res, next).catch(next);
  };
}

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) {
    const detail = result.error.issues
      .map((issue) => `${issue.path.join('.') || 'body'}: ${issue.message}`)
      .join('; ');
    throw new HttpError(400, detail, 'validation');
  }
  return result.data;
}

function hashDid(value: string): string {
  return ethers.keccak256(ethers.toUtf8Bytes(value.toLowerCase()));
}

export function createApp(adapter: RegistryAdapter, config: ServerConfig) {
  const app = express();
  app.disable('x-powered-by');
  app.use(cors({ origin: config.allowedOrigin ?? true }));
  app.use(express.json({ limit: '256kb' }));

  const auth = new AuthService(adapter, config);
  const inFlight = new Set<string>();

  async function withLock<T>(didHash: string, fn: () => Promise<T>): Promise<T> {
    if (inFlight.has(didHash)) {
      throw new HttpError(409, 'another transaction for this identity is in flight', 'busy');
    }
    inFlight.add(didHash);
    try {
      return await fn();
    } finally {
      inFlight.delete(didHash);
    }
  }

  async function resolve(didValue: string) {
    const didHash = hashDid(didValue);
    const [document, recovery] = await Promise.all([
      adapter.getDocument(didHash),
      adapter.getRecovery(didHash),
    ]);
    if (!document) throw new HttpError(404, 'DID is not registered', 'not_registered');
    return { didHash, document, recovery };
  }

  app.get('/api/health', (_req, res) => {
    res.json({
      ok: true,
      chainId: adapter.chainId,
      registry: adapter.registryAddress,
      relayer: adapter.relayerAddress,
      recoveryDelay: adapter.recoveryDelay,
      apps: config.apps,
      challengeTtlSeconds: config.challengeTtlSeconds,
      sessionTtlSeconds: config.sessionTtlSeconds,
    });
  });

  app.post(
    '/api/identity/prepare',
    route(async (req, res) => {
      const body = parse(
        z.object({
          did,
          didHash: bytes32,
          authKey: address,
          recoveryKey: address,
          shareRoot: bytes32,
          ...shareParams,
        }),
        req.body,
      );
      if (body.didHash.toLowerCase() !== hashDid(body.did)) {
        throw new HttpError(400, 'didHash does not match did', 'did_mismatch');
      }
      if (await adapter.getDocument(body.didHash)) {
        throw new HttpError(409, 'DID is already registered', 'already_registered');
      }
      const digest = await adapter.registerDigest(body);
      res.json({ digest });
    }),
  );

  app.post(
    '/api/identity/register',
    route(async (req, res) => {
      const body = parse(registerSchema, req.body);
      if (body.didHash.toLowerCase() !== hashDid(body.did)) {
        throw new HttpError(400, 'didHash does not match did', 'did_mismatch');
      }
      const existing = await adapter.getDocument(body.didHash);
      if (existing) throw new HttpError(409, 'DID is already registered', 'already_registered');

      const result = await withLock(body.didHash, () => adapter.register(body, body.signature));
      res.status(201).json({ did: body.did, didHash: body.didHash, ...result });
    }),
  );

  app.get(
    '/api/did/:did',
    route(async (req, res) => {
      const { did: didValue } = parse(didParamsSchema, req.params);
      const { didHash, document, recovery } = await resolve(didValue);
      res.json({
        did: didValue,
        didHash,
        document,
        recovery,
        chainId: adapter.chainId,
        registry: adapter.registryAddress,
        recoveryDelay: adapter.recoveryDelay,
      });
    }),
  );

  app.get(
    '/api/audit/:did',
    route(async (req, res) => {
      const { did: didValue } = parse(didParamsSchema, req.params);
      const didHash = hashDid(didValue);
      const document = await adapter.getDocument(didHash);
      if (!document) throw new HttpError(404, 'DID is not registered', 'not_registered');
      const events = await adapter.getAudit(didHash);
      res.json({ did: didValue, didHash, events });
    }),
  );

  app.post(
    '/api/auth/challenge',
    route(async (req, res) => {
      const body = parse(challengeSchema, req.body);
      const didHash = hashDid(body.did);
      await auth.requireDocument(didHash);
      const challenge = await auth.createChallenge(body.did, didHash, body.appId);
      res.json(challenge);
    }),
  );

  app.post(
    '/api/auth/verify',
    route(async (req, res) => {
      const body = parse(verifySchema, req.body);
      const verified = await auth.verify(body.challengeId, body.signature);
      res.json(verified);
    }),
  );

  app.get(
    '/api/auth/session',
    route(async (req, res) => {
      const header = req.headers.authorization ?? '';
      const token = header.startsWith('Bearer ') ? header.slice(7) : undefined;
      const session = auth.session(token);
      const document = await auth.requireDocument(hashDid(session.did));
      res.json({ session, document });
    }),
  );

  app.post(
    '/api/auth/logout',
    route(async (req, res) => {
      const header = req.headers.authorization ?? '';
      const token = header.startsWith('Bearer ') ? header.slice(7) : undefined;
      auth.logout(token);
      res.json({ ok: true });
    }),
  );

  app.post(
    '/api/recovery/initiate',
    route(async (req, res) => {
      const body = parse(recoverySchema, req.body);
      const didHash = hashDid(body.did);
      const { document, recovery } = await resolve(body.did);
      if (!document.active) throw new HttpError(409, 'identity is not active', 'inactive');
      if (body.newAuthKey.toLowerCase() === document.authKey.toLowerCase()) {
        throw new HttpError(400, 'new auth key must differ from the current one', 'same_key');
      }
      if (recovery && !recovery.executed && !recovery.cancelled) {
        throw new HttpError(409, 'a recovery request is already pending', 'recovery_pending');
      }
      const result = await withLock(didHash, () =>
        adapter.initiateRecovery({
          didHash,
          newAuthKey: body.newAuthKey,
          newRecoveryKey: body.newRecoveryKey,
          newShareRoot: body.newShareRoot,
          threshold: body.threshold,
          shareCount: body.shareCount,
        }),
      );
      res.status(201).json(result);
    }),
  );

  app.post(
    '/api/recovery/prepare',
    route(async (req, res) => {
      const { did: didValue } = parse(z.object({ did }), req.body);
      const { didHash, document, recovery } = await resolve(didValue);
      if (!recovery || recovery.executed || recovery.cancelled) {
        throw new HttpError(404, 'no pending recovery request', 'no_pending');
      }
      const digest = await adapter.recoveryDigest(didHash, recovery);
      res.json({
        did: didValue,
        document,
        request: recovery,
        digest,
        readyAt: recovery.executeAfter,
      });
    }),
  );

  app.post(
    '/api/recovery/execute',
    route(async (req, res) => {
      const body = parse(executeSchema, req.body);
      const didHash = hashDid(body.did);
      const { recovery } = await resolve(body.did);
      if (!recovery || recovery.executed || recovery.cancelled) {
        throw new HttpError(404, 'no pending recovery request', 'no_pending');
      }
      if (recovery.requestId !== body.requestId) {
        throw new HttpError(409, 'requestId does not match the pending request', 'stale_request');
      }
      const result = await withLock(didHash, () =>
        adapter.executeRecovery(didHash, body.requestId, body.signature),
      );
      const document = await adapter.getDocument(didHash);
      res.json({ ...result, document });
    }),
  );

  app.post(
    '/api/recovery/cancel/prepare',
    route(async (req, res) => {
      const { did: didValue } = parse(z.object({ did }), req.body);
      const { didHash, recovery } = await resolve(didValue);
      if (!recovery || recovery.executed || recovery.cancelled) {
        throw new HttpError(404, 'no pending recovery request', 'no_pending');
      }
      const digest = await adapter.cancelDigest(didHash, recovery.requestId);
      res.json({ requestId: recovery.requestId, digest });
    }),
  );

  app.post(
    '/api/recovery/cancel',
    route(async (req, res) => {
      const body = parse(cancelSchema, req.body);
      const didHash = hashDid(body.did);
      const { recovery } = await resolve(body.did);
      if (!recovery || recovery.executed || recovery.cancelled) {
        throw new HttpError(404, 'no pending recovery request', 'no_pending');
      }
      const result = await withLock(didHash, () =>
        adapter.cancelRecovery(didHash, body.requestId, body.signature),
      );
      res.json(result);
    }),
  );

  app.use((req, _res, next) => {
    next(new HttpError(404, `no route for ${req.method} ${req.path}`, 'not_found'));
  });

  app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (error instanceof HttpError) {
      res.status(error.status).json({ error: error.message, code: error.code });
      return;
    }
    console.error('[backend] unhandled error', error);
    res.status(500).json({ error: 'internal error', code: 'internal' });
  });

  return app;
}
