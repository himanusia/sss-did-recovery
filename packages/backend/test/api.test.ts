import { describe, expect, it } from 'vitest';
import request from 'supertest';
import { ethers } from 'ethers';
import { didHash, newDid } from '@sss/crypto';
import { createApp, type ServerConfig } from '../src/server.js';
import { FakeRegistry } from './fake-registry.js';

const APPS = { klinik: 'Portal Klinik', market: 'Pasar Digital' };

async function harness(options: { challengeTtlSeconds?: number } = {}) {
  const adapter = new FakeRegistry();
  const wallet = ethers.Wallet.createRandom();
  const did = newDid();
  const hash = didHash(did);
  await adapter.register(
    {
      didHash: hash,
      authKey: wallet.address,
      recoveryKey: ethers.Wallet.createRandom().address,
      shareRoot: `0x${'ab'.repeat(32)}`,
      threshold: 3,
      shareCount: 5,
    },
    '0x',
  );

  const config: ServerConfig = {
    chainId: adapter.chainId,
    registryAddress: adapter.registryAddress,
    apps: APPS,
    challengeTtlSeconds: options.challengeTtlSeconds ?? 120,
    sessionTtlSeconds: 900,
  };
  return { adapter, wallet, did, hash, app: createApp(adapter, config), config };
}

async function login(
  app: ReturnType<typeof createApp>,
  wallet: ethers.Wallet,
  did: string,
  appId = 'klinik',
) {
  const challenge = await request(app).post('/api/auth/challenge').send({ did, appId }).expect(200);
  const { domain, types, message } = challenge.body.typedData;
  const signature = await wallet.signTypedData(domain, types, message);
  return request(app)
    .post('/api/auth/verify')
    .send({ challengeId: challenge.body.challengeId, signature });
}

describe('identity and DID resolution', () => {
  it('reports registry wiring on the health endpoint', async () => {
    const { app, adapter } = await harness();
    const response = await request(app).get('/api/health').expect(200);
    expect(response.body.ok).toBe(true);
    expect(response.body.registry).toBe(adapter.registryAddress);
    expect(response.body.apps).toEqual(APPS);
  });

  it('resolves a registered DID', async () => {
    const { app, wallet, did } = await harness();
    const response = await request(app).get(`/api/did/${did}`).expect(200);
    expect(response.body.document.authKey).toBe(wallet.address);
    expect(response.body.document.version).toBe(1);
    expect(response.body.recovery).toBeNull();
  });

  it('returns 404 for an unknown DID', async () => {
    const { app } = await harness();
    const response = await request(app).get(`/api/did/${newDid()}`).expect(404);
    expect(response.body.code).toBe('not_registered');
  });

  it('rejects a registration whose didHash does not match the did', async () => {
    const { app, adapter } = await harness();
    const wallet = ethers.Wallet.createRandom();
    const did = newDid();
    const response = await request(app)
      .post('/api/identity/prepare')
      .send({
        did,
        didHash: `0x${'00'.repeat(32)}`,
        authKey: wallet.address,
        recoveryKey: ethers.Wallet.createRandom().address,
        shareRoot: `0x${'cd'.repeat(32)}`,
        threshold: 3,
        shareCount: 5,
      })
      .expect(400);
    expect(response.body.code).toBe('did_mismatch');
    expect(adapter.documents.size).toBe(1);
  });
});

describe('challenge-response authentication', () => {
  it('issues a session for a valid signature', async () => {
    const { app, wallet, did } = await harness();
    const response = await login(app, wallet, did);

    expect(response.status).toBe(200);
    expect(response.body.session.did).toBe(did);
    expect(response.body.session.appId).toBe('klinik');
    expect(response.body.session.authKey).toBe(wallet.address);
    expect(response.body.session.token).toHaveLength(64);

    const session = await request(app)
      .get('/api/auth/session')
      .set('Authorization', `Bearer ${response.body.session.token}`)
      .expect(200);
    expect(session.body.document.authKey).toBe(wallet.address);
  });

  it('issues independent sessions for two apps with the same DID', async () => {
    const { app, wallet, did } = await harness();
    const first = await login(app, wallet, did, 'klinik');
    const second = await login(app, wallet, did, 'market');

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(first.body.session.token).not.toBe(second.body.session.token);
    expect(second.body.session.appId).toBe('market');
  });

  it('refuses to reuse a challenge', async () => {
    const { app, wallet, did } = await harness();
    const challenge = await request(app).post('/api/auth/challenge').send({ did, appId: 'klinik' });
    const { domain, types, message } = challenge.body.typedData;
    const signature = await wallet.signTypedData(domain, types, message);

    await request(app)
      .post('/api/auth/verify')
      .send({ challengeId: challenge.body.challengeId, signature })
      .expect(200);

    const replay = await request(app)
      .post('/api/auth/verify')
      .send({ challengeId: challenge.body.challengeId, signature })
      .expect(404);
    expect(replay.body.code).toBe('unknown_challenge');
  });

  it('rejects a signature from another key', async () => {
    const { app, did } = await harness();
    const stranger = ethers.Wallet.createRandom();
    const response = await login(app, stranger, did);
    expect(response.status).toBe(401);
    expect(response.body.code).toBe('bad_signature');
  });

  it('rejects a signature replayed into another app context', async () => {
    const { app, wallet, did } = await harness();
    const challenge = await request(app).post('/api/auth/challenge').send({ did, appId: 'klinik' });
    const { domain, types, message } = challenge.body.typedData;
    const signature = await wallet.signTypedData(domain, types, { ...message, app: 'market' });

    const response = await request(app)
      .post('/api/auth/verify')
      .send({ challengeId: challenge.body.challengeId, signature })
      .expect(401);
    expect(response.body.code).toBe('bad_signature');
  });

  it('rejects unknown apps and expired challenges', async () => {
    const { app, did } = await harness();
    const unknown = await request(app)
      .post('/api/auth/challenge')
      .send({ did, appId: 'bank-lain' })
      .expect(400);
    expect(unknown.body.code).toBe('unknown_app');

    const expiring = await harness({ challengeTtlSeconds: 0 });
    const wallet = expiring.wallet;
    const challenge = await request(expiring.app)
      .post('/api/auth/challenge')
      .send({ did: expiring.did, appId: 'klinik' })
      .expect(200);
    const { domain, types, message } = challenge.body.typedData;
    const signature = await wallet.signTypedData(domain, types, message);
    const expired = await request(expiring.app)
      .post('/api/auth/verify')
      .send({ challengeId: challenge.body.challengeId, signature })
      .expect(410);
    expect(expired.body.code).toBe('challenge_expired');
  });
});

describe('recovery endpoints', () => {
  it('opens a request, then rotates the key with a recovery signature', async () => {
    const { app, adapter, did, wallet } = await harness();
    const newAuth = ethers.Wallet.createRandom();
    const newRecovery = ethers.Wallet.createRandom();

    const initiated = await request(app)
      .post('/api/recovery/initiate')
      .send({
        did,
        newAuthKey: newAuth.address,
        newRecoveryKey: newRecovery.address,
        newShareRoot: `0x${'ef'.repeat(32)}`,
        threshold: 2,
        shareCount: 3,
      })
      .expect(201);
    expect(initiated.body.requestId).toBe('1');

    const prepared = await request(app).post('/api/recovery/prepare').send({ did }).expect(200);
    expect(prepared.body.request.executeAfter).toBeGreaterThan(0);
    expect(prepared.body.digest).toMatch(/^0x[0-9a-f]{64}$/);

    const signature = await newRecovery.signMessage(ethers.getBytes(prepared.body.digest));
    const executed = await request(app)
      .post('/api/recovery/execute')
      .send({ did, requestId: initiated.body.requestId, signature })
      .expect(200);

    expect(executed.body.document.version).toBe(2);
    expect(executed.body.document.authKey).toBe(newAuth.address);
    expect(adapter.recoveries.get(didHash(did))?.executed).toBe(true);

    const newLogin = await login(app, newAuth, did);
    expect(newLogin.status).toBe(200);
    const oldLogin = await login(app, wallet, did);
    expect(oldLogin.status).toBe(401);
  });

  it('refuses a second request while one is pending', async () => {
    const { app, did } = await harness();
    const newAuth = ethers.Wallet.createRandom();
    const body = {
      did,
      newAuthKey: newAuth.address,
      newRecoveryKey: ethers.Wallet.createRandom().address,
      newShareRoot: `0x${'ef'.repeat(32)}`,
      threshold: 2,
      shareCount: 3,
    };
    await request(app).post('/api/recovery/initiate').send(body).expect(201);
    const second = await request(app).post('/api/recovery/initiate').send(body).expect(409);
    expect(second.body.code).toBe('recovery_pending');
  });

  it('cancels a pending request with an auth-key signature', async () => {
    const { app, adapter, did, wallet } = await harness();
    const initiated = await request(app)
      .post('/api/recovery/initiate')
      .send({
        did,
        newAuthKey: ethers.Wallet.createRandom().address,
        newRecoveryKey: ethers.Wallet.createRandom().address,
        newShareRoot: `0x${'ef'.repeat(32)}`,
        threshold: 2,
        shareCount: 3,
      })
      .expect(201);

    const prepared = await request(app).post('/api/recovery/cancel/prepare').send({ did }).expect(200);
    const signature = await wallet.signMessage(ethers.getBytes(prepared.body.digest));
    await request(app)
      .post('/api/recovery/cancel')
      .send({ did, requestId: initiated.body.requestId, signature })
      .expect(200);

    expect(adapter.recoveries.get(didHash(did))?.cancelled).toBe(true);
    const execute = await request(app)
      .post('/api/recovery/execute')
      .send({ did, requestId: initiated.body.requestId, signature })
      .expect(404);
    expect(execute.body.code).toBe('no_pending');
  });

  it('validates recovery parameters', async () => {
    const { app, did } = await harness();
    const response = await request(app)
      .post('/api/recovery/initiate')
      .send({
        did,
        newAuthKey: ethers.Wallet.createRandom().address,
        newRecoveryKey: ethers.Wallet.createRandom().address,
        newShareRoot: `0x${'ef'.repeat(32)}`,
        threshold: 4,
        shareCount: 3,
      })
      .expect(400);
    expect(response.body.code).toBe('validation');
  });
});
