/**
 * End-to-end demo against a real local chain.
 *
 * Starts the HTTP API in-process, then walks the whole story: register, log in
 * to two apps, lose the device, gather shares, reconstruct locally, rotate the
 * key, and prove the old key is dead.
 *
 * Usage: CONTRACT_ADDRESS=0x... npm run demo -w @sss/backend
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ethers } from 'ethers';
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
} from '@sss/crypto';
import { DID_REGISTRY_ABI, EthersRegistryAdapter } from '../src/chain.js';
import { createApp } from '../src/server.js';

const RPC_URL = process.env.RPC_URL ?? 'http://127.0.0.1:8545';
const RELAYER_KEY =
  process.env.RELAYER_PRIVATE_KEY ??
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

function contractAddress(): string {
  if (process.env.CONTRACT_ADDRESS) return process.env.CONTRACT_ADDRESS;
  const file = join(process.cwd(), '..', 'contracts', 'deployments', 'localhost.json');
  const deployment = JSON.parse(readFileSync(file, 'utf8')) as { address: string };
  return deployment.address;
}

function step(number: number, title: string): void {
  console.log(`\n\x1b[36m${String(number).padStart(2, '0')} · ${title}\x1b[0m`);
}

function line(label: string, value: string): void {
  console.log(`   ${label.padEnd(26)} ${value}`);
}

function pass(label: string): void {
  console.log(`   \x1b[32m✓\x1b[0m ${label}`);
}

function fail(label: string): void {
  console.log(`   \x1b[31m✗\x1b[0m ${label}`);
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    fail(message);
    throw new Error(message);
  }
}

interface ApiResult<T> {
  status: number;
  body: T;
}

async function main() {
  const address = contractAddress();
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const network = await provider.getNetwork();
  const adapter = await EthersRegistryAdapter.create({
    rpcUrl: RPC_URL,
    contractAddress: address,
    relayerPrivateKey: RELAYER_KEY,
  });

  const config = {
    chainId: Number(network.chainId),
    registryAddress: adapter.registryAddress,
    apps: { klinik: 'Portal Klinik', market: 'Pasar Digital' },
    challengeTtlSeconds: 120,
    sessionTtlSeconds: 900,
  };

  const server = createApp(adapter, config).listen(0, '127.0.0.1');
  await new Promise<void>((resolve) => server.once('listening', () => resolve()));
  const port = (server.address() as { port: number }).port;
  const base = `http://127.0.0.1:${port}`;

  async function call<T>(method: string, path: string, body?: unknown, token?: string): Promise<ApiResult<T>> {
    const response = await fetch(`${base}${path}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    return { status: response.status, body: (text ? JSON.parse(text) : null) as T };
  }

  console.log('\x1b[1mSSS / DID recovery — end-to-end demo\x1b[0m');
  line('rpc', RPC_URL);
  line('chain id', String(network.chainId));
  line('registry', address);
  line('recovery delay', `${adapter.recoveryDelay}s`);
  line('relayer', adapter.relayerAddress);

  // 1. Identity material, client-side only.
  step(1, 'Membuat identitas (kunci + share, semua di klien)');
  const auth = createAuthKeyPair();
  const did = newDid();
  const hash = didHash(did);
  const secret = randomScalar();
  const shares = splitSecret(secret, 3, 5);
  const root = shareRoot(shares);
  const proofs = shares.map((share) => buildShareProof(shares, share.index));
  const guardians = shares.map((share, index) => ({
    name: ['Laptop', 'Ponsel', 'Cloud', 'Kertas', 'Teman'][index],
    token: encodeShare(share),
    envelope: toEnvelope(share, proofs[index], root, `guardian-${index + 1}`),
  }));
  const recoveryKey = recoveryAddress(secret);

  line('did', did);
  line('auth key', auth.address);
  line('recovery key', recoveryKey);
  line('share root', root);
  line('secret di memori', 'ya (tidak pernah dikirim)');

  // 2. Register through the API: digest -> signature -> relayer.
  step(2, 'Registrasi DID lewat relayer');
  const prepare = await call<{ digest: string }>('POST', '/api/identity/prepare', {
    did,
    didHash: hash,
    authKey: auth.address,
    recoveryKey,
    shareRoot: root,
    threshold: 3,
    shareCount: 5,
  });
  assert(prepare.status === 200, `prepare gagal: ${JSON.stringify(prepare.body)}`);

  const wallet = new ethers.Wallet(auth.privateKey);
  const registerSignature = await wallet.signMessage(ethers.getBytes(prepare.body.digest));
  const registered = await call<{ txHash: string }>('POST', '/api/identity/register', {
    did,
    didHash: hash,
    authKey: auth.address,
    recoveryKey,
    shareRoot: root,
    threshold: 3,
    shareCount: 5,
    signature: registerSignature,
  });
  assert(registered.status === 201, `registrasi gagal: ${JSON.stringify(registered.body)}`);
  pass(`DID terdaftar · tx ${registered.body.txHash.slice(0, 12)}…`);

  // 3. Login to two apps with the same DID.
  step(3, 'Login ke dua aplikasi dengan DID yang sama');
  async function login(appId: string, signer: ethers.BaseWallet) {
    const challenge = await call<{
      challengeId: string;
      typedData: { domain: ethers.TypedDataDomain; types: Record<string, { name: string; type: string }[]>; message: Record<string, unknown> };
    }>('POST', '/api/auth/challenge', { did, appId });
    assert(challenge.status === 200, `challenge gagal: ${JSON.stringify(challenge.body)}`);
    const signature = await signer.signTypedData(
      challenge.body.typedData.domain,
      challenge.body.typedData.types,
      challenge.body.typedData.message,
    );
    return call<{ session: { token: string; appId: string; authKey: string } }>('POST', '/api/auth/verify', {
      challengeId: challenge.body.challengeId,
      signature,
    });
  }

  const started = performance.now();
  const klinik = await login('klinik', wallet);
  const klinikLatency = Math.round(performance.now() - started);
  assert(klinik.status === 200, `login klinik gagal: ${JSON.stringify(klinik.body)}`);
  line('app klinik', `sesi ${klinik.body.session.token.slice(0, 12)}… (${klinikLatency} ms)`);

  const market = await login('market', wallet);
  assert(market.status === 200, `login market gagal: ${JSON.stringify(market.body)}`);
  line('app market', `sesi ${market.body.session.token.slice(0, 12)}…`);
  pass('satu DID, dua sesi independen');

  // 4. Domain binding: signature for klinik cannot be used for market.
  step(4, 'Uji pengikatan domain');
  const challenge = await call<{
    challengeId: string;
    typedData: { domain: ethers.TypedDataDomain; types: Record<string, { name: string; type: string }[]>; message: Record<string, unknown> };
  }>('POST', '/api/auth/challenge', { did, appId: 'klinik' });
  const tampered = await wallet.signTypedData(
    challenge.body.typedData.domain,
    challenge.body.typedData.types,
    { ...challenge.body.typedData.message, app: 'market' },
  );
  const replay = await call('POST', '/api/auth/verify', {
    challengeId: challenge.body.challengeId,
    signature: tampered,
  });
  assert(replay.status === 401, 'signature lintas aplikasi seharusnya ditolak');
  pass('signature aplikasi lain ditolak (401)');

  // 5. Device loss: the auth key is gone, shares remain with guardians.
  step(5, 'Perangkat hilang');
  const lostKey = wallet;
  line('auth key di perangkat', 'dihapus');
  line('share guardian', `${guardians.length} tersisa`);
  const lostLogin = await login('klinik', ethers.Wallet.createRandom());
  assert(lostLogin.status === 401, 'login tanpa kunci valid seharusnya ditolak');
  pass('login tanpa kunci valid ditolak (401)');

  // 6. New key material + recovery request.
  step(6, 'Membuka permintaan pemulihan');
  const nextAuth = createAuthKeyPair();
  const nextSecret = randomScalar();
  const nextShares = splitSecret(nextSecret, 2, 3);
  const nextRoot = shareRoot(nextShares);
  const nextRecoveryKey = recoveryAddress(nextSecret);

  const initiated = await call<{ requestId: string; executeAfter: number }>('POST', '/api/recovery/initiate', {
    did,
    newAuthKey: nextAuth.address,
    newRecoveryKey: nextRecoveryKey,
    newShareRoot: nextRoot,
    threshold: 2,
    shareCount: 3,
  });
  assert(initiated.status === 201, `initiate gagal: ${JSON.stringify(initiated.body)}`);
  line('request id', initiated.body.requestId);
  line('eksekusi setelah', new Date(initiated.body.executeAfter * 1000).toISOString());
  pass('permintaan terbuka, belum ada perubahan dokumen');

  const early = await call<{ request: { requestId: string }; digest: string }>('POST', '/api/recovery/prepare', { did });
  assert(early.status === 200, 'prepare gagal');

  // Fast-forward chain time (hardhat only); otherwise wait out the timelock.
  try {
    await provider.send('evm_increaseTime', [adapter.recoveryDelay + 5]);
    await provider.send('evm_mine', []);
    pass(`waktu chain dipercepat ${adapter.recoveryDelay + 5}s (hardhat)`);
  } catch {
    console.log(`   menunggu timelock ${adapter.recoveryDelay}s…`);
    await new Promise((resolve) => setTimeout(resolve, (adapter.recoveryDelay + 2) * 1000));
  }

  // 7. Gather threshold shares, verify against on-chain root, reconstruct.
  step(7, 'Mengumpulkan share dan rekonstruksi (di klien)');
  const document = (await call<{ document: { shareRoot: string; recoveryKey: string; threshold: number } }>(
    'GET',
    `/api/did/${did}`,
  )).body.document;

  const gathered = guardians.slice(0, 3);
  for (const guardian of gathered) {
    const valid = verifyShareProof(guardian.envelope.proof, document.shareRoot);
    assert(valid, `share ${guardian.name} tidak cocok dengan root on-chain`);
  }
  pass(`${gathered.length} share lolos verifikasi Merkle`);

  const belowThreshold = combineShares(gathered.slice(0, 2).map((g) => decodeShare(g.token)));
  assert(recoveryAddress(belowThreshold) !== document.recoveryKey, 'k-1 share seharusnya tidak cukup');
  pass('2 share menghasilkan secret yang salah (threshold bekerja)');

  const reconstructed = combineShares(gathered.map((g) => decodeShare(g.token)));
  assert(
    recoveryAddress(reconstructed).toLowerCase() === document.recoveryKey.toLowerCase(),
    'rekonstruksi tidak cocok dengan recovery key on-chain',
  );
  line('secret direkonstruksi', 'cocok dengan recovery key on-chain');

  // 8. Sign the rotation with the reconstructed key and execute.
  step(8, 'Menandatangani rotasi dan mengeksekusi');
  const recoverPrepared = await call<{ digest: string; request: { requestId: string } }>(
    'POST',
    '/api/recovery/prepare',
    { did },
  );
  const recoveryWallet = new ethers.Wallet(`0x${reconstructed.toString(16).padStart(64, '0')}`);
  const rotateSignature = await recoveryWallet.signMessage(ethers.getBytes(recoverPrepared.body.digest));
  const executed = await call<{ document: { version: number; authKey: string; recoveryKey: string } }>(
    'POST',
    '/api/recovery/execute',
    { did, requestId: recoverPrepared.body.request.requestId, signature: rotateSignature },
  );
  assert(executed.status === 200, `eksekusi gagal: ${JSON.stringify(executed.body)}`);
  line('versi dokumen', String(executed.body.document.version));
  line('auth key baru', executed.body.document.authKey);
  pass('recovery dieksekusi, kunci dirotasi');

  // 9. Old key dead, new key works.
  step(9, 'Verifikasi pasca-pemulihan');
  const oldLogin = await login('klinik', lostKey);
  assert(oldLogin.status === 401, 'kunci lama seharusnya sudah ditolak');
  pass('kunci lama ditolak (401)');

  const newWallet = new ethers.Wallet(nextAuth.privateKey);
  const newLogin = await login('market', newWallet);
  assert(newLogin.status === 200, `kunci baru gagal login: ${JSON.stringify(newLogin.body)}`);
  pass('kunci baru diterima di aplikasi yang sama');

  // 10. Audit trail straight from chain events.
  step(10, 'Audit trail on-chain');
  const audit = await call<{ events: { type: string; txHash: string }[] }>('GET', `/api/audit/${did}`);
  assert(audit.status === 200, 'audit gagal');
  for (const event of audit.body.events) {
    line(event.type, `${event.txHash.slice(0, 14)}…`);
  }
  assert(
    audit.body.events.some((event) => event.type === 'recovery-executed'),
    'audit harus memuat event recovery',
  );
  assert(audit.body.events.some((event) => event.type === 'key-rotated'), 'audit harus memuat rotasi');
  pass(`${audit.body.events.length} event tercatat, termasuk eksekusi dan rotasi`);

  const contract = new ethers.Contract(address, DID_REGISTRY_ABI, provider);
  const finalDoc = await contract.getDocument(hash);
  line('dokumen final', `v${finalDoc.version} · ${finalDoc.authKey}`);

  console.log('\n\x1b[32m\x1b[1mSEMUA LANGKAH LULUS\x1b[0m');
  server.close();
}

main().catch((error) => {
  console.error('\n\x1b[31mDEMO GAGAL\x1b[0m', error instanceof Error ? error.stack : error);
  process.exit(1);
});
