import { expect } from 'chai';
import { ethers } from 'hardhat';
import { time } from '@nomicfoundation/hardhat-network-helpers';
import type { DIDRegistry } from '../typechain-types';

const DELAY = 3600;
const SHARE_ROOT = ethers.keccak256(ethers.toUtf8Bytes('share-set-1'));
const NEW_SHARE_ROOT = ethers.keccak256(ethers.toUtf8Bytes('share-set-2'));

async function deploy() {
  const [relayer, controller, attacker] = await ethers.getSigners();
  const factory = await ethers.getContractFactory('DIDRegistry');
  const registry = (await factory.deploy(DELAY)) as unknown as DIDRegistry;
  await registry.waitForDeployment();
  return { registry, relayer, controller, attacker };
}

function didHashFor(authAddress: string): string {
  return ethers.keccak256(ethers.toUtf8Bytes(`did:sss:${authAddress}`));
}

async function signedRegistration(
  registry: DIDRegistry,
  auth: ethers.HDNodeWallet | ethers.Wallet,
  recovery: ethers.HDNodeWallet | ethers.Wallet,
) {
  const didHash = didHashFor(auth.address);
  const digest = await registry.registerDigest(didHash, auth.address, recovery.address, SHARE_ROOT, 3, 5);
  const signature = await auth.signMessage(ethers.getBytes(digest));
  return { didHash, signature };
}

async function registeredIdentity() {
  const ctx = await deploy();
  const auth = ethers.Wallet.createRandom();
  const recovery = ethers.Wallet.createRandom();
  const { didHash, signature } = await signedRegistration(ctx.registry, auth, recovery);
  await ctx.registry.register(didHash, auth.address, recovery.address, SHARE_ROOT, 3, 5, signature);
  return { ...ctx, auth, recovery, didHash };
}

async function openRecovery(
  registry: DIDRegistry,
  didHash: string,
  newAuth: string,
  newRecovery: string,
) {
  await registry.initiateRecovery(didHash, newAuth, newRecovery, NEW_SHARE_ROOT, 2, 3);
  const requestId = await registry.recoveryRequestCount(didHash);
  return requestId;
}

describe('DIDRegistry registration', () => {
  it('registers a DID signed by its authentication key', async () => {
    const { registry, auth, recovery, didHash } = await registeredIdentity();
    const doc = await registry.getDocument(didHash);

    expect(doc.authKey).to.equal(auth.address);
    expect(doc.recoveryKey).to.equal(recovery.address);
    expect(doc.shareRoot).to.equal(SHARE_ROOT);
    expect(doc.threshold).to.equal(3);
    expect(doc.shareCount).to.equal(5);
    expect(doc.version).to.equal(1);
    expect(doc.active).to.equal(true);
  });

  it('emits DIDRegistered with the committed share configuration', async () => {
    const { registry } = await deploy();
    const auth = ethers.Wallet.createRandom();
    const recovery = ethers.Wallet.createRandom();
    const { didHash, signature } = await signedRegistration(registry, auth, recovery);

    await expect(registry.register(didHash, auth.address, recovery.address, SHARE_ROOT, 3, 5, signature))
      .to.emit(registry, 'DIDRegistered')
      .withArgs(didHash, auth.address, recovery.address, SHARE_ROOT, 3, 5);
  });

  it('rejects a registration signed by somebody else', async () => {
    const { registry, attacker } = await deploy();
    const auth = ethers.Wallet.createRandom();
    const recovery = ethers.Wallet.createRandom();
    const didHash = didHashFor(auth.address);
    const digest = await registry.registerDigest(didHash, auth.address, recovery.address, SHARE_ROOT, 3, 5);
    const forged = await attacker.signMessage(ethers.getBytes(digest));

    await expect(
      registry.register(didHash, auth.address, recovery.address, SHARE_ROOT, 3, 5, forged),
    ).to.be.revertedWithCustomError(registry, 'InvalidSignature');
  });

  it('rejects a duplicate DID', async () => {
    const { registry, auth, recovery, didHash } = await registeredIdentity();
    const digest = await registry.registerDigest(didHash, auth.address, recovery.address, SHARE_ROOT, 3, 5);
    const signature = await auth.signMessage(ethers.getBytes(digest));

    await expect(
      registry.register(didHash, auth.address, recovery.address, SHARE_ROOT, 3, 5, signature),
    ).to.be.revertedWithCustomError(registry, 'AlreadyRegistered');
  });

  it('rejects nonsensical key and threshold configurations', async () => {
    const { registry } = await deploy();
    const auth = ethers.Wallet.createRandom();
    const recovery = ethers.Wallet.createRandom();
    const didHash = didHashFor(auth.address);
    const digest = await registry.registerDigest(didHash, auth.address, recovery.address, SHARE_ROOT, 3, 5);
    const signature = await auth.signMessage(ethers.getBytes(digest));

    await expect(
      registry.register(didHash, auth.address, recovery.address, SHARE_ROOT, 1, 5, signature),
    ).to.be.revertedWithCustomError(registry, 'InvalidParameters');

    await expect(
      registry.register(didHash, auth.address, recovery.address, SHARE_ROOT, 4, 3, signature),
    ).to.be.revertedWithCustomError(registry, 'InvalidParameters');

    await expect(
      registry.register(didHash, auth.address, auth.address, SHARE_ROOT, 2, 3, signature),
    ).to.be.revertedWithCustomError(registry, 'InvalidParameters');

    await expect(
      registry.register(didHash, auth.address, recovery.address, ethers.ZeroHash, 2, 3, signature),
    ).to.be.revertedWithCustomError(registry, 'InvalidParameters');
  });
});

describe('DIDRegistry recovery', () => {
  it('rotates the auth key once the recovery key signs after the timelock', async () => {
    const { registry, auth, recovery, didHash } = await registeredIdentity();
    const newAuth = ethers.Wallet.createRandom();
    const newRecovery = ethers.Wallet.createRandom();

    await expect(
      registry.initiateRecovery(didHash, newAuth.address, newRecovery.address, NEW_SHARE_ROOT, 2, 3),
    ).to.emit(registry, 'RecoveryInitiated');

    const requestId = await registry.recoveryRequestCount(didHash);
    await time.increase(DELAY + 1);

    const digest = await registry.recoveryDigest(
      didHash,
      requestId,
      newAuth.address,
      newRecovery.address,
      NEW_SHARE_ROOT,
      2,
      3,
    );
    const signature = await recovery.signMessage(ethers.getBytes(digest));

    await expect(registry.executeRecovery(didHash, requestId, signature))
      .to.emit(registry, 'RecoveryExecuted')
      .withArgs(didHash, requestId, newAuth.address, 2);

    const doc = await registry.getDocument(didHash);
    expect(doc.authKey).to.equal(newAuth.address);
    expect(doc.recoveryKey).to.equal(newRecovery.address);
    expect(doc.shareRoot).to.equal(NEW_SHARE_ROOT);
    expect(doc.threshold).to.equal(2);
    expect(doc.shareCount).to.equal(3);
    expect(doc.version).to.equal(2);

    expect(await registry.isAuthKey(didHash, auth.address)).to.equal(false);
    expect(await registry.isAuthKey(didHash, newAuth.address)).to.equal(true);
  });

  it('refuses to execute before the timelock expires', async () => {
    const { registry, didHash } = await registeredIdentity();
    const newAuth = ethers.Wallet.createRandom();
    const newRecovery = ethers.Wallet.createRandom();
    const requestId = await openRecovery(registry, didHash, newAuth.address, newRecovery.address);

    const digest = await registry.recoveryDigest(
      didHash,
      requestId,
      newAuth.address,
      newRecovery.address,
      NEW_SHARE_ROOT,
      2,
      3,
    );
    const signature = await ethers.Wallet.createRandom().signMessage(ethers.getBytes(digest));

    await expect(registry.executeRecovery(didHash, requestId, signature)).to.be.revertedWithCustomError(
      registry,
      'TimelockActive',
    );
  });

  it('refuses a signature that does not come from the recovery key', async () => {
    const { registry, didHash } = await registeredIdentity();
    const newAuth = ethers.Wallet.createRandom();
    const newRecovery = ethers.Wallet.createRandom();
    const requestId = await openRecovery(registry, didHash, newAuth.address, newRecovery.address);
    await time.increase(DELAY + 1);

    const digest = await registry.recoveryDigest(
      didHash,
      requestId,
      newAuth.address,
      newRecovery.address,
      NEW_SHARE_ROOT,
      2,
      3,
    );
    const forged = await ethers.Wallet.createRandom().signMessage(ethers.getBytes(digest));

    await expect(registry.executeRecovery(didHash, requestId, forged)).to.be.revertedWithCustomError(
      registry,
      'InvalidSignature',
    );
  });

  it('cannot execute the same request twice', async () => {
    const { registry, recovery, didHash } = await registeredIdentity();
    const newAuth = ethers.Wallet.createRandom();
    const newRecovery = ethers.Wallet.createRandom();
    const requestId = await openRecovery(registry, didHash, newAuth.address, newRecovery.address);
    await time.increase(DELAY + 1);

    const digest = await registry.recoveryDigest(
      didHash,
      requestId,
      newAuth.address,
      newRecovery.address,
      NEW_SHARE_ROOT,
      2,
      3,
    );
    const signature = await recovery.signMessage(ethers.getBytes(digest));
    await registry.executeRecovery(didHash, requestId, signature);

    await expect(registry.executeRecovery(didHash, requestId, signature)).to.be.revertedWithCustomError(
      registry,
      'NoPendingRecovery',
    );
  });

  it('lets the current auth key cancel a pending request and blocks replay', async () => {
    const { registry, relayer, controller } = await deploy();
    const recovery = ethers.Wallet.createRandom();
    const didHash = didHashFor(controller.address);
    const digest = await registry.registerDigest(
      didHash,
      controller.address,
      recovery.address,
      SHARE_ROOT,
      3,
      5,
    );
    const signature = await controller.signMessage(ethers.getBytes(digest));
    await registry.register(didHash, controller.address, recovery.address, SHARE_ROOT, 3, 5, signature);

    const newAuth = ethers.Wallet.createRandom();
    const newRecovery = ethers.Wallet.createRandom();
    const requestId = await openRecovery(registry, didHash, newAuth.address, newRecovery.address);
    const cancelDigest = await registry.cancelDigest(didHash, requestId);

    const forged = await relayer.signMessage(ethers.getBytes(cancelDigest));
    await expect(registry.cancelRecovery(didHash, requestId, forged)).to.be.revertedWithCustomError(
      registry,
      'InvalidSignature',
    );

    const cancelSignature = await controller.signMessage(ethers.getBytes(cancelDigest));
    await expect(registry.cancelRecovery(didHash, requestId, cancelSignature)).to.emit(
      registry,
      'RecoveryCancelled',
    );
    await expect(
      registry.cancelRecovery(didHash, requestId, cancelSignature),
    ).to.be.revertedWithCustomError(registry, 'NoPendingRecovery');
  });

  it('rejects a second pending request while one is open', async () => {
    const { registry, didHash } = await registeredIdentity();
    const newAuth = ethers.Wallet.createRandom();
    const newRecovery = ethers.Wallet.createRandom();
    await openRecovery(registry, didHash, newAuth.address, newRecovery.address);

    await expect(
      registry.initiateRecovery(didHash, newAuth.address, newRecovery.address, NEW_SHARE_ROOT, 2, 3),
    ).to.be.revertedWithCustomError(registry, 'RecoveryPending');
  });

  it('rejects recovery for an unknown DID', async () => {
    const { registry } = await deploy();
    const newAuth = ethers.Wallet.createRandom();
    const newRecovery = ethers.Wallet.createRandom();
    const unknown = ethers.keccak256(ethers.toUtf8Bytes('did:sss:nobody'));

    await expect(
      registry.initiateRecovery(unknown, newAuth.address, newRecovery.address, NEW_SHARE_ROOT, 2, 3),
    ).to.be.revertedWithCustomError(registry, 'NotRegistered');
  });
});
