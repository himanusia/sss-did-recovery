import { ethers, network } from 'hardhat';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

async function main() {
  const delay = Number(process.env.RECOVERY_DELAY_SECONDS ?? '60');
  if (!Number.isInteger(delay) || delay < 0) throw new Error('RECOVERY_DELAY_SECONDS must be >= 0');

  const factory = await ethers.getContractFactory('DIDRegistry');
  const registry = await factory.deploy(delay);
  await registry.waitForDeployment();

  const address = await registry.getAddress();
  const deployment = {
    network: network.name,
    chainId: Number((await ethers.provider.getNetwork()).chainId),
    address,
    recoveryDelay: delay,
    deployedAt: new Date().toISOString(),
  };

  const dir = join(__dirname, '..', 'deployments');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${network.name}.json`), `${JSON.stringify(deployment, null, 2)}\n`);

  console.log(JSON.stringify(deployment));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
