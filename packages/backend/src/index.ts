import { JsonRpcProvider } from 'ethers';
import { EthersRegistryAdapter } from './chain.js';
import { createApp, type ServerConfig } from './server.js';

const DEFAULT_RELAYER_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'; // hardhat account #0
const DEFAULT_APPS = 'klinik:Portal Klinik,market:Pasar Digital';

function parseApps(value: string): Record<string, string> {
  return Object.fromEntries(
    value
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean)
      .map((entry) => {
        const [id, ...label] = entry.split(':');
        return [id.trim(), (label.join(':') || id).trim()];
      }),
  );
}

function numberEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) throw new Error(`${name} must be a positive number`);
  return value;
}

async function main() {
  const contractAddress = process.env.CONTRACT_ADDRESS;
  if (!contractAddress) {
    throw new Error('CONTRACT_ADDRESS is required (deploy with `npm run deploy:local` in packages/contracts)');
  }

  const adapter = await EthersRegistryAdapter.create({
    rpcUrl: process.env.RPC_URL ?? 'http://127.0.0.1:8545',
    contractAddress,
    relayerPrivateKey: process.env.RELAYER_PRIVATE_KEY ?? DEFAULT_RELAYER_KEY,
  });

  const provider = new JsonRpcProvider(process.env.RPC_URL ?? 'http://127.0.0.1:8545');
  const code = await provider.getCode(contractAddress);
  if (code === '0x') {
    throw new Error(`no contract deployed at ${contractAddress} on the configured RPC`);
  }

  const config: ServerConfig = {
    chainId: adapter.chainId,
    registryAddress: adapter.registryAddress,
    apps: parseApps(process.env.APPS ?? DEFAULT_APPS),
    challengeTtlSeconds: numberEnv('CHALLENGE_TTL_SECONDS', 120),
    sessionTtlSeconds: numberEnv('SESSION_TTL_SECONDS', 900),
    allowedOrigin: process.env.CORS_ORIGIN,
  };

  const port = numberEnv('PORT', 8787);
  createApp(adapter, config).listen(port, () => {
    console.log(
      `[backend] listening on http://127.0.0.1:${port} | chain ${adapter.chainId} | registry ${adapter.registryAddress} | relayer ${adapter.relayerAddress} | recovery delay ${adapter.recoveryDelay}s`,
    );
  });
}

main().catch((error: unknown) => {
  console.error('[backend] startup failed:', error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
