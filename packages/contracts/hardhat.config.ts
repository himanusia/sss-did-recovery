import type { HardhatUserConfig } from 'hardhat/config';
import '@nomicfoundation/hardhat-toolbox';

const config: HardhatUserConfig = {
  solidity: {
    version: '0.8.24',
    settings: {
      optimizer: { enabled: true, runs: 200 },
    },
  },
  networks: {
    hardhat: { chainId: 31337 },
    localhost: { url: 'http://127.0.0.1:8545', chainId: 31337 },
    // Private QBFT network (Hyperledger Besu). The relayer account is funded in
    // infra/besu/networkFiles/genesis.json; chainId must match that genesis.
    besu: {
      url: process.env.BESU_RPC_URL ?? 'http://127.0.0.1:8545',
      chainId: 1337,
      accounts: [
        process.env.RELAYER_PRIVATE_KEY ??
          '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
      ],
    },
  },
  paths: {
    sources: 'contracts',
    tests: 'test',
    cache: 'cache',
    artifacts: 'artifacts',
  },
};

export default config;
