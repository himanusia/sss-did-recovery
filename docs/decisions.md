# Decisions

Short ADRs for choices that a reviewer would otherwise question. Each entry records the
context, the decision, and what it costs.

## ADR-01 — TypeScript backend instead of Go/Python

**Context.** The specification leaves the backend language as TBD (Go or Python).

**Decision.** Node + TypeScript, in the same workspace as the crypto library and the web app.

**Why.** The share and commitment code is the part most likely to drift between client and
server. One implementation in one language removes that class of bug; the same module is used
by the browser, the tests and the e2e script. `ethers` also gives EIP-712 verification and
contract bindings without a second toolchain.

**Cost.** Weaker isolation than Go, and Node is not the typical choice for a high-throughput
relayer. The API surface here is small and stateless; this is acceptable for a prototype.

## ADR-02 — Random DID identifier, not a key-derived one

**Context.** A DID must remain stable when the authentication key rotates. Deriving the
identifier from the auth key (`did = f(pubkey)`) is common in simple demos.

**Decision.** `did:sss:0x<20 random bytes>`, generated once.

**Why.** Recovery exists to change the key. If the DID changes with it, every application
binding, session and share root reference breaks. A random namespace id decouples identity
from key material and matches the "identifier, not key" split that DID documents already make.

**Cost.** The identifier says nothing about the current key; resolution is always required.
That is a feature for privacy (no key history leak in the identifier).

## ADR-03 — The recovery secret is itself a secp256k1 private key

**Context.** Recovery must prove possession of the reconstructed secret without publishing it.

**Decision.** The secret is a scalar in `[1, n-1]`; its address is stored as `recoveryKey`.
After reconstruction the client signs the rotation digest with it.

**Why.** This gives a clean proof-of-possession: the chain verifies an ECDSA signature instead
of receiving the secret. The alternative — submitting the secret as a "proof" — would leak it
permanently to every chain observer, breaking the whole model.

**Cost.** The secret is constrained to the curve order, so the field for SSS is `n` rather than
a generic 256-bit prime. That is fine; all shares are still uniform in the same field.

## ADR-04 — Permissionless request, timelocked execution

**Context.** If opening a recovery request required the auth key, a user who lost that key
could never recover. If it required nothing at execution either, anyone could steal a DID.

**Decision.** `initiateRecovery` is open to anyone. Execution needs the recovery key signature
and can only happen after `executeAfter = requestedAt + delay`. The current auth key can cancel
during the window, with an off-chain signature so it stays gasless.

**Why.** It separates "asking" from "authorising". Griefing a DID with fake requests is
possible but harmless: nothing changes, and the owner can cancel or simply let it expire.
The timelock gives a user who still has the old key a chance to stop a malicious request.

**Cost.** A legitimate recovery is not instant (30–60 s in the demo, 24–72 h in production).
That is the intended trade-off for a recovery flow.

## ADR-05 — Relayer pays gas, signatures carry authority

**Context.** A user who just lost a phone is unlikely to hold the native token for gas.

**Decision.** The server holds a funded relayer key and submits every state change. Contracts
never trust `msg.sender`; they verify a signature over a digest that includes `chainId` and the
registry address.

**Why.** Gasless UX without delegating authority. The relayer can censor, but it cannot forge:
it has no access to auth or recovery keys.

**Cost.** A single point of failure and a metadata observer. Production needs multiple
relayers, quotas and/or user-paid gas. Already noted in the threat model.

## ADR-06 — One Merkle root for the share set

**Context.** The chain could store `n` share hashes, one per guardian.

**Decision.** Store one `bytes32` root; keep the proofs client-side.

**Why.** Same integrity guarantee, constant on-chain cost, and no per-guardian metadata on a
public ledger. It also keeps the document small enough to read on every login.

**Cost.** The client must carry a proof per share (33-byte share + ~log2(n) hashes). This is
trivial compared to the share itself.

## ADR-07 — Hardhat EVM for the prototype, Besu as the deployment target

**Context.** The specification names Hyperledger Besu (Ethereum-compatible, permissioned).

**Decision.** Develop and test against Hardhat's EVM; keep the contract free of any
Hardhat-specific behaviour. No Besu network is provisioned in this repository.

**Why.** The contract is plain Solidity 0.8.24 and uses only `ecrecover`/`keccak256`, so it is
portable. A local in-process EVM gives deterministic tests (timelock via `evm_increaseTime`)
without a 1 GB image in the loop.

**Cost.** Besu-specific behaviour (permissioning, gas price zero, private transactions) is not
exercised. Current Besu images dropped `--network=dev`, so a local Besu run needs a QBFT genesis;
that is deliberately not shipped half-working. The prototype does not claim to validate Besu.

## ADR-08 — In-memory challenges and sessions

**Context.** NFRs require nonces to be random, single-use and expiring; they do not require
persistence across restarts.

**Decision.** `Map`s in the API process, with TTL checks and deletion on use.

**Why.** The prototype runs as one process. A shared store would add infrastructure without
changing the protocol, and a restarted server invalidating sessions is acceptable (and safer).

**Cost.** Not horizontally scalable; restart drops sessions. Documented as a production gap.

## ADR-09 — No oracle

**Context.** The specification has an "Oracle & off-chain integration" section.

**Decision.** Not implemented; documented as unnecessary for this flow.

**Why.** The registry is already the source of truth and the backend reads it directly.
Oracles would matter for external attestations or cross-chain resolution, which are outside
account recovery.

## ADR-10 — Indonesian UI, English code and docs

**Decision.** User-facing copy is Indonesian (the course context and the report are in
Indonesian); identifiers, commits and documentation are English.

**Why.** Matches how the deliverable will be reviewed and demonstrated, and keeps the codebase
consistent with the rest of the author's repositories.
