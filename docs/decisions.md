# Decisions

Short ADRs for choices that a reviewer would otherwise question. Each entry records the
context, the decision, and what it costs.

## ADR-01 — Python backend (spec says Go or Python)

**Context.** The specification leaves the backend language open: "Go or Python (TBD)". The
first iteration used Node/TypeScript to share code with the browser, which quietly ignored
the column in the specification.

**Decision.** Python 3.12 + FastAPI, in `services/api`, with `pytest` and PostgreSQL.

**Why.** It matches the specification instead of arguing with it, and Python has first-class
Ethereum tooling (`web3.py` for contract calls and relaying, `eth_account` for EIP-191/EIP-712
recovery). The device-side crypto stays in TypeScript because it must run in the browser;
`services/api/demo_client` is the Python mirror used by tests and the e2e demo, and the two
implementations are checked against each other (same share vectors, same sealed-box format,
byte-identical ciphertext handling).

**Cost.** Two implementations of the client maths. Mitigated by keeping the Python copy in
`demo_client/` (not imported by request handlers) and by the e2e demo, which fails if the two
disagree on roots, proofs or addresses.

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

## ADR-07 — A real QBFT network, not a Hardhat stand-in

**Context.** The specification names Hyperledger Besu with proof of authority on a private
network. The previous iteration only ran Hardhat's in-process EVM and left Besu as future work.

**Decision.** Provision Besu QBFT with **four validators** (`infra/besu`), generated with
Besu's own `operator generate-blockchain-config`; deploy the registry to it; run the e2e demo
against it. Hardhat's in-process EVM remains the runner for contract unit tests only.

**Why.** "Ethereum-compatible" is not the same as "runs on the chosen network". Provisioning it
exercises the real path: 2 s blocks, a validator set in `extraData` (which needs the POA
middleware in web3), zero gas price, and transactions that actually take a block to confirm.

**Cost.** Generated validator keys and genesis are committed as **demo fixtures**; they must
never be reused on a reachable network. Unit tests still use the in-process EVM because
spinning four containers per test is slow; the e2e script is the Besu gate.

## ADR-08 — PostgreSQL for challenges, sessions, envelopes and locks

**Context.** NFRs require one-shot challenges and revocable sessions; the specification lists
PostgreSQL as the off-chain database.

**Decision.** `challenges`, `sessions`, `guardians`, `guardian_envelopes`, `share_requests`,
`relay_locks`, migrated on boot from `services/api/migrations`.

**Why.** A restarted API no longer logs everyone out, two API instances agree on challenges, and
`relay_locks` serialises relayer transactions per DID in a way an in-process `Set` cannot. The
chain stays the source of truth for identity documents; the database only holds what is
useless to an attacker: expired challenges, bearer sessions, and sealed ciphertext.

**Cost.** One more service to run and a migration step on startup. Both are handled by
`scripts/stack.sh` and by the container healthchecks.

## ADR-09 — No oracle

**Context.** The specification has an "Oracle & off-chain integration" section.

**Decision.** Not implemented; documented as unnecessary for this flow.

**Why.** The registry is already the source of truth and the backend reads it directly.
Oracles would matter for external attestations or cross-chain resolution, which are outside
account recovery.

## ADR-10 — Indonesian UI, English code and docs

**Decision.** User-facing copy is Indonesian (the course context is Indonesian); identifiers,
commits and documentation are English.

**Why.** Matches how the deliverable will be reviewed and demonstrated, and keeps the codebase
consistent with the rest of the author's repositories.

## ADR-11 — Randomised sealed distribution instead of share downloads

**Context.** The specification's discussion asks for randomised sharing: "setiap orang tidak
tahu siapa yang memegang apa; sistem yang akan request dan gabungkan secrets". The previous
iteration let the user download one envelope per named guardian and keep the whole set in
localStorage — the opposite of that requirement.

**Decision.** The device seals one envelope per guardian with X25519 + HKDF-SHA256 +
ChaCha20-Poly1305, shuffles the assignment, uploads only ciphertext, and drops its plaintext
set. Recovery asks the network for `k` shares; the API samples guardians server-side and each
guardian rewraps to the device's ephemeral transport key.

**Why.** Three properties fall out: the server never sees a share (only ciphertext), a guardian
cannot tell which share index it holds without opening its box, and the recovering device
cannot target a specific holder. It is also the only way to make FR-13 ("distribute shares
securely") true rather than "implemented with a manual file handoff".

**Cost.** Guardians are simulated inside the API process for reproducibility, so the social and
transport layer is documented as the main external-validity gap. The protocol itself is real:
boxes are opened with per-guardian keys, and the e2e test asserts the API's ciphertext does not
contain a plaintext share token.
