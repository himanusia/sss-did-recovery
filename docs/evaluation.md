# Evaluation

Evidence pack: what was measured, how, and which requirement each artefact answers. Numbers come from a local run (Apple silicon Mac, Node 26, Python 3.12, Hyperledger
Besu 25.9.0 QBFT with 4 validators, PostgreSQL 16 in Docker). They demonstrate behaviour,
not production performance.

## 1. Method

| Layer | Instrument | What it proves |
| --- | --- | --- |
| Crypto | `vitest` (`@sss/crypto`) | Shamir maths, commitments, DID helpers |
| Contract | `hardhat test` | signature authority, timelock, replay, cancellation |
| API | `pytest` + PostgreSQL (`services/api/tests`) | HTTP contract, challenge rules, recovery wiring, guardian mailbox rules |
| Client crypto | `npm run bench -w @sss/crypto` | split/combine/commitment cost per configuration |
| End-to-end | `scripts/stack.sh demo` | the whole story against the real QBFT network and the real API |
| UI | browser run against the Docker stack | round-trip time, no console errors, screens |

```bash
scripts/stack.sh boot     # 4 Besu validators + PostgreSQL + registry + API + console
scripts/stack.sh test     # 11 crypto, 12 contract, 34 API
scripts/stack.sh demo     # 10 steps, exits non-zero on any failed assertion
npm run bench -w @sss/crypto
```

## 2. Experiment E1 — recovery success

The e2e script runs the device side for real against `chainId 1337` and asserts, in order:

| Check | Expected | Observed |
| --- | --- | --- |
| register with auth-key signature | accepted, version 1 | pass |
| 5 sealed envelopes stored, 0 shares on device | random assignment, ciphertext only | pass |
| login app A and app B with the same DID | two independent sessions | pass (~30 ms each) |
| signature for app A used at app B | rejected | 401 `bad_signature` |
| login without the auth key | rejected | 401 |
| network returns k=3 rewrapped shares | each opens only with the device transport key | pass |
| Merkle proof per received share | matches on-chain `shareRoot` | 3/3 pass |
| 3 of 5 shares reconstruct the secret | address equals on-chain `recoveryKey` | pass |
| 2 of 5 shares | different secret | pass (threshold holds) |
| tampered share | Merkle proof fails | pass (unit test) |
| rotate after timelock with recovery signature | version 2, auth key replaced | pass |
| old auth key after rotation | rejected | 401 |
| new auth key after rotation | accepted | 200 |
| new share set deposited after rotation | 5 sealed envelopes under the new root | pass |
| audit trail | registration, request, execution, rotation | 4 events |

`k-1`, tampering and sealing are also covered by deterministic unit tests, so they do not
depend on one demo run.

## 3. Experiment E2 — timing

### Client-side (per operation, 500 iterations)

| Operation | 2-of-3 | 3-of-5 | 4-of-7 |
| --- | --- | --- | --- |
| split | 0.009 ms | 0.009 ms | 0.013 ms |
| combine (reconstruct) | 0.033 ms | 0.219 ms | 0.424 ms |
| commitment root | 0.058 ms | 0.093 ms | 0.115 ms |
| proof verify per share | 0.024 ms | 0.035 ms | 0.035 ms |
| encode + decode share | 0.003 ms | 0.002 ms | 0.002 ms |

Sealing adds one X25519 exchange plus HKDF-SHA256 and ChaCha20-Poly1305 per share, which
stays in the same sub-millisecond band. Reconstruction is the only super-linear step
(`O(k²)` field inversions per combine). Both are far below the NFR-10 budget ("reasonable
resources on a user device").

### Authentication round trip

Measured in the e2e run and in the console, from challenge request to session:

| App | Run | Notes |
| --- | --- | --- |
| Portal Klinik | ~30 ms | two HTTP round trips + one ECDSA sign; Besu is not contacted on this path |
| Pasar Digital | ~30 ms | independent challenge |

The NFR-08 target is 3 s excluding chain confirmation. Authentication never waits for a
transaction: the server verifies the signature against the key already stored on chain.

### Recovery

The only mandatory wait is the timelock (contract parameter, 20 s in the demo). Client work
— request, open 3 envelopes, verify 3 Merkle proofs, reconstruct, sign — is a few
milliseconds. Transactions land in the next QBFT block (2 s cadence); the demo waits for the
timelock by wall clock, no `evm_increaseTime` shortcut.

### Chain cost

| Operation | Gas used | Events |
| --- | --- | --- |
| `register` | 123,712 | 1 |
| `initiateRecovery` | 144,145 | 1 |
| `executeRecovery` | 69,224 | 2 (executed + rotated) |

The on-chain document carries no share and no secret: 20 B + 20 B + 32 B + 2 B + ~13 B per
identity, plus events.

## 4. Experiment E3 — security properties

| Property | Test | Evidence |
| --- | --- | --- |
| Registration cannot be forged | wrong signer | `DIDRegistry.test.ts` → `InvalidSignature` |
| Rotation cannot be forged | random signer, wrong request id | `InvalidSignature` / `NoPendingRecovery` |
| Rotation cannot replay | execute twice | second call reverts |
| Request cannot be duplicated | second initiate while pending | `RecoveryPending` |
| Cancellation needs the auth key | relayer-signed cancel | `InvalidSignature` |
| Timelock is enforced | execute before `executeAfter` | `TimelockActive` |
| Challenge is single use | verify same challenge twice | second → 404 |
| Challenge expires | expired row in PostgreSQL | 410 `challenge_expired` |
| Challenge is app-bound | sign with `app=market`, present to `klinik` | 401 |
| Threshold is enforced | ask for fewer than k shares | 400 `below_threshold` |
| Share tampering is detected | mutate one share | Merkle root changes, proof fails |
| Server cannot read a share | database dump review | rows start with `SD1`, the ciphertext only |
| A share is bound to one device | open with a different transport key | decryption fails |
| Sealed boxes are not deterministic | seal same plaintext twice | different ciphertexts |
| Envelope count is enforced | deposit 2 envelopes for a 5-share set | 400 `envelope_count` |
| One envelope per guardian | duplicate guardian id | 400 `duplicate_guardian` |
| Deposit must match the committed root | wrong `shareRoot` | 400 `root_mismatch` |
| Chain leaks no secrets | schema review | document holds addresses + root only |
| Concurrent relay is serialised | `relay_locks` row per DID | 409 `busy` while a transaction is in flight |

## 5. Functional requirements

Legend: **done** = implemented and covered by tests/e2e; **partial** = implemented with a
prototype-grade mechanism; **gap** = intentionally out of scope.

| ID | Requirement | Status | Where |
| --- | --- | --- | --- |
| FR-01 | Register a new digital identity | done | `/api/identity/register`, Identity screen |
| FR-02 | Generate public/private key pair securely on device | done | `createAuthKeyPair` (browser) |
| FR-03 | Create and register a DID on chain | done | `DIDRegistry.register` |
| FR-04 | Resolve DID to key/method/status | done | `GET /api/did/:did` |
| FR-05 | Show identity info and recovery status | done | Identity + Recovery screens |
| FR-06 | Login by signing a challenge | done | `/api/auth/challenge` + `verify` |
| FR-07 | Verify signature against the DID key | done | `AuthService.verify` (Python) |
| FR-08 | Use one DID on at least two apps | done | two app cards, e2e step 03 |
| FR-09 | Reject invalid/expired/replayed auth | done | pytest + e2e (401/404/410) |
| FR-10 | Logout per app | done | `POST /api/auth/logout` + UI |
| FR-11 | Recovery secret separate from auth key | done | independent scalars |
| FR-12 | Split secret with k-of-n SSS | done | `splitSecret`, pytest |
| FR-13 | Distribute shares securely | done | sealed envelopes per guardian, shuffled assignment, `POST /api/shares/deposit` |
| FR-14 | Recovery request with a new public key | done | `initiateRecovery` |
| FR-15 | Reconstruct locally after k valid shares | done | `combineShares` in the browser |
| FR-16 | Verify possession of the recovery secret | done | signature by the reconstructed key |
| FR-17 | Rotate the public key in the DID document | done | `executeRecovery` |
| FR-18 | Revoke the old authentication key | done | `authKey` overwritten, e2e 401 |
| FR-19 | Propagate the change to all apps | done | every login re-resolves the document |
| FR-20 | Record request/cancel/result on chain | done | events + `/api/audit` |

## 6. Non-functional requirements

| ID | Requirement | Status | Notes / evidence |
| --- | --- | --- | --- |
| NFR-01 | No plaintext secrets on server or chain | done | server stores signatures, ciphertext and commitments; DB dump reviewed |
| NFR-02 | Keygen, split, reconstruct on device | done | `apps/web/src/identity.ts`, `sealing.ts`; pytest asserts no share on the server |
| NFR-03 | Random, one-shot, expiring challenge | done | 32-byte nonce, 120 s TTL, delete-on-use in PostgreSQL |
| NFR-04 | Challenge bound to domain/app | done | EIP-712 domain + `app` field, e2e 401 |
| NFR-05 | Encrypted communication | partial | nginx can terminate TLS but the demo runs HTTP on localhost |
| NFR-06 | Smart-contract security mitigations | partial | no external calls/delegatecall, custom errors, malleability check, checked math; unaudited |
| NFR-07 | No recovery below k shares | done | contract cannot see shares; API refuses count < k; client and tests cover k−1 |
| NFR-08 | Authentication ≤ 3 s excl. chain | done | ~30 ms locally |
| NFR-09 | DID resolution responsive | done | single `eth_call`, sub-100 ms locally |
| NFR-10 | SSS efficient on device | done | 0.002–0.424 ms per operation |
| NFR-11 | Minimal on-chain data | done | ~87 bytes/document + events; one root instead of n hashes |
| NFR-12 | Tolerate lost shares | done | any k of n; demo loses 2 of 5 |
| NFR-13 | Identity consistency across apps | done | both apps read the same document |
| NFR-14 | Clear error handling | done | typed `{error, code}` + UI messages |
| NFR-15 | Retry without duplicate recovery | partial | `relay_locks` + contract guards prevent duplicates; no automatic retry queue |
| NFR-16 | No double execution | done | `executed` flag + latest request id |
| NFR-17 | No personal data on chain | done | no name/email/device/IP |
| NFR-18 | Only commitments of shares on chain | done | Merkle root only |
| NFR-19 | Auditable lifecycle | done | 5 event types, ordered by block/log index |
| NFR-20 | Clear auth/recovery status without leaking secrets | partial | counts and states only; the demo keeps ciphertexts in localStorage so a reload does not lose the pending set |

## 7. Threats to validity

- **Private test network.** QBFT with four validators on one machine gives deterministic
  finality and 2 s blocks; it says nothing about public-network gas markets or reorgs.
  Login latency excludes chain interaction by design; recovery latency is dominated by the
  timelock, not the EVM.
- **Simulated guardians.** Guardians are services co-located with the API. The envelopes are
  real (the server cannot open them), but the social layer — who the guardians are, how a
  user reaches them — is not modelled. This is the main external-validity gap.
- **Single machine.** Benchmarks do not cover low-end phones, browser crypto variance, or
  network jitter between the device and the API.
- **No independent audit.** Security claims are limited to the tested properties; the
  contract has not been reviewed by a third party.
- **Sample size.** Timing figures come from one machine and short runs; treat them as
  order-of-magnitude, not a benchmark suite.

## 8. What to run when demonstrating

1. `scripts/stack.sh boot` — capture the four validators, chain id and deployed registry.
2. `scripts/stack.sh test` — capture 11 + 12 + 34 passing tests.
3. `scripts/stack.sh demo` — capture the 10-step transcript.
4. `npm run bench -w @sss/crypto` — capture the timing table.
5. Open `http://127.0.0.1:8080`, create an identity, log in to both apps, simulate a lost
   device, run the recovery — screenshots are in `docs/screenshots`.
