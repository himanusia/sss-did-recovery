# Evaluation

This document is the evidence pack for the report: what was measured, how, and which
requirement each artefact answers. Numbers are from a local run (MacBook, Node 26, Hardhat
EVM). They demonstrate behaviour, not production performance.

## 1. Method

| Layer | Instrument | What it proves |
| --- | --- | --- |
| Unit | `vitest` (`@sss/crypto`, `@sss/backend`) | maths, replay/expiry rules, API contracts |
| Contract | `hardhat test` | signature authority, timelock, replay, cancellation |
| End-to-end | `npm run demo` | the whole story against a real EVM node |
| Client crypto | `npm run bench -w @sss/crypto` | split/combine/commitment cost per configuration |
| UI | manual run, latency shown per login | round-trip time vs the 3 s target |

```bash
npm test                 # 38 tests: 11 crypto, 12 contracts, 15 backend
npm run demo             # 10 steps, exits non-zero on any failed assertion
npm run bench -w @sss/crypto
```

## 2. Experiment E1 — recovery success

The e2e script asserts, in order:

| Check | Expected | Observed |
| --- | --- | --- |
| register with auth-key signature | accepted, version 1 | pass |
| login app A and app B with the same DID | two independent sessions | pass |
| signature for app A used at app B | rejected | 401 `bad_signature` |
| login without the auth key | rejected | 401 |
| 3 of 5 shares reconstruct the secret | address equals on-chain `recoveryKey` | pass |
| 2 of 5 shares | different secret | pass (threshold holds) |
| tampered share | Merkle proof fails | pass (unit test) |
| rotate after timelock with recovery signature | version 2, auth key replaced | pass |
| old auth key after rotation | rejected | 401 |
| new auth key after rotation | accepted | 200 |
| audit trail | registration, request, execution, rotation | 4 events |

`k-1` and tampering are also covered by deterministic unit tests, so they do not depend on
the demo run.

## 3. Experiment E2 — timing

### Client-side (per operation, 500 iterations)

| Operation | 2-of-3 | 3-of-5 | 4-of-7 |
| --- | --- | --- | --- |
| split | 0.012 ms | 0.011 ms | 0.018 ms |
| combine (reconstruct) | 0.044 ms | 0.284 ms | 0.542 ms |
| commitment root | 0.077 ms | 0.119 ms | 0.152 ms |
| proof verify per share | 0.033 ms | 0.045 ms | 0.045 ms |
| encode + decode share | 0.003 ms | 0.003 ms | 0.003 ms |

All client operations are far below the NFR-10 budget ("reasonable resources on a user
device"). Reconstruction is the only super-linear step (`O(k²)` field inversions per combine).

### Authentication round trip

Measured inside the UI, from challenge request to session:

| App | Run 1 | Notes |
| --- | --- | --- |
| Portal Klinik | 141–157 ms | includes two HTTP round trips and one ECDSA sign |
| Pasar Digital | 166–184 ms | same, independent challenge |

The NFR-08 target is 3 s excluding chain confirmation. On a local node the chain part is
instant; on a public network the login path does not wait for a transaction at all, because
authentication is off-chain verification against an already-stored key.

### Recovery

The only mandatory wait is the timelock (contract parameter; 30–60 s in the demo). Client work
(reconstruct + sign) is sub-millisecond, and the two transactions confirm in one block locally.
The demo shortens the wait with `evm_increaseTime` so the whole scenario runs in seconds.

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
| Challenge expires | TTL 0 harness | 410 `challenge_expired` |
| Challenge is app-bound | sign with `app=market`, present to `klinik` | 401 |
| Threshold is enforced | 2 of 3 shares | wrong secret |
| Share tampering is detected | mutate one share | Merkle root changes, proof fails |
| Chain leaks no secrets | schema review | document holds addresses + root only |

## 5. Functional requirements

Legend: **done** = implemented and covered by tests/e2e; **partial** = implemented with a
prototype-grade mechanism; **gap** = intentionally out of scope.

| ID | Requirement | Status | Where |
| --- | --- | --- | --- |
| FR-01 | Register a new digital identity | done | `/api/identity/register`, Identity screen |
| FR-02 | Generate public/private key pair securely on device | done | `createAuthKeyPair` (client) |
| FR-03 | Create and register a DID on chain | done | `DIDRegistry.register` |
| FR-04 | Resolve DID to key/method/status | done | `GET /api/did/:did` |
| FR-05 | Show identity info and recovery status | done | Identity + Recovery screens |
| FR-06 | Login by signing a challenge | done | `/api/auth/challenge` + `verify` |
| FR-07 | Verify signature against the DID key | done | `AuthService.verify` |
| FR-08 | Use one DID on at least two apps | done | two app cards, e2e step 3 |
| FR-09 | Reject invalid/expired/replayed auth | done | unit + e2e (401/404/410) |
| FR-10 | Logout per app | done | `POST /api/auth/logout` + UI |
| FR-11 | Recovery secret separate from auth key | done | independent scalars |
| FR-12 | Split secret with k-of-n SSS | done | `splitSecret` |
| FR-13 | Distribute shares securely | partial | envelope download; no guardian transport |
| FR-14 | Recovery request with a new public key | done | `initiateRecovery` |
| FR-15 | Reconstruct locally after k valid shares | done | `combineShares` in browser |
| FR-16 | Verify possession of the recovery secret | done | signature by reconstructed key |
| FR-17 | Rotate the public key in the DID document | done | `executeRecovery` |
| FR-18 | Revoke the old authentication key | done | `authKey` overwritten, e2e 401 |
| FR-19 | Propagate the change to all apps | done | every login re-resolves the document |
| FR-20 | Record request/cancel/result on chain | done | events + `/api/audit` |

## 6. Non-functional requirements

| ID | Requirement | Status | Notes / evidence |
| --- | --- | --- | --- |
| NFR-01 | No plaintext secrets on server or chain | done | server receives signatures only; document has addresses |
| NFR-02 | Keygen, split, reconstruct on device | done | `apps/web/src/identity.ts`, all crypto in browser |
| NFR-03 | Random, one-shot, expiring challenge | done | 32-byte nonce, 120 s TTL, delete-on-use |
| NFR-04 | Challenge bound to domain/app | done | EIP-712 domain + `app` field, e2e 401 |
| NFR-05 | Encrypted communication | partial | HTTP locally; TLS termination not configured in the prototype |
| NFR-06 | Smart-contract security mitigations | partial | no external calls/delegatecall, custom errors, malleability check, checked math; unaudited |
| NFR-07 | No recovery below k shares | done | contract cannot see shares; client refuses < k; k-1 test |
| NFR-08 | Authentication ≤ 3 s excl. chain | done | 141–184 ms locally |
| NFR-09 | DID resolution responsive | done | single `eth_call`, sub-100 ms locally |
| NFR-10 | SSS efficient on device | done | 0.01–0.54 ms per operation |
| NFR-11 | Minimal on-chain data | done | ~87 bytes/document + events; one root instead of n hashes |
| NFR-12 | Tolerate lost shares | done | any k of n; 3-of-5 demo |
| NFR-13 | Identity consistency across apps | done | both apps read the same document |
| NFR-14 | Clear error handling | done | typed `{error, code}` + UI messages |
| NFR-15 | Retry without duplicate recovery | partial | per-DID in-flight lock + contract guards; no automatic retry loop |
| NFR-16 | No double execution | done | `executed` flag + latest request id |
| NFR-17 | No personal data on chain | done | no name/email/device/IP |
| NFR-18 | Only commitments of shares on chain | done | Merkle root only |
| NFR-19 | Auditable lifecycle | done | 5 event types, ordered by block/log index |
| NFR-20 | Clear auth/recovery status without leaking secrets | partial | status is explicit; the demo shows truncated share tokens and allows download for demonstration |

## 7. Threats to validity

- **Local chain.** Block time, gas price and mempool behaviour do not resemble a public
  network. Login latency excludes any chain interaction by design; recovery latency is
  dominated by the timelock, not by the EVM.
- **Simulated guardians.** Shares are held in the same browser profile. The prototype tests
  the cryptographic flow, not the social or transport layer.
- **Single machine.** Benchmarks do not cover low-end phones or browser crypto variance.
- **No independent audit.** Security claims are limited to the tested properties; the contract
  has not been reviewed by a third party.
- **Sample size.** Each timing figure comes from one machine and a short run; treat the
  numbers as order-of-magnitude, not a benchmark suite.

## 8. What to run for the report

1. `npm test` — capture the 38 passing tests.
2. `npm run demo` — capture the 10-step transcript (registration → rotation → audit).
3. `npm run bench -w @sss/crypto` — capture the timing table.
4. Open the console and run both logins plus one recovery; screenshot the identity, auth,
   recovery success, and audit screens.
