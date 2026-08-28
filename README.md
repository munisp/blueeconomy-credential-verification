# Blue Economy Credential Verification

Seafarer Certificate of Competency (CoC) wallet credentialing for the Blue Economy Platform: a W3C Verifiable Credentials Data Model 2.0 issuer and offline-capable verifier for NIMASA-issued, STCW-aligned seafarer CoC credentials, plus the legacy issuer-backed JWT verification command.

## Credential profile (Workstream D)

- **Format**: W3C VC Data Model 2.0. `@context` is exactly `["https://www.w3.org/ns/credentials/v2"]`, type is `["VerifiableCredential", "SeafarerCoC"]`.
- **Subject**: STCW-aligned `credentialSubject` (holder-bound `id`, `seafarerReferenceNumber`, `capacity`, `stcwRegulation`, `limitations`, optional name/nationality) with `validFrom`/`validUntil` expiry.
- **Issuer**: did:web-style NIMASA DID, configured via `BLUEECONOMY_ISSUER_DID`; Ed25519 PKCS#8 key from `BLUEECONOMY_ISSUER_ED25519_PKCS8_PEM_PATH`.
- **Proof**: Data Integrity proof, **eddsa-jcs-2022** cryptosuite (JCS RFC 8785 canonicalization, SHA-256 hashes of proof options and document concatenated proof-first, Ed25519 signature, multibase base58btc `proofValue`). No external network calls at issue or verify time.
- **Revocation**: W3C Bitstring Status List v1.0 (`credentialStatus` BitstringStatusListEntry, purpose `revocation`); the status list snapshot is itself a signed VC served at `GET /v1/status-list/{id}`. Revocations are pushed to wallets as `seafarer.revocation.v1` events.
- **Verification**: offline — requires only the issuer Ed25519 public key and a status-list snapshot. Checks proof, issuer, expiry, holder binding and revocation bit. p99 ≤ 5 s (measured orders of magnitude below; guarded by a latency budget test).

## Issuance gating and lifecycle

Issuance is allowed only after the `SeafarerCredentialWorkflow` (Temporal) reports the credential-eligibility stage and the caller holds the `nimasa-approver` role:

`exam-registration → exam-result (must pass) → training-completion → credential-eligibility → issuance`, with `revocation-requested` accepted at any time. Every stage has an SLA timer; breaches are recorded in the `observer` query without advancing the stage machine.

## Temporal worker (seafarer-credential-worker)

`src/worker.ts` (`npm run worker` → `node dist/worker.js`) is the lifecycle worker the gitops chart deploys as `seafarer-credential-worker`. It registers the `SeafarerCredentialWorkflow` bundle and the revocation activity (ledger commit + signed envelope + outbox row) against a Temporal task queue, and shuts down gracefully on SIGINT/SIGTERM.

Worker configuration (all fail-closed unless noted): `BLUEECONOMY_TEMPORAL_ADDRESS`, `BLUEECONOMY_TEMPORAL_TASK_QUEUE` (chart default `seafarer-credential`), `BLUEECONOMY_STATUS_DATABASE_URL` (outbox enqueue), `BLUEECONOMY_TIGERBEETLE_ADDRESSES` (revocation ledger commit), `BLUEECONOMY_ISSUER_ED25519_PKCS8_PEM_PATH` (envelope signing). Optional: `BLUEECONOMY_TEMPORAL_NAMESPACE` (default `default`), `BLUEECONOMY_EVENT_PRODUCER`, `BLUEECONOMY_TIGERBEETLE_CLUSTER_ID`, `BLUEECONOMY_TIGERBEETLE_LEDGER`.

## HTTP API

| Route | Roles |
| --- | --- |
| `POST /v1/credentials` | `nimasa-approver` |
| `POST /v1/verify` | `employer`, `psc-inspector` |
| `GET /v1/status-list/{id}` | any approved role (incl. `auditor`) |
| `POST /v1/revoke` | `nimasa-approver` |
| `GET /healthz` `GET /readyz` `GET /metrics` | unauthenticated probes |

Authentication is Keycloak RS256 via JWKS (`jose`), ported from `blueeconomy-administration-service/internal/admin`: roles are read from `realm_access.roles` and configured `resource_access[client].roles`; the authorizer is fail-closed (roleless identities denied, `auditor` denied every mutation, unknown routes 404).

## Durability, events and ledger

- **Status registry**: PostgreSQL (`migrations/0001_credential_status.sql`, parameterized SQL, upsert + outbox in one transaction). Fail-closed without `BLUEECONOMY_STATUS_DATABASE_URL`; the legacy single-process JSONL store is available only behind the explicit `BLUEECONOMY_STATUS_JSONL_TEST_PATH` test flag.
- **Events**: platform envelope `envelopeVersion 1.0` with deterministic `eventId`, FHIR R4 Bundle message entry (VC carried as a base64 `DocumentReference` attachment), provenance (principalId, principalRole, Ed25519 signature over the SHA-256 digest of the JCS-canonical payload, TigerBeetle `ledgerCommitHash`), classification `CONFIDENTIAL`. Published through the transactional outbox to Kafka topics `seafarer.credential.v1` / `seafarer.revocation.v1` (`kafkajs`, idempotent producer).
- **Ledger**: TigerBeetle issuance ledger behind the `IssuanceLedger` interface; transfer IDs are deterministic SHA-256 derivations so retries are idempotent (`exists` is a successful replay). Fail-closed without `BLUEECONOMY_TIGERBEETLE_ADDRESSES`.

## Configuration

Required (fail-closed): `BLUEECONOMY_ISSUER_DID`, `BLUEECONOMY_ISSUER_ED25519_PKCS8_PEM_PATH`, `BLUEECONOMY_STATUS_LIST_URL`, `BLUEECONOMY_STATUS_DATABASE_URL`, `BLUEECONOMY_TIGERBEETLE_ADDRESSES`, `BLUEECONOMY_TEMPORAL_ADDRESS`, `BLUEECONOMY_OIDC_JWKS_URL`, `BLUEECONOMY_OIDC_ISSUER`, `BLUEECONOMY_OIDC_AUDIENCE`. Optional: `BLUEECONOMY_KAFKA_BROKERS` (outbox publisher), `BLUEECONOMY_OIDC_ROLES_CLIENT_IDS`, `PORT` (default 8080), `BLUEECONOMY_EVENT_PRODUCER`, `BLUEECONOMY_TEMPORAL_NAMESPACE`.

## Schema contracts

Files under `schemas/` are generated from `src/contracts.ts` (`npm run schemas:generate`). `tests/schema-drift.test.ts` fails CI whenever the committed schemas drift from the code or stop accepting the documents the code produces. Never edit the committed schema files by hand.

## Development

```bash
npm ci --ignore-scripts
npm run build   # tsc --noEmit
npm test        # node --test (VC round-trip, tamper/revoke/expire, offline, latency, drift, workflows, role matrix, ledger, outbox)
npm run compile # emit dist/ for the container image
npm start       # node dist/main.js (fail-closed configuration)
```

## Legacy JWT verification command

The original `src/verify.ts` command validates an **actual compact signed JWT credential** against an explicitly supplied HTTPS issuer, audience and JWKS endpoint; see `git log` and `src/verify.ts` usage text. It has no default issuer, audience, credential or sample token and stores only hashed references in its evidence output.

## Integration gate

A genuine NIMASA credential capability requires the approved credential profile and schema, DID/key-management process, holder binding, revocation approach, relying-party policy, STCW domain sign-off, privacy impact assessment and an authorised non-production environment before any issuer or credential integration is represented as live.
