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

Issuance and revocation execute under maker/checker dual control (mirroring `blueeconomy-administration-service`): one `nimasa-approver` officer submits the mutation into a persisted PENDING approval request (`credential_approval_requests`, migration 0005, which enforces `requester_subject <> approver_subject` as a database CHECK), and a second, distinct `nimasa-approver` approves it. The eligibility gate is evaluated at submission and re-evaluated at execution (fail-closed); the pending row binds payload, requester, approver and both timestamps as the audit trail.

## Temporal worker (seafarer-credential-worker)

`src/worker.ts` (`npm run worker` → `node dist/worker.js`) is the lifecycle worker the gitops chart deploys as `seafarer-credential-worker`. It registers the `SeafarerCredentialWorkflow` bundle and the revocation activity (ledger commit + signed envelope + outbox row) against a Temporal task queue, and shuts down gracefully on SIGINT/SIGTERM.

Worker configuration (all fail-closed unless noted): `BLUEECONOMY_TEMPORAL_ADDRESS`, `BLUEECONOMY_TEMPORAL_TASK_QUEUE` (chart default `seafarer-credential`), `BLUEECONOMY_STATUS_DATABASE_URL` (outbox enqueue), `BLUEECONOMY_TIGERBEETLE_ADDRESSES` (revocation ledger commit), `BLUEECONOMY_ISSUER_ED25519_PKCS8_PEM_PATH` (envelope signing). Optional: `BLUEECONOMY_TEMPORAL_NAMESPACE` (default `default`), `BLUEECONOMY_EVENT_PRODUCER`, `BLUEECONOMY_TIGERBEETLE_CLUSTER_ID`, `BLUEECONOMY_TIGERBEETLE_LEDGER`.

## HTTP API

| Route | Roles |
| --- | --- |
| `POST /v1/credentials` | `nimasa-approver` (maker: submits a PENDING issuance request, 202; nothing is issued yet) |
| `POST /v1/credentials/{requestId}/approve` | `nimasa-approver` (checker: a subject distinct from the requester; executes the issuance, 201; self-approval → 409) |
| `POST /v1/verify` | `employer`, `psc-inspector` |
| `GET /v1/status-list/{id}` | any approved role (incl. `auditor`, `seafarer`); 404 unless `{id}` matches the configured status-list credential id |
| `POST /v1/revoke` | `nimasa-approver` (maker: submits a PENDING revocation request, 202; the credential stays active) |
| `POST /v1/revocations/{requestId}/approve` | `nimasa-approver` (checker: a subject distinct from the requester; executes the revocation, 200; self-approval → 409) |
| `GET /v1/wallet/credentials/current` | `seafarer` (returns the authenticated holder's current ACTIVE, non-expired VC document; 404 when none) |
| `GET /v1/issuers/{issuer}/key` | public (issuer Ed25519 public key as `{ issuer, kid, public_key_hex }` for offline eddsa-jcs-2022 verification; 404 for unknown issuers) |
| `GET /healthz` `GET /readyz` `GET /metrics` | unauthenticated probes |

Authentication is Keycloak RS256 via JWKS (`jose`), ported from `blueeconomy-administration-service/internal/admin`: roles are read from `realm_access.roles` and configured `resource_access[client].roles`; the authorizer is fail-closed (roleless identities denied, `auditor` denied every mutation, unknown routes 404). Optional `tenant` and `clearance` JWT claims are propagated to the policy engine.

## Embedded PBAC (policy-based access control)

Every authenticated route is additionally gated by an embedded, deny-by-default policy engine (`src/auth/pbac.ts`). OPA's Go SDK is unavailable to TypeScript services, so the engine evaluates a small rego-independent JSON format any platform service can implement. Policies load once at startup from `POLICY_DIR`, fail-closed: a missing directory, no `*.policy.json` files, malformed JSON, a schema violation, a duplicate rule name, or zero rules aborts boot. There is no fail-open path; a request that matches no allow-rule is denied with 403 and counted (`blueeconomy_pbac_denied_total`).

### Policy file format (`<POLICY_DIR>/*.policy.json`)

```json
{
  "version": "1.0",
  "policies": [
    {
      "name": "nimasa-approver-issues-credentials",
      "roles": ["nimasa-approver"],
      "clearance": ["*"],
      "tenant": "*",
      "resource": "credential",
      "action": "issue",
      "classification": ["CONFIDENTIAL"]
    }
  ]
}
```

- `version` (required): must be `"1.0"`.
- `policies` (required): array of ALLOW rules; anything not matched is DENIED.
- `name` (required): stable rule identifier, unique across all loaded files.
- `roles` (required): non-empty list of principal roles, or `["*"]` for any authenticated role. A request matches when it holds at least one listed role.
- `resource`, `action` (required): identifiers (for example `credential`/`issue`, `wallet`/`read`, `status-list`/`read`) or `"*"`.
- `tenant` (optional): exact tenant id or `"*"`; a rule naming a tenant never matches a request without a tenant claim.
- `clearance` (optional): list of clearance labels or `["*"]`; a rule listing clearances never matches a request without a clearance claim.
- `classification` (optional): subset of `PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED | FIDUCIARY_SEGREGATED` or `["*"]`.

Unknown fields, unknown classification labels and malformed identifiers are boot-fatal. The shipped `policies/credential-verification.policy.json` encodes the route matrix in the table above.

## Envelope provenance signature verification

`src/events/envelope-verification.ts` is the shared consumer-side verifier for the fleet signature scheme (blueeconomy-contracts `docs/envelope-signature.md`): `provenance.signature` is a JWS compact serialization (EdDSA/Ed25519, via `jose`) over the JCS-canonicalized (RFC 8785) JSON of the full envelope excluding the signature field, with protected header `{"alg":"EdDSA","kid":"<producer>-<epoch>"}`. Producer public keys resolve from a mounted key directory shaped `{kid: base64url-ed25519-pubkey}` whose path comes from `KEY_DIRECTORY_PATH`; loading fails closed (unreadable file, invalid JSON, malformed kid or key all abort startup). Verification rejects with reason codes `malformed-jws`, `unsupported-alg`, `unknown-kid`, `payload-mismatch` (the JWS payload must byte-equal the re-canonicalized envelope) and `invalid-signature`; rejected envelopes must never be persisted.

## Durability, events and ledger

- **Status registry**: PostgreSQL (`migrations/`, parameterized SQL, upsert + outbox in one transaction). Fail-closed without `BLUEECONOMY_STATUS_DATABASE_URL`; the legacy single-process JSONL store is available only behind the explicit `BLUEECONOMY_STATUS_JSONL_TEST_PATH` test flag. **Revocation is terminal**: the status upsert is guarded (`WHERE status <> 'REVOKED'`) and migration `0004` enforces the invariant by trigger, so re-issuance after revocation is refused truthfully (409) instead of silently flipping REVOKED back to ACTIVE. Outbox event-id dedup is verified: an identical replay is a no-op, but a conflicting payload under an existing event id fails closed rather than swallowing a state transition.
- **Status-list index allocation**: durable per-list counter (`status_list_allocator`, migration `0003`) serialized by `INSERT ... ON CONFLICT DO UPDATE ... RETURNING`, so concurrent replicas allocate disjoint bitstring indices and restarts resume without collision; a `UNIQUE (issuer, status_list_id, status_list_index)` index backstops the invariant. The retired in-process counter (`BLUEECONOMY_STATUS_LIST_INDEX_START`) is removed.
- **Events**: platform envelope `envelopeVersion 1.0` with deterministic `eventId`, FHIR R4 Bundle message entry (VC carried as a base64 `DocumentReference` attachment), provenance (principalId, principalRole, Ed25519 signature over the SHA-256 digest of the JCS-canonical payload, TigerBeetle `ledgerCommitHash`), classification `CONFIDENTIAL`. Published through the transactional outbox to Kafka topics `seafarer.credential.v1` / `seafarer.revocation.v1` (`kafkajs`, idempotent producer).
- **Ledger**: TigerBeetle issuance ledger behind the `IssuanceLedger` interface; transfer IDs are deterministic SHA-256 derivations so retries are idempotent (`exists` is a successful replay). Fail-closed without `BLUEECONOMY_TIGERBEETLE_ADDRESSES`.

## Configuration

Required (fail-closed): `BLUEECONOMY_ISSUER_DID`, `BLUEECONOMY_ISSUER_ED25519_PKCS8_PEM_PATH`, `BLUEECONOMY_STATUS_LIST_URL`, `BLUEECONOMY_STATUS_DATABASE_URL`, `BLUEECONOMY_TIGERBEETLE_ADDRESSES`, `BLUEECONOMY_TEMPORAL_ADDRESS`, `BLUEECONOMY_OIDC_JWKS_URL`, `BLUEECONOMY_OIDC_ISSUER`, `BLUEECONOMY_OIDC_AUDIENCE`, `POLICY_DIR` (PBAC policy directory). Envelope-signature consumers additionally require `KEY_DIRECTORY_PATH` (mounted producer public-key directory). Optional: `BLUEECONOMY_KAFKA_BROKERS` (outbox publisher), `BLUEECONOMY_OIDC_ROLES_CLIENT_IDS`, `PORT` (default 8080), `BLUEECONOMY_EVENT_PRODUCER`, `BLUEECONOMY_TEMPORAL_NAMESPACE`.

## Crew welfare / MLC module (phase 8)

`src/welfare/` implements the crew-welfare bounded context (MLC 2006 Reg 5.1.5/5.2.2 complaints with anti-victimization identity withholding and maker/checker dual control, Reg 2.3 work/rest record surfacing with policy-versioned breach flags, Reg 4.4 shore-welfare provider directory and consent-bound referrals). Routes mount under `/v1/welfare/*` and `/v1/rest-hours/*`; events publish to the Kafka topic `seafarers.welfare.v1` through the shared transactional outbox with JWS-signed envelopes (fleet scheme, `docs/envelope-signature.md` in blueeconomy-contracts). Welfare envelopes carry an empty `ledgerCommitHash` by design (documented deviation): their durability binding is the outbox row, matching the contracts fixtures (`fixtures/welfare/*.json`). Schema lives in migration `0006_welfare_mlc.sql` (append-only audit triggers, maker≠checker CHECK, Reg 5.1.5(3) redress-ack CHECK).

Welfare-specific configuration:

- `BLUEECONOMY_WELFARE_NARRATIVE_KEY` — 64 lowercase hex chars (32 bytes), AES-256-GCM key for complaint narratives. Secrets are env-only; when unset, complaint intake answers 503-honest (fail-closed), never stores plaintext.
- `BLUEECONOMY_WELFARE_POLICY_PATH` — path to the signed welfare-policy document (JWS compact, EdDSA over JCS-canonical claims, verified against `KEY_DIRECTORY_PATH`). It selects the Reg 2.3 regime (`min_rest` vs `max_work`) and the complaint SLA budgets. Unset degrades mutation endpoints to 503; a set-but-invalid document aborts startup (fail-closed).
- `KEY_DIRECTORY_PATH` — shared producer public-key directory; also the trust root for the signed welfare policy.
- `BLUEECONOMY_WELFARE_TASK_QUEUE` — Temporal task queue for the complaint SLA observer workflows (default `seafarer-welfare`); the welfare worker runs as `npm run worker:welfare` (`node dist/welfare/worker.js`) against `BLUEECONOMY_TEMPORAL_ADDRESS`.
- `BLUEECONOMY_WELFARE_SIGNING_KID` — kid for emitted welfare envelopes (default `<producer>-1`).
- `BLUEECONOMY_WELFARE_CURATION_CONTACT` — contact surfaced by the honest empty-directory state.

Welfare tests: unit suites (`tests/welfare-rules-policy.test.ts`, `tests/welfare-service.test.ts`), the HTTP surface suite (`tests/welfare-http.test.ts`, 15 routes, PBAC denials included), the DB-gated suite (`tests/welfare-postgres.test.ts`, requires PostgreSQL; fresh dedicated database per run) and the broker-gated suite (`tests/welfare-broker.test.ts`, requires PostgreSQL + Kafka; drains the real outbox to `seafarers.welfare.v1` and verifies envelopes byte-for-byte with an independent consumer-side verifier).

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
