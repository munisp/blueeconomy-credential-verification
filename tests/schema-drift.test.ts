import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";

import { contractFiles, renderSchema, ISSUER_POLICY_SCHEMA, PLATFORM_ENVELOPE_SCHEMA, SEAFARER_COC_SUBJECT_SCHEMA } from "../src/contracts.js";
import { validateAgainstSchema } from "../src/json-schema-lite.js";
import { StatusRegistry } from "../src/status-registry.js";
import { buildPlatformEnvelope, vcDocumentReferenceResource } from "../src/events/envelope.js";
import { canonicalizeJson, asJsonValue } from "../src/vc/jcs.js";
import { generateEphemeralIssuerKeyPair, issueCoCCredential, type IssuerConfiguration } from "../src/vc/issuer.js";
import { SIGNED_STATUS_RECORD_SCHEMA } from "../src/contracts.js";

const repositoryRoot = resolve(fileURLToPath(new URL(".", import.meta.url)), "..");

test("committed schemas match the generated contracts (drift guard)", async () => {
  for (const contract of contractFiles()) {
    const committed = await readFile(join(repositoryRoot, contract.path), "utf8");
    assert.equal(
      committed,
      renderSchema(contract.schema),
      `schema drift detected in ${contract.path}: regenerate with scripts/generate-schemas.ts`,
    );
  }
});

test("issuer policy schema requires schema_version and accepts a valid policy", () => {
  const valid = {
    schema_version: "blueeconomy.credential.issuer-policy.v1",
    issuer: "https://issuer.example.test/",
    audience: "fmmbe",
    jwks_url: "https://issuer.example.test/.well-known/jwks.json",
    algorithms: ["RS256"],
    active: true,
  };
  assert.deepEqual(validateAgainstSchema(valid, ISSUER_POLICY_SCHEMA), []);
  const missingVersion = { ...valid } as Record<string, unknown>;
  delete missingVersion["schema_version"];
  assert.ok(validateAgainstSchema(missingVersion, ISSUER_POLICY_SCHEMA).some((error) => error.includes("schema_version")));
});

test("signed status record schema matches the records the registry writes", async () => {
  const directory = await mkdtemp(join(tmpdir(), "blueeconomy-schema-status-"));
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const registry = new StatusRegistry({
    path: join(directory, "status.jsonl"),
    issuer: "https://issuer.example.test",
    key: privateKey as never,
    algorithm: "RS256",
    keyId: "key-2026-01",
  });
  const record = await registry.setStatus("jti-schema-001", "ACTIVE", "issued", "issuer-operator");
  assert.deepEqual(
    validateAgainstSchema(JSON.parse(JSON.stringify(record)), SIGNED_STATUS_RECORD_SCHEMA),
    [],
  );
  const drifted = JSON.parse(JSON.stringify(record)) as Record<string, unknown>;
  delete drifted["protected_jws"];
  assert.ok(validateAgainstSchema(drifted, SIGNED_STATUS_RECORD_SCHEMA).some((error) => error.includes("protected_jws")));
});

test("seafarer CoC subject schema accepts the code-produced credential subject", () => {
  const { privateKey } = generateEphemeralIssuerKeyPair();
  const issuer: IssuerConfiguration = {
    issuerDid: "did:web:credentials.nimasa.gov.ng",
    verificationMethod: "did:web:credentials.nimasa.gov.ng#ed25519-key-1",
    privateKey,
    statusListCredentialUrl: "https://credentials.nimasa.gov.ng/v1/status-list/main",
  };
  const credential = issueCoCCredential(issuer, {
    credentialId: "urn:uuid:11111111-2222-3333-4444-555555555555",
    holderId: "did:web:wallet.example.test:seafarer:ng-0001",
    seafarerReferenceNumber: "NG-SRN-0001",
    capacity: "Master on ships of 500 GT or more",
    stcwRegulation: "STCW regulation II/2",
    limitations: ["Near-coastal voyages only"],
    statusListIndex: 0,
    validFrom: new Date("2026-01-01T00:00:00.000Z"),
    validUntil: new Date("2031-01-01T00:00:00.000Z"),
  }, new Date("2026-01-01T00:00:00.000Z"));
  assert.deepEqual(
    validateAgainstSchema(JSON.parse(JSON.stringify(credential.credentialSubject)), SEAFARER_COC_SUBJECT_SCHEMA),
    [],
  );
});

test("platform envelope schema accepts the code-produced envelope", () => {
  const { privateKey } = generateEphemeralIssuerKeyPair();
  const canonicalCredential = canonicalizeJson(asJsonValue({ credential: "payload" }));
  const envelope = buildPlatformEnvelope({
    eventType: "seafarer.credential.v1",
    producer: "blueeconomy-credential-verification",
    correlationId: "workflow-001",
    principal: { principalId: "nimasa-approver-01", principalRole: "nimasa-approver" },
    resource: vcDocumentReferenceResource("urn:uuid:abc", "did:web:wallet.example.test:seafarer:ng-0001", canonicalCredential),
    ledgerCommitHash: "a".repeat(64),
    signingKey: privateKey,
    deduplicationKey: "issue|urn:uuid:abc",
    occurredAt: new Date("2026-01-01T00:00:00.000Z"),
  });
  assert.deepEqual(
    validateAgainstSchema(JSON.parse(JSON.stringify(envelope)), PLATFORM_ENVELOPE_SCHEMA),
    [],
  );
});
