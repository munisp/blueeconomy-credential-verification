/**
 * Single source of truth for the committed JSON Schema contracts. The files
 * under schemas/ are generated from these definitions by
 * scripts/generate-schemas.ts and guarded against drift by
 * tests/schema-drift.test.ts. Never edit the committed files by hand.
 */

export interface JsonSchemaDocument {
  $schema: "https://json-schema.org/draft/2020-12/schema";
  $id: string;
  title: string;
  [key: string]: unknown;
}

export interface ContractFile {
  path: string;
  schema: JsonSchemaDocument;
}

const SHA256_HEX = "^[0-9a-f]{64}$";
const CANONICAL_KEY_ID = "^[A-Za-z0-9._:-]{1,128}$";

export const ISSUER_POLICY_SCHEMA: JsonSchemaDocument = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://contracts.blueeconomy.local/s4/issuer-policy.schema.json",
  title: "S4 Approved Issuer Policy",
  type: "object",
  additionalProperties: false,
  required: ["schema_version", "issuer", "audience", "jwks_url", "algorithms", "active"],
  properties: {
    schema_version: { const: "blueeconomy.credential.issuer-policy.v1" },
    issuer: { type: "string", format: "uri", pattern: "^https://" },
    audience: { type: "string", minLength: 1, maxLength: 256 },
    jwks_url: { type: "string", format: "uri", pattern: "^https://" },
    algorithms: { type: "array", minItems: 1, uniqueItems: true, items: { enum: ["RS256", "ES256", "EdDSA"] } },
    key_ids: { type: "array", minItems: 1, uniqueItems: true, items: { type: "string", pattern: CANONICAL_KEY_ID } },
    active: { type: "boolean" },
  },
};

export const SIGNED_STATUS_RECORD_SCHEMA: JsonSchemaDocument = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://contracts.blueeconomy.local/s4/signed-status-record.schema.json",
  title: "S4 Signed Credential Status Record",
  type: "object",
  additionalProperties: false,
  required: ["protected_jws", "claims"],
  properties: {
    protected_jws: { type: "string", minLength: 1, description: "Compact JWS over the canonical status claims." },
    claims: {
      type: "object",
      additionalProperties: false,
      required: ["schema_version", "sequence", "credential_id_reference_sha256", "status", "reason", "effective_at", "updated_by", "issuer"],
      properties: {
        schema_version: { const: "blueeconomy.credential.status.v1" },
        sequence: { type: "integer", minimum: 1 },
        credential_id_reference_sha256: { type: "string", pattern: SHA256_HEX },
        status: { enum: ["ACTIVE", "SUSPENDED", "REVOKED"] },
        reason: { type: "string", minLength: 1, maxLength: 512 },
        effective_at: { type: "string", format: "date-time" },
        updated_by: { type: "string", minLength: 1, maxLength: 256 },
        issuer: { type: "string", minLength: 1, maxLength: 512 },
      },
    },
  },
};

export const SEAFARER_COC_SUBJECT_SCHEMA: JsonSchemaDocument = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://contracts.blueeconomy.local/seafarer/seafarer-coc-subject.schema.json",
  title: "Seafarer Certificate of Competency Credential Subject",
  type: "object",
  additionalProperties: false,
  required: ["id", "type", "seafarerReferenceNumber", "capacity", "stcwRegulation", "limitations"],
  properties: {
    id: { type: "string", minLength: 1, maxLength: 256, description: "Holder binding identifier (DID or platform subject)." },
    type: { const: "Seafarer" },
    seafarerReferenceNumber: { type: "string", minLength: 1, maxLength: 64 },
    capacity: { type: "string", minLength: 1, maxLength: 128, description: "STCW capacity, e.g. 'Master on ships of 500 GT or more'." },
    stcwRegulation: { type: "string", pattern: "^STCW (regulation )?[A-Za-z]+(-[A-Za-z]+)?/[0-9]+(\\.[0-9]+)?( paragraph [0-9]+)?$" },
    limitations: { type: "array", uniqueItems: true, items: { type: "string", minLength: 1, maxLength: 256 } },
    name: { type: "string", minLength: 1, maxLength: 256 },
    nationality: { type: "string", minLength: 1, maxLength: 64 },
  },
};

export const PLATFORM_ENVELOPE_SCHEMA: JsonSchemaDocument = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://contracts.blueeconomy.local/events/platform-envelope.schema.json",
  title: "Blue Economy Platform Event Envelope",
  type: "object",
  additionalProperties: false,
  required: ["envelopeVersion", "eventId", "eventType", "occurredAt", "producer", "correlationId", "fhir", "provenance", "classification"],
  properties: {
    envelopeVersion: { const: "1.0" },
    eventId: { type: "string", pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" },
    // Phase-8 crew welfare / MLC event types mirror the contracts enum
    // (blueeconomy-contracts proto/blueeconomy/contracts/v1/welfare.proto,
    // topic seafarers.welfare.v1).
    eventType: {
      enum: [
        "seafarer.credential.v1",
        "seafarer.revocation.v1",
        "seafarer.welfare.complaint.v1",
        "seafarer.welfare.complaint_status.v1",
        "seafarer.welfare.referral.v1",
        "seafarer.rest_hours.flagged.v1",
      ],
    },
    occurredAt: { type: "string", format: "date-time" },
    producer: { type: "string", minLength: 1, maxLength: 128 },
    correlationId: { type: "string", minLength: 1, maxLength: 128 },
    fhir: {
      type: "object",
      required: ["resourceType", "type", "entry"],
      properties: {
        resourceType: { const: "Bundle" },
        type: { const: "message" },
        timestamp: { type: "string", format: "date-time" },
        entry: { type: "array", minItems: 1 },
      },
    },
    provenance: {
      type: "object",
      additionalProperties: false,
      required: ["principalId", "principalRole", "signature", "ledgerCommitHash"],
      properties: {
        principalId: { type: "string", minLength: 1, maxLength: 256 },
        principalRole: { type: "string", minLength: 1, maxLength: 128 },
        signature: {
          type: "string",
          pattern: "^(z[1-9A-HJ-NP-Za-km-z]+|[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+)$",
          description: "Either the legacy multibase base58btc Ed25519 signature over the SHA-256 digest of the JCS-canonical envelope payload, or the fleet JWS compact serialization (EdDSA) per docs/envelope-signature.md used by phase-8 producers.",
        },
        // Welfare events carry an empty ledgerCommitHash (their durability
        // binding is the transactional outbox row; the issuance TigerBeetle
        // ledger does not cover the welfare boundary) — matching the
        // committed contracts fixtures.
        ledgerCommitHash: { type: "string", pattern: "^([0-9a-f]{64})?$" },
      },
    },
    classification: { const: "CONFIDENTIAL" },
  },
};

export function contractFiles(): ContractFile[] {
  return [
    { path: "schemas/issuer-policy.schema.json", schema: ISSUER_POLICY_SCHEMA },
    { path: "schemas/signed-status-record.schema.json", schema: SIGNED_STATUS_RECORD_SCHEMA },
    { path: "schemas/seafarer-coc-subject.schema.json", schema: SEAFARER_COC_SUBJECT_SCHEMA },
    { path: "schemas/platform-envelope.schema.json", schema: PLATFORM_ENVELOPE_SCHEMA },
  ];
}

export function renderSchema(schema: JsonSchemaDocument): string {
  return `${JSON.stringify(schema, null, 2)}\n`;
}
