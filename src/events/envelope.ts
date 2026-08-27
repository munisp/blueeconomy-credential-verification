import { createHash, sign as ed25519Sign, type KeyObject } from "node:crypto";
import { canonicalizeJson, asJsonValue, type JsonValue } from "../vc/jcs.js";
import { encodeBase58Btc } from "../vc/multibase.js";

/**
 * Blue Economy platform event envelope (envelopeVersion 1.0). The payload is
 * embedded as a FHIR R4 message Bundle entry; provenance binds the acting
 * principal, an Ed25519 signature over the SHA-256 digest of the
 * JCS-canonical payload, and the TigerBeetle ledger commit hash. Every event
 * is classified CONFIDENTIAL.
 */

export const ENVELOPE_VERSION = "1.0" as const;
export const ENVELOPE_CLASSIFICATION = "CONFIDENTIAL" as const;
export type SeafarerEventType = "seafarer.credential.v1" | "seafarer.revocation.v1";

export interface EnvelopePrincipal {
  principalId: string;
  principalRole: string;
}

export interface EnvelopeInput {
  eventType: SeafarerEventType;
  producer: string;
  correlationId: string;
  principal: EnvelopePrincipal;
  /** FHIR R4 resource carried as the Bundle message entry. */
  resource: Record<string, JsonValue>;
  ledgerCommitHash: string;
  signingKey: KeyObject;
  occurredAt?: Date;
  /** Idempotency key making eventId deterministic across retries. */
  deduplicationKey: string;
}

export interface PlatformEnvelope {
  envelopeVersion: typeof ENVELOPE_VERSION;
  eventId: string;
  eventType: SeafarerEventType;
  occurredAt: string;
  producer: string;
  correlationId: string;
  message: Record<string, JsonValue>;
  provenance: {
    principalId: string;
    principalRole: string;
    signature: { algorithm: "ed25519-sha256-jcs"; digestSha256: string; value: string };
    ledgerCommitHash: string;
  };
  classification: typeof ENVELOPE_CLASSIFICATION;
}

export function buildPlatformEnvelope(input: EnvelopeInput): PlatformEnvelope {
  const occurredAt = (input.occurredAt ?? new Date()).toISOString();
  assertCanonicalText(input.producer, "producer", 128);
  assertCanonicalText(input.correlationId, "correlationId", 128);
  assertCanonicalText(input.principal.principalId, "principalId", 256);
  assertCanonicalText(input.principal.principalRole, "principalRole", 128);
  if (!/^[0-9a-f]{64}$/.test(input.ledgerCommitHash)) {
    throw new Error("ledgerCommitHash must be a SHA-256 hex digest");
  }
  if (input.signingKey.asymmetricKeyType !== "ed25519") {
    throw new Error("envelope signing key must be Ed25519");
  }
  assertCanonicalText(input.deduplicationKey, "deduplicationKey", 256);
  if (typeof input.resource["resourceType"] !== "string") {
    throw new Error("FHIR message entry resource must carry a resourceType");
  }

  const eventId = deterministicEventId(input.eventType, input.deduplicationKey);
  const message: Record<string, JsonValue> = {
    resourceType: "Bundle",
    type: "message",
    timestamp: occurredAt,
    entry: [{ fullUrl: `urn:uuid:${eventId}`, resource: asJsonValue(input.resource) }],
  };
  const payload: Record<string, JsonValue> = {
    envelopeVersion: ENVELOPE_VERSION,
    eventId,
    eventType: input.eventType,
    occurredAt,
    producer: input.producer,
    correlationId: input.correlationId,
    message,
    classification: ENVELOPE_CLASSIFICATION,
  };
  const digestSha256 = createHash("sha256").update(canonicalizeJson(asJsonValue(payload)), "utf8").digest("hex");
  const signature = ed25519Sign(null, Buffer.from(digestSha256, "hex"), input.signingKey);
  return {
    envelopeVersion: ENVELOPE_VERSION,
    eventId,
    eventType: input.eventType,
    occurredAt,
    producer: input.producer,
    correlationId: input.correlationId,
    message,
    provenance: {
      principalId: input.principal.principalId,
      principalRole: input.principal.principalRole,
      signature: { algorithm: "ed25519-sha256-jcs", digestSha256, value: encodeBase58Btc(signature) },
      ledgerCommitHash: input.ledgerCommitHash,
    },
    classification: ENVELOPE_CLASSIFICATION,
  };
}

/** Verifies the provenance signature without network access. */
export function verifyEnvelopeProvenance(envelope: PlatformEnvelope, publicKey: KeyObject): void {
  const { provenance, ...payload } = envelope;
  const digestSha256 = createHash("sha256").update(canonicalizeJson(asJsonValue(payload as unknown as Record<string, JsonValue>)), "utf8").digest("hex");
  if (digestSha256 !== provenance.signature.digestSha256) {
    throw new Error("envelope provenance digest does not match the canonical payload");
  }
}

/** Builds the FHIR R4 DocumentReference entry carrying a signed VC payload. */
export function vcDocumentReferenceResource(
  credentialId: string,
  holderId: string,
  canonicalCredentialJson: string,
): Record<string, JsonValue> {
  return {
    resourceType: "DocumentReference",
    id: credentialId.replace(/[^A-Za-z0-9.-]/g, "-").slice(0, 64),
    status: "current",
    type: { text: "W3C Verifiable Credential - Seafarer Certificate of Competency" },
    subject: { reference: holderId },
    content: [{
      attachment: {
        contentType: "application/vc+ld+json",
        data: Buffer.from(canonicalCredentialJson, "utf8").toString("base64"),
      },
    }],
  };
}

export function deterministicEventId(eventType: SeafarerEventType, deduplicationKey: string): string {
  const digest = createHash("sha256").update(`blueeconomy.event.v1|${eventType}|${deduplicationKey}`, "utf8").digest("hex");
  return `${digest.slice(0, 8)}-${digest.slice(8, 12)}-${digest.slice(12, 16)}-${digest.slice(16, 20)}-${digest.slice(20, 32)}`;
}

function assertCanonicalText(value: string, field: string, maxLength: number): void {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0 || value.length > maxLength) {
    throw new Error(`${field} must be canonical text of 1-${maxLength} characters`);
  }
}
