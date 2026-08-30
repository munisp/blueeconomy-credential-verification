import { CompactSign, type KeyObject } from "jose";
import { canonicalizeBytes, asJsonValue, type JsonValue } from "../vc/jcs.js";
import { deterministicUuid } from "./types.js";

/**
 * Welfare event envelopes (envelopeVersion 1.0) for the seafarers.welfare.v1
 * topic, signed per the fleet scheme in blueeconomy-contracts
 * docs/envelope-signature.md: provenance.signature is a JWS compact
 * serialization (EdDSA/Ed25519) whose payload byte-equals the
 * JCS-canonicalized (RFC 8785) envelope minus the signature field, with
 * protected header {"alg":"EdDSA","kid":"<producer>-<epoch>"}; consumers
 * verify with src/events/envelope-verification.ts against the mounted key
 * directory. Every welfare envelope is classified CONFIDENTIAL.
 *
 * Note (documented deviation from the legacy producer in
 * src/events/envelope.ts): that builder predates the fleet JWS scheme
 * (multibase raw signature) and mandates a TigerBeetle ledgerCommitHash.
 * Welfare events follow the normative contracts document and the committed
 * fixtures (fixtures/welfare/*.json carry an empty ledgerCommitHash): the
 * welfare module's durability binding is the transactional outbox row, not
 * the issuance ledger, so ledgerCommitHash is emitted empty.
 */

export const WELFARE_TOPIC = "seafarers.welfare.v1";
export const WELFARE_ENVELOPE_VERSION = "1.0" as const;
export const WELFARE_CLASSIFICATION = "CONFIDENTIAL" as const;

export const WELFARE_EVENT_TYPES = [
  "seafarer.welfare.complaint.v1",
  "seafarer.welfare.complaint_status.v1",
  "seafarer.welfare.referral.v1",
  "seafarer.rest_hours.flagged.v1",
] as const;
export type WelfareEventType = (typeof WELFARE_EVENT_TYPES)[number];

export interface WelfareEnvelopeInput {
  eventType: WelfareEventType;
  producer: string;
  correlationId: string;
  principal: { principalId: string; principalRole: string };
  /** Proto-JSON resource carried as the FHIR Bundle message entry. */
  resource: Record<string, JsonValue>;
  signingKey: KeyObject;
  /** kid of the producer signing key ("<producer>-<epoch>"). */
  keyId: string;
  /** Idempotency key making eventId deterministic across retries. */
  deduplicationKey: string;
  occurredAt?: Date;
}

export interface WelfareEnvelope {
  envelopeVersion: typeof WELFARE_ENVELOPE_VERSION;
  eventId: string;
  eventType: WelfareEventType;
  occurredAt: string;
  producer: string;
  correlationId: string;
  fhir: Record<string, JsonValue>;
  provenance: {
    principalId: string;
    principalRole: string;
    ledgerCommitHash: string;
    signature: string;
  };
  classification: typeof WELFARE_CLASSIFICATION;
  recordClassification: typeof WELFARE_CLASSIFICATION;
}

export async function buildWelfareEnvelope(input: WelfareEnvelopeInput): Promise<WelfareEnvelope> {
  if (!(WELFARE_EVENT_TYPES as readonly string[]).includes(input.eventType)) {
    throw new Error(`event type ${input.eventType} is not in the welfare contracts enum (fail-closed)`);
  }
  assertCanonicalText(input.producer, "producer", 128);
  assertCanonicalText(input.correlationId, "correlationId", 128);
  assertCanonicalText(input.principal.principalId, "principalId", 256);
  assertCanonicalText(input.principal.principalRole, "principalRole", 128);
  assertCanonicalText(input.deduplicationKey, "deduplicationKey", 256);
  if (!/^[A-Za-z0-9._-]{1,256}$/.test(input.keyId)) throw new Error("keyId is malformed");
  if ((input.signingKey as unknown as { asymmetricKeyType?: string }).asymmetricKeyType !== "ed25519") throw new Error("welfare envelope signing key must be Ed25519");
  if (typeof input.resource["@type"] !== "string") {
    throw new Error("welfare event resource must carry its proto @type");
  }
  const occurredAt = (input.occurredAt ?? new Date()).toISOString();
  const eventId = deterministicUuid("event", `${input.eventType}|${input.deduplicationKey}`).slice("urn:uuid:".length);
  const envelope: Record<string, JsonValue> = {
    envelopeVersion: WELFARE_ENVELOPE_VERSION,
    eventId,
    eventType: input.eventType,
    occurredAt,
    producer: input.producer,
    correlationId: input.correlationId,
    fhir: {
      resourceType: "Bundle",
      type: "message",
      timestamp: occurredAt,
      entry: [{ fullUrl: `urn:uuid:${eventId}`, resource: asJsonValue(input.resource) }],
    },
    provenance: {
      principalId: input.principal.principalId,
      principalRole: input.principal.principalRole,
      ledgerCommitHash: "",
    },
    classification: WELFARE_CLASSIFICATION,
    recordClassification: WELFARE_CLASSIFICATION,
  };
  const payload = canonicalizeBytes(asJsonValue(envelope));
  const signature = await new CompactSign(payload)
    .setProtectedHeader({ alg: "EdDSA", kid: input.keyId })
    .sign(input.signingKey);
  const provenance = envelope["provenance"] as Record<string, JsonValue>;
  provenance["signature"] = signature;
  return envelope as unknown as WelfareEnvelope;
}

function assertCanonicalText(value: string, field: string, maxLength: number): void {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0 || value.length > maxLength) {
    throw new Error(`${field} must be canonical text of 1-${maxLength} characters`);
  }
}
