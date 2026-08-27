import { createHash, createPublicKey, type KeyObject } from "node:crypto";
import { buildPlatformEnvelope, deterministicEventId, vcDocumentReferenceResource } from "../events/envelope.js";
import type { IssuanceLedger } from "../ledger/issuance-ledger.js";
import type { EligibilityGate } from "../temporal/eligibility-gate.js";
import type { OutboxMessage, StatusStore } from "../status/store.js";
import { canonicalizeJson, asJsonValue, type JsonValue } from "../vc/jcs.js";
import { addDataIntegrityProof } from "../vc/data-integrity.js";
import { issueCoCCredential, type IssuerConfiguration } from "../vc/issuer.js";
import {
  buildStatusListCredential,
  createBitstring,
  setStatusBit,
  statusListCredentialToJson,
  type BitstringStatusListCredential,
} from "../vc/status-list.js";
import { verifyCoCCredential, type VerificationResult } from "../vc/verifier.js";
import type { SeafarerCoCCredential } from "../vc/types.js";

/**
 * Composition layer for issuance, verification, revocation and status-list
 * publication. Issuance is gated on the credential-eligibility workflow stage
 * and the caller principal (role enforcement happens at the HTTP edge).
 */

export interface IssueCredentialInput {
  workflowId: string;
  seafarerId: string;
  holderId: string;
  seafarerReferenceNumber: string;
  capacity: string;
  stcwRegulation: string;
  limitations: string[];
  validUntil: string;
  name?: string;
  nationality?: string;
}

export interface Principal {
  subject: string;
  role: string;
}

export interface IssuedCredentialResult {
  credential: SeafarerCoCCredential;
  eventId: string;
  ledgerCommitHash: string;
}

export interface RevokeCredentialInput {
  credentialId: string;
  holderId: string;
  reason: string;
}

export interface CredentialServiceDependencies {
  issuer: IssuerConfiguration;
  statusStore: StatusStore;
  ledger: IssuanceLedger;
  eligibilityGate: EligibilityGate;
  producer: string;
  statusListId: string;
  allocateStatusListIndex(): number;
}

export class CredentialService {
  private readonly allocation: { next: number };

  public constructor(private readonly deps: CredentialServiceDependencies) {
    this.allocation = { next: 0 };
  }

  public async issueCredential(input: IssueCredentialInput, principal: Principal): Promise<IssuedCredentialResult> {
    const decision = await this.deps.eligibilityGate.check(input.workflowId, input.seafarerId);
    if (!decision.eligible) {
      throw new ServiceError(409, `seafarer workflow has not reached credential eligibility (stage ${decision.observation.stage})`);
    }
    const validUntil = new Date(input.validUntil);
    if (!Number.isFinite(validUntil.getTime())) throw new ServiceError(400, "validUntil must be a valid date-time");
    const now = new Date();
    const credentialId = `urn:uuid:${deterministicEventId("seafarer.credential.v1", `issue|${input.workflowId}|${input.holderId}`)}`;
    const statusListIndex = this.deps.allocateStatusListIndex();
    const credential = issueCoCCredential(this.deps.issuer, {
      credentialId,
      holderId: input.holderId,
      seafarerReferenceNumber: input.seafarerReferenceNumber,
      capacity: input.capacity,
      stcwRegulation: input.stcwRegulation,
      limitations: input.limitations,
      statusListIndex,
      validFrom: now,
      validUntil,
      ...(input.name !== undefined ? { name: input.name } : {}),
      ...(input.nationality !== undefined ? { nationality: input.nationality } : {}),
    });

    const commit = await this.deps.ledger.record({
      credentialId, holderReference: input.holderId, issuer: this.deps.issuer.issuerDid,
      kind: "issuance", occurredAt: now.toISOString(),
    });
    const canonicalCredential = canonicalizeJson(asJsonValue(credential));
    const envelope = buildPlatformEnvelope({
      eventType: "seafarer.credential.v1",
      producer: this.deps.producer,
      correlationId: decision.observation.correlationId,
      principal: { principalId: principal.subject, principalRole: principal.role },
      resource: vcDocumentReferenceResource(credentialId, input.holderId, canonicalCredential),
      ledgerCommitHash: commit.commitHash,
      signingKey: this.deps.issuer.privateKey,
      deduplicationKey: `issue|${credentialId}`,
    });
    const outbox: OutboxMessage = {
      topic: "seafarer.credential.v1",
      eventId: envelope.eventId,
      payload: envelope as unknown as Record<string, unknown>,
    };
    await this.deps.statusStore.setStatus({
      credentialId,
      status: "ACTIVE",
      reason: "issued",
      updatedBy: principal.subject,
      issuer: this.deps.issuer.issuerDid,
      statusListId: this.deps.statusListId,
      statusListIndex,
      effectiveAt: now,
    }, outbox);
    return { credential, eventId: envelope.eventId, ledgerCommitHash: commit.commitHash };
  }

  public async verifyCredential(credential: unknown, holderId: string): Promise<VerificationResult> {
    if (typeof holderId !== "string" || holderId.trim().length === 0) {
      throw new ServiceError(400, "holderId is required for holder binding verification");
    }
    const statusListCredential = await this.currentStatusListCredential();
    try {
      return verifyCoCCredential({
        credential,
        issuerPublicKey: issuerVerificationKey(this.deps.issuer),
        expectedIssuer: this.deps.issuer.issuerDid,
        expectedHolderId: holderId,
        statusListCredential,
      });
    } catch (error) {
      throw new ServiceError(422, error instanceof Error ? error.message : "credential verification failed");
    }
  }

  public async revokeCredential(input: RevokeCredentialInput, principal: Principal): Promise<{ eventId: string; ledgerCommitHash: string }> {
    const existing = await this.deps.statusStore.getStatus(input.credentialId, this.deps.issuer.issuerDid);
    if (existing === undefined) throw new ServiceError(404, "credential is unknown to this issuer");
    const now = new Date();
    const commit = await this.deps.ledger.record({
      credentialId: input.credentialId, holderReference: input.holderId,
      issuer: this.deps.issuer.issuerDid, kind: "revocation", occurredAt: now.toISOString(),
    });
    const envelope = buildPlatformEnvelope({
      eventType: "seafarer.revocation.v1",
      producer: this.deps.producer,
      correlationId: `revoke|${input.credentialId}`,
      principal: { principalId: principal.subject, principalRole: principal.role },
      resource: {
        resourceType: "Communication",
        status: "completed",
        subject: { reference: input.holderId },
        payload: [{ contentString: `revocation: ${input.reason}` }],
      },
      ledgerCommitHash: commit.commitHash,
      signingKey: this.deps.issuer.privateKey,
      deduplicationKey: `revocation|${input.credentialId}`,
    });
    await this.deps.statusStore.setStatus({
      credentialId: input.credentialId,
      status: "REVOKED",
      reason: input.reason,
      updatedBy: principal.subject,
      issuer: this.deps.issuer.issuerDid,
      statusListId: existing.statusListId,
      statusListIndex: existing.statusListIndex,
      effectiveAt: now,
    }, { topic: "seafarer.revocation.v1", eventId: envelope.eventId, payload: envelope as unknown as Record<string, unknown> });
    return { eventId: envelope.eventId, ledgerCommitHash: commit.commitHash };
  }

  /** Builds and signs the current Bitstring Status List credential snapshot. */
  public async currentStatusListCredential(): Promise<BitstringStatusListCredential> {
    const rows = await this.deps.statusStore.listStatusBits(this.deps.issuer.issuerDid, this.deps.statusListId);
    const bits = createBitstring();
    for (const row of rows) setStatusBit(bits, row.statusListIndex, row.revoked);
    const unsigned = buildStatusListCredential(this.deps.statusListId, this.deps.issuer.issuerDid, bits, new Date());
    const proof = addDataIntegrityProof(statusListCredentialToJson(unsigned), {
      created: new Date().toISOString(),
      verificationMethod: this.deps.issuer.verificationMethod,
      proofPurpose: "assertionMethod",
    }, this.deps.issuer.privateKey);
    return { ...unsigned, proof: proof as unknown as Record<string, JsonValue> };
  }
}

export class ServiceError extends Error {
  public constructor(
    public readonly statusCode: number,
    message: string,
  ) {
    super(message);
  }
}

export function issuerVerificationKey(configuration: IssuerConfiguration): KeyObject {
  return createPublicKey(configuration.privateKey);
}

export function credentialDigest(credential: SeafarerCoCCredential): string {
  return createHash("sha256").update(canonicalizeJson(asJsonValue(credential)), "utf8").digest("hex");
}
