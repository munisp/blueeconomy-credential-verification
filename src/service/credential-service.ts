import { createHash, createPublicKey, type KeyObject } from "node:crypto";
import { buildPlatformEnvelope, deterministicEventId, vcDocumentReferenceResource } from "../events/envelope.js";
import type { IssuanceLedger } from "../ledger/issuance-ledger.js";
import {
  ApprovalStateError,
  assertMakerCheckerSeparation,
  deterministicApprovalRequestId,
  type ApprovalRequest,
  type ApprovalStore,
} from "./maker-checker.js";
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
import { withSpan } from "../telemetry/spans.js";

/**
 * Composition layer for issuance, verification, revocation and status-list
 * publication. Issuance is gated on the credential-eligibility workflow stage
 * and the caller principal (role enforcement happens at the HTTP edge).
 * Issuance and revocation execute under maker/checker dual control: one
 * NIMASA-approver-tier officer submits a persisted PENDING request and a
 * second, distinct officer approves it; only then does the mutation run
 * (with the eligibility gate re-evaluated at execution time, fail-closed).
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

/** Pending maker/checker request returned to the submitting officer. */
export interface PendingApprovalResult {
  requestId: string;
  kind: "issuance" | "revocation";
  status: "PENDING";
  requester: string;
  requestedAt: string;
}

export interface CredentialServiceDependencies {
  issuer: IssuerConfiguration;
  statusStore: StatusStore;
  approvals: ApprovalStore;
  ledger: IssuanceLedger;
  eligibilityGate: EligibilityGate;
  producer: string;
  statusListId: string;
  allocateStatusListIndex(): Promise<number>;
}

export class CredentialService {
  public constructor(private readonly deps: CredentialServiceDependencies) {}

  public async issueCredential(input: IssueCredentialInput, principal: Principal): Promise<IssuedCredentialResult> {
    // Phase-7 OTel: manual span on the issuance decision path. No PII on the
    // span — no holder/seafarer identifiers, only operational attributes.
    return withSpan("vc.issue", {
      attributes: { "vc.stcw_regulation": input.stcwRegulation },
    }, async (span) => {
      const result = await this.issueCredentialInner(input, principal, span);
      return result;
    });
  }

  private async issueCredentialInner(input: IssueCredentialInput, principal: Principal, span: { setAttribute(key: string, value: string | number | boolean): void }): Promise<IssuedCredentialResult> {
    const decision = await this.deps.eligibilityGate.check(input.workflowId, input.seafarerId);
    if (!decision.eligible) {
      throw new ServiceError(409, `seafarer workflow has not reached credential eligibility (stage ${decision.observation.stage})`);
    }
    const validUntil = new Date(input.validUntil);
    if (!Number.isFinite(validUntil.getTime())) throw new ServiceError(400, "validUntil must be a valid date-time");
    const now = new Date();
    const credentialId = `urn:uuid:${deterministicEventId("seafarer.credential.v1", `issue|${input.workflowId}|${input.holderId}`)}`;
    // Revocation is terminal: re-issuing a revoked credential would silently
    // reverse a published revocation, so refuse truthfully before allocating.
    const existingStatus = await this.deps.statusStore.getStatus(credentialId, this.deps.issuer.issuerDid);
    if (existingStatus?.status === "REVOKED") {
      throw new ServiceError(409, "credential is revoked; re-issuance is prohibited because revocation is terminal");
    }
    const statusListIndex = await this.deps.allocateStatusListIndex();
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
      issuance: {
        holderId: input.holderId,
        document: credential as unknown as Record<string, unknown>,
        validUntil,
      },
    }, outbox);
    span.setAttribute("vc.status_list_index", statusListIndex);
    span.setAttribute("ledger.idempotent_replay", commit.idempotentReplay);
    return { credential, eventId: envelope.eventId, ledgerCommitHash: commit.commitHash };
  }

  /**
   * Maker step of dual-control issuance: validates the request against the
   * eligibility gate (re-evaluated again at execution) and persists a
   * PENDING approval request. Nothing is issued at this point.
   */
  public async requestCredentialIssuance(input: IssueCredentialInput, principal: Principal): Promise<PendingApprovalResult> {
    const decision = await this.deps.eligibilityGate.check(input.workflowId, input.seafarerId);
    if (!decision.eligible) {
      throw new ServiceError(409, `seafarer workflow has not reached credential eligibility (stage ${decision.observation.stage})`);
    }
    if (!Number.isFinite(Date.parse(input.validUntil))) throw new ServiceError(400, "validUntil must be a valid date-time");
    const credentialId = `urn:uuid:${deterministicEventId("seafarer.credential.v1", `issue|${input.workflowId}|${input.holderId}`)}`;
    const existingStatus = await this.deps.statusStore.getStatus(credentialId, this.deps.issuer.issuerDid);
    if (existingStatus?.status === "REVOKED") {
      throw new ServiceError(409, "credential is revoked; re-issuance is prohibited because revocation is terminal");
    }
    return this.submitApprovalRequest("issuance", { ...input }, principal);
  }

  /**
   * Checker step of dual-control issuance: a distinct NIMASA-approver-tier
   * officer approves the pending request and the credential is issued.
   */
  public async approveCredentialIssuance(requestId: string, principal: Principal): Promise<IssuedCredentialResult> {
    const request = await this.pendingRequest(requestId, "issuance", principal);
    const result = await this.issueCredential(issueInputFromPayload(request.payload), principal);
    await this.markApproved(request.requestId, principal.subject);
    return result;
  }

  /**
   * Maker step of dual-control revocation: verifies the credential exists
   * and is not already revoked, then persists a PENDING approval request.
   * The status bit is not flipped until a distinct approver completes.
   */
  public async requestCredentialRevocation(input: RevokeCredentialInput, principal: Principal): Promise<PendingApprovalResult> {
    const existing = await this.deps.statusStore.getStatus(input.credentialId, this.deps.issuer.issuerDid);
    if (existing === undefined) throw new ServiceError(404, "credential is unknown to this issuer");
    if (existing.status === "REVOKED") throw new ServiceError(409, "credential is already revoked; revocation is terminal");
    return this.submitApprovalRequest("revocation", { ...input }, principal);
  }

  /**
   * Checker step of dual-control revocation: a distinct NIMASA-approver-tier
   * officer approves the pending request and the revocation executes.
   */
  public async approveCredentialRevocation(requestId: string, principal: Principal): Promise<{ eventId: string; ledgerCommitHash: string }> {
    const request = await this.pendingRequest(requestId, "revocation", principal);
    const result = await this.revokeCredential(revokeInputFromPayload(request.payload), principal);
    await this.markApproved(request.requestId, principal.subject);
    return result;
  }

  private async submitApprovalRequest(
    kind: "issuance" | "revocation",
    payload: Record<string, unknown>,
    principal: Principal,
  ): Promise<PendingApprovalResult> {
    const request: ApprovalRequest = {
      requestId: deterministicApprovalRequestId(kind, payload),
      kind,
      payload,
      requesterSubject: principal.subject,
      requesterRole: principal.role,
      status: "PENDING",
      requestedAt: new Date().toISOString(),
    };
    const { record } = await this.deps.approvals.createApprovalRequest(request);
    if (record.status !== "PENDING") {
      throw new ServiceError(409, "an identical request was already approved and executed");
    }
    return { requestId: record.requestId, kind: record.kind, status: "PENDING", requester: record.requesterSubject, requestedAt: record.requestedAt };
  }

  private async pendingRequest(requestId: string, kind: "issuance" | "revocation", principal: Principal): Promise<ApprovalRequest> {
    const request = await this.deps.approvals.getApprovalRequest(requestId);
    if (request === undefined) throw new ServiceError(404, "approval request is unknown");
    if (request.kind !== kind) throw new ServiceError(409, `approval request ${requestId} is a ${request.kind} request`);
    if (request.status !== "PENDING") throw new ServiceError(409, "approval request is already approved");
    try {
      assertMakerCheckerSeparation(request.requesterSubject, principal.subject);
    } catch (error) {
      if (error instanceof ApprovalStateError) throw new ServiceError(409, error.message);
      throw error;
    }
    return request;
  }

  private async markApproved(requestId: string, approverSubject: string): Promise<void> {
    try {
      await this.deps.approvals.markApprovalRequestApproved(requestId, approverSubject);
    } catch (error) {
      if (error instanceof ApprovalStateError) throw new ServiceError(409, error.message);
      throw error;
    }
  }

  public async verifyCredential(credential: unknown, holderId: string): Promise<VerificationResult> {
    // Phase-7 OTel: manual span on the verification decision path. Only the
    // outcome and the checked status-list index are attributed — no PII.
    return withSpan("vc.verify", {}, async (span) => {
      if (typeof holderId !== "string" || holderId.trim().length === 0) {
        throw new ServiceError(400, "holderId is required for holder binding verification");
      }
      const statusListCredential = await this.currentStatusListCredential();
      try {
        const result = verifyCoCCredential({
          credential,
          issuerPublicKey: issuerVerificationKey(this.deps.issuer),
          expectedIssuer: this.deps.issuer.issuerDid,
          expectedHolderId: holderId,
          statusListCredential,
        });
        span.setAttribute("vc.verification.passed", true);
        span.setAttribute("vc.checked_status_list_index", result.checkedStatusListIndex);
        return result;
      } catch (error) {
        span.setAttribute("vc.verification.passed", false);
        throw new ServiceError(422, error instanceof Error ? error.message : "credential verification failed");
      }
    });
  }

  public async revokeCredential(input: RevokeCredentialInput, principal: Principal): Promise<{ eventId: string; ledgerCommitHash: string }> {
    // Phase-7 OTel: manual span on the revocation decision path; no PII.
    return withSpan("vc.revoke", {}, (span) => this.revokeCredentialInner(input, principal, span));
  }

  private async revokeCredentialInner(input: RevokeCredentialInput, principal: Principal, span: { setAttribute(key: string, value: string | number | boolean): void }): Promise<{ eventId: string; ledgerCommitHash: string }> {
    const existing = await this.deps.statusStore.getStatus(input.credentialId, this.deps.issuer.issuerDid);
    if (existing === undefined) throw new ServiceError(404, "credential is unknown to this issuer");
    if (existing.status === "REVOKED") throw new ServiceError(409, "credential is already revoked; revocation is terminal");
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
    span.setAttribute("ledger.idempotent_replay", commit.idempotentReplay);
    return { eventId: envelope.eventId, ledgerCommitHash: commit.commitHash };
  }

  /**
   * Returns the authenticated holder's current valid credential (ACTIVE,
   * non-expired), most recently issued first. Undefined when the holder has
   * none; the HTTP edge maps that to 404 so the wallet keeps its cache.
   */
  public async currentHolderCredential(holderSubject: string): Promise<SeafarerCoCCredential | undefined> {
    if (holderSubject.trim().length === 0) throw new ServiceError(400, "holder subject is required");
    const records = await this.deps.statusStore.listCurrentHolderCredentials(holderSubject, this.deps.issuer.issuerDid);
    const first = records[0];
    return first === undefined ? undefined : (first.document as unknown as SeafarerCoCCredential);
  }

  /**
   * Serves the signed status-list snapshot only when the requested id matches
   * the configured status-list credential id (or its trailing path segment,
   * which is how the singular route is addressed); anything else is a 404.
   */
  public async statusListCredential(requestedId: string): Promise<BitstringStatusListCredential> {
    if (!this.isConfiguredStatusListId(requestedId)) {
      throw new ServiceError(404, "status list is unknown to this issuer");
    }
    return this.currentStatusListCredential();
  }

  /** Public issuer key material for offline eddsa-jcs-2022 verification. */
  public issuerKeyMaterial(): { issuer: string; kid: string; publicKeyHex: string } {
    const jwk = createPublicKey(this.deps.issuer.privateKey).export({ format: "jwk" });
    const x = (jwk as { x?: string }).x;
    if (typeof x !== "string") throw new ServiceError(500, "issuer public key is unavailable");
    return {
      issuer: this.deps.issuer.issuerDid,
      kid: this.deps.issuer.verificationMethod,
      publicKeyHex: Buffer.from(x, "base64url").toString("hex"),
    };
  }

  private isConfiguredStatusListId(requestedId: string): boolean {
    const configured = this.deps.statusListId;
    if (requestedId === configured) return true;
    const segments = configured.split("/").filter((segment) => segment.length > 0);
    const trailing = segments[segments.length - 1];
    return trailing !== undefined && requestedId === trailing;
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

function payloadString(payload: Record<string, unknown>, field: string): string {
  const value = payload[field];
  if (typeof value !== "string" || value.trim() !== value || value.length === 0) {
    throw new ServiceError(422, `stored approval request payload field ${field} is invalid (fail-closed)`);
  }
  return value;
}

function payloadStringArray(payload: Record<string, unknown>, field: string): string[] {
  const value = payload[field];
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new ServiceError(422, `stored approval request payload field ${field} is invalid (fail-closed)`);
  }
  return value as string[];
}

/** Re-validates a persisted issuance payload fail-closed before execution. */
export function issueInputFromPayload(payload: Record<string, unknown>): IssueCredentialInput {
  const input: IssueCredentialInput = {
    workflowId: payloadString(payload, "workflowId"),
    seafarerId: payloadString(payload, "seafarerId"),
    holderId: payloadString(payload, "holderId"),
    seafarerReferenceNumber: payloadString(payload, "seafarerReferenceNumber"),
    capacity: payloadString(payload, "capacity"),
    stcwRegulation: payloadString(payload, "stcwRegulation"),
    limitations: payloadStringArray(payload, "limitations"),
    validUntil: payloadString(payload, "validUntil"),
  };
  if (typeof payload["name"] === "string") input.name = payload["name"];
  if (typeof payload["nationality"] === "string") input.nationality = payload["nationality"];
  return input;
}

/** Re-validates a persisted revocation payload fail-closed before execution. */
export function revokeInputFromPayload(payload: Record<string, unknown>): RevokeCredentialInput {
  return {
    credentialId: payloadString(payload, "credentialId"),
    holderId: payloadString(payload, "holderId"),
    reason: payloadString(payload, "reason"),
  };
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
