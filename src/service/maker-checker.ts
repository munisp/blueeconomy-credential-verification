import { createHash } from "node:crypto";

/**
 * Maker/checker (dual control) for seafarer credential issuance and
 * revocation, mirroring the separation-of-duties pattern of
 * blueeconomy-administration-service (ErrMakerCheckerViolation /
 * CanApprove): a mutation is submitted by one NIMASA-approver-tier officer
 * (the maker) into a persisted PENDING state and only executes when a
 * second, distinct officer of the same tier approves it (the checker).
 * The pending record is the audit trail: it binds the request payload to
 * the requester subject, the decision to the approver subject, and both
 * timestamps; the completing mutation additionally emits its signed
 * platform envelope naming the approver as principal.
 */

export type ApprovalKind = "issuance" | "revocation";
export type ApprovalStatus = "PENDING" | "APPROVED";

export interface ApprovalRequest {
  requestId: string;
  kind: ApprovalKind;
  payload: Record<string, unknown>;
  requesterSubject: string;
  requesterRole: string;
  status: ApprovalStatus;
  requestedAt: string;
  approverSubject?: string;
  decidedAt?: string;
}

export interface ApprovalRequestCreated {
  created: boolean;
  record: ApprovalRequest;
}

/**
 * Durable pending-approval store. Production deployments use the PostgreSQL
 * implementation (migration 0005), which enforces
 * requester_subject <> approver_subject as a database CHECK constraint as
 * defense in depth behind the service-layer comparison.
 */
export interface ApprovalStore {
  createApprovalRequest(request: ApprovalRequest): Promise<ApprovalRequestCreated>;
  getApprovalRequest(requestId: string): Promise<ApprovalRequest | undefined>;
  markApprovalRequestApproved(requestId: string, approverSubject: string): Promise<ApprovalRequest>;
}

/**
 * Thrown when an approval transition is refused: unknown request, wrong
 * state, or a maker/checker violation. The service maps it to 409.
 */
export class ApprovalStateError extends Error {}

/**
 * Maker/checker separation of duties, fail-closed: the approver must exist
 * and must differ from the requester.
 */
export function assertMakerCheckerSeparation(requesterSubject: string, approverSubject: string): void {
  if (requesterSubject.trim().length === 0 || approverSubject.trim().length === 0) {
    throw new ApprovalStateError("requester and approver subjects are required");
  }
  if (requesterSubject === approverSubject) {
    throw new ApprovalStateError("maker/checker violation: the requester cannot approve their own credential mutation");
  }
}

/**
 * Deterministic request id over the full request payload, so a retried
 * submission returns the existing pending request instead of duplicating it.
 */
export function deterministicApprovalRequestId(kind: ApprovalKind, payload: Record<string, unknown>): string {
  const digest = createHash("sha256")
    .update(`blueeconomy.approval.v1|${kind}|${canonicalPayload(payload)}`, "utf8")
    .digest("hex");
  return `urn:uuid:${digest.slice(0, 8)}-${digest.slice(8, 12)}-${digest.slice(12, 16)}-${digest.slice(16, 20)}-${digest.slice(20, 32)}`;
}

/** Canonical JSON (sorted keys) so equivalent payloads yield one request id. */
export function canonicalPayload(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalPayload).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalPayload(entry)}`);
  return `{${entries.join(",")}}`;
}

export function assertApprovalRequest(request: ApprovalRequest): void {
  if (!/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(request.requestId)) {
    throw new Error("approval request id must be a deterministic urn:uuid");
  }
  if (request.kind !== "issuance" && request.kind !== "revocation") {
    throw new Error("approval request kind must be issuance or revocation");
  }
  if (typeof request.payload !== "object" || request.payload === null || Array.isArray(request.payload)) {
    throw new Error("approval request payload must be a JSON object");
  }
  if (request.requestId !== deterministicApprovalRequestId(request.kind, request.payload)) {
    throw new Error("approval request id does not match its payload (fail-closed)");
  }
  if (request.requesterSubject.trim().length === 0 || request.requesterSubject.length > 256) {
    throw new Error("approval requester subject must be canonical text of 1-256 characters");
  }
  if (request.status !== "PENDING" && request.status !== "APPROVED") {
    throw new Error("approval request status must be PENDING or APPROVED");
  }
  if (!Number.isFinite(Date.parse(request.requestedAt))) {
    throw new Error("approval request requestedAt must be a valid date-time");
  }
  if (request.status === "PENDING" && (request.approverSubject !== undefined || request.decidedAt !== undefined)) {
    throw new Error("a pending request must not carry an approver or decision time");
  }
  if (request.status === "APPROVED") {
    if (request.approverSubject === undefined || request.decidedAt === undefined || !Number.isFinite(Date.parse(request.decidedAt))) {
      throw new Error("an approved request must record the approver subject and decision time");
    }
    assertMakerCheckerSeparation(request.requesterSubject, request.approverSubject);
  }
}
