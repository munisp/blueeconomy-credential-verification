import type {
  ComplaintCategory,
  ComplaintChannel,
  ComplaintStatus,
  ProviderKind,
  ReferralStatus,
  RestHourRegime,
  RestHourRule,
} from "./types.js";
import type { RestHourPeriod } from "./rest-rules.js";
import type { OutboxMessage } from "../status/store.js";

/**
 * Durable welfare store contract (migration 0006). The PostgreSQL
 * implementation enforces the invariants that matter legally: complaint
 * audit events and operator rest-hour records are append-only
 * (trigger-enforced), transition requests enforce requester <> approver by
 * CHECK, and every write that emits an event commits with its outbox row in
 * one transaction.
 */

export interface ProviderInput {
  name: string;
  kind: ProviderKind;
  portCode: string;
  address: string;
  contact: Record<string, unknown>;
  hours: string;
  /** Documented public source the entry was curated from (mandatory). */
  sourceReference: string;
}

export interface ProviderRecord extends ProviderInput {
  providerId: string;
  status: "ACTIVE" | "SUSPENDED";
  curatedBy: string;
  curatedAt: string;
}

export interface ServiceRecord {
  serviceId: string;
  providerId: string;
  description: string;
  eligibility: string;
  languages: string[];
}

export interface ProviderWithServices extends ProviderRecord {
  services: ServiceRecord[];
}

export interface ComplaintRecord {
  complaintId: string;
  channel: ComplaintChannel;
  seafarerRef: string;
  vesselRef: string;
  operatorRef: string | null;
  category: ComplaintCategory;
  narrativeEnc: string;
  narrativeDigestSha256: string;
  attachments: Array<{ name: string; sha256: string }>;
  idempotencyKey: string;
  status: ComplaintStatus;
  rightToRedressNoticeAck: true;
  disclosureScope: "withheld" | "disclosed";
  disclosedAt: string | null;
  disclosedReasonCode: string | null;
  createdBySubject: string;
  submittedAt: string;
}

export interface ComplaintEventRecord {
  id: number;
  complaintId: string;
  at: string;
  actorRole: string;
  transition: string;
  noteDigestSha256: string | null;
  disclosureEvent: boolean;
}

export type TransitionRequestKind = "transition" | "disclosure";

export interface TransitionRequest {
  requestId: string;
  kind: TransitionRequestKind;
  complaintId: string;
  payload: Record<string, unknown>;
  requesterSubject: string;
  requesterRole: string;
  status: "PENDING" | "APPROVED";
  requestedAt: string;
  approverSubject?: string;
  decidedAt?: string;
}

export interface ReferralRecord {
  referralId: string;
  complaintId: string | null;
  seafarerRef: string;
  serviceId: string;
  consentAt: string;
  status: ReferralStatus;
  outcomeNoteDigestSha256: string | null;
  idempotencyKey: string;
  createdBySubject: string;
  recordedAt: string;
}

export interface RestHourRecordRow {
  recordId: string;
  seafarerRef: string;
  vesselRef: string;
  recordDate: string;
  periods: RestHourPeriod[];
  regime: RestHourRegime;
  submittedBy: string;
  submittedByRole: "operator" | "master";
  sourceDigestSha256: string;
  policyVersion: string;
  idempotencyKey: string;
  submittedAt: string;
}

export interface RestHourFlagRow {
  flagId: string;
  recordId: string;
  rule: RestHourRule;
  detail: string;
  policyVersion: string;
  computedAt: string;
}

export interface Created<T> {
  created: boolean;
  record: T;
}

export class WelfareStateError extends Error {}

export interface WelfareStore {
  insertProvider(input: ProviderInput, services: Array<Pick<ServiceRecord, "description" | "eligibility" | "languages">>, curatedBy: string): Promise<ProviderWithServices>;
  listProviders(portCode?: string): Promise<ProviderWithServices[]>;
  getProvider(providerId: string): Promise<ProviderWithServices | undefined>;
  getService(serviceId: string): Promise<(ServiceRecord & { providerStatus: "ACTIVE" | "SUSPENDED" }) | undefined>;

  /** Idempotent under idempotency_key; writes the intake audit event and the outbox row in one transaction. */
  createComplaint(record: ComplaintRecord, outbox: OutboxMessage): Promise<Created<ComplaintRecord>>;
  getComplaint(complaintId: string): Promise<ComplaintRecord | undefined>;
  listComplaintsBySeafarer(seafarerRef: string): Promise<ComplaintRecord[]>;
  listComplaints(filter: { status?: ComplaintStatus; vesselRef?: string }): Promise<ComplaintRecord[]>;
  listComplaintEvents(complaintId: string): Promise<ComplaintEventRecord[]>;

  createTransitionRequest(request: TransitionRequest): Promise<Created<TransitionRequest>>;
  getTransitionRequest(requestId: string): Promise<TransitionRequest | undefined>;
  /** Guarded update: only a PENDING row whose requester differs from the approver. */
  markTransitionRequestApproved(requestId: string, approverSubject: string): Promise<TransitionRequest>;

  /**
   * Applies a maker/checker-approved status transition: guarded status update
   * (from must match), append-only audit event, outbox row — one transaction.
   */
  applyComplaintTransition(
    complaintId: string,
    from: ComplaintStatus,
    to: ComplaintStatus,
    actorRole: string,
    noteDigestSha256: string | null,
    outbox: OutboxMessage,
  ): Promise<ComplaintRecord>;

  /** Governed identity disclosure (Reg 5.1.5(2)): sets disclosure_scope, logs the disclosure event, emits the event — one transaction. */
  applyComplaintDisclosure(
    complaintId: string,
    reasonCode: string,
    actorRole: string,
    noteDigestSha256: string | null,
    outbox: OutboxMessage,
  ): Promise<ComplaintRecord>;

  createReferral(record: ReferralRecord, outbox: OutboxMessage): Promise<Created<ReferralRecord>>;
  getReferral(referralId: string): Promise<ReferralRecord | undefined>;
  listReferralsBySeafarer(seafarerRef: string): Promise<ReferralRecord[]>;
  transitionReferral(
    referralId: string,
    from: ReferralStatus,
    to: ReferralStatus,
    outcomeNoteDigestSha256: string | null,
    outbox: OutboxMessage,
  ): Promise<ReferralRecord>;

  /** Idempotent under idempotency_key; flags and their outbox events commit with the record in one transaction. */
  insertRestRecord(record: RestHourRecordRow, flags: RestHourFlagRow[], outboxes: OutboxMessage[]): Promise<Created<RestHourRecordRow>>;
  getRestRecord(recordId: string): Promise<RestHourRecordRow | undefined>;
  listRestRecordsBySeafarer(seafarerRef: string, from?: string, to?: string): Promise<RestHourRecordRow[]>;
  listRestFlagsForRecords(recordIds: readonly string[]): Promise<RestHourFlagRow[]>;
  listRestFlags(filter: { vesselRef?: string }): Promise<Array<RestHourFlagRow & { vesselRef: string; seafarerRef: string; recordDate: string }>>;

  /** Inserts (complaint_id, stage) markers; returns the stages newly observed. */
  recordSlaBreachesObserved(complaintId: string, stages: readonly string[]): Promise<string[]>;

  healthCheck(): Promise<void>;
  close(): Promise<void>;
}
