/**
 * Shared test doubles for the welfare module: an in-memory WelfareStore
 * honoring the same invariants as PgWelfareStore (idempotency-key replay,
 * maker/checker separation, guarded transitions, append-only audit events).
 */

import type { OutboxMessage } from "../src/status/store.js";
import { isLegalComplaintTransition, isLegalReferralTransition } from "../src/welfare/types.js";
import {
  WelfareStateError,
  type ComplaintEventRecord,
  type ComplaintRecord,
  type Created,
  type ProviderInput,
  type ProviderWithServices,
  type ReferralRecord,
  type RestHourFlagRow,
  type RestHourRecordRow,
  type ServiceRecord,
  type TransitionRequest,
  type WelfareStore,
} from "../src/welfare/store.js";
import { canonicalPayload } from "../src/service/maker-checker.js";
import { deterministicUuid, type ComplaintStatus, type ReferralStatus } from "../src/welfare/types.js";

export class InMemoryWelfareStore implements WelfareStore {
  public readonly providers = new Map<string, ProviderWithServices>();
  public readonly complaints = new Map<string, ComplaintRecord>();
  public readonly events: ComplaintEventRecord[] = [];
  public readonly requests = new Map<string, TransitionRequest>();
  public readonly referrals = new Map<string, ReferralRecord>();
  public readonly restRecords = new Map<string, RestHourRecordRow>();
  public readonly restFlags: RestHourFlagRow[] = [];
  public readonly outbox: OutboxMessage[] = [];
  private readonly slaObserved = new Set<string>();
  private eventSequence = 0;

  public async insertProvider(input: ProviderInput, services: Array<Pick<ServiceRecord, "description" | "eligibility" | "languages">>, curatedBy: string): Promise<ProviderWithServices> {
    const providerId = deterministicUuid("provider", `${input.portCode}|${input.kind}|${input.name}|${input.sourceReference}`);
    const provider: ProviderWithServices = {
      ...input,
      providerId,
      status: "ACTIVE",
      curatedBy,
      curatedAt: new Date().toISOString(),
      services: services.map((service) => ({
        ...service,
        providerId,
        serviceId: deterministicUuid("service", `${providerId}|${service.description}`),
      })),
    };
    this.providers.set(providerId, provider);
    return provider;
  }

  public async listProviders(portCode?: string): Promise<ProviderWithServices[]> {
    return [...this.providers.values()].filter((provider) => portCode === undefined || provider.portCode === portCode);
  }

  public async getProvider(providerId: string): Promise<ProviderWithServices | undefined> {
    return this.providers.get(providerId);
  }

  public async getService(serviceId: string): Promise<(ServiceRecord & { providerStatus: "ACTIVE" | "SUSPENDED" }) | undefined> {
    for (const provider of this.providers.values()) {
      const service = provider.services.find((candidate) => candidate.serviceId === serviceId);
      if (service !== undefined) return { ...service, providerStatus: provider.status };
    }
    return undefined;
  }

  public async createComplaint(record: ComplaintRecord, outbox: OutboxMessage): Promise<Created<ComplaintRecord>> {
    for (const complaint of this.complaints.values()) {
      if (complaint.idempotencyKey === record.idempotencyKey) {
        if (complaint.complaintId !== record.complaintId || complaint.narrativeDigestSha256 !== record.narrativeDigestSha256) {
          throw new WelfareStateError("idempotency key was reused for a different complaint (fail-closed)");
        }
        return { created: false, record: complaint };
      }
    }
    this.complaints.set(record.complaintId, record);
    this.appendEvent(record.complaintId, "seafarer", "RECEIVED", record.narrativeDigestSha256, false);
    this.outbox.push(outbox);
    return { created: true, record };
  }

  private appendEvent(complaintId: string, actorRole: string, transition: string, noteDigestSha256: string | null, disclosureEvent: boolean): void {
    this.eventSequence += 1;
    this.events.push({
      id: this.eventSequence,
      complaintId,
      at: new Date().toISOString(),
      actorRole,
      transition,
      noteDigestSha256,
      disclosureEvent,
    });
  }

  public async getComplaint(complaintId: string): Promise<ComplaintRecord | undefined> {
    return this.complaints.get(complaintId);
  }

  public async listComplaintsBySeafarer(seafarerRef: string): Promise<ComplaintRecord[]> {
    return [...this.complaints.values()].filter((complaint) => complaint.seafarerRef === seafarerRef);
  }

  public async listComplaints(filter: { status?: ComplaintStatus; vesselRef?: string }): Promise<ComplaintRecord[]> {
    return [...this.complaints.values()].filter((complaint) =>
      (filter.status === undefined || complaint.status === filter.status) &&
      (filter.vesselRef === undefined || complaint.vesselRef === filter.vesselRef));
  }

  public async listComplaintEvents(complaintId: string): Promise<ComplaintEventRecord[]> {
    return this.events.filter((event) => event.complaintId === complaintId);
  }

  public async createTransitionRequest(request: TransitionRequest): Promise<Created<TransitionRequest>> {
    const existing = this.requests.get(request.requestId);
    if (existing !== undefined) {
      if (existing.kind !== request.kind || canonicalPayload(existing.payload) !== canonicalPayload(request.payload)) {
        throw new WelfareStateError(`transition request id ${request.requestId} already exists with different content (fail-closed)`);
      }
      return { created: false, record: existing };
    }
    this.requests.set(request.requestId, { ...request });
    return { created: true, record: request };
  }

  public async getTransitionRequest(requestId: string): Promise<TransitionRequest | undefined> {
    return this.requests.get(requestId);
  }

  public async markTransitionRequestApproved(requestId: string, approverSubject: string): Promise<TransitionRequest> {
    const request = this.requests.get(requestId);
    if (request === undefined) throw new WelfareStateError("transition request is unknown");
    if (request.status !== "PENDING") throw new WelfareStateError("transition request is already approved");
    if (request.requesterSubject === approverSubject) {
      throw new WelfareStateError("maker/checker violation: the requesting officer cannot approve their own complaint transition");
    }
    const approved: TransitionRequest = {
      ...request,
      status: "APPROVED",
      approverSubject,
      decidedAt: new Date().toISOString(),
    };
    this.requests.set(requestId, approved);
    return approved;
  }

  public async applyComplaintTransition(complaintId: string, from: ComplaintStatus, to: ComplaintStatus, actorRole: string, noteDigestSha256: string | null, outbox: OutboxMessage): Promise<ComplaintRecord> {
    const complaint = this.complaints.get(complaintId);
    if (complaint === undefined) throw new WelfareStateError("complaint is unknown");
    if (complaint.status !== from || !isLegalComplaintTransition(from, to)) {
      throw new WelfareStateError(`complaint is ${complaint.status}; the approved transition ${from} -> ${to} no longer applies (fail-closed)`);
    }
    const updated = { ...complaint, status: to };
    this.complaints.set(complaintId, updated);
    this.appendEvent(complaintId, actorRole, `${from}->${to}`, noteDigestSha256, false);
    this.outbox.push(outbox);
    return updated;
  }

  public async applyComplaintDisclosure(complaintId: string, reasonCode: string, actorRole: string, noteDigestSha256: string | null, outbox: OutboxMessage): Promise<ComplaintRecord> {
    const complaint = this.complaints.get(complaintId);
    if (complaint === undefined) throw new WelfareStateError("complaint is unknown");
    if (complaint.disclosureScope === "disclosed") {
      throw new WelfareStateError("complainant identity is already disclosed; disclosure is a one-time governed event (fail-closed)");
    }
    const updated: ComplaintRecord = {
      ...complaint,
      disclosureScope: "disclosed",
      disclosedAt: new Date().toISOString(),
      disclosedReasonCode: reasonCode,
    };
    this.complaints.set(complaintId, updated);
    this.appendEvent(complaintId, actorRole, `DISCLOSE:${reasonCode}`, noteDigestSha256, true);
    this.outbox.push(outbox);
    return updated;
  }

  public async createReferral(record: ReferralRecord, outbox: OutboxMessage): Promise<Created<ReferralRecord>> {
    for (const referral of this.referrals.values()) {
      if (referral.idempotencyKey === record.idempotencyKey) {
        if (referral.referralId !== record.referralId || referral.serviceId !== record.serviceId || referral.seafarerRef !== record.seafarerRef) {
          throw new WelfareStateError("idempotency key was reused for a different referral (fail-closed)");
        }
        return { created: false, record: referral };
      }
    }
    this.referrals.set(record.referralId, record);
    this.outbox.push(outbox);
    return { created: true, record };
  }

  public async getReferral(referralId: string): Promise<ReferralRecord | undefined> {
    return this.referrals.get(referralId);
  }

  public async listReferralsBySeafarer(seafarerRef: string): Promise<ReferralRecord[]> {
    return [...this.referrals.values()].filter((referral) => referral.seafarerRef === seafarerRef);
  }

  public async transitionReferral(referralId: string, from: ReferralStatus, to: ReferralStatus, outcomeNoteDigestSha256: string | null, outbox: OutboxMessage): Promise<ReferralRecord> {
    const referral = this.referrals.get(referralId);
    if (referral === undefined) throw new WelfareStateError("referral is unknown");
    if (referral.status !== from || !isLegalReferralTransition(from, to)) {
      throw new WelfareStateError(`referral is ${referral.status}; the transition ${from} -> ${to} does not apply (fail-closed)`);
    }
    const updated: ReferralRecord = {
      ...referral,
      status: to,
      outcomeNoteDigestSha256: outcomeNoteDigestSha256 ?? referral.outcomeNoteDigestSha256,
    };
    this.referrals.set(referralId, updated);
    this.outbox.push(outbox);
    return updated;
  }

  public async insertRestRecord(record: RestHourRecordRow, flags: RestHourFlagRow[], outboxes: OutboxMessage[]): Promise<Created<RestHourRecordRow>> {
    for (const existing of this.restRecords.values()) {
      if (existing.idempotencyKey === record.idempotencyKey) {
        if (existing.recordId !== record.recordId || existing.sourceDigestSha256 !== record.sourceDigestSha256) {
          throw new WelfareStateError("idempotency key was reused for a different rest-hour record (fail-closed)");
        }
        return { created: false, record: existing };
      }
    }
    this.restRecords.set(record.recordId, record);
    this.restFlags.push(...flags);
    this.outbox.push(...outboxes);
    return { created: true, record };
  }

  public async getRestRecord(recordId: string): Promise<RestHourRecordRow | undefined> {
    return this.restRecords.get(recordId);
  }

  public async listRestRecordsBySeafarer(seafarerRef: string, from?: string, to?: string): Promise<RestHourRecordRow[]> {
    return [...this.restRecords.values()].filter((record) =>
      record.seafarerRef === seafarerRef &&
      (from === undefined || record.recordDate >= from) &&
      (to === undefined || record.recordDate <= to));
  }

  public async listRestFlagsForRecords(recordIds: readonly string[]): Promise<RestHourFlagRow[]> {
    return this.restFlags.filter((flag) => recordIds.includes(flag.recordId));
  }

  public async listRestFlags(filter: { vesselRef?: string }): Promise<Array<RestHourFlagRow & { vesselRef: string; seafarerRef: string; recordDate: string }>> {
    const rows: Array<RestHourFlagRow & { vesselRef: string; seafarerRef: string; recordDate: string }> = [];
    for (const flag of this.restFlags) {
      const record = this.restRecords.get(flag.recordId);
      if (record === undefined) continue;
      if (filter.vesselRef !== undefined && record.vesselRef !== filter.vesselRef) continue;
      rows.push({ ...flag, vesselRef: record.vesselRef, seafarerRef: record.seafarerRef, recordDate: record.recordDate });
    }
    return rows;
  }

  public async recordSlaBreachesObserved(complaintId: string, stages: readonly string[]): Promise<string[]> {
    const observed: string[] = [];
    for (const stage of stages) {
      const key = `${complaintId}|${stage}`;
      if (!this.slaObserved.has(key)) {
        this.slaObserved.add(key);
        observed.push(stage);
      }
    }
    return observed;
  }

  public async healthCheck(): Promise<void> {}
  public async close(): Promise<void> {}
}
