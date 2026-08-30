import { ServiceError } from "../service/credential-service.js";
import { assertMakerCheckerSeparation, canonicalPayload, ApprovalStateError } from "../service/maker-checker.js";
import type { OutboxMessage } from "../status/store.js";
import { canonicalizeJson, asJsonValue } from "../vc/jcs.js";
import { withSpan } from "../telemetry/spans.js";
import { buildWelfareEnvelope, WELFARE_TOPIC, type WelfareEnvelope } from "./envelope.js";
import type { NarrativeKey } from "./confidentiality.js";
import type { ComplaintLifecycle } from "./lifecycle.js";
import type { WelfarePolicy } from "./policy.js";
import {
  WelfareStateError,
  type ComplaintEventRecord,
  type ComplaintRecord,
  type ProviderInput,
  type ProviderWithServices,
  type ReferralRecord,
  type RestHourFlagRow,
  type RestHourRecordRow,
  type TransitionRequest,
  type WelfareStore,
} from "./store.js";
import { evaluateRestHours, parsePeriods, RestRecordValidationError, type RestHourPeriod } from "./rest-rules.js";
import {
  COMPLAINT_STATUSES,
  PROTO_NAMES,
  deterministicUuid,
  isLegalComplaintTransition,
  isLegalReferralTransition,
  isMember,
  sha256Hex,
  tokenizeReference,
  type ComplaintCategory,
  type ComplaintChannel,
  type ComplaintStatus,
  type ReferralStatus,
} from "./types.js";
import type { KeyObject } from "node:crypto";

/**
 * Crew Welfare / MLC 2006 service (phase 8). Composes the welfare store,
 * the signed welfare-policy document, narrative encryption, the Temporal
 * complaint lifecycle and the JWS envelope/outbox path. Reuses the repo
 * machinery: seafarerReferenceNumber VC identity binding, maker/checker
 * separation (src/service/maker-checker.ts), fail-closed PBAC at the HTTP
 * edge, Temporal SLA observation and the transactional outbox.
 *
 * Confidentiality: complainant identity (seafarer_ref / created_by_subject)
 * is returned ONLY to the complainant themselves; officer caseload views
 * withhold it until a governed disclosure (disclosure_scope = 'disclosed').
 * Narratives decrypt only inside this boundary and never enter events,
 * logs, metrics or traces.
 */

export interface Principal {
  subject: string;
  role: string;
}

export interface SeafarerIdentity {
  /** Resolves the caller's verified VC seafarerReferenceNumber; undefined when the subject holds no current CoC credential. */
  referenceFor(subject: string): Promise<string | undefined>;
}

export interface WelfareServiceDependencies {
  store: WelfareStore;
  /** Signed welfare policy; undefined until NIMASA's signed selection deploys (mutations 503-honest). */
  policy: WelfarePolicy | undefined;
  /** Human-readable reason when policy is undefined. */
  policyUnavailableReason?: string;
  narrativeKey: NarrativeKey | undefined;
  signing: { privateKey: KeyObject; keyId: string };
  producer: string;
  identity: SeafarerIdentity;
  lifecycle: ComplaintLifecycle;
  /** Curation contact surfaced by the honest empty-directory state. */
  curationContact: string;
}

export interface ComplaintSubmitInput {
  channel: ComplaintChannel;
  vesselRef: string;
  operatorRef?: string;
  category: ComplaintCategory;
  narrative: string;
  attachments: Array<{ name: string; sha256: string }>;
  rightToRedressNoticeAck: boolean;
}

const MAX_NARRATIVE_CHARS = 8192;

export class WelfareService {
  public constructor(private readonly deps: WelfareServiceDependencies) {}

  // ------------------------------------------------------------ directory

  public async listProviders(portCode?: string): Promise<{ providers: ProviderWithServices[]; empty?: { message: string; curationContact: string } }> {
    const providers = await this.deps.store.listProviders(portCode);
    if (providers.length === 0) {
      // Directory honesty (spec §5.1): empty is an honest state; no fixtures.
      return {
        providers: [],
        empty: {
          message: portCode === undefined
            ? "No welfare providers are registered yet"
            : `No providers registered for port ${portCode} yet`,
          curationContact: this.deps.curationContact,
        },
      };
    }
    return { providers };
  }

  public async getProvider(providerId: string): Promise<ProviderWithServices> {
    const provider = await this.deps.store.getProvider(providerId);
    if (provider === undefined) throw new ServiceError(404, "welfare provider is unknown");
    return provider;
  }

  public async curateProvider(
    input: ProviderInput,
    services: Array<{ description: string; eligibility: string; languages: string[] }>,
    principal: Principal,
  ): Promise<ProviderWithServices> {
    if (input.sourceReference.trim().length === 0) {
      throw new ServiceError(400, "source_reference is mandatory: directory entries require documented provenance");
    }
    return withSpan(
      "welfare.provider.curate",
      { attributes: { "welfare.port_code": input.portCode, "welfare.provider_kind": input.kind } },
      () => this.deps.store.insertProvider(input, services, principal.subject),
    );
  }

  // ----------------------------------------------------------- complaints

  public async submitComplaint(
    input: ComplaintSubmitInput,
    idempotencyKey: string,
    principal: Principal,
  ): Promise<{ complaintId: string; status: ComplaintStatus; created: boolean; eventId: string }> {
    return withSpan("complaint.submit", {
      attributes: {
        "welfare.channel": input.channel,
        "welfare.category": input.category,
        "welfare.vessel_ref_hashed": sha256Hex(input.vesselRef).slice(0, 12),
      },
    }, async () => {
      const policy = this.requirePolicy();
      const narrativeKey = this.requireNarrativeKey();
      if (input.rightToRedressNoticeAck !== true) {
        throw new ServiceError(400, "the right-to-external-redress notice (Reg 5.1.5(3)) must be acknowledged at intake");
      }
      assertCanonical(input.vesselRef, "vesselRef", 128);
      if (input.operatorRef !== undefined) assertCanonical(input.operatorRef, "operatorRef", 128);
      if (typeof input.narrative !== "string" || input.narrative.trim().length === 0 || input.narrative.length > MAX_NARRATIVE_CHARS) {
        throw new ServiceError(400, `narrative must be 1-${MAX_NARRATIVE_CHARS} characters`);
      }
      assertAttachments(input.attachments);
      const seafarerRef = await this.deps.identity.referenceFor(principal.subject);
      if (seafarerRef === undefined) {
        throw new ServiceError(409, "the authenticated seafarer holds no current CoC credential; complaints bind to a verified seafarer identity");
      }
      const complaintId = deterministicUuid("complaint", idempotencyKey);
      const narrativeDigest = sha256Hex(canonicalizeJson(asJsonValue({ attachments: input.attachments, narrative: input.narrative })));
      const now = new Date();
      const envelope = await buildWelfareEnvelope({
        eventType: "seafarer.welfare.complaint.v1",
        producer: this.deps.producer,
        correlationId: complaintId,
        principal: { principalId: principal.subject, principalRole: principal.role },
        resource: {
          "@type": "type.googleapis.com/blueeconomy.contracts.v1.WelfareComplaintSubmitted",
          complaintId,
          channel: PROTO_NAMES.channel[input.channel],
          seafarerReference: tokenizeReference("sfr", seafarerRef),
          vesselReference: tokenizeReference("vsl", input.vesselRef),
          operatorReference: input.operatorRef === undefined ? "" : tokenizeReference("opr", input.operatorRef),
          category: PROTO_NAMES.category[input.category],
          narrativeDigestSha256: `sha256:${narrativeDigest}`,
          rightToRedressAcknowledged: true,
          idempotencyKey,
          submittedAt: now.toISOString(),
        },
        signingKey: this.deps.signing.privateKey,
        keyId: this.deps.signing.keyId,
        deduplicationKey: `complaint|${complaintId}`,
        occurredAt: now,
      });
      // Start the SLA tracker first: it is idempotent (USE_EXISTING on the
      // deterministic workflow id) and an orphan tracker has no side effects,
      // whereas a persisted complaint without its tracker would be silently
      // unobserved. A start failure refuses the intake honestly (503).
      try {
        await this.deps.lifecycle.start({
          complaintId,
          channel: input.channel,
          correlationId: complaintId,
          slaSeconds: {
            ack: policy.claims.complaint_sla_seconds.ack,
            onboard_process: policy.claims.complaint_sla_seconds.onboard_process,
            escalation: policy.claims.complaint_sla_seconds.escalation,
            resolution: policy.claims.complaint_sla_seconds.resolution,
          },
        });
      } catch {
        throw new ServiceError(503, "complaint lifecycle tracking is unavailable; the complaint was NOT recorded — retry");
      }
      const record: ComplaintRecord = {
        complaintId,
        channel: input.channel,
        seafarerRef,
        vesselRef: input.vesselRef,
        operatorRef: input.operatorRef ?? null,
        category: input.category,
        narrativeEnc: narrativeKey.encrypt(input.narrative),
        narrativeDigestSha256: narrativeDigest,
        attachments: input.attachments,
        idempotencyKey,
        status: "RECEIVED",
        rightToRedressNoticeAck: true,
        disclosureScope: "withheld",
        disclosedAt: null,
        disclosedReasonCode: null,
        createdBySubject: principal.subject,
        submittedAt: now.toISOString(),
      };
      const result = await this.deps.store.createComplaint(record, {
        topic: WELFARE_TOPIC,
        eventId: envelope.eventId,
        payload: envelope as unknown as Record<string, unknown>,
      });
      return { complaintId: result.record.complaintId, status: result.record.status, created: result.created, eventId: envelope.eventId };
    });
  }

  public async myComplaints(subject: string): Promise<{ seafarerReference: string | null; complaints: unknown[] }> {
    const seafarerRef = await this.deps.identity.referenceFor(subject);
    if (seafarerRef === undefined) return { seafarerReference: null, complaints: [] };
    const complaints = await this.deps.store.listComplaintsBySeafarer(seafarerRef);
    const views: unknown[] = [];
    for (const complaint of complaints) {
      const events = await this.deps.store.listComplaintEvents(complaint.complaintId);
      views.push(this.complainantView(complaint, events));
    }
    return { seafarerReference: seafarerRef, complaints: views };
  }

  public async caseload(filter: { status?: ComplaintStatus; vesselRef?: string }): Promise<{ complaints: unknown[]; newlyObservedBreaches: Array<{ complaintId: string; stage: string }> }> {
    const complaints = await this.deps.store.listComplaints(filter);
    const newlyObserved: Array<{ complaintId: string; stage: string }> = [];
    const views: unknown[] = [];
    for (const complaint of complaints) {
      const observation = await this.deps.lifecycle.observe(complaint.complaintId);
      if (observation !== undefined && observation.slaBreachedStages.length > 0) {
        for (const stage of await this.deps.store.recordSlaBreachesObserved(complaint.complaintId, observation.slaBreachedStages)) {
          newlyObserved.push({ complaintId: complaint.complaintId, stage });
        }
      }
      views.push(this.officerView(complaint, observation));
    }
    return { complaints: views, newlyObservedBreaches: newlyObserved };
  }

  public async requestTransition(
    complaintId: string,
    input: { to: ComplaintStatus; reasonCode: string; note?: string },
    principal: Principal,
  ): Promise<{ requestId: string; status: "PENDING"; kind: "transition" }> {
    return withSpan("complaint.transition", { attributes: { "welfare.transition_to": input.to } }, async () => {
      this.requirePolicy();
      const complaint = await this.requireComplaint(complaintId);
      if (!isLegalComplaintTransition(complaint.status, input.to)) {
        throw new ServiceError(409, `complaint status ${complaint.status} cannot transition to ${input.to}`);
      }
      assertCanonical(input.reasonCode, "reasonCode", 64);
      const payload: Record<string, unknown> = {
        complaintId,
        from: complaint.status,
        to: input.to,
        reasonCode: input.reasonCode,
        noteDigest: input.note === undefined ? null : sha256Hex(input.note),
      };
      const result = await this.submitTransitionRequest("transition", complaintId, payload, principal);
      return { ...result, kind: "transition" };
    });
  }

  public async requestDisclosure(
    complaintId: string,
    input: { reasonCode: string; note?: string },
    principal: Principal,
  ): Promise<{ requestId: string; status: "PENDING"; kind: "disclosure" }> {
    this.requirePolicy();
    const complaint = await this.requireComplaint(complaintId);
    if (complaint.disclosureScope === "disclosed") {
      throw new ServiceError(409, "complainant identity is already disclosed; disclosure is a one-time governed event");
    }
    assertCanonical(input.reasonCode, "reasonCode", 64);
    const payload: Record<string, unknown> = {
      complaintId,
      reasonCode: input.reasonCode,
      noteDigest: input.note === undefined ? null : sha256Hex(input.note),
    };
    const result = await this.submitTransitionRequest("disclosure", complaintId, payload, principal);
    return { ...result, kind: "disclosure" };
  }

  private async submitTransitionRequest(
    kind: "transition" | "disclosure",
    complaintId: string,
    payload: Record<string, unknown>,
    principal: Principal,
  ): Promise<{ requestId: string; status: "PENDING"; kind: "transition" | "disclosure" }> {
    const request: TransitionRequest = {
      requestId: deterministicUuid("transition-request", canonicalPayload({ kind, ...payload })),
      kind,
      complaintId,
      payload,
      requesterSubject: principal.subject,
      requesterRole: principal.role,
      status: "PENDING",
      requestedAt: new Date().toISOString(),
    };
    const { record } = await this.deps.store.createTransitionRequest(request);
    if (record.status !== "PENDING") {
      throw new ServiceError(409, "an identical request was already approved and executed");
    }
    return { requestId: record.requestId, status: "PENDING", kind: record.kind };
  }

  public async approveTransitionRequest(requestId: string, principal: Principal): Promise<{
    complaintId: string;
    kind: "transition" | "disclosure";
    status: ComplaintStatus;
    disclosureEvent: boolean;
    eventId: string;
    lifecycleSignalled: boolean;
    newlyObservedBreaches: string[];
  }> {
    const request = await this.deps.store.getTransitionRequest(requestId);
    if (request === undefined) throw new ServiceError(404, "transition request is unknown");
    if (request.status !== "PENDING") throw new ServiceError(409, "transition request is already approved");
    try {
      assertMakerCheckerSeparation(request.requesterSubject, principal.subject);
    } catch (error) {
      if (error instanceof ApprovalStateError) throw new ServiceError(409, error.message);
      throw error;
    }
    const complaint = await this.requireComplaint(request.complaintId);
    const now = new Date();
    if (request.kind === "transition") {
      const from = payloadStatus(request.payload, "from");
      const to = payloadStatus(request.payload, "to");
      const reasonCode = payloadText(request.payload, "reasonCode");
      const noteDigest = payloadDigest(request.payload, "noteDigest");
      if (complaint.status !== from || !isLegalComplaintTransition(from, to)) {
        throw new ServiceError(409, `complaint is ${complaint.status}; the approved transition ${from} -> ${to} no longer applies`);
      }
      const envelope = await this.statusEnvelope(complaint, from, to, reasonCode, false, noteDigest, principal, now);
      try {
        await this.deps.store.applyComplaintTransition(complaint.complaintId, from, to, principal.role, noteDigest, {
          topic: WELFARE_TOPIC, eventId: envelope.eventId, payload: envelope as unknown as Record<string, unknown>,
        });
      } catch (error) {
        if (error instanceof WelfareStateError) throw new ServiceError(409, error.message);
        throw error;
      }
      await this.markApproved(requestId, principal.subject);
      const signalled = await this.signalLifecycle(complaint.complaintId, to);
      const breaches = await this.observeBreaches(complaint.complaintId);
      return { complaintId: complaint.complaintId, kind: "transition", status: to, disclosureEvent: false, eventId: envelope.eventId, lifecycleSignalled: signalled, newlyObservedBreaches: breaches };
    }
    // Disclosure: legally gated, maker/checker, always a logged event.
    const reasonCode = payloadText(request.payload, "reasonCode");
    const noteDigest = payloadDigest(request.payload, "noteDigest");
    const envelope = await this.statusEnvelope(complaint, complaint.status, complaint.status, reasonCode, true, noteDigest, principal, now);
    try {
      await this.deps.store.applyComplaintDisclosure(complaint.complaintId, reasonCode, principal.role, noteDigest, {
        topic: WELFARE_TOPIC, eventId: envelope.eventId, payload: envelope as unknown as Record<string, unknown>,
      });
    } catch (error) {
      if (error instanceof WelfareStateError) throw new ServiceError(409, error.message);
      throw error;
    }
    await this.markApproved(requestId, principal.subject);
    const breaches = await this.observeBreaches(complaint.complaintId);
    return { complaintId: complaint.complaintId, kind: "disclosure", status: complaint.status, disclosureEvent: true, eventId: envelope.eventId, lifecycleSignalled: false, newlyObservedBreaches: breaches };
  }

  private async markApproved(requestId: string, approverSubject: string): Promise<void> {
    try {
      await this.deps.store.markTransitionRequestApproved(requestId, approverSubject);
    } catch (error) {
      if (error instanceof WelfareStateError) throw new ServiceError(409, error.message);
      throw error;
    }
  }

  private async statusEnvelope(
    complaint: ComplaintRecord,
    priorStatus: ComplaintStatus,
    status: ComplaintStatus,
    reasonCode: string,
    disclosureEvent: boolean,
    noteDigest: string | null,
    principal: Principal,
    occurredAt: Date,
  ): Promise<WelfareEnvelope> {
    return buildWelfareEnvelope({
      eventType: "seafarer.welfare.complaint_status.v1",
      producer: this.deps.producer,
      correlationId: complaint.complaintId,
      principal: { principalId: principal.subject, principalRole: principal.role },
      resource: {
        "@type": "type.googleapis.com/blueeconomy.contracts.v1.WelfareComplaintStatusTransitioned",
        complaintId: complaint.complaintId,
        priorStatus,
        status,
        transitionReasonCode: reasonCode,
        disclosureEvent,
        noteDigestSha256: noteDigest === null ? "" : `sha256:${noteDigest}`,
        transitionedAt: occurredAt.toISOString(),
      },
      signingKey: this.deps.signing.privateKey,
      keyId: this.deps.signing.keyId,
      deduplicationKey: disclosureEvent
        ? `complaint-disclosure|${complaint.complaintId}`
        : `complaint-transition|${complaint.complaintId}|${priorStatus}|${status}`,
      occurredAt,
    });
  }

  private async signalLifecycle(complaintId: string, status: ComplaintStatus): Promise<boolean> {
    try {
      await this.deps.lifecycle.signal(complaintId, status);
      return true;
    } catch {
      // The applied transition and its event are committed and authoritative;
      // the SLA tracker is observation-only and resynchronizes on the next
      // signal it can accept. Reported honestly to the approver.
      return false;
    }
  }

  private async observeBreaches(complaintId: string): Promise<string[]> {
    const observation = await this.deps.lifecycle.observe(complaintId);
    if (observation === undefined || observation.slaBreachedStages.length === 0) return [];
    return this.deps.store.recordSlaBreachesObserved(complaintId, observation.slaBreachedStages);
  }

  // ------------------------------------------------------------ referrals

  public async createReferral(
    input: { complaintId?: string; serviceId: string; consentAt: string; seafarerRef?: string },
    idempotencyKey: string,
    principal: Principal,
  ): Promise<{ referralId: string; status: ReferralStatus; created: boolean; eventId: string }> {
    return withSpan("referral.create", {}, async () => {
      assertCanonical(input.serviceId, "serviceId", 128);
      const consentAt = new Date(input.consentAt);
      if (!Number.isFinite(consentAt.getTime())) throw new ServiceError(400, "consent_at is mandatory and must be a valid date-time");
      if (consentAt.getTime() > Date.now() + 60_000) throw new ServiceError(400, "consent_at must not be in the future");
      const service = await this.deps.store.getService(input.serviceId);
      if (service === undefined) throw new ServiceError(404, "welfare service is unknown to the directory");
      if (service.providerStatus !== "ACTIVE") throw new ServiceError(409, "the welfare provider is not active");

      let seafarerRef: string;
      if (principal.role === "seafarer") {
        const own = await this.deps.identity.referenceFor(principal.subject);
        if (own === undefined) {
          throw new ServiceError(409, "the authenticated seafarer holds no current CoC credential");
        }
        if (input.seafarerRef !== undefined && input.seafarerRef !== own) {
          throw new ServiceError(403, "a seafarer may only create referrals for themselves");
        }
        seafarerRef = own;
      } else {
        if (input.seafarerRef === undefined) throw new ServiceError(400, "seafarerRef is required for officer-created referrals");
        assertCanonical(input.seafarerRef, "seafarerRef", 128);
        seafarerRef = input.seafarerRef;
      }

      let complaintId: string | null = null;
      if (input.complaintId !== undefined) {
        const complaint = await this.requireComplaint(input.complaintId);
        if (principal.role === "seafarer" && complaint.seafarerRef !== seafarerRef) {
          throw new ServiceError(403, "the linked complaint does not belong to the authenticated seafarer");
        }
        complaintId = complaint.complaintId;
      }

      const referralId = deterministicUuid("referral", idempotencyKey);
      const now = new Date();
      const envelope = await this.referralEnvelope(referralId, complaintId, seafarerRef, input.serviceId, "OFFERED", consentAt, null, principal, now, `referral|${referralId}`);
      const record: ReferralRecord = {
        referralId,
        complaintId,
        seafarerRef,
        serviceId: input.serviceId,
        consentAt: consentAt.toISOString(),
        status: "OFFERED",
        outcomeNoteDigestSha256: null,
        idempotencyKey,
        createdBySubject: principal.subject,
        recordedAt: now.toISOString(),
      };
      const result = await this.deps.store.createReferral(record, {
        topic: WELFARE_TOPIC, eventId: envelope.eventId, payload: envelope as unknown as Record<string, unknown>,
      });
      return { referralId: result.record.referralId, status: result.record.status, created: result.created, eventId: envelope.eventId };
    });
  }

  public async myReferrals(subject: string): Promise<{ seafarerReference: string | null; referrals: unknown[] }> {
    const seafarerRef = await this.deps.identity.referenceFor(subject);
    if (seafarerRef === undefined) return { seafarerReference: null, referrals: [] };
    const referrals = await this.deps.store.listReferralsBySeafarer(seafarerRef);
    return {
      seafarerReference: seafarerRef,
      referrals: referrals.map((referral) => ({
        referralId: referral.referralId,
        complaintId: referral.complaintId,
        serviceId: referral.serviceId,
        consentAt: referral.consentAt,
        status: referral.status,
        recordedAt: referral.recordedAt,
      })),
    };
  }

  public async transitionReferral(
    referralId: string,
    input: { to: ReferralStatus; outcomeNote?: string },
    principal: Principal,
  ): Promise<{ referralId: string; status: ReferralStatus; eventId: string }> {
    const referral = await this.deps.store.getReferral(referralId);
    if (referral === undefined) throw new ServiceError(404, "referral is unknown");
    if (!isLegalReferralTransition(referral.status, input.to)) {
      throw new ServiceError(409, `referral status ${referral.status} cannot transition to ${input.to}`);
    }
    if (input.to === "CLOSED" && (input.outcomeNote === undefined || input.outcomeNote.trim().length === 0)) {
      throw new ServiceError(400, "closing a referral requires an outcome note (outcome feedback to NIMASA case officers)");
    }
    const outcomeDigest = input.outcomeNote === undefined ? null : sha256Hex(input.outcomeNote);
    const now = new Date();
    const envelope = await this.referralEnvelope(
      referral.referralId, referral.complaintId, referral.seafarerRef, referral.serviceId,
      input.to, new Date(referral.consentAt), outcomeDigest, principal, now,
      `referral-transition|${referral.referralId}|${referral.status}|${input.to}`,
    );
    try {
      await this.deps.store.transitionReferral(referral.referralId, referral.status, input.to, outcomeDigest, {
        topic: WELFARE_TOPIC, eventId: envelope.eventId, payload: envelope as unknown as Record<string, unknown>,
      });
    } catch (error) {
      if (error instanceof WelfareStateError) throw new ServiceError(409, error.message);
      throw error;
    }
    return { referralId: referral.referralId, status: input.to, eventId: envelope.eventId };
  }

  private async referralEnvelope(
    referralId: string,
    complaintId: string | null,
    seafarerRef: string,
    serviceId: string,
    status: ReferralStatus,
    consentAt: Date,
    outcomeNoteDigest: string | null,
    principal: Principal,
    occurredAt: Date,
    deduplicationKey: string,
  ): Promise<WelfareEnvelope> {
    return buildWelfareEnvelope({
      eventType: "seafarer.welfare.referral.v1",
      producer: this.deps.producer,
      correlationId: referralId,
      principal: { principalId: principal.subject, principalRole: principal.role },
      resource: {
        "@type": "type.googleapis.com/blueeconomy.contracts.v1.WelfareReferralRecorded",
        referralId,
        complaintId: complaintId ?? "",
        seafarerReference: tokenizeReference("sfr", seafarerRef),
        serviceReference: tokenizeReference("svc", serviceId),
        status,
        consentAt: consentAt.toISOString(),
        outcomeNoteDigestSha256: outcomeNoteDigest === null ? "" : `sha256:${outcomeNoteDigest}`,
        recordedAt: occurredAt.toISOString(),
      },
      signingKey: this.deps.signing.privateKey,
      keyId: this.deps.signing.keyId,
      deduplicationKey,
      occurredAt,
    });
  }

  // ------------------------------------------------------------ rest hours

  public async submitRestRecord(
    input: { seafarerRef: string; vesselRef: string; recordDate: string; periods: RestHourPeriod[] },
    idempotencyKey: string,
    principal: Principal,
  ): Promise<{ recordId: string; created: boolean; flags: RestHourFlagRow[]; policyVersion: string; eventIds: string[] }> {
    const policy = this.requirePolicy();
    return withSpan("resthours.submit", {
      attributes: { "welfare.policy_version": policy.claims.policy_version, "welfare.vessel_ref_hashed": sha256Hex(input.vesselRef).slice(0, 12) },
    }, async () => {
      if (principal.role !== "operator" && principal.role !== "master") {
        throw new ServiceError(403, "rest-hour records are originated by the operator or master only");
      }
      assertCanonical(input.seafarerRef, "seafarerRef", 128);
      assertCanonical(input.vesselRef, "vesselRef", 128);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(input.recordDate) || !Number.isFinite(Date.parse(`${input.recordDate}T00:00:00Z`))) {
        throw new ServiceError(400, "recordDate must be a YYYY-MM-DD calendar date");
      }
      try {
        parsePeriods(input.periods);
      } catch (error) {
        if (error instanceof RestRecordValidationError) throw new ServiceError(400, error.message);
        throw error;
      }
      // A daily record's periods belong to the record date, allowing
      // cross-midnight extension into the next day (Reg 2.3 worked examples).
      const dayStart = Date.parse(`${input.recordDate}T00:00:00.000Z`);
      const dayEnd = dayStart + 48 * 3_600_000;
      for (const period of input.periods) {
        const startMs = Date.parse(period.start);
        const endMs = Date.parse(period.end);
        if (startMs < dayStart || endMs > dayEnd) {
          throw new ServiceError(400, "periods must fall within the record date and the following day (cross-midnight)");
        }
      }
      const regime = policy.claims.regime;
      const sourceDigest = sha256Hex(canonicalizeJson(asJsonValue({
        recordDate: input.recordDate,
        seafarerRef: input.seafarerRef,
        vesselRef: input.vesselRef,
        periods: input.periods,
      })));
      const recordId = deterministicUuid("rest-record", idempotencyKey);
      const breaches = await withSpan("resthours.evaluate", {
        attributes: { "welfare.policy_version": policy.claims.policy_version, "welfare.regime": regime },
      }, async () => evaluateRestHours(input.periods, regime));
      const now = new Date();
      const flags: RestHourFlagRow[] = [];
      const outboxes: OutboxMessage[] = [];
      for (const breach of breaches) {
        const flagId = deterministicUuid("rest-flag", `${recordId}|${breach.rule}|${policy.claims.policy_version}`);
        flags.push({
          flagId,
          recordId,
          rule: breach.rule,
          detail: breach.detail,
          policyVersion: policy.claims.policy_version,
          computedAt: now.toISOString(),
        });
        const envelope = await buildWelfareEnvelope({
          eventType: "seafarer.rest_hours.flagged.v1",
          producer: this.deps.producer,
          correlationId: recordId,
          principal: { principalId: principal.subject, principalRole: principal.role },
          resource: {
            "@type": "type.googleapis.com/blueeconomy.contracts.v1.RestHoursBreachFlagged",
            flagId,
            recordReference: recordId,
            seafarerReference: tokenizeReference("sfr", input.seafarerRef),
            vesselReference: tokenizeReference("vsl", input.vesselRef),
            rule: PROTO_NAMES.rule[breach.rule],
            regime: PROTO_NAMES.regime[regime],
            policyVersion: policy.claims.policy_version,
            sourceRecordDigestSha256: `sha256:${sourceDigest}`,
            computedAt: now.toISOString(),
          },
          signingKey: this.deps.signing.privateKey,
          keyId: this.deps.signing.keyId,
          deduplicationKey: `rest-flag|${flagId}`,
          occurredAt: now,
        });
        outboxes.push({ topic: WELFARE_TOPIC, eventId: envelope.eventId, payload: envelope as unknown as Record<string, unknown> });
      }
      const record: RestHourRecordRow = {
        recordId,
        seafarerRef: input.seafarerRef,
        vesselRef: input.vesselRef,
        recordDate: input.recordDate,
        periods: input.periods,
        regime,
        submittedBy: principal.subject,
        submittedByRole: principal.role as "operator" | "master",
        sourceDigestSha256: sourceDigest,
        policyVersion: policy.claims.policy_version,
        idempotencyKey,
        submittedAt: now.toISOString(),
      };
      const result = await this.deps.store.insertRestRecord(record, flags, outboxes);
      if (!result.created) {
        // Idempotent replay: report the retained flags, not a recomputation.
        const retained = await this.deps.store.listRestFlagsForRecords([result.record.recordId]);
        return { recordId: result.record.recordId, created: false, flags: retained, policyVersion: result.record.policyVersion, eventIds: [] };
      }
      return { recordId, created: true, flags, policyVersion: policy.claims.policy_version, eventIds: outboxes.map((outbox) => outbox.eventId) };
    });
  }

  public async myRestRecords(
    subject: string,
    range: { from?: string; to?: string; vesselRef?: string },
  ): Promise<{ seafarerReference: string | null; records: unknown[]; days?: unknown[]; missingCount?: number }> {
    const seafarerRef = await this.deps.identity.referenceFor(subject);
    if (seafarerRef === undefined) return { seafarerReference: null, records: [] };
    const hasRange = range.from !== undefined || range.to !== undefined;
    if (hasRange) {
      if (range.from === undefined || range.to === undefined || !isIsoDate(range.from) || !isIsoDate(range.to)) {
        throw new ServiceError(400, "from and to must both be YYYY-MM-DD dates");
      }
      if (range.from > range.to) throw new ServiceError(400, "from must not be after to");
      const spanDays = (Date.parse(`${range.to}T00:00:00Z`) - Date.parse(`${range.from}T00:00:00Z`)) / 86_400_000;
      if (spanDays > 31) throw new ServiceError(400, "the range is limited to 31 days");
      if (range.vesselRef === undefined) {
        throw new ServiceError(400, "vessel_ref is required for a date-range view so missing days can be reported as NOT_SUBMITTED");
      }
      assertCanonical(range.vesselRef, "vesselRef", 128);
    }
    const records = hasRange
      ? await this.deps.store.listRestRecordsBySeafarer(seafarerRef, range.from, range.to)
      : await this.deps.store.listRestRecordsBySeafarer(seafarerRef);
    const flags = await this.deps.store.listRestFlagsForRecords(records.map((record) => record.recordId));
    const views = records.map((record) => ({
      recordId: record.recordId,
      vesselRef: record.vesselRef,
      recordDate: record.recordDate,
      periods: record.periods,
      regime: record.regime,
      sourceDigestSha256: record.sourceDigestSha256,
      policyVersion: record.policyVersion,
      submittedAt: record.submittedAt,
      submittedByRole: record.submittedByRole,
      flags: flags.filter((flag) => flag.recordId === record.recordId),
    }));
    if (!hasRange) return { seafarerReference: seafarerRef, records: views };
    // Reg 2.3 honesty: days without an operator-submitted record are reported
    // NOT_SUBMITTED — never as compliant, never as fabricated zeros.
    const byDate = new Map(records.map((record) => [record.recordDate, record.recordId]));
    const days: unknown[] = [];
    let missingCount = 0;
    const fromMs = Date.parse(`${range.from ?? ""}T00:00:00.000Z`);
    const toMs = Date.parse(`${range.to ?? ""}T00:00:00.000Z`);
    for (let day = fromMs; day <= toMs; day += 86_400_000) {
      const date = new Date(day).toISOString().slice(0, 10);
      const recordId = byDate.get(date);
      if (recordId === undefined) {
        missingCount += 1;
        days.push({ date, status: "NOT_SUBMITTED" });
      } else {
        days.push({ date, status: "RECORDED", recordId });
      }
    }
    return { seafarerReference: seafarerRef, records: views, days, missingCount };
  }

  public async listRestFlags(filter: { vesselRef?: string }): Promise<unknown[]> {
    const rows = await this.deps.store.listRestFlags(filter);
    return rows.map((row) => ({
      flagId: row.flagId,
      recordId: row.recordId,
      vesselRef: row.vesselRef,
      recordDate: row.recordDate,
      rule: row.rule,
      detail: row.detail,
      policyVersion: row.policyVersion,
      computedAt: row.computedAt,
    }));
  }

  // ---------------------------------------------------------------- views

  /** Complainant-facing view: full record, own timeline, no officer internals. */
  private complainantView(complaint: ComplaintRecord, events: ComplaintEventRecord[]): Record<string, unknown> {
    return {
      complaintId: complaint.complaintId,
      channel: complaint.channel,
      vesselRef: complaint.vesselRef,
      operatorRef: complaint.operatorRef,
      category: complaint.category,
      status: complaint.status,
      narrative: this.deps.narrativeKey === undefined ? null : this.deps.narrativeKey.decrypt(complaint.narrativeEnc),
      narrativeDigestSha256: complaint.narrativeDigestSha256,
      attachments: complaint.attachments,
      rightToRedressNoticeAck: complaint.rightToRedressNoticeAck,
      disclosureScope: complaint.disclosureScope,
      submittedAt: complaint.submittedAt,
      timeline: events.map((event) => ({
        at: event.at,
        transition: event.transition,
        actorRole: event.actorRole,
        disclosureEvent: event.disclosureEvent,
      })),
    };
  }

  /**
   * Flag-state caseload view. Anti-victimization (Reg 5.1.5(2)): the
   * complainant identity (seafarer_ref, created_by_subject) is withheld until
   * a governed disclosure; the narrative (decrypted) is available to NIMASA
   * officers inside the CONFIDENTIAL boundary.
   */
  private officerView(complaint: ComplaintRecord, observation: unknown): Record<string, unknown> {
    const disclosed = complaint.disclosureScope === "disclosed";
    return {
      complaintId: complaint.complaintId,
      channel: complaint.channel,
      category: complaint.category,
      status: complaint.status,
      vesselRef: complaint.vesselRef,
      operatorRef: complaint.operatorRef,
      narrative: this.deps.narrativeKey === undefined ? null : this.deps.narrativeKey.decrypt(complaint.narrativeEnc),
      narrativeDigestSha256: complaint.narrativeDigestSha256,
      attachments: complaint.attachments,
      submittedAt: complaint.submittedAt,
      disclosureScope: complaint.disclosureScope,
      ...(disclosed
        ? { seafarerRef: complaint.seafarerRef, disclosedAt: complaint.disclosedAt, disclosedReasonCode: complaint.disclosedReasonCode }
        : {}),
      sla: observation === undefined || observation === null ? null : {
        stage: (observation as { stage: string }).stage,
        slaBreachedStages: (observation as { slaBreachedStages: string[] }).slaBreachedStages,
      },
    };
  }

  // -------------------------------------------------------------- helpers

  private requirePolicy(): WelfarePolicy {
    if (this.deps.policy === undefined) {
      throw new ServiceError(503, this.deps.policyUnavailableReason ?? "welfare policy is not configured; this endpoint is closed until NIMASA's signed welfare policy is deployed");
    }
    return this.deps.policy;
  }

  private requireNarrativeKey(): NarrativeKey {
    if (this.deps.narrativeKey === undefined) {
      throw new ServiceError(503, "complaint narrative encryption is not configured; complaint intake is closed (fail-closed)");
    }
    return this.deps.narrativeKey;
  }

  private async requireComplaint(complaintId: string): Promise<ComplaintRecord> {
    const complaint = await this.deps.store.getComplaint(complaintId);
    if (complaint === undefined) throw new ServiceError(404, "complaint is unknown");
    return complaint;
  }
}

function assertCanonical(value: string, field: string, maxLength: number): void {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0 || value.length > maxLength) {
    throw new ServiceError(400, `${field} must be canonical text of 1-${maxLength} characters`);
  }
}

function assertAttachments(attachments: Array<{ name: string; sha256: string }>): void {
  if (!Array.isArray(attachments) || attachments.length > 16) {
    throw new ServiceError(400, "attachments must be an array of at most 16 descriptors");
  }
  for (const [index, attachment] of attachments.entries()) {
    if (typeof attachment !== "object" || attachment === null) throw new ServiceError(400, `attachment ${index} must be an object`);
    if (typeof attachment.name !== "string" || attachment.name.trim().length === 0 || attachment.name.length > 256) {
      throw new ServiceError(400, `attachment ${index} name must be 1-256 characters`);
    }
    if (!/^[0-9a-f]{64}$/.test(attachment.sha256)) {
      throw new ServiceError(400, `attachment ${index} sha256 must be a SHA-256 hex digest; attachments carry digests, never content`);
    }
  }
}

function isIsoDate(value: string): boolean {
  return /^\d{4}-\d{2}-\d{2}$/.test(value) && Number.isFinite(Date.parse(`${value}T00:00:00Z`));
}

function payloadText(payload: Record<string, unknown>, field: string): string {
  const value = payload[field];
  if (typeof value !== "string" || value.trim() !== value || value.length === 0 || value.length > 64) {
    throw new ServiceError(422, `stored transition request payload field ${field} is invalid (fail-closed)`);
  }
  return value;
}

function payloadStatus(payload: Record<string, unknown>, field: string): ComplaintStatus {
  const value = payload[field];
  if (!isMember(COMPLAINT_STATUSES, value)) {
    throw new ServiceError(422, `stored transition request payload field ${field} is not a complaint status (fail-closed)`);
  }
  return value;
}

function payloadDigest(payload: Record<string, unknown>, field: string): string | null {
  const value = payload[field];
  if (value === null) return null;
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw new ServiceError(422, `stored transition request payload field ${field} is not a digest or null (fail-closed)`);
  }
  return value;
}
