import type pg from "pg";
import { enqueueOutboxMessage, type SqlExecutor } from "../status/postgres.js";
import type { OutboxMessage } from "../status/store.js";
import { canonicalPayload } from "../service/maker-checker.js";
import {
  COMPLAINT_CATEGORIES,
  COMPLAINT_CHANNELS,
  COMPLAINT_STATUSES,
  REFERRAL_STATUSES,
  REST_HOUR_RULES,
  deterministicUuid,
  isMember,
  type ComplaintStatus,
  type ReferralStatus,
} from "./types.js";
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
} from "./store.js";

/**
 * PostgreSQL welfare store (migration 0006). All statements are parameterized;
 * every mutation that emits an event commits with its outbox row in a single
 * transaction, mirroring PgStatusStore. Guarded UPDATEs make illegal or stale
 * transitions yield no row so the service can refuse truthfully instead of
 * relying on raw constraint violations.
 */

export class PgWelfareStore implements WelfareStore {
  private readonly executor: SqlExecutor;
  private readonly onClose?: () => Promise<void>;

  public constructor(options: { executor: SqlExecutor; ownsExecutor?: () => Promise<void> }) {
    this.executor = options.executor;
    if (options.ownsExecutor !== undefined) this.onClose = options.ownsExecutor;
  }

  // ------------------------------------------------------------- directory

  public async insertProvider(
    input: ProviderInput,
    services: Array<Pick<ServiceRecord, "description" | "eligibility" | "languages">>,
    curatedBy: string,
  ): Promise<ProviderWithServices> {
    const providerId = deterministicUuid("provider", `${input.portCode}|${input.kind}|${input.name}|${input.sourceReference}`);
    await this.executor.query("BEGIN");
    try {
      await this.executor.query(
        `INSERT INTO welfare_provider (provider_id, name, kind, port_code, address, contact, hours, source_reference, status, curated_by)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, 'ACTIVE', $9)`,
        [providerId, input.name, input.kind, input.portCode, input.address, JSON.stringify(input.contact), input.hours, input.sourceReference, curatedBy],
      );
      for (const service of services) {
        const serviceId = deterministicUuid("service", `${providerId}|${service.description}`);
        await this.executor.query(
          `INSERT INTO welfare_service (service_id, provider_id, description, eligibility, languages)
           VALUES ($1, $2, $3, $4, $5::jsonb)`,
          [serviceId, providerId, service.description, service.eligibility, JSON.stringify(service.languages)],
        );
      }
      await this.executor.query("COMMIT");
    } catch (error) {
      await this.rollback();
      throw error;
    }
    const provider = await this.getProvider(providerId);
    if (provider === undefined) throw new Error("provider insert committed but the row is not visible (fail-closed)");
    return provider;
  }

  public async listProviders(portCode?: string): Promise<ProviderWithServices[]> {
    const result = portCode === undefined
      ? await this.executor.query<ProviderRow>(`SELECT * FROM welfare_provider ORDER BY port_code, name`)
      : await this.executor.query<ProviderRow>(`SELECT * FROM welfare_provider WHERE port_code = $1 ORDER BY name`, [portCode]);
    return this.withServices(result.rows);
  }

  public async getProvider(providerId: string): Promise<ProviderWithServices | undefined> {
    const result = await this.executor.query<ProviderRow>(`SELECT * FROM welfare_provider WHERE provider_id = $1`, [providerId]);
    const row = result.rows[0];
    if (row === undefined) return undefined;
    const withServices = await this.withServices([row]);
    return withServices[0];
  }

  public async getService(serviceId: string): Promise<(ServiceRecord & { providerStatus: "ACTIVE" | "SUSPENDED" }) | undefined> {
    const result = await this.executor.query<ServiceRow & { provider_status: "ACTIVE" | "SUSPENDED" }>(
      `SELECT s.*, p.status AS provider_status
         FROM welfare_service s JOIN welfare_provider p ON p.provider_id = s.provider_id
        WHERE s.service_id = $1`,
      [serviceId],
    );
    const row = result.rows[0];
    if (row === undefined) return undefined;
    return { ...mapServiceRow(row), providerStatus: row.provider_status };
  }

  private async withServices(rows: ProviderRow[]): Promise<ProviderWithServices[]> {
    const providers: ProviderWithServices[] = [];
    for (const row of rows) {
      const services = await this.executor.query<ServiceRow>(
        `SELECT * FROM welfare_service WHERE provider_id = $1 ORDER BY service_id`,
        [row.provider_id],
      );
      providers.push({ ...mapProviderRow(row), services: services.rows.map(mapServiceRow) });
    }
    return providers;
  }

  // ------------------------------------------------------------ complaints

  public async createComplaint(record: ComplaintRecord, outbox: OutboxMessage): Promise<Created<ComplaintRecord>> {
    assertComplaintRecord(record);
    await this.executor.query("BEGIN");
    try {
      const inserted = await this.executor.query<ComplaintRow>(
        `INSERT INTO welfare_complaint (
           complaint_id, channel, seafarer_ref, vessel_ref, operator_ref, category,
           narrative_enc, narrative_digest_sha256, attachments, idempotency_key,
           status, right_to_redress_notice_ack, created_by_subject
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,'RECEIVED',$11,$12)
         ON CONFLICT (idempotency_key) DO NOTHING
         RETURNING *`,
        [
          record.complaintId, record.channel, record.seafarerRef, record.vesselRef, record.operatorRef,
          record.category, record.narrativeEnc, record.narrativeDigestSha256, JSON.stringify(record.attachments),
          record.idempotencyKey, record.rightToRedressNoticeAck, record.createdBySubject,
        ],
      );
      if (inserted.rows[0] === undefined) {
        // Idempotent replay: return the retained complaint, but fail closed if
        // the same key was reused for different content.
        const existing = await this.findComplaintByIdempotencyKey(record.idempotencyKey);
        if (existing === undefined) throw new Error("complaint insert conflicted but no stored row is visible (fail-closed)");
        if (existing.complaintId !== record.complaintId || existing.narrativeDigestSha256 !== record.narrativeDigestSha256) {
          throw new WelfareStateError("idempotency key was reused for a different complaint (fail-closed)");
        }
        await this.executor.query("COMMIT");
        return { created: false, record: existing };
      }
      await this.executor.query(
        `INSERT INTO welfare_complaint_event (complaint_id, actor_role, transition, note_digest_sha256, disclosure_event)
         VALUES ($1, $2, $3, $4, false)`,
        [record.complaintId, "seafarer", "RECEIVED", record.narrativeDigestSha256],
      );
      await insertOutbox(this.executor, outbox);
      await this.executor.query("COMMIT");
      return { created: true, record: mapComplaintRow(inserted.rows[0]) };
    } catch (error) {
      await this.rollback();
      throw error;
    }
  }

  private async findComplaintByIdempotencyKey(key: string): Promise<ComplaintRecord | undefined> {
    const result = await this.executor.query<ComplaintRow>(`SELECT * FROM welfare_complaint WHERE idempotency_key = $1`, [key]);
    const row = result.rows[0];
    return row === undefined ? undefined : mapComplaintRow(row);
  }

  public async getComplaint(complaintId: string): Promise<ComplaintRecord | undefined> {
    const result = await this.executor.query<ComplaintRow>(`SELECT * FROM welfare_complaint WHERE complaint_id = $1`, [complaintId]);
    const row = result.rows[0];
    return row === undefined ? undefined : mapComplaintRow(row);
  }

  public async listComplaintsBySeafarer(seafarerRef: string): Promise<ComplaintRecord[]> {
    const result = await this.executor.query<ComplaintRow>(
      `SELECT * FROM welfare_complaint WHERE seafarer_ref = $1 ORDER BY submitted_at, complaint_id`,
      [seafarerRef],
    );
    return result.rows.map(mapComplaintRow);
  }

  public async listComplaints(filter: { status?: ComplaintStatus; vesselRef?: string }): Promise<ComplaintRecord[]> {
    const conditions: string[] = [];
    const params: unknown[] = [];
    if (filter.status !== undefined) {
      params.push(filter.status);
      conditions.push(`status = $${params.length}`);
    }
    if (filter.vesselRef !== undefined) {
      params.push(filter.vesselRef);
      conditions.push(`vessel_ref = $${params.length}`);
    }
    const where = conditions.length === 0 ? "" : ` WHERE ${conditions.join(" AND ")}`;
    const result = await this.executor.query<ComplaintRow>(
      `SELECT * FROM welfare_complaint${where} ORDER BY submitted_at, complaint_id`,
      params,
    );
    return result.rows.map(mapComplaintRow);
  }

  public async listComplaintEvents(complaintId: string): Promise<ComplaintEventRecord[]> {
    const result = await this.executor.query<ComplaintEventRow>(
      `SELECT * FROM welfare_complaint_event WHERE complaint_id = $1 ORDER BY id`,
      [complaintId],
    );
    return result.rows.map(mapComplaintEventRow);
  }

  // ------------------------------------------------ maker/checker control

  public async createTransitionRequest(request: TransitionRequest): Promise<Created<TransitionRequest>> {
    const inserted = await this.executor.query<TransitionRequestRow>(
      `INSERT INTO welfare_transition_requests (request_id, kind, complaint_id, payload, requester_subject, requester_role, status, requested_at)
       VALUES ($1, $2, $3, $4::jsonb, $5, $6, 'PENDING', $7)
       ON CONFLICT (request_id) DO NOTHING
       RETURNING *`,
      [request.requestId, request.kind, request.complaintId, JSON.stringify(request.payload), request.requesterSubject, request.requesterRole, request.requestedAt],
    );
    if (inserted.rows[0] !== undefined) return { created: true, record: mapTransitionRequestRow(inserted.rows[0]) };
    const existing = await this.getTransitionRequest(request.requestId);
    if (existing === undefined) throw new Error("transition request insert conflicted but no stored request is visible (fail-closed)");
    if (existing.kind !== request.kind || canonicalPayload(existing.payload) !== canonicalPayload(request.payload)) {
      throw new WelfareStateError(`transition request id ${request.requestId} already exists with different content (fail-closed)`);
    }
    return { created: false, record: existing };
  }

  public async getTransitionRequest(requestId: string): Promise<TransitionRequest | undefined> {
    const result = await this.executor.query<TransitionRequestRow>(
      `SELECT * FROM welfare_transition_requests WHERE request_id = $1`,
      [requestId],
    );
    const row = result.rows[0];
    return row === undefined ? undefined : mapTransitionRequestRow(row);
  }

  public async markTransitionRequestApproved(requestId: string, approverSubject: string): Promise<TransitionRequest> {
    const result = await this.executor.query<TransitionRequestRow>(
      `UPDATE welfare_transition_requests
          SET status = 'APPROVED', approver_subject = $2, decided_at = now()
        WHERE request_id = $1 AND status = 'PENDING' AND requester_subject <> $2
        RETURNING *`,
      [requestId, approverSubject],
    );
    const row = result.rows[0];
    if (row !== undefined) return mapTransitionRequestRow(row);
    const current = await this.getTransitionRequest(requestId);
    if (current === undefined) throw new WelfareStateError("transition request is unknown");
    if (current.status !== "PENDING") throw new WelfareStateError("transition request is already approved");
    throw new WelfareStateError("maker/checker violation: the requesting officer cannot approve their own complaint transition");
  }

  public async applyComplaintTransition(
    complaintId: string,
    from: ComplaintStatus,
    to: ComplaintStatus,
    actorRole: string,
    noteDigestSha256: string | null,
    outbox: OutboxMessage,
  ): Promise<ComplaintRecord> {
    await this.executor.query("BEGIN");
    try {
      const updated = await this.executor.query<ComplaintRow>(
        `UPDATE welfare_complaint SET status = $3
          WHERE complaint_id = $1 AND status = $2
          RETURNING *`,
        [complaintId, from, to],
      );
      if (updated.rows[0] === undefined) {
        const current = await this.getComplaint(complaintId);
        if (current === undefined) throw new WelfareStateError("complaint is unknown");
        throw new WelfareStateError(`complaint is ${current.status}; the approved transition ${from} -> ${to} no longer applies (fail-closed)`);
      }
      await this.executor.query(
        `INSERT INTO welfare_complaint_event (complaint_id, actor_role, transition, note_digest_sha256, disclosure_event)
         VALUES ($1, $2, $3, $4, false)`,
        [complaintId, actorRole, `${from}->${to}`, noteDigestSha256],
      );
      await insertOutbox(this.executor, outbox);
      await this.executor.query("COMMIT");
      return mapComplaintRow(updated.rows[0]);
    } catch (error) {
      await this.rollback();
      throw error;
    }
  }

  public async applyComplaintDisclosure(
    complaintId: string,
    reasonCode: string,
    actorRole: string,
    noteDigestSha256: string | null,
    outbox: OutboxMessage,
  ): Promise<ComplaintRecord> {
    await this.executor.query("BEGIN");
    try {
      const updated = await this.executor.query<ComplaintRow>(
        `UPDATE welfare_complaint
            SET disclosure_scope = 'disclosed', disclosed_at = now(), disclosed_reason_code = $2
          WHERE complaint_id = $1 AND disclosure_scope = 'withheld'
          RETURNING *`,
        [complaintId, reasonCode],
      );
      if (updated.rows[0] === undefined) {
        const current = await this.getComplaint(complaintId);
        if (current === undefined) throw new WelfareStateError("complaint is unknown");
        throw new WelfareStateError("complainant identity is already disclosed; disclosure is a one-time governed event (fail-closed)");
      }
      await this.executor.query(
        `INSERT INTO welfare_complaint_event (complaint_id, actor_role, transition, note_digest_sha256, disclosure_event)
         VALUES ($1, $2, $3, $4, true)`,
        [complaintId, actorRole, `DISCLOSE:${reasonCode}`, noteDigestSha256],
      );
      await insertOutbox(this.executor, outbox);
      await this.executor.query("COMMIT");
      return mapComplaintRow(updated.rows[0]);
    } catch (error) {
      await this.rollback();
      throw error;
    }
  }

  // -------------------------------------------------------------- referrals

  public async createReferral(record: ReferralRecord, outbox: OutboxMessage): Promise<Created<ReferralRecord>> {
    await this.executor.query("BEGIN");
    try {
      const inserted = await this.executor.query<ReferralRow>(
        `INSERT INTO welfare_referral (referral_id, complaint_id, seafarer_ref, service_id, consent_at, status, idempotency_key, created_by_subject)
         VALUES ($1, $2, $3, $4, $5, 'OFFERED', $6, $7)
         ON CONFLICT (idempotency_key) DO NOTHING
         RETURNING *`,
        [record.referralId, record.complaintId, record.seafarerRef, record.serviceId, record.consentAt, record.idempotencyKey, record.createdBySubject],
      );
      if (inserted.rows[0] === undefined) {
        const existing = await this.executor.query<ReferralRow>(`SELECT * FROM welfare_referral WHERE idempotency_key = $1`, [record.idempotencyKey]);
        const row = existing.rows[0];
        if (row === undefined) throw new Error("referral insert conflicted but no stored row is visible (fail-closed)");
        const mapped = mapReferralRow(row);
        if (mapped.referralId !== record.referralId || mapped.serviceId !== record.serviceId || mapped.seafarerRef !== record.seafarerRef) {
          throw new WelfareStateError("idempotency key was reused for a different referral (fail-closed)");
        }
        await this.executor.query("COMMIT");
        return { created: false, record: mapped };
      }
      await insertOutbox(this.executor, outbox);
      await this.executor.query("COMMIT");
      return { created: true, record: mapReferralRow(inserted.rows[0]) };
    } catch (error) {
      await this.rollback();
      throw error;
    }
  }

  public async getReferral(referralId: string): Promise<ReferralRecord | undefined> {
    const result = await this.executor.query<ReferralRow>(`SELECT * FROM welfare_referral WHERE referral_id = $1`, [referralId]);
    const row = result.rows[0];
    return row === undefined ? undefined : mapReferralRow(row);
  }

  public async listReferralsBySeafarer(seafarerRef: string): Promise<ReferralRecord[]> {
    const result = await this.executor.query<ReferralRow>(
      `SELECT * FROM welfare_referral WHERE seafarer_ref = $1 ORDER BY recorded_at, referral_id`,
      [seafarerRef],
    );
    return result.rows.map(mapReferralRow);
  }

  public async transitionReferral(
    referralId: string,
    from: ReferralStatus,
    to: ReferralStatus,
    outcomeNoteDigestSha256: string | null,
    outbox: OutboxMessage,
  ): Promise<ReferralRecord> {
    await this.executor.query("BEGIN");
    try {
      const updated = await this.executor.query<ReferralRow>(
        `UPDATE welfare_referral
            SET status = $3, outcome_note_digest_sha256 = COALESCE($4, outcome_note_digest_sha256)
          WHERE referral_id = $1 AND status = $2
          RETURNING *`,
        [referralId, from, to, outcomeNoteDigestSha256],
      );
      if (updated.rows[0] === undefined) {
        const current = await this.getReferral(referralId);
        if (current === undefined) throw new WelfareStateError("referral is unknown");
        throw new WelfareStateError(`referral is ${current.status}; the transition ${from} -> ${to} does not apply (fail-closed)`);
      }
      await insertOutbox(this.executor, outbox);
      await this.executor.query("COMMIT");
      return mapReferralRow(updated.rows[0]);
    } catch (error) {
      await this.rollback();
      throw error;
    }
  }

  // -------------------------------------------------------------- rest hours

  public async insertRestRecord(
    record: RestHourRecordRow,
    flags: RestHourFlagRow[],
    outboxes: OutboxMessage[],
  ): Promise<Created<RestHourRecordRow>> {
    if (flags.length !== outboxes.length) throw new Error("each rest-hour flag must carry exactly one outbox event");
    await this.executor.query("BEGIN");
    try {
      const inserted = await this.executor.query<RestRecordRow>(
        `INSERT INTO rest_hour_record (
           record_id, seafarer_ref, vessel_ref, record_date, periods, regime,
           submitted_by, submitted_by_role, source_digest_sha256, policy_version, idempotency_key
         ) VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10,$11)
         ON CONFLICT (idempotency_key) DO NOTHING
         RETURNING *`,
        [
          record.recordId, record.seafarerRef, record.vesselRef, record.recordDate, JSON.stringify(record.periods),
          record.regime, record.submittedBy, record.submittedByRole, record.sourceDigestSha256, record.policyVersion, record.idempotencyKey,
        ],
      );
      if (inserted.rows[0] === undefined) {
        const existing = await this.executor.query<RestRecordRow>(`SELECT * FROM rest_hour_record WHERE idempotency_key = $1`, [record.idempotencyKey]);
        const row = existing.rows[0];
        if (row === undefined) throw new Error("rest-hour record insert conflicted but no stored row is visible (fail-closed)");
        const mapped = mapRestRecordRow(row);
        if (mapped.recordId !== record.recordId || mapped.sourceDigestSha256 !== record.sourceDigestSha256) {
          throw new WelfareStateError("idempotency key was reused for a different rest-hour record (fail-closed)");
        }
        await this.executor.query("COMMIT");
        return { created: false, record: mapped };
      }
      for (const flag of flags) {
        await this.executor.query(
          `INSERT INTO rest_hour_flag (flag_id, record_id, rule, detail, policy_version)
           VALUES ($1, $2, $3, $4, $5)`,
          [flag.flagId, flag.recordId, flag.rule, flag.detail, flag.policyVersion],
        );
      }
      for (const outbox of outboxes) {
        await insertOutbox(this.executor, outbox);
      }
      await this.executor.query("COMMIT");
      return { created: true, record: mapRestRecordRow(inserted.rows[0]) };
    } catch (error) {
      await this.rollback();
      throw error;
    }
  }

  public async getRestRecord(recordId: string): Promise<RestHourRecordRow | undefined> {
    const result = await this.executor.query<RestRecordRow>(`SELECT * FROM rest_hour_record WHERE record_id = $1`, [recordId]);
    const row = result.rows[0];
    return row === undefined ? undefined : mapRestRecordRow(row);
  }

  public async listRestRecordsBySeafarer(seafarerRef: string, from?: string, to?: string): Promise<RestHourRecordRow[]> {
    const conditions = ["seafarer_ref = $1"];
    const params: unknown[] = [seafarerRef];
    if (from !== undefined) {
      params.push(from);
      conditions.push(`record_date >= $${params.length}`);
    }
    if (to !== undefined) {
      params.push(to);
      conditions.push(`record_date <= $${params.length}`);
    }
    const result = await this.executor.query<RestRecordRow>(
      `SELECT * FROM rest_hour_record WHERE ${conditions.join(" AND ")} ORDER BY record_date, record_id`,
      params,
    );
    return result.rows.map(mapRestRecordRow);
  }

  public async listRestFlagsForRecords(recordIds: readonly string[]): Promise<RestHourFlagRow[]> {
    if (recordIds.length === 0) return [];
    const result = await this.executor.query<RestFlagRow>(
      `SELECT * FROM rest_hour_flag WHERE record_id = ANY($1::text[]) ORDER BY computed_at, flag_id`,
      [[...recordIds]],
    );
    return result.rows.map(mapRestFlagRow);
  }

  public async listRestFlags(filter: { vesselRef?: string }): Promise<Array<RestHourFlagRow & { vesselRef: string; seafarerRef: string; recordDate: string }>> {
    const conditions: string[] = [];
    const params: unknown[] = [];
    if (filter.vesselRef !== undefined) {
      params.push(filter.vesselRef);
      conditions.push(`r.vessel_ref = $${params.length}`);
    }
    const where = conditions.length === 0 ? "" : ` WHERE ${conditions.join(" AND ")}`;
    const result = await this.executor.query<RestFlagRow & { vessel_ref: string; seafarer_ref: string; record_date: Date }>(
      `SELECT f.*, r.vessel_ref, r.seafarer_ref, r.record_date
         FROM rest_hour_flag f JOIN rest_hour_record r ON r.record_id = f.record_id${where}
        ORDER BY f.computed_at, f.flag_id`,
      params,
    );
    return result.rows.map((row) => ({
      ...mapRestFlagRow(row),
      vesselRef: row.vessel_ref,
      seafarerRef: row.seafarer_ref,
      recordDate: toIsoDate(row.record_date),
    }));
  }

  public async recordSlaBreachesObserved(complaintId: string, stages: readonly string[]): Promise<string[]> {
    const observed: string[] = [];
    for (const stage of stages) {
      const result = await this.executor.query(
        `INSERT INTO welfare_sla_breach_observed (complaint_id, stage) VALUES ($1, $2)
         ON CONFLICT (complaint_id, stage) DO NOTHING
         RETURNING stage`,
        [complaintId, stage],
      );
      if (result.rows.length > 0) observed.push(stage);
    }
    return observed;
  }

  public async healthCheck(): Promise<void> {
    await this.executor.query("SELECT 1");
  }

  public async close(): Promise<void> {
    if (this.onClose !== undefined) await this.onClose();
  }

  private async rollback(): Promise<void> {
    try {
      await this.executor.query("ROLLBACK");
    } catch {
      // Original failure is authoritative.
    }
  }
}

// ---------------------------------------------------------------------------
// Rows and mappers
// ---------------------------------------------------------------------------

interface ProviderRow extends pg.QueryResultRow {
  provider_id: string;
  name: string;
  kind: ProviderWithServices["kind"];
  port_code: string;
  address: string;
  contact: Record<string, unknown>;
  hours: string;
  source_reference: string;
  status: "ACTIVE" | "SUSPENDED";
  curated_by: string;
  curated_at: Date;
}

interface ServiceRow extends pg.QueryResultRow {
  service_id: string;
  provider_id: string;
  description: string;
  eligibility: string;
  languages: unknown;
}

interface ComplaintRow extends pg.QueryResultRow {
  complaint_id: string;
  channel: ComplaintRecord["channel"];
  seafarer_ref: string;
  vessel_ref: string;
  operator_ref: string | null;
  category: ComplaintRecord["category"];
  narrative_enc: string;
  narrative_digest_sha256: string;
  attachments: unknown;
  idempotency_key: string;
  status: ComplaintRecord["status"];
  right_to_redress_notice_ack: boolean;
  disclosure_scope: "withheld" | "disclosed";
  disclosed_at: Date | null;
  disclosed_reason_code: string | null;
  created_by_subject: string;
  submitted_at: Date;
}

interface ComplaintEventRow extends pg.QueryResultRow {
  id: string;
  complaint_id: string;
  at: Date;
  actor_role: string;
  transition: string;
  note_digest_sha256: string | null;
  disclosure_event: boolean;
}

interface TransitionRequestRow extends pg.QueryResultRow {
  request_id: string;
  kind: TransitionRequest["kind"];
  complaint_id: string;
  payload: unknown;
  requester_subject: string;
  requester_role: string;
  status: TransitionRequest["status"];
  requested_at: Date;
  approver_subject: string | null;
  decided_at: Date | null;
}

interface ReferralRow extends pg.QueryResultRow {
  referral_id: string;
  complaint_id: string | null;
  seafarer_ref: string;
  service_id: string;
  consent_at: Date;
  status: ReferralRecord["status"];
  outcome_note_digest_sha256: string | null;
  idempotency_key: string;
  created_by_subject: string;
  recorded_at: Date;
}

interface RestRecordRow extends pg.QueryResultRow {
  record_id: string;
  seafarer_ref: string;
  vessel_ref: string;
  record_date: Date;
  periods: unknown;
  regime: RestHourRecordRow["regime"];
  submitted_by: string;
  submitted_by_role: "operator" | "master";
  source_digest_sha256: string;
  policy_version: string;
  idempotency_key: string;
  submitted_at: Date;
}

interface RestFlagRow extends pg.QueryResultRow {
  flag_id: string;
  record_id: string;
  rule: RestHourFlagRow["rule"];
  detail: string;
  policy_version: string;
  computed_at: Date;
}

function mapProviderRow(row: ProviderRow): ProviderWithServices {
  return {
    providerId: row.provider_id,
    name: row.name,
    kind: row.kind,
    portCode: row.port_code,
    address: row.address,
    contact: row.contact,
    hours: row.hours,
    sourceReference: row.source_reference,
    status: row.status,
    curatedBy: row.curated_by,
    curatedAt: new Date(row.curated_at).toISOString(),
    services: [],
  };
}

function mapServiceRow(row: ServiceRow): ServiceRecord {
  return {
    serviceId: row.service_id,
    providerId: row.provider_id,
    description: row.description,
    eligibility: row.eligibility,
    languages: Array.isArray(row.languages) ? (row.languages as string[]) : [],
  };
}

function mapComplaintRow(row: ComplaintRow): ComplaintRecord {
  if (!isMember(COMPLAINT_CHANNELS, row.channel) || !isMember(COMPLAINT_CATEGORIES, row.category) || !isMember(COMPLAINT_STATUSES, row.status)) {
    throw new Error(`stored complaint ${row.complaint_id} violates the domain vocabulary (fail-closed)`);
  }
  if (row.right_to_redress_notice_ack !== true) {
    throw new Error(`stored complaint ${row.complaint_id} lacks the right-to-redress acknowledgement (fail-closed)`);
  }
  return {
    complaintId: row.complaint_id,
    channel: row.channel,
    seafarerRef: row.seafarer_ref,
    vesselRef: row.vessel_ref,
    operatorRef: row.operator_ref,
    category: row.category,
    narrativeEnc: row.narrative_enc,
    narrativeDigestSha256: row.narrative_digest_sha256,
    attachments: parseAttachments(row.attachments),
    idempotencyKey: row.idempotency_key,
    status: row.status,
    rightToRedressNoticeAck: true,
    disclosureScope: row.disclosure_scope,
    disclosedAt: row.disclosed_at === null ? null : new Date(row.disclosed_at).toISOString(),
    disclosedReasonCode: row.disclosed_reason_code,
    createdBySubject: row.created_by_subject,
    submittedAt: new Date(row.submitted_at).toISOString(),
  };
}

function mapComplaintEventRow(row: ComplaintEventRow): ComplaintEventRecord {
  return {
    id: Number(row.id),
    complaintId: row.complaint_id,
    at: new Date(row.at).toISOString(),
    actorRole: row.actor_role,
    transition: row.transition,
    noteDigestSha256: row.note_digest_sha256,
    disclosureEvent: row.disclosure_event,
  };
}

function mapTransitionRequestRow(row: TransitionRequestRow): TransitionRequest {
  const payload = typeof row.payload === "string" ? (JSON.parse(row.payload) as Record<string, unknown>) : (row.payload as Record<string, unknown>);
  const request: TransitionRequest = {
    requestId: row.request_id,
    kind: row.kind,
    complaintId: row.complaint_id,
    payload,
    requesterSubject: row.requester_subject,
    requesterRole: row.requester_role,
    status: row.status,
    requestedAt: new Date(row.requested_at).toISOString(),
  };
  if (row.approver_subject !== null) request.approverSubject = row.approver_subject;
  if (row.decided_at !== null) request.decidedAt = new Date(row.decided_at).toISOString();
  return request;
}

function mapReferralRow(row: ReferralRow): ReferralRecord {
  if (!isMember(REFERRAL_STATUSES, row.status)) {
    throw new Error(`stored referral ${row.referral_id} violates the domain vocabulary (fail-closed)`);
  }
  return {
    referralId: row.referral_id,
    complaintId: row.complaint_id,
    seafarerRef: row.seafarer_ref,
    serviceId: row.service_id,
    consentAt: new Date(row.consent_at).toISOString(),
    status: row.status,
    outcomeNoteDigestSha256: row.outcome_note_digest_sha256,
    idempotencyKey: row.idempotency_key,
    createdBySubject: row.created_by_subject,
    recordedAt: new Date(row.recorded_at).toISOString(),
  };
}

function mapRestRecordRow(row: RestRecordRow): RestHourRecordRow {
  const periods = typeof row.periods === "string" ? (JSON.parse(row.periods) as unknown) : row.periods;
  if (!Array.isArray(periods)) throw new Error(`stored rest-hour record ${row.record_id} periods are invalid (fail-closed)`);
  return {
    recordId: row.record_id,
    seafarerRef: row.seafarer_ref,
    vesselRef: row.vessel_ref,
    recordDate: toIsoDate(row.record_date),
    periods: periods as RestHourRecordRow["periods"],
    regime: row.regime,
    submittedBy: row.submitted_by,
    submittedByRole: row.submitted_by_role,
    sourceDigestSha256: row.source_digest_sha256,
    policyVersion: row.policy_version,
    idempotencyKey: row.idempotency_key,
    submittedAt: new Date(row.submitted_at).toISOString(),
  };
}

function mapRestFlagRow(row: RestFlagRow): RestHourFlagRow {
  if (!isMember(REST_HOUR_RULES, row.rule)) {
    throw new Error(`stored rest-hour flag ${row.flag_id} carries an unknown rule (fail-closed)`);
  }
  return {
    flagId: row.flag_id,
    recordId: row.record_id,
    rule: row.rule,
    detail: row.detail,
    policyVersion: row.policy_version,
    computedAt: new Date(row.computed_at).toISOString(),
  };
}

function toIsoDate(value: Date | string): string {
  if (value instanceof Date) return value.toISOString().slice(0, 10);
  return String(value).slice(0, 10);
}

function parseAttachments(value: unknown): Array<{ name: string; sha256: string }> {
  const parsed = typeof value === "string" ? (JSON.parse(value) as unknown) : value;
  if (!Array.isArray(parsed)) throw new Error("stored complaint attachments are invalid (fail-closed)");
  return parsed as Array<{ name: string; sha256: string }>;
}

function assertComplaintRecord(record: ComplaintRecord): void {
  if (!/^urn:uuid:[0-9a-f-]{36}$/.test(record.complaintId)) throw new Error("complaint id must be a deterministic urn:uuid");
  if (!/^[0-9a-f]{64}$/.test(record.narrativeDigestSha256)) throw new Error("narrative digest must be a SHA-256 hex digest");
  if (record.rightToRedressNoticeAck !== true) throw new Error("the right-to-redress notice acknowledgement is mandatory (Reg 5.1.5(3))");
  if (record.status !== "RECEIVED") throw new Error("a new complaint enters as RECEIVED");
  if (record.attachments.length > 16) throw new Error("a complaint carries at most 16 attachment descriptors");
}

/**
 * Inserts a welfare outbox row. The shared credential_outbox table drains
 * through the existing OutboxPublisher; the topic allowlist in
 * src/status/postgres.ts includes the welfare topic.
 */
async function insertOutbox(executor: SqlExecutor, message: OutboxMessage): Promise<void> {
  await enqueueOutboxMessage(executor, message);
}

export function createPgWelfareStore(executor: SqlExecutor, ownsExecutor?: () => Promise<void>): PgWelfareStore {
  return new PgWelfareStore({ executor, ...(ownsExecutor !== undefined ? { ownsExecutor } : {}) });
}
