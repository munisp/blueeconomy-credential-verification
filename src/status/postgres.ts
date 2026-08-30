import { readFile, readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import pg from "pg";
import {
  ApprovalStateError,
  assertApprovalRequest,
  canonicalPayload,
  type ApprovalRequest,
  type ApprovalRequestCreated,
  type ApprovalStore,
} from "../service/maker-checker.js";
import {
  assertStatusEntry,
  credentialIdReference,
  type HolderCredentialRecord,
  type OutboxMessage,
  type StatusEntry,
  type StatusListBitRow,
  type StatusRecord,
  type StatusStore,
} from "./store.js";

/** Narrow query surface so tests can exercise SQL behavior with a recorder. */
export interface SqlExecutor {
  query<Row extends pg.QueryResultRow = pg.QueryResultRow>(text: string, params?: readonly unknown[]): Promise<pg.QueryResult<Row>>;
}

export interface PgStatusStoreOptions {
  executor: SqlExecutor;
  /** Owns pool lifecycle (close on store close). */
  ownsExecutor?: () => Promise<void>;
}

interface StatusRow extends pg.QueryResultRow {
  credential_id_reference_sha256: string;
  issuer: string;
  status: StatusRecord["status"];
  reason: string;
  status_list_id: string;
  status_list_index: number;
  updated_by: string;
  effective_at: Date;
  updated_at: Date;
  sequence: string;
}

// The WHERE clause makes REVOKED terminal at the statement layer: an update
// against a revoked row matches nothing, RETURNING yields no row and the
// caller surfaces a truthful refusal instead of silently reversing the
// revocation. Migration 0004 additionally enforces the invariant by trigger.
const UPSERT_STATUS = `
INSERT INTO credential_status (
  credential_id_reference_sha256, issuer, status, reason,
  status_list_id, status_list_index, updated_by, effective_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
ON CONFLICT (credential_id_reference_sha256) DO UPDATE SET
  status = EXCLUDED.status,
  reason = EXCLUDED.reason,
  status_list_id = EXCLUDED.status_list_id,
  status_list_index = EXCLUDED.status_list_index,
  updated_by = EXCLUDED.updated_by,
  effective_at = EXCLUDED.effective_at,
  updated_at = now()
WHERE credential_status.status <> 'REVOKED'
RETURNING credential_id_reference_sha256, issuer, status, reason,
  status_list_id, status_list_index, updated_by, effective_at, updated_at, sequence`;

const SELECT_CURRENT_STATUS = `
SELECT status
  FROM credential_status
 WHERE credential_id_reference_sha256 = $1`;

// RETURNING exposes dedup swallows: when the event id already exists the
// insert yields no row and the caller must verify the stored payload matches
// (benign replay) or fail closed (a state transition was being swallowed).
const INSERT_OUTBOX = `
INSERT INTO credential_outbox (topic, event_id, payload)
VALUES ($1, $2, $3::jsonb)
ON CONFLICT (event_id) DO NOTHING
RETURNING id`;

const SELECT_OUTBOX_BY_EVENT_ID = `
SELECT topic, payload::text AS payload_text
  FROM credential_outbox
 WHERE event_id = $1`;

// Serialized per-list allocation: the UPDATE takes a row lock on the counter
// row, so concurrent replicas allocate disjoint indices, and the row survives
// restarts so allocation resumes without collision. The 0003 UNIQUE index on
// (issuer, status_list_id, status_list_index) backstops the invariant.
const ALLOCATE_STATUS_LIST_INDEX = `
INSERT INTO status_list_allocator (status_list_id, next_index)
VALUES ($1, 1)
ON CONFLICT (status_list_id) DO UPDATE SET
  next_index = status_list_allocator.next_index + 1
WHERE status_list_allocator.next_index < 1048576
RETURNING next_index - 1 AS allocated_index`;

const INSERT_HOLDER_CREDENTIAL = `
INSERT INTO holder_credentials (
  credential_id_reference_sha256, holder_id, issuer, credential_document, valid_until
) VALUES ($1, $2, $3, $4::jsonb, $5)
ON CONFLICT (credential_id_reference_sha256) DO NOTHING`;

const APPROVAL_REQUEST_COLUMNS = `request_id, kind, payload::text AS payload_text, requester_subject, requester_role,
  status, requested_at, approver_subject, decided_at`;

// Maker/checker pending-approval ledger. The insert is idempotent under the
// deterministic request id; the approve update only matches a PENDING row
// whose requester differs from the approver (the 0005 CHECK constraint
// backstops the separation of duties at the database layer).
const INSERT_APPROVAL_REQUEST = `
INSERT INTO credential_approval_requests (
  request_id, kind, payload, requester_subject, requester_role, status, requested_at
) VALUES ($1, $2, $3::jsonb, $4, $5, 'PENDING', $6)
ON CONFLICT (request_id) DO NOTHING
RETURNING ${APPROVAL_REQUEST_COLUMNS}`;

const SELECT_APPROVAL_REQUEST = `
SELECT ${APPROVAL_REQUEST_COLUMNS}
  FROM credential_approval_requests
 WHERE request_id = $1`;

const APPROVE_PENDING_REQUEST = `
UPDATE credential_approval_requests
   SET status = 'APPROVED', approver_subject = $2, decided_at = now()
 WHERE request_id = $1
   AND status = 'PENDING'
   AND requester_subject <> $2
RETURNING ${APPROVAL_REQUEST_COLUMNS}`;

const SELECT_CURRENT_HOLDER_CREDENTIALS = `
SELECT h.credential_document, h.valid_until
  FROM holder_credentials h
  JOIN credential_status s
    ON s.credential_id_reference_sha256 = h.credential_id_reference_sha256
 WHERE h.holder_id = $1 AND h.issuer = $2
   AND s.status = 'ACTIVE'
   AND h.valid_until > now()
 ORDER BY h.issued_at DESC, h.credential_id_reference_sha256 ASC`;

interface ApprovalRequestRow extends pg.QueryResultRow {
  request_id: string;
  kind: ApprovalRequest["kind"];
  payload_text: string;
  requester_subject: string;
  requester_role: string;
  status: ApprovalRequest["status"];
  requested_at: Date;
  approver_subject: string | null;
  decided_at: Date | null;
}

function mapApprovalRow(row: ApprovalRequestRow): ApprovalRequest {
  const request: ApprovalRequest = {
    requestId: row.request_id,
    kind: row.kind,
    payload: JSON.parse(row.payload_text) as Record<string, unknown>,
    requesterSubject: row.requester_subject,
    requesterRole: row.requester_role,
    status: row.status,
    requestedAt: new Date(row.requested_at).toISOString(),
  };
  if (row.approver_subject !== null) request.approverSubject = row.approver_subject;
  if (row.decided_at !== null) request.decidedAt = new Date(row.decided_at).toISOString();
  assertApprovalRequest(request);
  return request;
}

export class PgStatusStore implements StatusStore, ApprovalStore {
  private readonly executor: SqlExecutor;
  private readonly onClose?: () => Promise<void>;

  public constructor(options: PgStatusStoreOptions) {
    this.executor = options.executor;
    if (options.ownsExecutor !== undefined) this.onClose = options.ownsExecutor;
  }

  public async setStatus(entry: StatusEntry, outbox?: OutboxMessage): Promise<StatusRecord> {
    assertStatusEntry(entry);
    if (outbox !== undefined) assertOutboxMessage(outbox);
    const reference = credentialIdReference(entry.credentialId);
    const effectiveAt = (entry.effectiveAt ?? new Date()).toISOString();
    const client = this.executor;
    const transactional = outbox !== undefined || entry.issuance !== undefined;
    if (transactional) await client.query("BEGIN");
    try {
      const result = await client.query<StatusRow>(UPSERT_STATUS, [
        reference, entry.issuer, entry.status, entry.reason,
        entry.statusListId, entry.statusListIndex, entry.updatedBy, effectiveAt,
      ]);
      const row = result.rows[0];
      if (row === undefined) {
        // The guarded upsert only yields no row when the existing record is
        // REVOKED; verify and report truthfully (fail closed).
        const current = await client.query<{ status: StatusRecord["status"] } & pg.QueryResultRow>(SELECT_CURRENT_STATUS, [reference]);
        const status = current.rows[0]?.status;
        if (status === "REVOKED") {
          throw new Error("credential status REVOKED is terminal; the requested transition was refused");
        }
        throw new Error("status upsert returned no row");
      }
      if (entry.issuance !== undefined) {
        await client.query(INSERT_HOLDER_CREDENTIAL, [
          reference, entry.issuance.holderId, entry.issuer,
          JSON.stringify(entry.issuance.document), entry.issuance.validUntil.toISOString(),
        ]);
      }
      if (outbox !== undefined) {
        await insertOutboxVerified(client, outbox);
      }
      if (transactional) await client.query("COMMIT");
      return mapRow(row);
    } catch (error) {
      if (transactional) {
        try {
          await client.query("ROLLBACK");
        } catch {
          // Original error is authoritative; rollback failure is secondary.
        }
      }
      throw error;
    }
  }

  public async getStatus(credentialId: string, issuer: string): Promise<StatusRecord | undefined> {
    const reference = credentialIdReference(credentialId);
    const result = await this.executor.query<StatusRow>(
      `SELECT credential_id_reference_sha256, issuer, status, reason,
              status_list_id, status_list_index, updated_by, effective_at, updated_at, sequence
         FROM credential_status
        WHERE credential_id_reference_sha256 = $1 AND issuer = $2`,
      [reference, issuer],
    );
    const row = result.rows[0];
    return row === undefined ? undefined : mapRow(row);
  }

  public async listStatusBits(issuer: string, statusListId: string): Promise<StatusListBitRow[]> {
    const result = await this.executor.query<{ status_list_index: number; status: StatusRecord["status"] } & pg.QueryResultRow>(
      `SELECT status_list_index, status
         FROM credential_status
        WHERE issuer = $1 AND status_list_id = $2
        ORDER BY status_list_index ASC`,
      [issuer, statusListId],
    );
    return result.rows.map((row) => ({ statusListIndex: row.status_list_index, revoked: row.status === "REVOKED" }));
  }

  public async listCurrentHolderCredentials(holderId: string, issuer: string): Promise<HolderCredentialRecord[]> {
    const result = await this.executor.query<{ credential_document: Record<string, unknown>; valid_until: Date } & pg.QueryResultRow>(
      SELECT_CURRENT_HOLDER_CREDENTIALS,
      [holderId, issuer],
    );
    return result.rows.map((row) => ({
      document: row.credential_document,
      validUntil: new Date(row.valid_until).toISOString(),
    }));
  }

  public async allocateStatusListIndex(statusListId: string): Promise<number> {
    if (!/^[A-Za-z0-9._:/-]{1,512}$/.test(statusListId)) {
      throw new Error("status list id must be a canonical identifier or URL");
    }
    const result = await this.executor.query<{ allocated_index: number | string } & pg.QueryResultRow>(
      ALLOCATE_STATUS_LIST_INDEX,
      [statusListId],
    );
    const row = result.rows[0];
    if (row === undefined) {
      throw new Error(`status list ${statusListId} bitstring index space is exhausted (fail-closed)`);
    }
    const allocated = Number(row.allocated_index);
    if (!Number.isInteger(allocated) || allocated < 0 || allocated >= 1_048_576) {
      throw new Error("status list allocator returned an out-of-range index (fail-closed)");
    }
    return allocated;
  }

  public async createApprovalRequest(request: ApprovalRequest): Promise<ApprovalRequestCreated> {
    assertApprovalRequest(request);
    const inserted = await this.executor.query<ApprovalRequestRow>(INSERT_APPROVAL_REQUEST, [
      request.requestId, request.kind, JSON.stringify(request.payload),
      request.requesterSubject, request.requesterRole, request.requestedAt,
    ]);
    const row = inserted.rows[0];
    if (row !== undefined) return { created: true, record: mapApprovalRow(row) };
    // Deterministic-id conflict: a replayed submission is a benign no-op only
    // when the stored request is identical; anything else fails closed.
    const existing = await this.getApprovalRequest(request.requestId);
    if (existing === undefined) {
      throw new Error("approval request insert conflicted but no stored request is visible (fail-closed)");
    }
    if (existing.kind !== request.kind || canonicalPayload(existing.payload) !== canonicalPayload(request.payload)) {
      throw new Error(`approval request id ${request.requestId} already exists with different content (fail-closed)`);
    }
    return { created: false, record: existing };
  }

  public async getApprovalRequest(requestId: string): Promise<ApprovalRequest | undefined> {
    const result = await this.executor.query<ApprovalRequestRow>(SELECT_APPROVAL_REQUEST, [requestId]);
    const row = result.rows[0];
    return row === undefined ? undefined : mapApprovalRow(row);
  }

  public async markApprovalRequestApproved(requestId: string, approverSubject: string): Promise<ApprovalRequest> {
    const result = await this.executor.query<ApprovalRequestRow>(APPROVE_PENDING_REQUEST, [requestId, approverSubject]);
    const row = result.rows[0];
    if (row !== undefined) return mapApprovalRow(row);
    // The guarded update only yields no row when the request is missing,
    // already decided, or a maker/checker self-approval; report truthfully.
    const current = await this.getApprovalRequest(requestId);
    if (current === undefined) throw new ApprovalStateError("approval request is unknown");
    if (current.status !== "PENDING") throw new ApprovalStateError("approval request is already approved");
    throw new ApprovalStateError("maker/checker violation: the requester cannot approve their own credential mutation");
  }

  public async healthCheck(): Promise<void> {
    await this.executor.query("SELECT 1");
  }

  public async close(): Promise<void> {
    if (this.onClose !== undefined) await this.onClose();
  }
}

/**
 * Enqueues a single outbox message into credential_outbox. Used by the
 * Temporal worker, whose revocation activity publishes events without a
 * companion status-row upsert (the status transition happens via the API).
 */
export async function enqueueOutboxMessage(executor: SqlExecutor, message: OutboxMessage): Promise<void> {
  assertOutboxMessage(message);
  await insertOutboxVerified(executor, message);
}

/**
 * Inserts an outbox message without letting event-id dedup swallow a state
 * transition. An idempotent replay (identical topic and payload already
 * stored under the same deterministic event id) is accepted as a no-op; a
 * conflicting payload under the same event id means a distinct transition was
 * being silently dropped, which fails closed.
 */
async function insertOutboxVerified(client: SqlExecutor, message: OutboxMessage): Promise<void> {
  const payloadText = JSON.stringify(message.payload);
  const inserted = await client.query<{ id: number | string } & pg.QueryResultRow>(
    INSERT_OUTBOX,
    [message.topic, message.eventId, payloadText],
  );
  if (inserted.rows.length > 0) return;
  const existing = await client.query<{ topic: string; payload_text: string } & pg.QueryResultRow>(
    SELECT_OUTBOX_BY_EVENT_ID,
    [message.eventId],
  );
  const row = existing.rows[0];
  if (row === undefined) {
    throw new Error("outbox insert conflicted but no stored event is visible (fail-closed)");
  }
  if (row.topic !== message.topic || !jsonDeepEqual(row.payload_text, payloadText)) {
    throw new Error(
      `outbox event id ${message.eventId} already exists with different content; refusing to swallow a state transition (fail-closed)`,
    );
  }
}

/** Compares two JSON texts semantically (jsonb key order is not significant). */
function jsonDeepEqual(stored: string, candidate: string): boolean {
  try {
    return canonicalJson(JSON.parse(stored)) === canonicalJson(JSON.parse(candidate));
  } catch {
    return false;
  }
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`);
  return `{${entries.join(",")}}`;
}

export function createPgStatusStore(databaseUrl: string): PgStatusStore {
  const pool = new pg.Pool({ connectionString: databaseUrl, max: 4, connectionTimeoutMillis: 5_000 });
  return new PgStatusStore({ executor: pool, ownsExecutor: () => pool.end() });
}

/** Applies pending SQL migrations in lexical order, parameterized per file. */
export async function runMigrations(executor: SqlExecutor, migrationsDirectory: string): Promise<string[]> {
  const directory = resolve(migrationsDirectory);
  const files = (await readdir(directory)).filter((name) => /^[0-9]{4}_[a-z0-9_]+\.sql$/.test(name)).sort();
  const applied: string[] = [];
  await executor.query(
    `CREATE TABLE IF NOT EXISTS schema_migrations (
       migration text PRIMARY KEY,
       applied_at timestamptz NOT NULL DEFAULT now()
     )`,
  );
  for (const file of files) {
    const migration = file.replace(/\.sql$/, "");
    const existing = await executor.query<{ migration: string } & pg.QueryResultRow>(
      "SELECT migration FROM schema_migrations WHERE migration = $1",
      [migration],
    );
    if (existing.rows.length > 0) continue;
    const sql = await readFile(join(directory, file), "utf8");
    await executor.query(sql);
    applied.push(migration);
  }
  return applied;
}

/**
 * Fail-closed store factory. Production requires BLUEECONOMY_STATUS_DATABASE_URL;
 * the single-process JSONL store exists only when the explicit test flag
 * BLUEECONOMY_STATUS_JSONL_TEST_PATH is set.
 */
export async function createStatusStoreFromEnv(env: NodeJS.ProcessEnv = process.env): Promise<StatusStore & ApprovalStore> {
  const databaseUrl = env["BLUEECONOMY_STATUS_DATABASE_URL"];
  const jsonlTestPath = env["BLUEECONOMY_STATUS_JSONL_TEST_PATH"];
  if (databaseUrl !== undefined && databaseUrl.trim().length > 0) {
    if (jsonlTestPath !== undefined) {
      throw new Error("BLUEECONOMY_STATUS_JSONL_TEST_PATH must not be combined with a production status database");
    }
    return createPgStatusStore(databaseUrl);
  }
  if (jsonlTestPath !== undefined && jsonlTestPath.trim().length > 0) {
    const { createJsonlTestStatusStore } = await import("./jsonl-test-store.js");
    return createJsonlTestStatusStore(jsonlTestPath, env);
  }
  throw new Error("status store is not configured: set BLUEECONOMY_STATUS_DATABASE_URL (fail-closed)");
}

function mapRow(row: StatusRow): StatusRecord {
  return {
    credentialIdReferenceSha256: row.credential_id_reference_sha256,
    issuer: row.issuer,
    status: row.status,
    reason: row.reason,
    statusListId: row.status_list_id,
    statusListIndex: row.status_list_index,
    updatedBy: row.updated_by,
    effectiveAt: new Date(row.effective_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
    sequence: Number(row.sequence),
  };
}

function assertOutboxMessage(message: OutboxMessage): void {
  // Phase-8: the crew-welfare module drains its CONFIDENTIAL events through
  // this same outbox on the seafarers.welfare.v1 topic.
  if (
    message.topic !== "seafarer.credential.v1" &&
    message.topic !== "seafarer.revocation.v1" &&
    message.topic !== "seafarers.welfare.v1"
  ) {
    throw new Error("outbox topic must be an approved seafarer platform topic");
  }
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(message.eventId)) {
    throw new Error("outbox event id must be a deterministic UUID");
  }
  if (typeof message.payload !== "object" || message.payload === null || Array.isArray(message.payload)) {
    throw new Error("outbox payload must be a JSON object");
  }
}
