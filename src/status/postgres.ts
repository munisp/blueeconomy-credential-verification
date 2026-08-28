import { readFile, readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import pg from "pg";
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
RETURNING credential_id_reference_sha256, issuer, status, reason,
  status_list_id, status_list_index, updated_by, effective_at, updated_at, sequence`;

const INSERT_OUTBOX = `
INSERT INTO credential_outbox (topic, event_id, payload)
VALUES ($1, $2, $3::jsonb)
ON CONFLICT (event_id) DO NOTHING`;

const INSERT_HOLDER_CREDENTIAL = `
INSERT INTO holder_credentials (
  credential_id_reference_sha256, holder_id, issuer, credential_document, valid_until
) VALUES ($1, $2, $3, $4::jsonb, $5)
ON CONFLICT (credential_id_reference_sha256) DO NOTHING`;

const SELECT_CURRENT_HOLDER_CREDENTIALS = `
SELECT h.credential_document, h.valid_until
  FROM holder_credentials h
  JOIN credential_status s
    ON s.credential_id_reference_sha256 = h.credential_id_reference_sha256
 WHERE h.holder_id = $1 AND h.issuer = $2
   AND s.status = 'ACTIVE'
   AND h.valid_until > now()
 ORDER BY h.issued_at DESC, h.credential_id_reference_sha256 ASC`;

export class PgStatusStore implements StatusStore {
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
      if (row === undefined) throw new Error("status upsert returned no row");
      if (entry.issuance !== undefined) {
        await client.query(INSERT_HOLDER_CREDENTIAL, [
          reference, entry.issuance.holderId, entry.issuer,
          JSON.stringify(entry.issuance.document), entry.issuance.validUntil.toISOString(),
        ]);
      }
      if (outbox !== undefined) {
        await client.query(INSERT_OUTBOX, [outbox.topic, outbox.eventId, JSON.stringify(outbox.payload)]);
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
  await executor.query(INSERT_OUTBOX, [message.topic, message.eventId, JSON.stringify(message.payload)]);
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
export async function createStatusStoreFromEnv(env: NodeJS.ProcessEnv = process.env): Promise<StatusStore> {
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
  if (message.topic !== "seafarer.credential.v1" && message.topic !== "seafarer.revocation.v1") {
    throw new Error("outbox topic must be an approved seafarer credential topic");
  }
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(message.eventId)) {
    throw new Error("outbox event id must be a deterministic UUID");
  }
  if (typeof message.payload !== "object" || message.payload === null || Array.isArray(message.payload)) {
    throw new Error("outbox payload must be a JSON object");
  }
}
