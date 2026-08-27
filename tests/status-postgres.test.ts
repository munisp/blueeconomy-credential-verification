import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { PgStatusStore, createStatusStoreFromEnv, runMigrations, type SqlExecutor } from "../src/status/postgres.js";
import type { OutboxMessage, StatusEntry } from "../src/status/store.js";

interface RecordedQuery { text: string; params: readonly unknown[] }

function recordingExecutor(responder?: (query: RecordedQuery) => { rows: Record<string, unknown>[] }) {
  const queries: RecordedQuery[] = [];
  const executor: SqlExecutor = {
    async query<Row extends import("pg").QueryResultRow>(text: string, params: readonly unknown[] = []) {
      const query = { text, params };
      queries.push(query);
      const response = responder?.(query) ?? { rows: [] };
      return { rows: response.rows as unknown as Row[], command: "", rowCount: response.rows.length, oid: 0, fields: [] };
    },
  };
  return { executor, queries };
}

const entry: StatusEntry = {
  credentialId: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  status: "REVOKED",
  reason: "compromised",
  updatedBy: "nimasa-approver-01",
  issuer: "did:web:credentials.nimasa.gov.ng",
  statusListId: "https://credentials.nimasa.gov.ng/v1/status-list/main",
  statusListIndex: 7,
  effectiveAt: new Date("2026-06-01T00:00:00.000Z"),
};

const outbox: OutboxMessage = {
  topic: "seafarer.revocation.v1",
  eventId: "11111111-2222-3333-4444-555555555555",
  payload: { envelopeVersion: "1.0" },
};

test("postgres status store uses parameterized SQL and commits outbox atomically", async () => {
  const statusRow = {
    credential_id_reference_sha256: "f".repeat(64),
    issuer: entry.issuer,
    status: "REVOKED",
    reason: entry.reason,
    status_list_id: entry.statusListId,
    status_list_index: 7,
    updated_by: entry.updatedBy,
    effective_at: new Date("2026-06-01T00:00:00.000Z"),
    updated_at: new Date("2026-06-01T00:00:00.000Z"),
    sequence: "3",
  };
  const { executor, queries } = recordingExecutor((query) => query.text.includes("RETURNING") ? { rows: [statusRow] } : { rows: [] });
  const store = new PgStatusStore({ executor });
  const record = await store.setStatus(entry, outbox);
  assert.equal(record.status, "REVOKED");
  assert.equal(record.sequence, 3);
  assert.equal(queries[0]?.text, "BEGIN");
  const upsert = queries.find((query) => query.text.includes("INSERT INTO credential_status"));
  assert.ok(upsert, "expected a credential_status upsert");
  assert.ok(upsert.text.includes("$1") && !upsert.text.includes(entry.credentialId), "upsert must use bound parameters only");
  assert.equal(upsert.params.length, 8);
  assert.equal(upsert.params[1], entry.issuer);
  assert.equal(upsert.params[4], entry.statusListId);
  const outboxInsert = queries.find((query) => query.text.includes("INSERT INTO credential_outbox"));
  assert.ok(outboxInsert, "expected an outbox insert in the same transaction");
  assert.deepEqual(outboxInsert.params.slice(0, 2), [outbox.topic, outbox.eventId]);
  assert.equal(queries.at(-1)?.text, "COMMIT");
});

test("postgres status store rolls back when the outbox write fails", async () => {
  const { executor, queries } = recordingExecutor((query) => {
    if (query.text.includes("INSERT INTO credential_outbox")) throw new Error("outbox write failed");
    if (query.text.includes("RETURNING")) {
      return { rows: [{ ...statusRowTemplate(), status: "ACTIVE" }] };
    }
    return { rows: [] };
  });
  const store = new PgStatusStore({ executor });
  await assert.rejects(() => store.setStatus(entry, outbox), /outbox write failed/);
  assert.ok(queries.some((query) => query.text === "ROLLBACK"), "expected ROLLBACK after outbox failure");
});

function statusRowTemplate() {
  return {
    credential_id_reference_sha256: "f".repeat(64),
    issuer: entry.issuer,
    status: "ACTIVE",
    reason: entry.reason,
    status_list_id: entry.statusListId,
    status_list_index: 7,
    updated_by: entry.updatedBy,
    effective_at: new Date("2026-06-01T00:00:00.000Z"),
    updated_at: new Date("2026-06-01T00:00:00.000Z"),
    sequence: "1",
  };
}

test("postgres status lookup binds parameters and returns undefined when absent", async () => {
  const { executor, queries } = recordingExecutor();
  const store = new PgStatusStore({ executor });
  const result = await store.getStatus(entry.credentialId, entry.issuer);
  assert.equal(result, undefined);
  const lookup = queries[0];
  assert.ok(lookup !== undefined && lookup.text.includes("WHERE credential_id_reference_sha256 = $1 AND issuer = $2"));
  assert.equal(lookup.params.length, 2);
  assert.match(String(lookup.params[0]), /^[0-9a-f]{64}$/);
});

test("status store factory fails closed without configuration", async () => {
  await assert.rejects(
    () => createStatusStoreFromEnv({}),
    /not configured.*fail-closed/,
  );
});

test("status store factory refuses to combine JSONL test flag with a production DSN", async () => {
  await assert.rejects(
    () => createStatusStoreFromEnv({
      BLUEECONOMY_STATUS_DATABASE_URL: "postgres://localhost:5432/blueeconomy",
      BLUEECONOMY_STATUS_JSONL_TEST_PATH: "/tmp/status.jsonl",
    }),
    /must not be combined/,
  );
});

test("JSONL test store works only behind the explicit test flag", async () => {
  const directory = await mkdtemp(join(tmpdir(), "blueeconomy-jsonl-store-"));
  const path = join(directory, "status.jsonl");
  const env = {
    BLUEECONOMY_STATUS_JSONL_TEST_PATH: path,
    BLUEECONOMY_STATUS_ISSUER: entry.issuer,
  };
  const store = await createStatusStoreFromEnv(env);
  await store.setStatus({ ...entry, status: "ACTIVE", reason: "issued" });
  await store.setStatus(entry);
  const record = await store.getStatus(entry.credentialId, entry.issuer);
  assert.equal(record?.status, "REVOKED");
  const bits = await store.listStatusBits(entry.issuer, entry.statusListId);
  assert.deepEqual(bits, [{ statusListIndex: 7, revoked: true }]);
  await store.close();
});

test("migration runner applies pending files once and is parameterized", async () => {
  const migrationsDirectory = join(new URL("..", import.meta.url).pathname, "migrations");
  const { executor, queries } = recordingExecutor(() => ({ rows: [] }));
  const applied = await runMigrations(executor, migrationsDirectory);
  assert.deepEqual(applied, ["0001_credential_status"]);
  const lookup = queries.find((query) => query.text.includes("FROM schema_migrations WHERE migration = $1"));
  assert.ok(lookup !== undefined && Array.isArray(lookup.params));
  const ddl = queries.find((query) => query.text.includes("CREATE TABLE credential_status"));
  assert.ok(ddl !== undefined && ddl.params.length === 0, "migration DDL must not interpolate values");
});
