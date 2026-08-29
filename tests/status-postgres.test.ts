import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { PgStatusStore, createStatusStoreFromEnv, runMigrations, type SqlExecutor } from "../src/status/postgres.js";
import { deterministicApprovalRequestId } from "../src/service/maker-checker.js";
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

test("postgres approval store persists pending maker/checker requests with bound parameters", async () => {
  const payload = { workflowId: "wf-1" };
  const { executor, queries } = recordingExecutor((query) => {
    if (query.text.includes("INSERT INTO credential_approval_requests")) {
      return {
        rows: [{
          request_id: deterministicApprovalRequestId("issuance", payload),
          kind: "issuance",
          payload_text: JSON.stringify(payload),
          requester_subject: "principal-01",
          requester_role: "nimasa-approver",
          status: "PENDING",
          requested_at: new Date("2026-06-01T00:00:00.000Z"),
          approver_subject: null,
          decided_at: null,
        }],
      };
    }
    return { rows: [] };
  });
  const store = new PgStatusStore({ executor });
  const result = await store.createApprovalRequest({
    requestId: deterministicApprovalRequestId("issuance", payload),
    kind: "issuance",
    payload,
    requesterSubject: "principal-01",
    requesterRole: "nimasa-approver",
    status: "PENDING",
    requestedAt: "2026-06-01T00:00:00.000Z",
  });
  assert.equal(result.created, true);
  const insert = queries.find((query) => query.text.includes("INSERT INTO credential_approval_requests"));
  assert.ok(insert !== undefined);
  assert.ok(insert.text.includes("ON CONFLICT (request_id) DO NOTHING"), "submission must be idempotent under the deterministic id");
  assert.ok(!insert.text.includes("principal-01"), "subjects must be bound parameters, never interpolated");
});

test("postgres approval store only approves a pending row of a distinct approver", async () => {
  const { executor, queries } = recordingExecutor(() => ({ rows: [] }));
  const store = new PgStatusStore({ executor });
  await assert.rejects(
    () => store.markApprovalRequestApproved("urn:uuid:11111111-2222-3333-4444-555555555555", "principal-02"),
    /unknown/,
  );
  const approve = queries.find((query) => query.text.includes("UPDATE credential_approval_requests"));
  assert.ok(approve !== undefined);
  assert.ok(approve.text.includes("status = 'PENDING'"), "the guarded update must only match PENDING rows");
  assert.ok(approve.text.includes("requester_subject <> $2"), "the SQL must refuse maker/checker self-approval");
  assert.deepEqual(approve.params, ["urn:uuid:11111111-2222-3333-4444-555555555555", "principal-02"]);
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
  assert.deepEqual(applied, ["0001_credential_status", "0002_holder_credentials", "0003_status_list_allocator", "0004_revocation_terminal", "0005_credential_approval_requests"]);
  const lookup = queries.find((query) => query.text.includes("FROM schema_migrations WHERE migration = $1"));
  assert.ok(lookup !== undefined && Array.isArray(lookup.params));
  const ddl = queries.find((query) => query.text.includes("CREATE TABLE credential_status"));
  assert.ok(ddl !== undefined && ddl.params.length === 0, "migration DDL must not interpolate values");
  const holderDdl = queries.find((query) => query.text.includes("CREATE TABLE holder_credentials"));
  assert.ok(holderDdl !== undefined && holderDdl.params.length === 0, "holder credential DDL must not interpolate values");
});

test("issuance persists the holder credential document atomically with the status upsert", async () => {
  const issuanceEntry: StatusEntry = {
    ...entry,
    status: "ACTIVE",
    reason: "issued",
    issuance: {
      holderId: "principal-01",
      document: { id: entry.credentialId, type: ["VerifiableCredential", "SeafarerCoC"] },
      validUntil: new Date("2031-01-01T00:00:00.000Z"),
    },
  };
  const { executor, queries } = recordingExecutor((query) =>
    query.text.includes("RETURNING") ? { rows: [statusRowTemplate()] } : { rows: [] });
  const store = new PgStatusStore({ executor });
  await store.setStatus(issuanceEntry, { ...outbox, topic: "seafarer.credential.v1" });
  assert.equal(queries[0]?.text, "BEGIN");
  const holderInsert = queries.find((query) => query.text.includes("INSERT INTO holder_credentials"));
  assert.ok(holderInsert, "expected a holder_credentials insert in the same transaction");
  assert.equal(holderInsert.params[1], "principal-01");
  assert.equal(holderInsert.params[2], entry.issuer);
  assert.match(String(holderInsert.params[4]), /^2031-01-01/);
  assert.ok(holderInsert.text.includes("$4::jsonb"), "document must be bound as a parameter, never interpolated");
  assert.equal(queries.at(-1)?.text, "COMMIT");
});

test("holder credential lookup filters to ACTIVE, non-expired rows with bound parameters", async () => {
  const { executor, queries } = recordingExecutor(() => ({
    rows: [{ credential_document: { id: "urn:uuid:x" }, valid_until: new Date("2031-01-01T00:00:00.000Z") }],
  }));
  const store = new PgStatusStore({ executor });
  const records = await store.listCurrentHolderCredentials("principal-01", entry.issuer);
  assert.equal(records.length, 1);
  assert.equal(records[0]?.validUntil, "2031-01-01T00:00:00.000Z");
  const lookup = queries[0];
  assert.ok(lookup !== undefined);
  assert.ok(lookup.text.includes("FROM holder_credentials"));
  assert.ok(lookup.text.includes("s.status = 'ACTIVE'") && lookup.text.includes("h.valid_until > now()"));
  assert.deepEqual(lookup.params, ["principal-01", entry.issuer]);
});

test("issuance documents are rejected on non-ACTIVE transitions", async () => {
  const { executor } = recordingExecutor();
  const store = new PgStatusStore({ executor });
  await assert.rejects(
    () => store.setStatus({
      ...entry,
      issuance: { holderId: "principal-01", document: { id: "x" }, validUntil: new Date("2031-01-01T00:00:00.000Z") },
    }),
    /issuance documents may only accompany an ACTIVE/,
  );
});

// ---------------------------------------------------------------------------
// P0-A: durable status-list index allocation
// ---------------------------------------------------------------------------

test("status-list allocator uses the serialized per-list counter statement", async () => {
  const { executor, queries } = recordingExecutor((query) =>
    query.text.includes("status_list_allocator") ? { rows: [{ allocated_index: 41 }] } : { rows: [] });
  const store = new PgStatusStore({ executor });
  const index = await store.allocateStatusListIndex(entry.statusListId);
  assert.equal(index, 41);
  const allocation = queries.find((query) => query.text.includes("status_list_allocator"));
  assert.ok(allocation !== undefined);
  assert.ok(allocation.text.includes("ON CONFLICT (status_list_id) DO UPDATE"), "allocation must serialize on the counter row");
  assert.ok(allocation.text.includes("next_index < 1048576"), "allocation must respect the bitstring bound");
  assert.deepEqual(allocation.params, [entry.statusListId]);
});

test("concurrent allocations are unique and a restart resumes without collision", async () => {
  // Simulate the database counter row: the INSERT .. ON CONFLICT DO UPDATE
  // semantics are replayed against a shared map so allocator instances
  // (i.e. restarts/replicas) share durable state.
  const counters = new Map<string, number>();
  const executorFactory = () => {
    const executor: SqlExecutor = {
      async query<Row extends import("pg").QueryResultRow>(text: string, params: readonly unknown[] = []) {
        if (text.includes("status_list_allocator")) {
          const statusListId = String(params[0]);
          const current = counters.get(statusListId) ?? 0;
          if (current >= 1_048_576) {
            return { rows: [] as unknown as Row[], command: "", rowCount: 0, oid: 0, fields: [] };
          }
          counters.set(statusListId, current + 1);
          return { rows: [{ allocated_index: current }] as unknown as Row[], command: "", rowCount: 1, oid: 0, fields: [] };
        }
        return { rows: [] as unknown as Row[], command: "", rowCount: 0, oid: 0, fields: [] };
      },
    };
    return executor;
  };
  // "Replica A" allocates, a "restart" replaces the store instance, then
  // "replica B" allocates concurrently; indices must be globally unique.
  const replicaA = new PgStatusStore({ executor: executorFactory() });
  const first = await Promise.all([...Array(8)].map(() => replicaA.allocateStatusListIndex(entry.statusListId)));
  const replicaB = new PgStatusStore({ executor: executorFactory() });
  const second = await Promise.all([...Array(8)].map(() => replicaB.allocateStatusListIndex(entry.statusListId)));
  const all = [...first, ...second];
  assert.equal(new Set(all).size, all.length, "every allocation must be unique across restarts and replicas");
  assert.deepEqual([...all].sort((a, b) => a - b), [...Array(16).keys()]);
});

test("status-list allocator fails closed on exhaustion and out-of-range rows", async () => {
  const exhausted = new PgStatusStore({ executor: recordingExecutor().executor });
  await assert.rejects(() => exhausted.allocateStatusListIndex(entry.statusListId), /exhausted/);
  const { executor } = recordingExecutor((query) =>
    query.text.includes("status_list_allocator") ? { rows: [{ allocated_index: -3 }] } : { rows: [] });
  const outOfRange = new PgStatusStore({ executor });
  await assert.rejects(() => outOfRange.allocateStatusListIndex(entry.statusListId), /out-of-range/);
  await assert.rejects(() => exhausted.allocateStatusListIndex("bad list id!"), /canonical/);
});

// ---------------------------------------------------------------------------
// P0-B: revocation is terminal and the outbox cannot swallow transitions
// ---------------------------------------------------------------------------

test("the status upsert is guarded so REVOKED rows cannot transition", async () => {
  const { executor, queries } = recordingExecutor((query) => {
    if (query.text.includes("INSERT INTO credential_status")) return { rows: [] };
    if (query.text.includes("SELECT status")) return { rows: [{ status: "REVOKED" }] };
    return { rows: [] };
  });
  const store = new PgStatusStore({ executor });
  await assert.rejects(
    () => store.setStatus({ ...entry, status: "ACTIVE", reason: "re-issued" }, { ...outbox, topic: "seafarer.credential.v1" }),
    /REVOKED is terminal/,
  );
  const upsert = queries.find((query) => query.text.includes("INSERT INTO credential_status"));
  assert.ok(upsert !== undefined && upsert.text.includes("WHERE credential_status.status <> 'REVOKED'"), "upsert must refuse REVOKED rows");
  assert.ok(queries.some((query) => query.text === "ROLLBACK"), "the refused transition must roll back");
});

test("outbox dedup accepts an identical replay but never swallows a new transition", async () => {
  // Identical replay: conflict with the same stored content is a no-op.
  const replay = recordingExecutor((query) => {
    if (query.text.includes("INSERT INTO credential_status")) return { rows: [statusRowTemplate()] };
    if (query.text.includes("INSERT INTO credential_outbox")) return { rows: [] };
    if (query.text.includes("FROM credential_outbox")) {
      return { rows: [{ topic: outbox.topic, payload_text: JSON.stringify(outbox.payload) }] };
    }
    return { rows: [] };
  });
  const replayStore = new PgStatusStore({ executor: replay.executor });
  await replayStore.setStatus({ ...entry, status: "ACTIVE", reason: "issued" }, outbox);

  // Conflicting payload under the same event id: a swallowed transition — fail.
  const conflict = recordingExecutor((query) => {
    if (query.text.includes("INSERT INTO credential_status")) return { rows: [statusRowTemplate()] };
    if (query.text.includes("INSERT INTO credential_outbox")) return { rows: [] };
    if (query.text.includes("FROM credential_outbox")) {
      return { rows: [{ topic: outbox.topic, payload_text: JSON.stringify({ envelopeVersion: "0.9" }) }] };
    }
    return { rows: [] };
  });
  const conflictStore = new PgStatusStore({ executor: conflict.executor });
  await assert.rejects(
    () => conflictStore.setStatus({ ...entry, status: "ACTIVE", reason: "issued" }, outbox),
    /refusing to swallow a state transition/,
  );
  assert.ok(conflict.queries.some((query) => query.text === "ROLLBACK"));
});

test("enqueueOutboxMessage verifies dedup conflicts the same way", async () => {
  const { enqueueOutboxMessage } = await import("../src/status/postgres.js");
  const { executor } = recordingExecutor((query) => {
    if (query.text.includes("INSERT INTO credential_outbox")) return { rows: [] };
    if (query.text.includes("FROM credential_outbox")) {
      return { rows: [{ topic: "seafarer.credential.v1", payload_text: "{}" }] };
    }
    return { rows: [] };
  });
  await assert.rejects(() => enqueueOutboxMessage(executor, outbox), /refusing to swallow/);
});
