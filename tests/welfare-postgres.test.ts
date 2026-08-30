import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { randomInt } from "node:crypto";
import pg from "pg";

import { runMigrations } from "../src/status/postgres.js";
import { PgWelfareStore } from "../src/welfare/postgres.js";
import { WelfareService } from "../src/welfare/service.js";
import { InMemoryComplaintLifecycle } from "../src/welfare/lifecycle.js";
import { NarrativeKey } from "../src/welfare/confidentiality.js";
import { WelfareStateError, type ComplaintRecord, type TransitionRequest } from "../src/welfare/store.js";
import { deterministicUuid, sha256Hex } from "../src/welfare/types.js";
import { generateEphemeralIssuerKeyPair } from "../src/vc/issuer.js";
import { canonicalizeJson, asJsonValue } from "../src/vc/jcs.js";
import type { WelfarePolicy } from "../src/welfare/policy.js";

/**
 * DB-gated welfare integration tests. Require a real PostgreSQL (local stack:
 * local_stack.sh). Fresh dedicated database per run; the schema is rebuilt
 * from the committed migrations (DROP SCHEMA public CASCADE harness, per the
 * blueeconomy-port-interoperability store_test.go precedent) and the database
 * is dropped on teardown. No part of the store layer is mocked.
 */

const ADMIN_URL = process.env["BLUEECONOMY_TEST_ADMIN_DATABASE_URL"] ?? "postgres://postgres@127.0.0.1:5432/postgres";
const MIGRATIONS = fileURLToPath(new URL("../migrations", import.meta.url));

const POLICY: WelfarePolicy = {
  claims: {
    schema_version: "blueeconomy.welfare.policy.v1",
    policy_version: "ng-mlc-2026.1",
    regime: "min_rest",
    complaint_sla_seconds: { ack: 3_600, onboard_process: 86_400, escalation: 172_800, resolution: 604_800 },
    issued_by: "nimasa-welfare-desk",
    effective_at: "2026-08-01T00:00:00.000Z",
  },
  keyId: "blueeconomy-credential-verification-1",
};

const NARRATIVE_KEY = NarrativeKey.fromHex("e".repeat(64));
const NARRATIVE = "Wages unpaid for three months; master threatens retaliation.";

const database = `cv_welfare_test_${process.pid}_${randomInt(1_000_000)}`;
const databaseUrl = `postgres://postgres@127.0.0.1:5432/${database}`;

let pool: pg.Pool;
let store: PgWelfareStore;
let appliedMigrations: string[] = [];

test.before(async () => {
  const admin = new pg.Pool({ connectionString: ADMIN_URL, max: 2 });
  await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
  await admin.query(`CREATE DATABASE ${database}`);
  await admin.end();
  pool = new pg.Pool({ connectionString: databaseUrl, max: 4 });
  // Fresh schema per run, then the committed migrations build everything.
  await pool.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public");
  appliedMigrations = await runMigrations(pool, MIGRATIONS);
  store = new PgWelfareStore({ executor: pool });
});

test.after(async () => {
  if (pool !== undefined) await pool.end();
  const admin = new pg.Pool({ connectionString: ADMIN_URL, max: 2 });
  await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
  await admin.end();
});

function makeService(): WelfareService {
  return new WelfareService({
    store,
    policy: POLICY,
    narrativeKey: NARRATIVE_KEY,
    signing: { privateKey: generateEphemeralIssuerKeyPair().privateKey, keyId: "blueeconomy-credential-verification-1" },
    producer: "blueeconomy-credential-verification",
    identity: { referenceFor: async (subject) => (subject === "seafarer-01" ? "NG-SRN-DB-01" : undefined) },
    lifecycle: new InMemoryComplaintLifecycle(),
    curationContact: "welfare-desk@example.test",
  });
}

function complaintRecord(overrides: Partial<ComplaintRecord> = {}): ComplaintRecord {
  const narrativeDigest = sha256Hex(canonicalizeJson(asJsonValue({ attachments: [], narrative: NARRATIVE })));
  return {
    complaintId: deterministicUuid("complaint", `db-${randomInt(1_000_000_000)}`),
    channel: "onboard_r515",
    seafarerRef: "NG-SRN-DB-01",
    vesselRef: "NG-LKJ-0001",
    operatorRef: null,
    category: "wages",
    narrativeEnc: NARRATIVE_KEY.encrypt(NARRATIVE),
    narrativeDigestSha256: narrativeDigest,
    attachments: [],
    idempotencyKey: `idem-db-${randomInt(1_000_000_000)}`,
    status: "RECEIVED",
    rightToRedressNoticeAck: true,
    disclosureScope: "withheld",
    disclosedAt: null,
    disclosedReasonCode: null,
    createdBySubject: "seafarer-01",
    submittedAt: new Date().toISOString(),
    ...overrides,
  };
}

const OUTBOX = { topic: "seafarers.welfare.v1", eventId: deterministicUuid("event", `db-${randomInt(1_000_000)}`).slice("urn:uuid:".length), payload: { envelopeVersion: "1.0" } };

test("pg: committed migrations 0001-0006 build the welfare schema and are applied once", async () => {
  assert.deepEqual(appliedMigrations, [
    "0001_credential_status", "0002_holder_credentials", "0003_status_list_allocator",
    "0004_revocation_terminal", "0005_credential_approval_requests", "0006_welfare_mlc",
  ]);
  const again = await runMigrations(pool, MIGRATIONS);
  assert.deepEqual(again, [], "migrations are idempotent");
  const tables = await pool.query<{ tablename: string }>(
    `SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename`,
  );
  for (const expected of ["welfare_complaint", "welfare_complaint_event", "welfare_provider", "welfare_referral", "welfare_service", "welfare_transition_requests", "rest_hour_record", "rest_hour_flag", "welfare_sla_breach_observed"]) {
    assert.ok(tables.rows.some((row) => row.tablename === expected), `missing table ${expected}`);
  }
});

test("pg: narrative encryption round-trip — plaintext never reaches the database", async () => {
  const service = makeService();
  const submitted = await service.submitComplaint({
    channel: "onboard_r515",
    vesselRef: "NG-LKJ-0001",
    category: "wages",
    narrative: NARRATIVE,
    attachments: [],
    rightToRedressNoticeAck: true,
  }, "idem-db-svc-1", { subject: "seafarer-01", role: "seafarer" });
  assert.equal(submitted.created, true);

  const raw = await pool.query<{ narrative_enc: string; narrative_digest_sha256: string }>(
    "SELECT narrative_enc, narrative_digest_sha256 FROM welfare_complaint WHERE complaint_id = $1",
    [submitted.complaintId],
  );
  const row = raw.rows[0]!;
  assert.ok(!row.narrative_enc.includes(NARRATIVE), "ciphertext only at rest");
  assert.ok(!Buffer.from(row.narrative_enc, "base64").toString("utf8").includes("Wages unpaid"), "no plaintext inside the envelope bytes");
  assert.match(row.narrative_digest_sha256, /^[0-9a-f]{64}$/);
  // Decryption inside the boundary round-trips the exact narrative.
  assert.equal(NARRATIVE_KEY.decrypt(row.narrative_enc), NARRATIVE);
  const mine = await service.myComplaints("seafarer-01");
  assert.equal((mine.complaints[0] as Record<string, unknown>)["narrative"], NARRATIVE);

  // The intake event and its outbox row committed atomically.
  const outboxRows = await pool.query("SELECT event_id FROM credential_outbox WHERE event_id = $1", [submitted.eventId]);
  assert.equal(outboxRows.rows.length, 1, "complaint event enqueued transactionally");
  const events = await pool.query("SELECT transition FROM welfare_complaint_event WHERE complaint_id = $1", [submitted.complaintId]);
  assert.deepEqual(events.rows.map((row) => row.transition), ["RECEIVED"]);
});

test("pg: complaint idempotency-key replay returns the stored complaint and never double-writes", async () => {
  const record = complaintRecord({ idempotencyKey: "idem-db-replay-1" });
  const first = await store.createComplaint(record, OUTBOX);
  assert.equal(first.created, true);
  const replay = await store.createComplaint({ ...record, narrativeEnc: NARRATIVE_KEY.encrypt(NARRATIVE) }, OUTBOX);
  assert.equal(replay.created, false);
  assert.equal(replay.record.complaintId, record.complaintId);
  // Key reuse with a different complaint payload fails closed.
  await assert.rejects(
    store.createComplaint({ ...record, complaintId: deterministicUuid("complaint", "other"), narrativeDigestSha256: "f".repeat(64) }, OUTBOX),
    /reused for a different complaint/,
  );
  const count = await pool.query("SELECT count(*)::int AS n FROM welfare_complaint WHERE idempotency_key = $1", ["idem-db-replay-1"]);
  assert.equal(count.rows[0]!.n, 1);
});

test("pg: append-only triggers reject UPDATE and DELETE on audit events and rest records", async () => {
  const record = complaintRecord();
  await store.createComplaint(record, OUTBOX);
  await assert.rejects(
    pool.query("UPDATE welfare_complaint_event SET transition = 'FORGED' WHERE complaint_id = $1", [record.complaintId]),
    /append-only/,
  );
  await assert.rejects(
    pool.query("DELETE FROM welfare_complaint_event WHERE complaint_id = $1", [record.complaintId]),
    /append-only/,
  );

  await store.insertRestRecord({
    recordId: deterministicUuid("rest-record", "db-1"),
    seafarerRef: "NG-SRN-DB-01",
    vesselRef: "NG-LKJ-0001",
    recordDate: "2026-08-10",
    periods: [{ start: "2026-08-10T00:00:00.000Z", end: "2026-08-10T10:00:00.000Z", kind: "rest" }],
    regime: "min_rest",
    submittedBy: "operator-01",
    submittedByRole: "operator",
    sourceDigestSha256: "a".repeat(64),
    policyVersion: "ng-mlc-2026.1",
    idempotencyKey: "idem-db-rest-1",
    submittedAt: new Date().toISOString(),
  }, [], []);
  await assert.rejects(
    pool.query("UPDATE rest_hour_record SET periods = '[]'::jsonb WHERE record_id = $1", [deterministicUuid("rest-record", "db-1")]),
    /append-only/,
  );
  await assert.rejects(
    pool.query("DELETE FROM rest_hour_record WHERE record_id = $1", [deterministicUuid("rest-record", "db-1")]),
    /append-only/,
  );
});

test("pg: maker/checker separation is a database CHECK, not just service code", async () => {
  const record = complaintRecord();
  await store.createComplaint(record, OUTBOX);
  const request: TransitionRequest = {
    requestId: deterministicUuid("transition-request", "db-mc-1"),
    kind: "transition",
    complaintId: record.complaintId,
    payload: { complaintId: record.complaintId, from: "RECEIVED", to: "ACKED", reasonCode: "ack", noteDigest: null },
    requesterSubject: "officer-a",
    requesterRole: "nimasa-labour-officer",
    status: "PENDING",
    requestedAt: new Date().toISOString(),
  };
  await store.createTransitionRequest(request);

  // The store's guarded approve refuses the maker as checker...
  await assert.rejects(
    store.markTransitionRequestApproved(request.requestId, "officer-a"),
    WelfareStateError,
  );
  // ...and the CHECK constraint refuses even a hand-written SQL approval by the maker.
  await assert.rejects(
    pool.query(
      "UPDATE welfare_transition_requests SET status = 'APPROVED', approver_subject = $1, decided_at = now() WHERE request_id = $2",
      ["officer-a", request.requestId],
    ),
    /violates check constraint|welfare_transition_requests/,
  );
  // A direct INSERT with approver == requester violates the CHECK as well.
  await assert.rejects(
    pool.query(
      `INSERT INTO welfare_transition_requests (request_id, kind, complaint_id, payload, requester_subject, requester_role, status, approver_subject, decided_at)
       VALUES ($1, 'transition', $2, '{}'::jsonb, 'officer-a', 'nimasa-labour-officer', 'APPROVED', 'officer-a', now())`,
      [deterministicUuid("transition-request", "db-mc-2"), record.complaintId],
    ),
    /violates check constraint/,
  );
  // A distinct checker succeeds.
  const approved = await store.markTransitionRequestApproved(request.requestId, "officer-b");
  assert.equal(approved.status, "APPROVED");
  assert.equal(approved.approverSubject, "officer-b");
});

test("pg: Reg 5.1.5(3) right-to-redress acknowledgement is a CHECK constraint", async () => {
  const record = complaintRecord({ idempotencyKey: "idem-db-redress-1" });
  await assert.rejects(
    pool.query(
      `INSERT INTO welfare_complaint (complaint_id, channel, seafarer_ref, vessel_ref, category, narrative_enc, narrative_digest_sha256, idempotency_key, status, right_to_redress_notice_ack, created_by_subject)
       VALUES ($1, 'onboard_r515', 'NG-SRN-DB-01', 'NG-LKJ-0001', 'wages', $2, $3, $4, 'RECEIVED', false, 'seafarer-01')`,
      [record.complaintId, record.narrativeEnc, record.narrativeDigestSha256, record.idempotencyKey],
    ),
    /violates check constraint/,
  );
  const count = await pool.query("SELECT count(*)::int AS n FROM welfare_complaint WHERE complaint_id = $1", [record.complaintId]);
  assert.equal(count.rows[0]!.n, 0, "a complaint without the redress acknowledgement must not exist");
});

test("pg: referral consent is mandatory and idempotency holds at the database", async () => {
  // Seed a provider + service through the store (provenance path).
  const provider = await store.insertProvider({
    name: "Lagos Seafarer Centre", kind: "seafarer_centre", portCode: "NGLOS",
    address: "Apapa", contact: {}, hours: "24/7", sourceReference: "https://example.test/los",
  }, [{ description: "Shelter", eligibility: "all", languages: ["en"] }], "officer-a");
  const serviceId = provider.services[0]!.serviceId;

  // consent_at is NOT NULL: a consentless referral cannot exist.
  await assert.rejects(
    pool.query(
      `INSERT INTO welfare_referral (referral_id, seafarer_ref, service_id, consent_at, status, idempotency_key, created_by_subject)
       VALUES ($1, 'NG-SRN-DB-01', $2, NULL, 'OFFERED', $3, 'seafarer-01')`,
      [deterministicUuid("referral", "db-no-consent"), serviceId, "idem-db-noconsent"],
    ),
    /null value.*consent_at|violates not-null constraint/,
  );

  const referral = {
    referralId: deterministicUuid("referral", "db-ref-1"),
    complaintId: null,
    seafarerRef: "NG-SRN-DB-01",
    serviceId,
    consentAt: new Date().toISOString(),
    status: "OFFERED" as const,
    outcomeNoteDigestSha256: null,
    idempotencyKey: "idem-db-ref-1",
    createdBySubject: "seafarer-01",
    recordedAt: new Date().toISOString(),
  };
  const created = await store.createReferral(referral, OUTBOX);
  assert.equal(created.created, true);
  const replay = await store.createReferral({ ...referral }, OUTBOX);
  assert.equal(replay.created, false);
  const transitioned = await store.transitionReferral(referral.referralId, "OFFERED", "ACCEPTED", null, OUTBOX);
  assert.equal(transitioned.status, "ACCEPTED");
  // Guarded update: stale/illegal transitions yield a fail-closed error, not a silent write.
  await assert.rejects(store.transitionReferral(referral.referralId, "OFFERED", "ENGAGED", null, OUTBOX), WelfareStateError);
});

test("pg: complaint transition applies with outbox atomically; SLA breach observed exactly once", async () => {
  const record = complaintRecord();
  await store.createComplaint(record, OUTBOX);
  const applied = await store.applyComplaintTransition(record.complaintId, "RECEIVED", "ACKED", "nimasa-labour-officer", null, OUTBOX);
  assert.equal(applied.status, "ACKED");
  await assert.rejects(
    store.applyComplaintTransition(record.complaintId, "RECEIVED", "ONBOARD_PROCESS", "nimasa-labour-officer", null, OUTBOX),
    WelfareStateError,
    "stale from-state fails closed",
  );
  const events = await store.listComplaintEvents(record.complaintId);
  assert.deepEqual(events.map((event) => event.transition), ["RECEIVED", "RECEIVED->ACKED"]);

  const first = await store.recordSlaBreachesObserved(record.complaintId, ["ack"]);
  assert.deepEqual(first, ["ack"]);
  const second = await store.recordSlaBreachesObserved(record.complaintId, ["ack"]);
  assert.deepEqual(second, [], "breach markers are idempotent per (complaint, stage)");

  // Governed disclosure flips the scope and logs the disclosure event.
  const disclosed = await store.applyComplaintDisclosure(record.complaintId, "flag-state-investigation", "nimasa-labour-officer", null, OUTBOX);
  assert.equal(disclosed.disclosureScope, "disclosed");
  await assert.rejects(
    store.applyComplaintDisclosure(record.complaintId, "again", "nimasa-labour-officer", null, OUTBOX),
    WelfareStateError,
  );
});

test("pg: rest record idempotent replay retains flags without duplication", async () => {
  const recordRow = {
    recordId: deterministicUuid("rest-record", "db-2"),
    seafarerRef: "NG-SRN-DB-01",
    vesselRef: "NG-LKJ-0001",
    recordDate: "2026-08-11",
    periods: [
      { start: "2026-08-11T00:00:00.000Z", end: "2026-08-11T06:00:00.000Z", kind: "rest" as const },
      { start: "2026-08-11T06:00:00.000Z", end: "2026-08-12T00:00:00.000Z", kind: "work" as const },
    ],
    regime: "min_rest" as const,
    submittedBy: "operator-01",
    submittedByRole: "operator" as const,
    sourceDigestSha256: "b".repeat(64),
    policyVersion: "ng-mlc-2026.1",
    idempotencyKey: "idem-db-rest-2",
    submittedAt: new Date().toISOString(),
  };
  const flags = [{
    flagId: deterministicUuid("rest-flag", `${recordRow.recordId}|min_rest_10h_24|ng-mlc-2026.1`),
    recordId: recordRow.recordId,
    rule: "min_rest_10h_24" as const,
    detail: "rest totals 6h 0m in the 24 h window, below the 10h 0m minimum",
    policyVersion: "ng-mlc-2026.1",
    computedAt: new Date().toISOString(),
  }];
  const first = await store.insertRestRecord(recordRow, flags, [OUTBOX]);
  assert.equal(first.created, true);
  const replay = await store.insertRestRecord({ ...recordRow }, flags, [OUTBOX]);
  assert.equal(replay.created, false);
  const flagCount = await pool.query("SELECT count(*)::int AS n FROM rest_hour_flag WHERE record_id = $1", [recordRow.recordId]);
  assert.equal(flagCount.rows[0]!.n, 1, "recomputation under the same policy version is idempotent (UNIQUE key)");
  const listed = await store.listRestFlags({ vesselRef: "NG-LKJ-0001" });
  assert.ok(listed.some((flag) => flag.recordId === recordRow.recordId));
  // Key reuse with a different source payload fails closed.
  await assert.rejects(
    store.insertRestRecord({ ...recordRow, sourceDigestSha256: "9".repeat(64) }, [], []),
    /reused for a different rest-hour record/,
  );
});
