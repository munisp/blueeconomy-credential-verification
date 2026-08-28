import assert from "node:assert/strict";
import test from "node:test";
import { buildPlatformEnvelope, deterministicEventId, verifyEnvelopeProvenance } from "../src/events/envelope.js";
import { OutboxPublisher, createKafkaProducerFromEnv, type KafkaProducerLike } from "../src/events/outbox.js";
import type { SqlExecutor } from "../src/status/postgres.js";
import { generateEphemeralIssuerKeyPair } from "../src/vc/issuer.js";

test("envelope is deterministic, signed and CONFIDENTIAL", () => {
  const { privateKey, publicKey } = generateEphemeralIssuerKeyPair();
  const input = {
    eventType: "seafarer.credential.v1" as const,
    producer: "blueeconomy-credential-verification",
    correlationId: "corr-0001",
    principal: { principalId: "nimasa-approver-01", principalRole: "nimasa-approver" },
    resource: { resourceType: "DocumentReference", status: "current" },
    ledgerCommitHash: "b".repeat(64),
    signingKey: privateKey,
    deduplicationKey: "issue|cred-1",
    occurredAt: new Date("2026-06-01T00:00:00.000Z"),
  };
  const first = buildPlatformEnvelope(input);
  const second = buildPlatformEnvelope(input);
  assert.equal(first.eventId, second.eventId, "eventId must be deterministic for idempotent retries");
  assert.equal(first.envelopeVersion, "1.0");
  assert.equal(first.classification, "CONFIDENTIAL");
  assert.equal(first.provenance.ledgerCommitHash, "b".repeat(64));
  assert.equal((first.fhir as { resourceType: string }).resourceType, "Bundle");
  assert.equal((first.fhir as { type: string }).type, "message");
  assert.ok(!("message" in first), "platform canonical envelope carries the bundle under 'fhir'");
  assert.match(first.provenance.signature, /^z[1-9A-HJ-NP-Za-km-z]+$/, "provenance signature must be a base58btc string");
  assert.doesNotThrow(() => verifyEnvelopeProvenance(first, publicKey));

  const tampered = JSON.parse(JSON.stringify(first)) as typeof first;
  tampered.correlationId = "corr-9999";
  assert.throws(() => verifyEnvelopeProvenance(tampered, publicKey), /digest does not match/);

  const wrongKey = generateEphemeralIssuerKeyPair();
  assert.throws(() => verifyEnvelopeProvenance(first, wrongKey.publicKey), /digest does not match/);

  const malformed = JSON.parse(JSON.stringify(first)) as typeof first;
  malformed.provenance.signature = "not-multibase";
  assert.throws(() => verifyEnvelopeProvenance(malformed, publicKey), /not valid multibase base58btc/);
});

test("deterministic event ids differ across event types and keys", () => {
  const one = deterministicEventId("seafarer.credential.v1", "issue|a");
  const two = deterministicEventId("seafarer.revocation.v1", "issue|a");
  const three = deterministicEventId("seafarer.credential.v1", "issue|b");
  assert.match(one, /^[0-9a-f-]{36}$/);
  assert.notEqual(one, two);
  assert.notEqual(one, three);
});

function recordingExecutor(outboxRows: Array<Record<string, unknown>>) {
  const queries: Array<{ text: string; params: readonly unknown[] }> = [];
  const executor: SqlExecutor = {
    async query<Row extends import("pg").QueryResultRow>(text: string, params: readonly unknown[] = []) {
      queries.push({ text, params });
      const rows = text.includes("FROM credential_outbox") ? outboxRows : [];
      return { rows: rows as unknown as Row[], command: "", rowCount: rows.length, oid: 0, fields: [] };
    },
  };
  return { executor, queries };
}

test("outbox publisher drains pending rows to Kafka and marks them published", async () => {
  const rows = [
    { id: "1", topic: "seafarer.credential.v1", event_id: "e-1", payload: { envelopeVersion: "1.0" } },
    { id: "2", topic: "seafarer.revocation.v1", event_id: "e-2", payload: { envelopeVersion: "1.0" } },
  ];
  const { executor, queries } = recordingExecutor(rows);
  const sent: Array<{ topic: string; keys: string[] }> = [];
  const producer: KafkaProducerLike = {
    async connect() {},
    async send(batch) {
      sent.push({ topic: batch.topic, keys: batch.messages.map((message) => message.key) });
      return {};
    },
    async disconnect() {},
  };
  const publisher = new OutboxPublisher(executor, producer);
  const delivered = await publisher.publishPending();
  assert.equal(delivered, 2);
  assert.deepEqual(sent, [
    { topic: "seafarer.credential.v1", keys: ["e-1"] },
    { topic: "seafarer.revocation.v1", keys: ["e-2"] },
  ]);
  const marks = queries.filter((query) => query.text.includes("UPDATE credential_outbox"));
  assert.equal(marks.length, 2);
  assert.ok(queries[0]?.text === "BEGIN" && queries.at(-1)?.text === "COMMIT");
});

test("outbox publisher rolls back when Kafka delivery fails", async () => {
  const rows = [{ id: "1", topic: "seafarer.credential.v1", event_id: "e-1", payload: {} }];
  const { executor, queries } = recordingExecutor(rows);
  const producer: KafkaProducerLike = {
    async connect() {},
    async send() {
      throw new Error("broker unavailable");
    },
    async disconnect() {},
  };
  const publisher = new OutboxPublisher(executor, producer);
  await assert.rejects(() => publisher.publishPending(), /broker unavailable/);
  assert.ok(queries.some((query) => query.text === "ROLLBACK"));
  assert.ok(!queries.some((query) => query.text.includes("UPDATE credential_outbox")), "no row may be marked published after a failed send");
});

test("kafka producer factory fails closed without brokers", () => {
  assert.throws(() => createKafkaProducerFromEnv({}), /not configured.*fail-closed/);
  assert.throws(() => createKafkaProducerFromEnv({ BLUEECONOMY_KAFKA_BROKERS: " , " }), /at least one broker/);
});
