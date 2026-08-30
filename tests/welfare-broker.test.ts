import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { randomInt } from "node:crypto";
import pg from "pg";
import { Kafka } from "kafkajs";
import { exportJWK, importJWK, decodeProtectedHeader } from "jose";

import { runMigrations } from "../src/status/postgres.js";
import { PgWelfareStore } from "../src/welfare/postgres.js";
import { WelfareService } from "../src/welfare/service.js";
import { InMemoryComplaintLifecycle } from "../src/welfare/lifecycle.js";
import { NarrativeKey } from "../src/welfare/confidentiality.js";
import { OutboxPublisher, createKafkaProducerFromEnv } from "../src/events/outbox.js";
import { verifyEnvelopeSignature, type KeyDirectory } from "../src/events/envelope-verification.js";
import { canonicalizeBytes, asJsonValue, type JsonValue } from "../src/vc/jcs.js";
import { generateEphemeralIssuerKeyPair } from "../src/vc/issuer.js";
import type { WelfarePolicy } from "../src/welfare/policy.js";

/**
 * Broker-gated welfare emission test. Requires the real local stack
 * (local_stack.sh: PostgreSQL on 5432, Kafka on 9092). A complaint and a
 * breaching rest-hour record are committed through the real PgWelfareStore,
 * the shared credential_outbox is drained by the real OutboxPublisher through
 * a real kafkajs producer, and the messages consumed from seafarers.welfare.v1
 * are verified byte-for-byte (JWS payload == JCS-canonical envelope) against a
 * consumer-side verifier, independent of the producing code path.
 */

const ADMIN_URL = process.env["BLUEECONOMY_TEST_ADMIN_DATABASE_URL"] ?? "postgres://postgres@127.0.0.1:5432/postgres";
const BROKERS = (process.env["BLUEECONOMY_KAFKA_BROKERS"] ?? "127.0.0.1:9092").split(",");
const MIGRATIONS = fileURLToPath(new URL("../migrations", import.meta.url));
const TOPIC = "seafarers.welfare.v1";

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

/** Consumer-side envelope check, reimplemented from docs/envelope-signature.md. */
async function independentVerify(envelope: Record<string, unknown>, publicJwkX: string, expectedKid: string): Promise<void> {
  const provenance = envelope["provenance"] as Record<string, unknown>;
  const signature = provenance["signature"] as string;
  const header = decodeProtectedHeader(signature);
  assert.equal(header.alg, "EdDSA");
  assert.equal(header.kid, expectedKid);
  // Rebuild the signed document: envelope minus provenance.signature.
  const signed: Record<string, JsonValue> = {};
  for (const [key, value] of Object.entries(envelope)) {
    if (key === "provenance") continue;
    signed[key] = asJsonValue(value);
  }
  const provenanceUnsigned: Record<string, JsonValue> = {};
  for (const [key, value] of Object.entries(provenance)) {
    if (key === "signature") continue;
    provenanceUnsigned[key] = asJsonValue(value);
  }
  signed["provenance"] = asJsonValue(provenanceUnsigned);
  const expectedPayload = Buffer.from(canonicalizeBytes(asJsonValue(signed)));
  const actualPayload = Buffer.from(signature.split(".")[1]!, "base64url");
  assert.ok(actualPayload.equals(expectedPayload), "JWS payload must byte-equal the JCS-canonical envelope (RFC 8785)");
  const { compactVerify } = await import("jose");
  const key = await importJWK({ kty: "OKP", crv: "Ed25519", x: publicJwkX }, "EdDSA");
  await compactVerify(signature, key); // throws on any signature deviation
}

test("broker: welfare events drain through the outbox to Kafka and verify byte-for-byte", async (t) => {
  // Fresh database per run.
  const database = `cv_welfare_broker_${process.pid}_${randomInt(1_000_000)}`;
  const admin = new pg.Pool({ connectionString: ADMIN_URL, max: 2 });
  await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
  await admin.query(`CREATE DATABASE ${database}`);
  await admin.end();
  const pool = new pg.Pool({ connectionString: `postgres://postgres@127.0.0.1:5432/${database}`, max: 4 });
  const kafka = new Kafka({ clientId: "welfare-broker-test", brokers: BROKERS, retry: { retries: 2 } });
  const consumer = kafka.consumer({ groupId: `welfare-test-${process.pid}-${randomInt(1_000_000)}` });

  try {
    await pool.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public");
    await runMigrations(pool, MIGRATIONS);
    const store = new PgWelfareStore({ executor: pool });

    const { privateKey, publicKey } = generateEphemeralIssuerKeyPair();
    const keyId = "blueeconomy-credential-verification-1";
    const publicJwkX = (await exportJWK(publicKey)).x!;
    const service = new WelfareService({
      store,
      policy: POLICY,
      narrativeKey: NarrativeKey.fromHex("f".repeat(64)),
      signing: { privateKey, keyId },
      producer: "blueeconomy-credential-verification",
      identity: { referenceFor: async () => "NG-SRN-KAFKA-01" },
      lifecycle: new InMemoryComplaintLifecycle(),
      curationContact: "welfare-desk@example.test",
    });

    const complaint = await service.submitComplaint({
      channel: "flagstate_r522",
      vesselRef: "NG-LKJ-0002",
      category: "repatriation",
      narrative: "Crew abandoned at berth; wages and repatriation unpaid.",
      attachments: [],
      rightToRedressNoticeAck: true,
    }, `idem-kafka-complaint-${process.pid}`, { subject: "seafarer-kafka", role: "seafarer" });

    const rest = await service.submitRestRecord({
      seafarerRef: "NG-SRN-KAFKA-01",
      vesselRef: "NG-LKJ-0002",
      recordDate: "2026-08-10",
      periods: [
        { start: "2026-08-10T00:00:00.000Z", end: "2026-08-10T06:00:00.000Z", kind: "rest" },
        { start: "2026-08-10T06:00:00.000Z", end: "2026-08-11T00:00:00.000Z", kind: "work" },
      ],
    }, `idem-kafka-rest-${process.pid}`, { subject: "operator-kafka", role: "operator" });
    assert.ok(rest.eventIds.length >= 1, "the breaching record must emit flag events");

    const expectedEventIds = new Set([complaint.eventId, ...rest.eventIds]);

    // Ensure the topic exists and metadata has settled before the drain
    // (cold auto-creation races the first produce on a fresh broker).
    const adminClient = kafka.admin();
    await adminClient.connect();
    const existingTopics = await adminClient.listTopics();
    if (!existingTopics.includes(TOPIC)) {
      await adminClient.createTopics({ topics: [{ topic: TOPIC, numPartitions: 1, replicationFactor: 1 }] });
      await new Promise((resolve) => setTimeout(resolve, 1_000));
    }
    await adminClient.disconnect();

    // Consumer attached BEFORE the drain so no message can be missed.
    await consumer.connect();
    await consumer.subscribe({ topic: TOPIC, fromBeginning: true });
    const received = new Map<string, Record<string, unknown>>();
    await consumer.run({
      eachMessage: async ({ message }) => {
        const envelope = JSON.parse(message.value!.toString("utf8")) as Record<string, unknown>;
        received.set(message.key!.toString("utf8"), envelope);
      },
    });

    // Drain the shared outbox through the real publisher and real producer.
    const producer = createKafkaProducerFromEnv({ BLUEECONOMY_KAFKA_BROKERS: BROKERS.join(",") });
    await producer.connect();
    const publisher = new OutboxPublisher(pool, producer);
    const drained = await publisher.publishPending();
    assert.equal(drained, expectedEventIds.size, "every committed welfare event is drained");
    await producer.disconnect();

    // Outbox rows are marked published exactly once.
    const unpublished = await pool.query("SELECT count(*)::int AS n FROM credential_outbox WHERE published_at IS NULL");
    assert.equal(unpublished.rows[0]!.n, 0);

    // Wait for the broker to deliver all expected events.
    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline && ![...expectedEventIds].every((id) => received.has(id))) {
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    for (const eventId of expectedEventIds) {
      assert.ok(received.has(eventId), `event ${eventId} must arrive on ${TOPIC}`);
    }

    // Consumer-side verification, independent of the producing code path.
    const complaintEnvelope = received.get(complaint.eventId)!;
    assert.equal(complaintEnvelope["eventType"], "seafarer.welfare.complaint.v1");
    assert.equal(complaintEnvelope["classification"], "CONFIDENTIAL");
    const resource = ((complaintEnvelope["fhir"] as { entry: Array<{ resource: Record<string, unknown> }> }).entry[0]!).resource;
    assert.equal(resource["@type"], "type.googleapis.com/blueeconomy.contracts.v1.WelfareComplaintSubmitted");
    assert.match(String(resource["seafarerReference"]), /^sfr-[0-9a-f]{12}$/, "tokenized reference only");
    assert.ok(!JSON.stringify(complaintEnvelope).includes("abandoned at berth"), "the narrative never leaves the service boundary");
    await independentVerify(complaintEnvelope, publicJwkX, keyId);

    for (const eventId of rest.eventIds) {
      const envelope = received.get(eventId)!;
      assert.equal(envelope["eventType"], "seafarer.rest_hours.flagged.v1");
      await independentVerify(envelope, publicJwkX, keyId);
    }

    // The repo's own consumer verifier agrees with the independent check.
    const resolvedKey = await importJWK({ kty: "OKP", crv: "Ed25519", x: publicJwkX }, "EdDSA");
    const repoDirectory: KeyDirectory = { size: 1, resolve: (kid) => (kid === keyId ? resolvedKey : undefined) };
    for (const eventId of expectedEventIds) {
      assert.equal(await verifyEnvelopeSignature(received.get(eventId)!, repoDirectory), keyId);
    }
    t.diagnostic(`verified ${expectedEventIds.size} welfare envelopes from ${TOPIC}`);
  } finally {
    await consumer.disconnect().catch(() => {});
    await pool.end().catch(() => {});
    const cleanup = new pg.Pool({ connectionString: ADMIN_URL, max: 2 });
    await cleanup.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`).catch(() => {});
    await cleanup.end().catch(() => {});
  }
});
