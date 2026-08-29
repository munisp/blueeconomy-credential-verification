import { Kafka, type Producer } from "kafkajs";
import { SpanKind } from "@opentelemetry/api";
import type { SqlExecutor } from "../status/postgres.js";
import { injectTraceContext, withSpan } from "../telemetry/spans.js";

/**
 * Transactional outbox publisher. Status transitions write envelope rows to
 * credential_outbox in the same database transaction; this publisher drains
 * unpublished rows to Kafka (seafarer.credential.v1 / seafarer.revocation.v1)
 * and marks them published. The publisher fails closed when no Kafka brokers
 * are configured.
 */

export interface OutboxRow {
  id: string;
  topic: string;
  event_id: string;
  payload: Record<string, unknown>;
}

export interface KafkaProducerLike {
  connect(): Promise<void>;
  send(batch: { topic: string; messages: Array<{ key: string; value: string; headers?: Record<string, string> }> }): Promise<unknown>;
  disconnect(): Promise<void>;
}

const SELECT_UNPUBLISHED = `
SELECT id, topic, event_id, payload
  FROM credential_outbox
 WHERE published_at IS NULL
 ORDER BY id ASC
 LIMIT $1
 FOR UPDATE SKIP LOCKED`;

const MARK_PUBLISHED = `
UPDATE credential_outbox
   SET published_at = now()
 WHERE id = $1 AND published_at IS NULL`;

export class OutboxPublisher {
  public constructor(
    private readonly executor: SqlExecutor,
    private readonly producer: KafkaProducerLike,
    private readonly batchSize = 100,
  ) {
    if (!Number.isInteger(batchSize) || batchSize <= 0 || batchSize > 1_000) {
      throw new Error("outbox batch size must be an integer in 1-1000");
    }
  }

  /** Publishes one batch; returns the number of events delivered. */
  public async publishPending(): Promise<number> {
    await this.executor.query("BEGIN");
    try {
      const result = await this.executor.query<OutboxRow & { [key: string]: unknown }>(SELECT_UNPUBLISHED, [this.batchSize]);
      const rows = result.rows;
      const byTopic = new Map<string, OutboxRow[]>();
      for (const row of rows) {
        const bucket = byTopic.get(row.topic) ?? [];
        bucket.push(row);
        byTopic.set(row.topic, bucket);
      }
      for (const [topic, topicRows] of byTopic) {
        // Phase-7 OTel: PRODUCER span per topic batch with the W3C
        // traceparent injected into each message's headers (manual carrier —
        // consumers extract it to continue the trace). No-op propagator when
        // telemetry is disabled, so headers stay empty and the wire format
        // for consumers is unchanged.
        await withSpan(`outbox.publish ${topic}`, {
          kind: SpanKind.PRODUCER,
          attributes: {
            "messaging.system": "kafka",
            "messaging.destination.name": topic,
            "messaging.message_count": topicRows.length,
          },
        }, async () => {
          await this.producer.send({
            topic,
            messages: topicRows.map((row) => {
              const headers: Record<string, string> = {};
              injectTraceContext(headers);
              return { key: row.event_id, value: JSON.stringify(row.payload), headers };
            }),
          });
        });
        for (const row of topicRows) {
          await this.executor.query(MARK_PUBLISHED, [row.id]);
        }
      }
      await this.executor.query("COMMIT");
      return rows.length;
    } catch (error) {
      try {
        await this.executor.query("ROLLBACK");
      } catch {
        // Original failure is authoritative.
      }
      throw error;
    }
  }
}

/** Fail-closed factory: requires BLUEECONOMY_KAFKA_BROKERS. */
export function createKafkaProducerFromEnv(env: NodeJS.ProcessEnv = process.env): KafkaProducerLike {
  const brokers = env["BLUEECONOMY_KAFKA_BROKERS"];
  if (brokers === undefined || brokers.trim().length === 0) {
    throw new Error("Kafka is not configured: set BLUEECONOMY_KAFKA_BROKERS (fail-closed)");
  }
  const brokerList = brokers.split(",").map((entry) => entry.trim()).filter((entry) => entry.length > 0);
  if (brokerList.length === 0) throw new Error("BLUEECONOMY_KAFKA_BROKERS must contain at least one broker");
  const kafka = new Kafka({
    clientId: env["BLUEECONOMY_KAFKA_CLIENT_ID"] ?? "blueeconomy-credential-verification",
    brokers: brokerList,
    retry: { retries: 3 },
  });
  const producer: Producer = kafka.producer({ idempotent: true, maxInFlightRequests: 1 });
  return producer;
}
