import type { KeyObject } from "node:crypto";
import { buildPlatformEnvelope, type PlatformEnvelope } from "../events/envelope.js";
import type { IssuanceLedger } from "../ledger/issuance-ledger.js";
import type { OutboxMessage } from "../status/store.js";

/**
 * Workflow activity implementations. Side effects (ledger, envelope signing,
 * outbox) live here so the workflow body stays deterministic.
 */

export interface PublishRevocationEventInput {
  seafarerId: string;
  correlationId: string;
  reason: string;
  requestedBy: string;
  credentialId?: string;
}

export interface LifecycleActivities {
  publishRevocationEvent(input: PublishRevocationEventInput): Promise<void>;
}

export interface LifecycleActivityDependencies {
  ledger: IssuanceLedger;
  signingKey: KeyObject;
  producer: string;
  enqueue(message: OutboxMessage): Promise<void>;
}

export function createLifecycleActivities(deps: LifecycleActivityDependencies): LifecycleActivities {
  return {
    async publishRevocationEvent(input: PublishRevocationEventInput): Promise<void> {
      const credentialId = input.credentialId ?? `workflow:${input.correlationId}`;
      const commit = await deps.ledger.record({
        credentialId,
        holderReference: input.seafarerId,
        issuer: "did:web:credentials.nimasa.gov.ng",
        kind: "revocation",
        occurredAt: new Date().toISOString(),
      });
      const envelope = buildPlatformEnvelope({
        eventType: "seafarer.revocation.v1",
        producer: deps.producer,
        correlationId: input.correlationId,
        principal: { principalId: input.requestedBy, principalRole: "nimasa-approver" },
        resource: {
          resourceType: "Communication",
          status: "completed",
          subject: { reference: input.seafarerId },
          payload: [{ contentString: `revocation: ${input.reason}` }],
        },
        ledgerCommitHash: commit.commitHash,
        signingKey: deps.signingKey,
        deduplicationKey: `revocation|${credentialId}|${input.correlationId}`,
      });
      await deps.enqueue({
        topic: "seafarer.revocation.v1",
        eventId: envelope.eventId,
        payload: envelope as unknown as Record<string, unknown>,
      });
    },
  };
}

export type { PlatformEnvelope };
