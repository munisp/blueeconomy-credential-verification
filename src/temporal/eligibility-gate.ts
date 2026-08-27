import { Client, Connection } from "@temporalio/client";
import { observerQuery, type WorkflowObservation } from "./workflows.js";

/**
 * Issuance gate: a CoC credential may only be issued for a seafarer whose
 * SeafarerCredentialWorkflow has reached the credential-eligibility stage.
 * Production queries the Temporal workflow; the gate fails closed when no
 * Temporal address is configured.
 */

export interface EligibilityDecision {
  eligible: boolean;
  observation: WorkflowObservation;
}

export interface EligibilityGate {
  check(workflowId: string, seafarerId: string): Promise<EligibilityDecision>;
}

export class TemporalEligibilityGate implements EligibilityGate {
  public constructor(private readonly client: Pick<Client["workflow"], "getHandle">) {}

  public async check(workflowId: string, seafarerId: string): Promise<EligibilityDecision> {
    const handle = this.client.getHandle(workflowId);
    const observation = await handle.query(observerQuery);
    const eligible = observation.seafarerId === seafarerId
      && (observation.stage === "ELIGIBLE" || observation.stage === "ISSUED");
    return { eligible, observation };
  }
}

export async function createEligibilityGateFromEnv(env: NodeJS.ProcessEnv = process.env): Promise<EligibilityGate> {
  const address = env["BLUEECONOMY_TEMPORAL_ADDRESS"];
  if (address === undefined || address.trim().length === 0) {
    throw new Error("Temporal is not configured: set BLUEECONOMY_TEMPORAL_ADDRESS (fail-closed)");
  }
  const connection = await Connection.connect({ address });
  const client = new Client({
    connection,
    ...(env["BLUEECONOMY_TEMPORAL_NAMESPACE"] !== undefined
      ? { namespace: env["BLUEECONOMY_TEMPORAL_NAMESPACE"] }
      : {}),
  });
  return new TemporalEligibilityGate(client.workflow);
}
