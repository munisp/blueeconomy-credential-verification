import { condition, defineQuery, defineSignal, setHandler } from "@temporalio/workflow";

/**
 * ComplaintWorkflow (MLC 2006 Reg 5.1.5 "fair, effective and expeditious"):
 * tracks the complaint lifecycle with SLA timers — received → ack SLA (48 h
 * per the signed welfare policy) → onboard-process SLA → escalation →
 * resolution SLA. Status advancement is driven by signals from the welfare
 * service (which applies maker/checker-approved transitions); an SLA breach
 * is recorded in the observer query without advancing the state machine —
 * the same pattern as SeafarerCredentialWorkflow. The workflow has no
 * activities: it is a pure observation/SLA tracker, so there is nothing to
 * undo and no side effect inside the workflow body.
 */

export type ComplaintWorkflowStage =
  | "AWAITING_ACK"
  | "AWAITING_ONBOARD_PROCESS"
  | "AWAITING_ESCALATION"
  | "AWAITING_RESOLUTION"
  | "AWAITING_CLOSURE"
  | "CLOSED";

export type ComplaintWorkflowStatus =
  | "RECEIVED"
  | "ACKED"
  | "ONBOARD_PROCESS"
  | "ESCALATED_FLAGSTATE"
  | "REFERRED"
  | "RESOLVED"
  | "CLOSED";

export interface ComplaintWorkflowInput {
  complaintId: string;
  channel: "onboard_r515" | "flagstate_r522";
  correlationId: string;
  /** SLA budgets in seconds from the signed welfare-policy document. */
  slaSeconds: {
    ack: number;
    onboard_process: number;
    escalation: number;
    resolution: number;
  };
}

export interface ComplaintWorkflowObservation {
  complaintId: string;
  channel: "onboard_r515" | "flagstate_r522";
  stage: ComplaintWorkflowStage;
  status: ComplaintWorkflowStatus;
  slaBreachedStages: ComplaintWorkflowStage[];
}

export interface ComplaintStatusSignal {
  status: ComplaintWorkflowStatus;
}

export const complaintStatusSignal = defineSignal<[ComplaintStatusSignal]>("complaint-status");
export const complaintObserverQuery = defineQuery<ComplaintWorkflowObservation>("complaint-observer");

/** "At or beyond" gate membership; ESCALATED/REFERRED are branches of the process stage. */
function reached(status: ComplaintWorkflowStatus, targets: readonly ComplaintWorkflowStatus[]): boolean {
  return targets.includes(status);
}

const ACKED_OR_BEYOND: readonly ComplaintWorkflowStatus[] = ["ACKED", "ONBOARD_PROCESS", "ESCALATED_FLAGSTATE", "REFERRED", "RESOLVED", "CLOSED"];
const PROCESSED_OR_BEYOND: readonly ComplaintWorkflowStatus[] = ["ONBOARD_PROCESS", "ESCALATED_FLAGSTATE", "REFERRED", "RESOLVED", "CLOSED"];
const ESCALATED_OR_RESOLVED: readonly ComplaintWorkflowStatus[] = ["ESCALATED_FLAGSTATE", "REFERRED", "RESOLVED", "CLOSED"];
const RESOLVED_OR_CLOSED: readonly ComplaintWorkflowStatus[] = ["RESOLVED", "CLOSED"];

export async function ComplaintWorkflow(input: ComplaintWorkflowInput): Promise<ComplaintWorkflowObservation> {
  let status: ComplaintWorkflowStatus = "RECEIVED";
  const slaBreached: ComplaintWorkflowStage[] = [];

  setHandler(complaintStatusSignal, (signal) => {
    status = signal.status;
  });

  function currentStage(): ComplaintWorkflowStage {
    if (status === "CLOSED") return "CLOSED";
    if (!reached(status, ACKED_OR_BEYOND)) return "AWAITING_ACK";
    if (input.channel === "onboard_r515" && !reached(status, PROCESSED_OR_BEYOND)) return "AWAITING_ONBOARD_PROCESS";
    if (input.channel === "onboard_r515" && !reached(status, ESCALATED_OR_RESOLVED)) return "AWAITING_ESCALATION";
    if (!reached(status, RESOLVED_OR_CLOSED)) return "AWAITING_RESOLUTION";
    return "AWAITING_CLOSURE";
  }

  const observation = (): ComplaintWorkflowObservation => ({
    complaintId: input.complaintId,
    channel: input.channel,
    stage: currentStage(),
    status,
    slaBreachedStages: [...slaBreached],
  });
  setHandler(complaintObserverQuery, observation);

  /** Waits for a gate or its SLA timer; records a breach without advancing. */
  async function awaitStage(stage: ComplaintWorkflowStage, gate: () => boolean, slaSeconds: number): Promise<void> {
    const withinSla = await condition(gate, slaSeconds * 1_000);
    if (!withinSla) {
      slaBreached.push(stage);
      await condition(gate);
    }
  }

  await awaitStage("AWAITING_ACK", () => reached(status, ACKED_OR_BEYOND), input.slaSeconds.ack);
  if (input.channel === "onboard_r515") {
    await awaitStage("AWAITING_ONBOARD_PROCESS", () => reached(status, PROCESSED_OR_BEYOND), input.slaSeconds.onboard_process);
    await awaitStage("AWAITING_ESCALATION", () => reached(status, ESCALATED_OR_RESOLVED), input.slaSeconds.escalation);
  }
  await awaitStage("AWAITING_RESOLUTION", () => reached(status, RESOLVED_OR_CLOSED), input.slaSeconds.resolution);
  // Closure has no SLA budget: the workflow completes when the complaint is CLOSED.
  await condition(() => status === "CLOSED");
  return observation();
}
