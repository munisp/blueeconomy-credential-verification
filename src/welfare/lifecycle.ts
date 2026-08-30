import { Client, Connection, WorkflowIdConflictPolicy, WorkflowIdReusePolicy, type ClientInterceptors } from "@temporalio/client";
import {
  complaintObserverQuery,
  complaintStatusSignal,
  type ComplaintWorkflowInput,
  type ComplaintWorkflowObservation,
  type ComplaintWorkflowStatus,
} from "./workflow.js";

/**
 * Complaint lifecycle tracker interface: the welfare service starts one
 * ComplaintWorkflow per complaint on the `seafarer-welfare` task queue and
 * signals maker/checker-approved transitions into it. Observation is used to
 * surface SLA breaches (recorded once per stage via
 * welfare_sla_breach_observed). Mirrors the Temporal-SLA machinery of
 * src/temporal/eligibility-gate.ts.
 */

export interface ComplaintLifecycle {
  /** Idempotent: starting an existing workflow id returns the running one. */
  start(input: ComplaintWorkflowInput): Promise<void>;
  signal(complaintId: string, status: ComplaintWorkflowStatus): Promise<void>;
  /** Undefined when the complaint's workflow is not visible (fail-open read). */
  observe(complaintId: string): Promise<ComplaintWorkflowObservation | undefined>;
}

export const WELFARE_TASK_QUEUE_DEFAULT = "seafarer-welfare";

export class TemporalComplaintLifecycle implements ComplaintLifecycle {
  private constructor(
    private readonly workflowClient: Client["workflow"],
    private readonly taskQueue: string,
  ) {}

  public static async create(env: NodeJS.ProcessEnv, telemetry?: { interceptors: ClientInterceptors }): Promise<TemporalComplaintLifecycle> {
    const address = env["BLUEECONOMY_TEMPORAL_ADDRESS"];
    if (address === undefined || address.trim().length === 0) {
      throw new Error("Temporal is not configured: set BLUEECONOMY_TEMPORAL_ADDRESS (fail-closed)");
    }
    const connection = await Connection.connect({ address });
    const client = new Client({
      connection,
      ...(env["BLUEECONOMY_TEMPORAL_NAMESPACE"] !== undefined ? { namespace: env["BLUEECONOMY_TEMPORAL_NAMESPACE"] } : {}),
      ...(telemetry !== undefined ? { interceptors: telemetry.interceptors } : {}),
    });
    return new TemporalComplaintLifecycle(client.workflow, env["BLUEECONOMY_WELFARE_TASK_QUEUE"] ?? WELFARE_TASK_QUEUE_DEFAULT);
  }

  public async start(input: ComplaintWorkflowInput): Promise<void> {
    const { ComplaintWorkflow } = await import("./workflow.js");
    await this.workflowClient.start(ComplaintWorkflow, {
      taskQueue: this.taskQueue,
      workflowId: input.complaintId,
      workflowIdReusePolicy: WorkflowIdReusePolicy.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE,
      workflowIdConflictPolicy: WorkflowIdConflictPolicy.USE_EXISTING,
      args: [input],
    });
  }

  public async signal(complaintId: string, status: ComplaintWorkflowStatus): Promise<void> {
    await this.workflowClient.getHandle(complaintId).signal(complaintStatusSignal, { status });
  }

  public async observe(complaintId: string): Promise<ComplaintWorkflowObservation | undefined> {
    try {
      return await this.workflowClient.getHandle(complaintId).query(complaintObserverQuery);
    } catch {
      // A completed or not-yet-visible workflow yields no observation; the
      // read surface reports the database state, which is authoritative.
      return undefined;
    }
  }
}

/** Test lifecycle: in-memory, deterministic, with injectable failures. */
export class InMemoryComplaintLifecycle implements ComplaintLifecycle {
  private readonly observations = new Map<string, ComplaintWorkflowObservation>();
  public readonly started: ComplaintWorkflowInput[] = [];
  public readonly signalled: Array<{ complaintId: string; status: ComplaintWorkflowStatus }> = [];

  public constructor(private readonly failOnStart = false) {}

  public async start(input: ComplaintWorkflowInput): Promise<void> {
    if (this.failOnStart) throw new Error("temporal unavailable");
    if (!this.observations.has(input.complaintId)) {
      this.observations.set(input.complaintId, {
        complaintId: input.complaintId,
        channel: input.channel,
        stage: "AWAITING_ACK",
        status: "RECEIVED",
        slaBreachedStages: [],
      });
      this.started.push(input);
    }
  }

  public async signal(complaintId: string, status: ComplaintWorkflowStatus): Promise<void> {
    const observation = this.observations.get(complaintId);
    if (observation !== undefined) this.observations.set(complaintId, { ...observation, status });
    this.signalled.push({ complaintId, status });
  }

  public async observe(complaintId: string): Promise<ComplaintWorkflowObservation | undefined> {
    return this.observations.get(complaintId);
  }

  public setBreaches(complaintId: string, stages: ComplaintWorkflowObservation["slaBreachedStages"]): void {
    const observation = this.observations.get(complaintId);
    if (observation !== undefined) this.observations.set(complaintId, { ...observation, slaBreachedStages: [...stages] });
  }
}
