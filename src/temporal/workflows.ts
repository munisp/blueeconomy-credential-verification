import { condition, defineQuery, defineSignal, proxyActivities, setHandler } from "@temporalio/workflow";
import type { LifecycleActivities } from "./activities.js";

/**
 * SeafarerCredentialWorkflow: exam-registration → exam-result →
 * training-completion → credential-eligibility → issuance, with revocation
 * accepted as a signal at any point. Each stage carries an SLA timer; a
 * breach is recorded in the observer query without silently advancing the
 * stage machine. Only the eligibility stage unlocks API issuance.
 */

export type WorkflowStage =
  | "AWAITING_EXAM_REGISTRATION"
  | "AWAITING_EXAM_RESULT"
  | "AWAITING_TRAINING_COMPLETION"
  | "ELIGIBLE"
  | "ISSUED"
  | "REVOKED";

export interface SeafarerCredentialWorkflowInput {
  seafarerId: string;
  correlationId: string;
  /** SLA budgets in seconds for each transition. */
  examRegistrationSlaSeconds: number;
  examResultSlaSeconds: number;
  trainingCompletionSlaSeconds: number;
  issuanceSlaSeconds: number;
}

export interface WorkflowObservation {
  seafarerId: string;
  correlationId: string;
  stage: WorkflowStage;
  slaBreachedStages: WorkflowStage[];
  credentialId?: string;
  revocationReason?: string;
  revocationRequestedBy?: string;
}

export interface ExamRegistrationSignal { examId: string; provider: string }
export interface ExamResultSignal { examId: string; passed: boolean; score?: number }
export interface TrainingCompletionSignal { provider: string; completedAt: string }
export interface CredentialIssuedSignal { credentialId: string; holderId: string }
export interface RevocationSignal { reason: string; requestedBy: string; credentialId?: string }

export const examRegisteredSignal = defineSignal<[ExamRegistrationSignal]>("exam-registered");
export const examResultSignal = defineSignal<[ExamResultSignal]>("exam-result-recorded");
export const trainingCompletedSignal = defineSignal<[TrainingCompletionSignal]>("training-completed");
export const credentialIssuedSignal = defineSignal<[CredentialIssuedSignal]>("credential-issued");
export const revocationRequestedSignal = defineSignal<[RevocationSignal]>("revocation-requested");
export const observerQuery = defineQuery<WorkflowObservation>("observer");

const activities = proxyActivities<LifecycleActivities>({
  startToCloseTimeout: "30 seconds",
  retry: { maximumAttempts: 5 },
});

export async function SeafarerCredentialWorkflow(input: SeafarerCredentialWorkflowInput): Promise<WorkflowObservation> {
  let stage: WorkflowStage = "AWAITING_EXAM_REGISTRATION";
  const slaBreached: WorkflowStage[] = [];
  let examRegistered: ExamRegistrationSignal | undefined;
  let examPassed = false;
  let trainingCompleted: TrainingCompletionSignal | undefined;
  let issued: CredentialIssuedSignal | undefined;
  let revocation: RevocationSignal | undefined;

  setHandler(examRegisteredSignal, (signal) => {
    if (examRegistered === undefined) examRegistered = signal;
  });
  setHandler(examResultSignal, (signal) => {
    if (examRegistered !== undefined && signal.examId === examRegistered.examId && signal.passed) examPassed = true;
  });
  setHandler(trainingCompletedSignal, (signal) => {
    if (trainingCompleted === undefined) trainingCompleted = signal;
  });
  setHandler(credentialIssuedSignal, (signal) => {
    if (issued === undefined) issued = signal;
  });
  setHandler(revocationRequestedSignal, (signal) => {
    if (revocation === undefined) revocation = signal;
  });

  const observation = (): WorkflowObservation => {
    const result: WorkflowObservation = {
      seafarerId: input.seafarerId,
      correlationId: input.correlationId,
      stage,
      slaBreachedStages: [...slaBreached],
    };
    if (issued !== undefined) result.credentialId = issued.credentialId;
    if (revocation !== undefined) {
      result.revocationReason = revocation.reason;
      result.revocationRequestedBy = revocation.requestedBy;
      if (revocation.credentialId !== undefined) result.credentialId = revocation.credentialId;
    }
    return result;
  };
  setHandler(observerQuery, observation);

  /** Waits for a stage gate, its SLA timer, or revocation — revocation wins. */
  async function awaitStage(currentStage: WorkflowStage, gate: () => boolean, slaSeconds: number): Promise<boolean> {
    const withinSla = await condition(() => gate() || revocation !== undefined, slaSeconds * 1_000);
    if (revocation !== undefined) return false;
    if (!withinSla) {
      slaBreached.push(currentStage);
      await condition(() => gate() || revocation !== undefined);
      if (revocation !== undefined) return false;
    }
    return true;
  }

  if (await awaitStage("AWAITING_EXAM_REGISTRATION", () => examRegistered !== undefined, input.examRegistrationSlaSeconds)) {
    stage = "AWAITING_EXAM_RESULT";
    if (await awaitStage("AWAITING_EXAM_RESULT", () => examPassed, input.examResultSlaSeconds)) {
      stage = "AWAITING_TRAINING_COMPLETION";
      if (await awaitStage("AWAITING_TRAINING_COMPLETION", () => trainingCompleted !== undefined, input.trainingCompletionSlaSeconds)) {
        stage = "ELIGIBLE";
        if (await awaitStage("ELIGIBLE", () => issued !== undefined, input.issuanceSlaSeconds)) {
          stage = "ISSUED";
          await condition(() => revocation !== undefined);
        }
      }
    }
  }

  stage = "REVOKED";
  const finalRevocation = revocation as RevocationSignal;
  await activities.publishRevocationEvent({
    seafarerId: input.seafarerId,
    correlationId: input.correlationId,
    reason: finalRevocation.reason,
    requestedBy: finalRevocation.requestedBy,
    ...(finalRevocation.credentialId !== undefined
      ? { credentialId: finalRevocation.credentialId }
      : issued !== undefined ? { credentialId: issued.credentialId } : {}),
  });
  return observation();
}
