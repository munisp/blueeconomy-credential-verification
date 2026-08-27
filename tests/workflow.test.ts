import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { TestWorkflowEnvironment } from "@temporalio/testing";
import { Worker } from "@temporalio/worker";
import type { WorkflowHandle } from "@temporalio/client";

import type { PublishRevocationEventInput } from "../src/temporal/activities.js";
import {
  SeafarerCredentialWorkflow,
  credentialIssuedSignal,
  examRegisteredSignal,
  examResultSignal,
  observerQuery,
  revocationRequestedSignal,
  trainingCompletedSignal,
  type SeafarerCredentialWorkflowInput,
} from "../src/temporal/workflows.js";

const INPUT: SeafarerCredentialWorkflowInput = {
  seafarerId: "seafarer-ng-0001",
  correlationId: "corr-0001",
  examRegistrationSlaSeconds: 60,
  examResultSlaSeconds: 60,
  trainingCompletionSlaSeconds: 60,
  issuanceSlaSeconds: 60,
};

let environment: TestWorkflowEnvironment;

test.before(async () => {
  environment = await TestWorkflowEnvironment.createTimeSkipping();
});

test.after(async () => {
  await environment?.teardown();
});

async function withWorkflow(
  name: string,
  input: SeafarerCredentialWorkflowInput,
  publishedRevocations: PublishRevocationEventInput[],
  drive: (handle: WorkflowHandle) => Promise<void>,
): Promise<void> {
  const taskQueue = `test-${name}`;
  const worker = await Worker.create({
    connection: environment.nativeConnection,
    taskQueue,
    workflowsPath: fileURLToPath(new URL("../src/temporal/workflows.ts", import.meta.url)),
    activities: {
      async publishRevocationEvent(activityInput: PublishRevocationEventInput): Promise<void> {
        publishedRevocations.push(activityInput);
      },
    },
  });
  await worker.runUntil(async () => {
    const handle = await environment.client.workflow.start(SeafarerCredentialWorkflow, {
      taskQueue,
      workflowId: `wf-${name}-${Date.now()}`,
      args: [input],
    });
    await drive(handle);
  });
}

test("workflow advances registration to eligibility and observes issuance", async () => {
  const published: PublishRevocationEventInput[] = [];
  await withWorkflow("happy", INPUT, published, async (handle) => {
    assert.equal((await handle.query(observerQuery)).stage, "AWAITING_EXAM_REGISTRATION");
    await handle.signal(examRegisteredSignal, { examId: "exam-1", provider: "nimasa-exam-centre" });
    assert.equal((await handle.query(observerQuery)).stage, "AWAITING_EXAM_RESULT");
    await handle.signal(examResultSignal, { examId: "exam-1", passed: false });
    assert.equal((await handle.query(observerQuery)).stage, "AWAITING_EXAM_RESULT", "failed exam must not advance the stage");
    await handle.signal(examResultSignal, { examId: "exam-1", passed: true });
    assert.equal((await handle.query(observerQuery)).stage, "AWAITING_TRAINING_COMPLETION");
    await handle.signal(trainingCompletedSignal, { provider: "nimasa-training", completedAt: "2026-05-01T00:00:00Z" });
    assert.equal((await handle.query(observerQuery)).stage, "ELIGIBLE");
    await handle.signal(credentialIssuedSignal, { credentialId: "urn:uuid:cred-1", holderId: "did:web:wallet:ng-0001" });
    assert.equal((await handle.query(observerQuery)).stage, "ISSUED");
    await handle.cancel();
  });
  assert.equal(published.length, 0);
});

test("workflow records an SLA breach without advancing the stage", async () => {
  const published: PublishRevocationEventInput[] = [];
  await withWorkflow("sla", { ...INPUT, examResultSlaSeconds: 30 }, published, async (handle) => {
    await handle.signal(examRegisteredSignal, { examId: "exam-1", provider: "nimasa-exam-centre" });
    await environment.sleep(35_000);
    const duringBreach = await handle.query(observerQuery);
    assert.equal(duringBreach.stage, "AWAITING_EXAM_RESULT");
    assert.deepEqual(duringBreach.slaBreachedStages, ["AWAITING_EXAM_RESULT"]);
    await handle.signal(examResultSignal, { examId: "exam-1", passed: true });
    const after = await handle.query(observerQuery);
    assert.equal(after.stage, "AWAITING_TRAINING_COMPLETION");
    assert.deepEqual(after.slaBreachedStages, ["AWAITING_EXAM_RESULT"]);
    await handle.cancel();
  });
});

test("revocation signal at any time publishes seafarer.revocation.v1 and closes the workflow", async () => {
  const published: PublishRevocationEventInput[] = [];
  await withWorkflow("revoke", INPUT, published, async (handle) => {
    await handle.signal(examRegisteredSignal, { examId: "exam-1", provider: "nimasa-exam-centre" });
    await handle.signal(revocationRequestedSignal, { reason: "fraudulent application", requestedBy: "nimasa-approver-01" });
    const result = await handle.result();
    assert.equal(result.stage, "REVOKED");
    assert.equal(result.revocationReason, "fraudulent application");
  });
  assert.equal(published.length, 1);
  assert.equal(published[0]?.reason, "fraudulent application");
  assert.equal(published[0]?.requestedBy, "nimasa-approver-01");
});
