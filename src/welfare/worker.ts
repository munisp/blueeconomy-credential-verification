import process from "node:process";
import { fileURLToPath } from "node:url";
import { NativeConnection, Worker } from "@temporalio/worker";
import { startTelemetry, temporalWorkerInterceptors } from "../telemetry/telemetry.js";
import { WELFARE_TASK_QUEUE_DEFAULT } from "./lifecycle.js";

/**
 * Temporal worker entrypoint for the crew-welfare module (the
 * `seafarer-welfare` task queue). Runs ComplaintWorkflow only — the workflow
 * is a pure SLA observer with no activities, so the worker needs no database,
 * ledger or key material. Fail-closed: a missing Temporal address aborts
 * startup; telemetry is guarded fail-open (phase-7 convention).
 */

async function main(): Promise<void> {
  const env = process.env;
  const telemetry = await startTelemetry({ env });
  const address = required(env, "BLUEECONOMY_TEMPORAL_ADDRESS");
  const taskQueue = env["BLUEECONOMY_WELFARE_TASK_QUEUE"] ?? WELFARE_TASK_QUEUE_DEFAULT;
  const namespace = env["BLUEECONOMY_TEMPORAL_NAMESPACE"] ?? "default";

  const connection = await NativeConnection.connect({ address });
  const interceptors = telemetry.enabled ? await temporalWorkerInterceptors() : undefined;
  const worker = await Worker.create({
    connection,
    namespace,
    taskQueue,
    workflowsPath: fileURLToPath(new URL("./workflow.js", import.meta.url)),
    ...(interceptors !== undefined ? { interceptors } : {}),
  });

  process.on("SIGINT", () => worker.shutdown());
  process.on("SIGTERM", () => worker.shutdown());
  process.stdout.write(`seafarer-welfare-worker polling ${taskQueue} (namespace ${namespace}) at ${address}\n`);
  try {
    await worker.run();
  } finally {
    await telemetry.shutdown();
  }
}

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (value === undefined || value.trim().length === 0) {
    throw new Error(`${name} is required (fail-closed)`);
  }
  return value;
}

if (process.argv[1] !== undefined && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  main().catch((error: unknown) => {
    process.stderr.write(`seafarer-welfare-worker startup failed: ${error instanceof Error ? error.message : "unknown"}\n`);
    process.exitCode = 1;
  });
}
