import { readFile } from "node:fs/promises";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { NativeConnection, Worker } from "@temporalio/worker";
import pg from "pg";
import { createIssuanceLedgerFromEnv } from "./ledger/issuance-ledger.js";
import { enqueueOutboxMessage } from "./status/postgres.js";
import { createLifecycleActivities } from "./temporal/activities.js";
import { loadIssuerPrivateKey } from "./vc/issuer.js";

/**
 * Temporal worker entrypoint (seafarer-credential-worker in the gitops
 * chart). Runs the SeafarerCredentialWorkflow lifecycle: registers the
 * workflow bundle plus the revocation activity whose side effects (issuance
 * ledger commit, signed platform envelope, transactional outbox row) must
 * not live in the workflow body. Every dependency is fail-closed: missing
 * Temporal address/task-queue, TigerBeetle cluster, status database or
 * issuer key material aborts startup instead of degrading.
 */

async function main(): Promise<void> {
  const env = process.env;
  const address = required(env, "BLUEECONOMY_TEMPORAL_ADDRESS");
  const taskQueue = required(env, "BLUEECONOMY_TEMPORAL_TASK_QUEUE");
  const namespace = env["BLUEECONOMY_TEMPORAL_NAMESPACE"] ?? "default";
  const producer = env["BLUEECONOMY_EVENT_PRODUCER"] ?? "blueeconomy-credential-verification";

  const privateKeyPemPath = required(env, "BLUEECONOMY_ISSUER_ED25519_PKCS8_PEM_PATH");
  const signingKey = loadIssuerPrivateKey(await readFile(privateKeyPemPath, "utf8"));
  const ledger = createIssuanceLedgerFromEnv(env);
  const databaseUrl = required(env, "BLUEECONOMY_STATUS_DATABASE_URL");
  const pool = new pg.Pool({ connectionString: databaseUrl, max: 4, connectionTimeoutMillis: 5_000 });

  const connection = await NativeConnection.connect({ address });
  const worker = await Worker.create({
    connection,
    namespace,
    taskQueue,
    workflowsPath: fileURLToPath(new URL("./temporal/workflows.js", import.meta.url)),
    activities: createLifecycleActivities({
      ledger,
      signingKey,
      producer,
      enqueue: (message) => enqueueOutboxMessage(pool, message),
    }),
  });

  process.on("SIGINT", () => worker.shutdown());
  process.on("SIGTERM", () => worker.shutdown());
  process.stdout.write(`seafarer-credential-worker polling ${taskQueue} (namespace ${namespace}) at ${address}\n`);
  try {
    await worker.run();
  } finally {
    await pool.end();
    await ledger.close();
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
    process.stderr.write(`seafarer-credential-worker startup failed: ${error instanceof Error ? error.message : "unknown"}\n`);
    process.exitCode = 1;
  });
}
