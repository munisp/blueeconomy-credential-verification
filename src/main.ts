import { readFile } from "node:fs/promises";
import process from "node:process";
import pg from "pg";
import { createAuthenticatorFromEnv } from "./auth/keycloak.js";
import { PolicyEngine } from "./auth/pbac.js";
import { createHttpService } from "./http/server.js";
import { createIssuanceLedgerFromEnv } from "./ledger/issuance-ledger.js";
import { CredentialService } from "./service/credential-service.js";
import { createStatusStoreFromEnv } from "./status/postgres.js";
import { createEligibilityGateFromEnv } from "./temporal/eligibility-gate.js";
import { assertIssuerDid, loadIssuerPrivateKey } from "./vc/issuer.js";
import { startTelemetry, temporalClientInterceptors } from "./telemetry/telemetry.js";
import { narrativeKeyFromEnv } from "./welfare/confidentiality.js";
import { TemporalComplaintLifecycle } from "./welfare/lifecycle.js";
import { loadWelfarePolicyFromEnv } from "./welfare/policy.js";
import { PgWelfareStore } from "./welfare/postgres.js";
import { welfareRoutes } from "./welfare/routes.js";
import { WelfareService } from "./welfare/service.js";

/**
 * Production entrypoint. Every dependency is fail-closed: missing status DSN,
 * TigerBeetle cluster, Temporal address, OIDC configuration or issuer key
 * material aborts startup instead of degrading to an insecure mode.
 */

async function main(): Promise<void> {
  const env = process.env;
  // Phase-7 OTel: guarded fail-open — no OTEL_EXPORTER_OTLP_ENDPOINT means
  // telemetry disabled and zero OTel modules loaded; boot is unaffected.
  const telemetry = await startTelemetry({ env });
  const issuerDid = assertIssuerDid(required(env, "BLUEECONOMY_ISSUER_DID"));
  const verificationMethod = env["BLUEECONOMY_ISSUER_VERIFICATION_METHOD"] ?? `${issuerDid}#ed25519-key-1`;
  const privateKeyPemPath = required(env, "BLUEECONOMY_ISSUER_ED25519_PKCS8_PEM_PATH");
  const privateKey = loadIssuerPrivateKey(await readFile(privateKeyPemPath, "utf8"));
  const statusListId = required(env, "BLUEECONOMY_STATUS_LIST_URL");
  const producer = env["BLUEECONOMY_EVENT_PRODUCER"] ?? "blueeconomy-credential-verification";
  const port = Number.parseInt(env["PORT"] ?? "8080", 10);
  if (!Number.isInteger(port) || port <= 0 || port > 65_535) throw new Error("PORT must be a valid TCP port");

  const statusStore = await createStatusStoreFromEnv(env);
  const ledger = createIssuanceLedgerFromEnv(env);
  const eligibilityGate = telemetry.enabled
    ? await createEligibilityGateFromEnv(env, { interceptors: (await temporalClientInterceptors()) ?? {} })
    : await createEligibilityGateFromEnv(env);
  const authenticator = createAuthenticatorFromEnv(env);
  // Deny-by-default PBAC, loaded fail-closed from POLICY_DIR before listening.
  const policyEngine = await PolicyEngine.fromEnv(env);
  const service = new CredentialService({
    issuer: { issuerDid, verificationMethod, privateKey, statusListCredentialUrl: statusListId },
    statusStore,
    // Maker/checker pending-approval ledger (migration 0005), served by the
    // same durable store as the credential status registry.
    approvals: statusStore,
    ledger,
    eligibilityGate,
    producer,
    statusListId,
    // Durable per-list allocation (restart- and replica-safe), replacing the
    // retired in-process BLUEECONOMY_STATUS_LIST_INDEX_START counter.
    allocateStatusListIndex: () => statusStore.allocateStatusListIndex(statusListId),
  });

  // ---------------------------------------------------------------------
  // Phase-8 Crew Welfare / MLC module (bounded: src/welfare/*). The signed
  // welfare-policy document selects the Reg 2.3 regime and complaint SLA
  // budgets; until it is deployed, complaint/rest mutation endpoints answer
  // 503-honest (directory and referral surfaces still serve).
  // ---------------------------------------------------------------------
  const welfarePolicyResult = await loadWelfarePolicyFromEnv(env);
  const welfarePool = new pg.Pool({ connectionString: required(env, "BLUEECONOMY_STATUS_DATABASE_URL"), max: 4, connectionTimeoutMillis: 5_000 });
  const welfareStore = new PgWelfareStore({ executor: welfarePool, ownsExecutor: () => welfarePool.end() });
  const welfareLifecycle = telemetry.enabled
    ? await TemporalComplaintLifecycle.create(env, { interceptors: (await temporalClientInterceptors()) ?? {} })
    : await TemporalComplaintLifecycle.create(env);
  const welfareService = new WelfareService({
    store: welfareStore,
    policy: welfarePolicyResult.configured ? welfarePolicyResult.policy : undefined,
    ...(welfarePolicyResult.configured ? {} : { policyUnavailableReason: welfarePolicyResult.reason }),
    narrativeKey: narrativeKeyFromEnv(env),
    signing: {
      privateKey,
      keyId: env["BLUEECONOMY_WELFARE_SIGNING_KID"] ?? `${producer}-1`,
    },
    producer,
    identity: {
      // seafarerReferenceNumber VC identity binding (repo convention): the
      // complaint binds to the caller's current CoC credential subject claim.
      referenceFor: async (subject) => {
        const credentials = await statusStore.listCurrentHolderCredentials(subject, issuerDid);
        for (const credential of credentials) {
          const subjectClaims = credential.document["credentialSubject"];
          if (typeof subjectClaims === "object" && subjectClaims !== null) {
            const reference = (subjectClaims as Record<string, unknown>)["seafarerReferenceNumber"];
            if (typeof reference === "string" && reference.trim() === reference && reference.length > 0) return reference;
          }
        }
        return undefined;
      },
    },
    lifecycle: welfareLifecycle,
    curationContact: env["BLUEECONOMY_WELFARE_CURATION_CONTACT"] ?? "NIMASA welfare desk (directory curation pending)",
  });
  if (!welfarePolicyResult.configured) {
    process.stdout.write(`welfare: ${welfarePolicyResult.reason}\n`);
  }

  const { server } = createHttpService({
    authenticator,
    policyEngine,
    service,
    statusStore,
    telemetryMetrics: telemetry.metrics,
    additionalRoutes: (metrics) => welfareRoutes(welfareService, metrics),
  });
  await new Promise<void>((resolveListen) => server.listen(port, resolveListen));
  process.stdout.write(`credential-verification listening on :${port}\n`);
  // Graceful telemetry flush (5 s ceiling inside shutdown) on stop signals.
  const flushTelemetry = (): void => {
    void telemetry.shutdown();
  };
  process.on("SIGINT", flushTelemetry);
  process.on("SIGTERM", flushTelemetry);
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
    process.stderr.write(`credential-verification startup failed: ${error instanceof Error ? error.message : "unknown"}\n`);
    process.exitCode = 1;
  });
}
