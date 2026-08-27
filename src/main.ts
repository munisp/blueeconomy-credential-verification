import { readFile } from "node:fs/promises";
import process from "node:process";
import { createAuthenticatorFromEnv } from "./auth/keycloak.js";
import { createHttpService } from "./http/server.js";
import { createIssuanceLedgerFromEnv } from "./ledger/issuance-ledger.js";
import { CredentialService } from "./service/credential-service.js";
import { createStatusStoreFromEnv } from "./status/postgres.js";
import { createEligibilityGateFromEnv } from "./temporal/eligibility-gate.js";
import { assertIssuerDid, loadIssuerPrivateKey } from "./vc/issuer.js";

/**
 * Production entrypoint. Every dependency is fail-closed: missing status DSN,
 * TigerBeetle cluster, Temporal address, OIDC configuration or issuer key
 * material aborts startup instead of degrading to an insecure mode.
 */

async function main(): Promise<void> {
  const env = process.env;
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
  const eligibilityGate = await createEligibilityGateFromEnv(env);
  const authenticator = createAuthenticatorFromEnv(env);
  let nextIndex = Number.parseInt(env["BLUEECONOMY_STATUS_LIST_INDEX_START"] ?? "0", 10);
  const service = new CredentialService({
    issuer: { issuerDid, verificationMethod, privateKey, statusListCredentialUrl: statusListId },
    statusStore,
    ledger,
    eligibilityGate,
    producer,
    statusListId,
    allocateStatusListIndex: () => nextIndex++,
  });
  const { server } = createHttpService({ authenticator, service, statusStore });
  await new Promise<void>((resolveListen) => server.listen(port, resolveListen));
  process.stdout.write(`credential-verification listening on :${port}\n`);
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
