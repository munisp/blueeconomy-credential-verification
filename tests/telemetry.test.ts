import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { context, trace } from "@opentelemetry/api";
import { InMemorySpanExporter } from "@opentelemetry/sdk-trace-base";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";

import { KeycloakAuthenticator, ROLE_EMPLOYER, ROLE_NIMASA_APPROVER, type PrincipalRole } from "../src/auth/keycloak.js";
import { PolicyEngine } from "../src/auth/pbac.js";
import { OutboxPublisher, type KafkaProducerLike, type OutboxRow } from "../src/events/outbox.js";
import { createHttpService } from "../src/http/server.js";
import { TigerBeetleIssuanceLedger, type TigerBeetleClientLike } from "../src/ledger/issuance-ledger.js";
import { CredentialService } from "../src/service/credential-service.js";
import { createJsonlTestStatusStore } from "../src/status/jsonl-test-store.js";
import type { SqlExecutor } from "../src/status/postgres.js";
import type { EligibilityGate } from "../src/temporal/eligibility-gate.js";
import { serviceTracer, withContext } from "../src/telemetry/spans.js";
import { startTelemetry, type TelemetryHandle } from "../src/telemetry/telemetry.js";
import { generateEphemeralIssuerKeyPair } from "../src/vc/issuer.js";

/**
 * Phase-7 OTel behavior tests. One NodeSDK (in-memory exporter seam) is
 * started for this whole process; node --test isolates each file in its own
 * subprocess, so the global provider never leaks across files.
 *
 *  (b) Kafka outbox carrier propagation round-trip.
 *  (c) TigerBeetle ledger-op span.
 *  (+) HTTP dispatch SERVER span: traceparent extraction, tenant.id
 *      attribution from the existing Keycloak claim, PBAC child span.
 *  (+) vc.issue / vc.verify manual decision-path spans.
 */

const ISSUER_DID = "did:web:credentials.nimasa.gov.ng";
const OIDC_ISSUER = "https://keycloak.blueeconomy.example/realms/blueeconomy";
const OIDC_AUDIENCE = "credential-verification";
const TENANT = "nimasa";

const exporter = new InMemorySpanExporter();
let telemetry: TelemetryHandle;

test.before(async () => {
  telemetry = await startTelemetry({
    env: { OTEL_EXPORTER_OTLP_ENDPOINT: "http://collector.invalid:4318" },
    spanExporter: exporter,
  });
  assert.equal(telemetry.enabled, true);
});

test.after(async () => {
  await telemetry.shutdown();
});

function spansNamed(name: string) {
  return exporter.getFinishedSpans().filter((span) => span.name === name);
}

/* ---------------------------------------------------------------- (b) --- */

test("(b) kafka outbox: traceparent carrier round-trip + producer span", async () => {
  const rows: OutboxRow[] = [
    { id: "1", topic: "seafarer.credential.v1", event_id: "evt-1", payload: { hello: "world" } },
    { id: "2", topic: "seafarer.credential.v1", event_id: "evt-2", payload: { hello: "again" } },
  ];
  const sent: Array<{ topic: string; messages: Array<{ key: string; value: string; headers?: Record<string, string> }> }> = [];
  const producer: KafkaProducerLike = {
    connect: () => Promise.resolve(),
    send: (batch) => {
      sent.push(batch);
      return Promise.resolve({});
    },
    disconnect: () => Promise.resolve(),
  };
  const queries: string[] = [];
  const executor: SqlExecutor = {
    query: <Row extends object>(text: string): Promise<{ rows: Row[] }> => {
      queries.push(text);
      if (text.includes("FROM credential_outbox")) return Promise.resolve({ rows: rows as unknown as Row[] });
      return Promise.resolve({ rows: [] as Row[] });
    },
  } as unknown as SqlExecutor;

  // Run inside a parent span: the injected traceparent must carry THIS
  // trace id, proving the carrier round-trips the active context.
  const parent = serviceTracer().startSpan("test.parent");
  const parentContext = trace.setSpan(context.active(), parent);
  const published = await withContext(parentContext, () => new OutboxPublisher(executor, producer).publishPending());
  parent.end();

  assert.equal(published, 2);
  assert.equal(sent.length, 1);
  const messages = sent[0]?.messages ?? [];
  assert.equal(messages.length, 2);
  const parentTraceId = parent.spanContext().traceId;
  for (const message of messages) {
    const traceparent = message.headers?.["traceparent"];
    assert.match(traceparent ?? "", /^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/, "traceparent header injected");
    assert.ok(traceparent?.includes(parentTraceId), "carrier trace id matches the publishing trace");
  }

  const publishSpans = spansNamed("outbox.publish seafarer.credential.v1");
  assert.equal(publishSpans.length, 1);
  assert.equal(publishSpans[0]?.spanContext().traceId, parentTraceId, "producer span joins the publishing trace");
  assert.equal(publishSpans[0]?.attributes["messaging.system"], "kafka");
  assert.equal(publishSpans[0]?.attributes["messaging.message_count"], 2);
});

/* ---------------------------------------------------------------- (c) --- */

test("(c) tigerbeetle ledger op: client-side span with operational attributes", async () => {
  const client: TigerBeetleClientLike = {
    createAccounts: () => Promise.resolve([]),
    createTransfers: () => Promise.resolve([]),
  };
  const ledger = new TigerBeetleIssuanceLedger({ clusterId: 0n, replicaAddresses: ["127.0.0.1:3000"], ledger: 1, client });

  const parent = serviceTracer().startSpan("test.ledger-parent");
  const commit = await withContext(trace.setSpan(context.active(), parent), () =>
    ledger.record({
      credentialId: "urn:uuid:11111111-2222-3333-4444-555555555555",
      holderReference: "holder-ref",
      issuer: ISSUER_DID,
      kind: "issuance",
      occurredAt: new Date().toISOString(),
    }));
  parent.end();

  assert.equal(commit.idempotentReplay, false);
  const ledgerSpans = spansNamed("tigerbeetle.record");
  assert.equal(ledgerSpans.length, 1);
  const ledgerSpan = ledgerSpans[0];
  assert.equal(ledgerSpan?.attributes["db.system"], "tigerbeetle");
  assert.equal(ledgerSpan?.attributes["ledger.entry.kind"], "issuance");
  assert.equal(ledgerSpan?.attributes["ledger.idempotent_replay"], false);
  assert.equal(typeof ledgerSpan?.attributes["ledger.transfer_id"], "string");
  assert.equal(ledgerSpan?.spanContext().traceId, parent.spanContext().traceId, "ledger span joins the caller trace");
  assert.equal(ledgerSpan?.parentSpanContext?.spanId, parent.spanContext().spanId, "ledger span is a child of the caller");
});

/* ------------------------------------------- HTTP dispatch + VC paths --- */

const POLICY_DOCUMENT = {
  version: "1.0",
  policies: [
    { name: "nimasa-approver-issues-credentials", roles: ["nimasa-approver"], tenant: "*", resource: "credential", action: "issue", classification: ["CONFIDENTIAL"] },
    { name: "verifiers-verify-credentials", roles: ["employer", "psc-inspector"], tenant: "*", resource: "credential", action: "verify", classification: ["CONFIDENTIAL"] },
  ],
};

const ISSUE_BODY = {
  workflowId: "wf-eligible",
  seafarerId: "seafarer-ng-0001",
  holderId: "did:web:wallet.seafarer.example:ng-0001",
  seafarerReferenceNumber: "NG-SRN-0001",
  capacity: "Officer in charge of a navigational watch",
  stcwRegulation: "STCW regulation II/1",
  limitations: [],
  validUntil: "2031-01-01T00:00:00.000Z",
};

test("HTTP dispatch span: traceparent extraction, tenant.id, PBAC child span; vc.issue + vc.verify spans", async (t) => {
  const { privateKey: oidcKey, publicKey: oidcPublic } = await generateKeyPair("RS256");
  const jwk = await exportJWK(oidcPublic);
  jwk.kid = "keycloak-test-key";
  jwk.alg = "RS256";
  jwk.use = "sig";
  const authenticator = new KeycloakAuthenticator({
    issuer: OIDC_ISSUER,
    audience: OIDC_AUDIENCE,
    roleClientIds: [],
    getKey: createLocalJWKSet({ keys: [jwk] }),
  });

  const directory = await mkdtemp(join(tmpdir(), "blueeconomy-telemetry-http-"));
  const { writeFile, mkdir } = await import("node:fs/promises");
  const policyDirectory = join(directory, "policies");
  await mkdir(policyDirectory);
  await writeFile(join(policyDirectory, "test.policy.json"), JSON.stringify(POLICY_DOCUMENT));
  const policyEngine = await PolicyEngine.load(policyDirectory);
  const statusStore = createJsonlTestStatusStore(join(directory, "status.jsonl"), {
    BLUEECONOMY_STATUS_JSONL_TEST_PATH: join(directory, "status.jsonl"),
    BLUEECONOMY_STATUS_ISSUER: ISSUER_DID,
  });
  const { privateKey: issuerKey } = generateEphemeralIssuerKeyPair();
  const eligibilityGate: EligibilityGate = {
    check: (workflowId, seafarerId) =>
      Promise.resolve({
        eligible: workflowId === "wf-eligible" && seafarerId === "seafarer-ng-0001",
        observation: {
          seafarerId,
          correlationId: "corr-0001",
          stage: workflowId === "wf-eligible" ? "ELIGIBLE" : "AWAITING_EXAM_RESULT",
          slaBreachedStages: [],
        },
      }),
  };
  let nextIndex = 0;
  const service = new CredentialService({
    issuer: {
      issuerDid: ISSUER_DID,
      verificationMethod: `${ISSUER_DID}#ed25519-key-1`,
      privateKey: issuerKey,
      statusListCredentialUrl: "https://credentials.nimasa.gov.ng/v1/status-list/main",
    },
    statusStore,
    approvals: statusStore,
    ledger: {
      record: () => Promise.resolve({ transferIdHex: "ab".repeat(16), commitHash: "c".repeat(64), idempotentReplay: false }),
      healthCheck: () => Promise.resolve(),
      close: () => Promise.resolve(),
    },
    eligibilityGate,
    producer: "blueeconomy-credential-verification",
    statusListId: "https://credentials.nimasa.gov.ng/v1/status-list/main",
    allocateStatusListIndex: () => Promise.resolve(nextIndex++),
  });

  const { server } = createHttpService({ authenticator, policyEngine, service, statusStore, telemetryMetrics: telemetry.metrics });
  await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  const address = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${address.port}`;
  t.after(async () => {
    await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
    await statusStore.close();
  });

  const token = (roles: PrincipalRole[], subject: string) =>
    new SignJWT({ realm_access: { roles }, tenant: TENANT })
      .setProtectedHeader({ alg: "RS256", kid: "keycloak-test-key" })
      .setIssuer(OIDC_ISSUER)
      .setAudience(OIDC_AUDIENCE)
      .setSubject(subject)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(oidcKey);

  // Inbound W3C traceparent (edge root) — the dispatch span must join it.
  const edgeTraceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
  const approver = await token([ROLE_NIMASA_APPROVER], "maker-01");
  const submitted = await fetch(`${baseUrl}/v1/credentials`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${approver}`, traceparent: edgeTraceparent },
    body: JSON.stringify(ISSUE_BODY),
  });
  assert.equal(submitted.status, 202);
  const pending = (await submitted.json()) as { requestId: string };

  const checker = await token([ROLE_NIMASA_APPROVER], "checker-02");
  const approved = await fetch(`${baseUrl}/v1/credentials/${pending.requestId}/approve`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${checker}` },
    body: "{}",
  });
  assert.equal(approved.status, 201);
  const issued = (await approved.json()) as { credential: unknown };

  const verifier = await token([ROLE_EMPLOYER], "employer-01");
  const verified = await fetch(`${baseUrl}/v1/verify`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${verifier}` },
    body: JSON.stringify({ credential: issued.credential, holderId: ISSUE_BODY.holderId }),
  });
  assert.equal(verified.status, 200);

  // Dispatch span: extracted parent, tenant.id, status, PBAC child span.
  const submitSpan = spansNamed("credential-api POST /v1/credentials").find(
    (span) => span.spanContext().traceId === "4bf92f3577b34da6a3ce929d0e0e4736",
  );
  assert.ok(submitSpan !== undefined, "dispatch span joins the inbound edge trace");
  assert.equal(submitSpan.attributes["tenant.id"], TENANT, "tenant.id attributed from the Keycloak claim");
  assert.equal(submitSpan.attributes["http.response.status_code"], 202);
  assert.equal(submitSpan.parentSpanContext?.spanId, "00f067aa0ba902b7", "dispatch span is a child of the edge span");

  const pbacSpans = spansNamed("pbac.evaluate");
  assert.ok(pbacSpans.length >= 3, "PBAC child span on each authenticated policy route");
  assert.ok(pbacSpans.every((span) => span.attributes["pbac.allowed"] === true));

  // Manual decision-path spans.
  const issueSpans = spansNamed("vc.issue");
  assert.equal(issueSpans.length, 1, "vc.issue span on the approval execution path");
  assert.equal(issueSpans[0]?.attributes["vc.stcw_regulation"], ISSUE_BODY.stcwRegulation);
  assert.equal(issueSpans[0]?.attributes["ledger.idempotent_replay"], false);

  const verifySpans = spansNamed("vc.verify");
  assert.equal(verifySpans.length, 1, "vc.verify span on the verification decision path");
  assert.equal(verifySpans[0]?.attributes["vc.verification.passed"], true);

  // Deny-by-default path still traced, still denied.
  const denied = await fetch(`${baseUrl}/v1/credentials`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${verifier}` },
    body: JSON.stringify(ISSUE_BODY),
  });
  assert.equal(denied.status, 403);
  const deniedSpan = spansNamed("credential-api POST /v1/credentials").find(
    (span) => span.attributes["http.response.status_code"] === 403,
  );
  assert.ok(deniedSpan !== undefined, "denied requests are traced with their 403 status");
});
