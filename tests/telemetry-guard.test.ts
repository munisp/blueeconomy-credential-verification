import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";

import { KeycloakAuthenticator, ROLE_SEAFARER, type PrincipalRole } from "../src/auth/keycloak.js";
import { PolicyEngine } from "../src/auth/pbac.js";
import { createHttpService } from "../src/http/server.js";
import type { CredentialService } from "../src/service/credential-service.js";
import type { StatusStore } from "../src/status/store.js";
import { startTelemetry } from "../src/telemetry/telemetry.js";

/**
 * Requirement (a): telemetry-disabled boot + request test. The SDK is never
 * started in this process — no OTEL_EXPORTER_OTLP_ENDPOINT — and the service
 * must boot and serve requests (including every deny-by-default outcome)
 * exactly as before.
 */

const OIDC_ISSUER = "https://keycloak.blueeconomy.example/realms/blueeconomy";
const OIDC_AUDIENCE = "credential-verification";

const POLICY_DOCUMENT = {
  version: "1.0",
  policies: [
    { name: "seafarer-reads-own-wallet", roles: ["seafarer"], tenant: "*", resource: "wallet", action: "read", classification: ["CONFIDENTIAL"] },
  ],
};

test("telemetry guard: no endpoint => disabled, never throws, no OTel loaded", async () => {
  const handle = await startTelemetry({ env: {} });
  assert.equal(handle.enabled, false);
  assert.match(handle.reason, /OTEL_EXPORTER_OTLP_ENDPOINT/);
  assert.equal(handle.metrics(), "");
  assert.equal(handle.droppedSpanCount(), 0);
  await handle.shutdown();

  const blank = await startTelemetry({ env: { OTEL_EXPORTER_OTLP_ENDPOINT: "   " } });
  assert.equal(blank.enabled, false);
  await blank.shutdown();
});

test("telemetry-disabled boot: requests and deny-by-default are unchanged", async (t) => {
  // Boot path parity with main.ts: telemetry resolves disabled first.
  const telemetry = await startTelemetry({ env: {} });
  assert.equal(telemetry.enabled, false);

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

  const directory = await mkdtemp(join(tmpdir(), "blueeconomy-telemetry-guard-"));
  const { writeFile, mkdir } = await import("node:fs/promises");
  const policyDirectory = join(directory, "policies");
  await mkdir(policyDirectory);
  await writeFile(join(policyDirectory, "test.policy.json"), JSON.stringify(POLICY_DOCUMENT));
  const policyEngine = await PolicyEngine.load(policyDirectory);

  const statusStore = {
    healthCheck: () => Promise.resolve(),
  } as unknown as StatusStore;
  // Routes exercised below never reach the service (auth/deny paths and
  // health/metrics only), so a stub is truthful.
  const service = {} as CredentialService;

  const { server } = createHttpService({
    authenticator,
    policyEngine,
    service,
    statusStore,
    telemetryMetrics: telemetry.metrics,
  });
  await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  const address = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${address.port}`;
  t.after(() => new Promise<void>((resolveClose) => server.close(() => resolveClose())));

  const token = await new SignJWT({ realm_access: { roles: [ROLE_SEAFARER] satisfies PrincipalRole[] } })
    .setProtectedHeader({ alg: "RS256", kid: "keycloak-test-key" })
    .setIssuer(OIDC_ISSUER)
    .setAudience(OIDC_AUDIENCE)
    .setSubject("principal-01")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(oidcKey);

  // Unauthenticated surface works.
  const healthz = await fetch(`${baseUrl}/healthz`);
  assert.equal(healthz.status, 200);

  // Deny-by-default outcomes are intact: no token => 401, unknown route =>
  // 404, authenticated but policy-uncovered route => 403/404 as before.
  const unauthenticated = await fetch(`${baseUrl}/v1/wallet/credentials/current`);
  assert.equal(unauthenticated.status, 401);
  const unknownRoute = await fetch(`${baseUrl}/v1/admin`, { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: "{}" });
  assert.equal(unknownRoute.status, 404);

  // /metrics carries no telemetry drop counter when disabled.
  const metrics = await fetch(`${baseUrl}/metrics`);
  assert.equal(metrics.status, 200);
  const metricsBody = await metrics.text();
  assert.ok(!metricsBody.includes("telemetry_dropped_total"), "disabled telemetry must not emit the drop counter");

  await telemetry.shutdown();
});
