import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from "jose";

import { KeycloakAuthenticator, authorizeRequest, AuthorizationError, ROLE_AUDITOR, ROLE_EMPLOYER, ROLE_NIMASA_APPROVER, ROLE_PSC_INSPECTOR, ROLE_SEAFARER, type PrincipalRole } from "../src/auth/keycloak.js";
import { createHttpService } from "../src/http/server.js";
import { CredentialService } from "../src/service/credential-service.js";
import { PolicyEngine } from "../src/auth/pbac.js";
import { createJsonlTestStatusStore } from "../src/status/jsonl-test-store.js";
import { generateEphemeralIssuerKeyPair } from "../src/vc/issuer.js";
import type { EligibilityGate } from "../src/temporal/eligibility-gate.js";
import type { IssuanceLedger } from "../src/ledger/issuance-ledger.js";
import type { StatusStore } from "../src/status/store.js";

const ISSUER_DID = "did:web:credentials.nimasa.gov.ng";
const OIDC_ISSUER = "https://keycloak.blueeconomy.example/realms/blueeconomy";
const OIDC_AUDIENCE = "credential-verification";

interface Harness {
  baseUrl: string;
  close(): Promise<void>;
  token(roles: PrincipalRole[], subject?: string): Promise<string>;
}

const POLICY_DOCUMENT = {
  version: "1.0",
  policies: [
    { name: "nimasa-approver-issues-credentials", roles: ["nimasa-approver"], tenant: "*", resource: "credential", action: "issue", classification: ["CONFIDENTIAL"] },
    { name: "nimasa-approver-revokes-credentials", roles: ["nimasa-approver"], tenant: "*", resource: "credential", action: "revoke", classification: ["CONFIDENTIAL"] },
    { name: "verifiers-verify-credentials", roles: ["employer", "psc-inspector"], tenant: "*", resource: "credential", action: "verify", classification: ["CONFIDENTIAL"] },
    { name: "seafarer-reads-own-wallet", roles: ["seafarer"], tenant: "*", resource: "wallet", action: "read", classification: ["CONFIDENTIAL"] },
    { name: "authenticated-roles-read-status-list", roles: ["nimasa-approver", "employer", "psc-inspector", "auditor", "seafarer"], tenant: "*", resource: "status-list", action: "read", classification: ["CONFIDENTIAL"] },
  ],
};

async function startHarness(options: { policyDocument?: Record<string, unknown> } = {}): Promise<Harness> {
  const { privateKey: oidcKey, publicKey: oidcPublic } = await generateKeyPair("RS256");
  const jwk = await exportJWK(oidcPublic);
  jwk.kid = "keycloak-test-key";
  jwk.alg = "RS256";
  jwk.use = "sig";
  const authenticator = new KeycloakAuthenticator({
    issuer: OIDC_ISSUER,
    audience: OIDC_AUDIENCE,
    roleClientIds: ["credential-api"],
    getKey: createLocalJWKSet({ keys: [jwk] }),
  });

  const directory = await mkdtemp(join(tmpdir(), "blueeconomy-http-"));
  const { writeFile, mkdir } = await import("node:fs/promises");
  const policyDirectory = join(directory, "policies");
  await mkdir(policyDirectory);
  await writeFile(join(policyDirectory, "test.policy.json"), JSON.stringify(options.policyDocument ?? POLICY_DOCUMENT));
  const policyEngine = await PolicyEngine.load(policyDirectory);
  const statusStore: StatusStore = createJsonlTestStatusStore(join(directory, "status.jsonl"), {
    BLUEECONOMY_STATUS_JSONL_TEST_PATH: join(directory, "status.jsonl"),
    BLUEECONOMY_STATUS_ISSUER: ISSUER_DID,
  });
  const { privateKey: issuerKey } = generateEphemeralIssuerKeyPair();
  const ledger: IssuanceLedger = {
    async record(entry) {
      return {
        transferIdHex: "ab".repeat(16),
        commitHash: "c".repeat(64),
        idempotentReplay: false,
      };
    },
    async healthCheck() {},
    async close() {},
  };
  const eligibilityGate: EligibilityGate = {
    async check(workflowId, seafarerId) {
      return {
        eligible: workflowId === "wf-eligible" && seafarerId === "seafarer-ng-0001",
        observation: {
          seafarerId,
          correlationId: "corr-0001",
          stage: workflowId === "wf-eligible" ? "ELIGIBLE" : "AWAITING_EXAM_RESULT",
          slaBreachedStages: [],
        },
      };
    },
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
    ledger,
    eligibilityGate,
    producer: "blueeconomy-credential-verification",
    statusListId: "https://credentials.nimasa.gov.ng/v1/status-list/main",
    allocateStatusListIndex: async () => nextIndex++,
  });

  const { server } = createHttpService({ authenticator, policyEngine, service, statusStore });
  await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  const address = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    async close() {
      await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
      await statusStore.close();
    },
    async token(roles: PrincipalRole[], subject = "principal-01") {
      return new SignJWT({ realm_access: { roles } })
        .setProtectedHeader({ alg: "RS256", kid: "keycloak-test-key" })
        .setIssuer(OIDC_ISSUER)
        .setAudience(OIDC_AUDIENCE)
        .setSubject(subject)
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(oidcKey);
    },
  };
}

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

async function post(baseUrl: string, path: string, body: unknown, token?: string) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token !== undefined ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() as Record<string, unknown> };
}

async function get(baseUrl: string, path: string, token?: string) {
  const response = await fetch(`${baseUrl}${path}`, {
    headers: token !== undefined ? { authorization: `Bearer ${token}` } : {},
  });
  const contentType = response.headers.get("content-type") ?? "";
  const body = contentType.includes("application/json") ? await response.json() : await response.text();
  return { status: response.status, body: body as Record<string, unknown> };
}

test("issuer and verifier HTTP surface with role matrix", async (t) => {
  const harness = await startHarness();
  t.after(() => harness.close());

  await t.test("healthz and readyz are unauthenticated", async () => {
    assert.equal((await get(harness.baseUrl, "/healthz")).status, 200);
    assert.equal((await get(harness.baseUrl, "/readyz")).status, 200);
    const metrics = await get(harness.baseUrl, "/metrics");
    assert.equal(metrics.status, 200);
  });

  await t.test("requests without a token are rejected", async () => {
    assert.equal((await post(harness.baseUrl, "/v1/credentials", ISSUE_BODY)).status, 401);
    assert.equal((await post(harness.baseUrl, "/v1/verify", {})).status, 401);
    assert.equal((await get(harness.baseUrl, "/v1/status-list/main")).status, 401);
  });

  await t.test("unknown routes are denied by default", async () => {
    const token = await harness.token([ROLE_NIMASA_APPROVER]);
    assert.equal((await post(harness.baseUrl, "/v1/admin", {}, token)).status, 404);
  });

  await t.test("employer and psc-inspector cannot issue", async () => {
    for (const role of [ROLE_EMPLOYER, ROLE_PSC_INSPECTOR] as const) {
      const token = await harness.token([role]);
      assert.equal((await post(harness.baseUrl, "/v1/credentials", ISSUE_BODY, token)).status, 403);
    }
  });

  await t.test("auditor is read-only and denied every mutation", async () => {
    const token = await harness.token([ROLE_AUDITOR]);
    assert.equal((await post(harness.baseUrl, "/v1/credentials", ISSUE_BODY, token)).status, 403);
    assert.equal((await post(harness.baseUrl, "/v1/revoke", { credentialId: "x", holderId: "y", reason: "z" }, token)).status, 403);
  });

  await t.test("token without approved roles is denied", async () => {
    const token = await harness.token([]);
    assert.equal((await get(harness.baseUrl, "/v1/status-list/main", token)).status, 403);
  });

  let issuedCredential: unknown;
  let issuedCredentialId = "";

  await t.test("nimasa-approver issues a gated credential", async () => {
    const token = await harness.token([ROLE_NIMASA_APPROVER]);
    const blocked = await post(harness.baseUrl, "/v1/credentials", { ...ISSUE_BODY, workflowId: "wf-not-eligible" }, token);
    assert.equal(blocked.status, 409, "issuance before credential-eligibility must be refused");
    const issued = await post(harness.baseUrl, "/v1/credentials", ISSUE_BODY, token);
    assert.equal(issued.status, 201);
    const credential = issued.body["credential"] as Record<string, unknown>;
    assert.deepEqual(credential["@context"], ["https://www.w3.org/ns/credentials/v2"]);
    assert.deepEqual(credential["type"], ["VerifiableCredential", "SeafarerCoC"]);
    assert.equal(credential["issuer"], ISSUER_DID);
    const proof = credential["proof"] as Record<string, unknown>;
    assert.equal(proof["cryptosuite"], "eddsa-jcs-2022");
    issuedCredential = credential;
    issuedCredentialId = String(credential["id"]);
  });

  await t.test("employer verifies the issued credential online via the service", async () => {
    const token = await harness.token([ROLE_EMPLOYER]);
    const verified = await post(harness.baseUrl, "/v1/verify", { credential: issuedCredential, holderId: ISSUE_BODY.holderId }, token);
    assert.equal(verified.status, 200);
    assert.equal((verified.body as Record<string, unknown>)["credentialId"], issuedCredentialId);
  });

  await t.test("nimasa-approver revokes and verification then fails closed", async () => {
    const approver = await harness.token([ROLE_NIMASA_APPROVER]);
    const revoked = await post(harness.baseUrl, "/v1/revoke", {
      credentialId: issuedCredentialId,
      holderId: ISSUE_BODY.holderId,
      reason: "certificate withdrawn",
    }, approver);
    assert.equal(revoked.status, 200);
    const employer = await harness.token([ROLE_PSC_INSPECTOR]);
    const verified = await post(harness.baseUrl, "/v1/verify", { credential: issuedCredential, holderId: ISSUE_BODY.holderId }, employer);
    assert.equal(verified.status, 422);
    assert.match(String((verified.body as Record<string, unknown>)["error"]), /revoked/);
  });

  await t.test("revocation is terminal: re-issuance and double revocation are refused", async () => {
    const approver = await harness.token([ROLE_NIMASA_APPROVER]);
    const reissued = await post(harness.baseUrl, "/v1/credentials", ISSUE_BODY, approver);
    assert.equal(reissued.status, 409, "re-issuing a revoked credential must be refused");
    assert.match(String(reissued.body["error"]), /revocation is terminal/);
    const revokedAgain = await post(harness.baseUrl, "/v1/revoke", {
      credentialId: issuedCredentialId,
      holderId: ISSUE_BODY.holderId,
      reason: "duplicate revocation",
    }, approver);
    assert.equal(revokedAgain.status, 409, "revoking an already-revoked credential must be refused");
    assert.match(String(revokedAgain.body["error"]), /already revoked/);
  });

  await t.test("auditor reads the signed status list", async () => {
    const token = await harness.token([ROLE_AUDITOR]);
    const statusList = await get(harness.baseUrl, "/v1/status-list/main", token);
    assert.equal(statusList.status, 200);
    assert.deepEqual((statusList.body as Record<string, unknown>)["type"], ["VerifiableCredential", "BitstringStatusListCredential"]);
    assert.ok((statusList.body as Record<string, unknown>)["proof"] !== undefined);
  });
});

test("wallet, issuer-key and status-list-id contract for the mobile app", async (t) => {
  const harness = await startHarness();
  t.after(() => harness.close());

  const holderSubject = "principal-01";
  let credentialId = "";

  await t.test("status-list route rejects unknown ids fail-closed", async () => {
    const token = await harness.token([ROLE_AUDITOR]);
    const missing = await get(harness.baseUrl, "/v1/status-list/bogus", token);
    assert.equal(missing.status, 404);
    const known = await get(harness.baseUrl, "/v1/status-list/main", token);
    assert.equal(known.status, 200);
  });

  await t.test("wallet endpoint requires the seafarer role", async () => {
    assert.equal((await get(harness.baseUrl, "/v1/wallet/credentials/current")).status, 401);
    const employer = await harness.token([ROLE_EMPLOYER]);
    assert.equal((await get(harness.baseUrl, "/v1/wallet/credentials/current", employer)).status, 403);
  });

  await t.test("wallet endpoint 404s before the holder has any credential", async () => {
    const seafarer = await harness.token([ROLE_SEAFARER], holderSubject);
    assert.equal((await get(harness.baseUrl, "/v1/wallet/credentials/current", seafarer)).status, 404);
  });

  await t.test("holder fetches exactly the issued credential document", async () => {
    const approver = await harness.token([ROLE_NIMASA_APPROVER]);
    const issued = await post(harness.baseUrl, "/v1/credentials", { ...ISSUE_BODY, holderId: holderSubject }, approver);
    assert.equal(issued.status, 201);
    const credential = issued.body["credential"] as Record<string, unknown>;
    credentialId = String(credential["id"]);

    const seafarer = await harness.token([ROLE_SEAFARER], holderSubject);
    const wallet = await get(harness.baseUrl, "/v1/wallet/credentials/current", seafarer);
    assert.equal(wallet.status, 200);
    // The mobile fetcher parses the body directly as the VC document.
    assert.equal(wallet.body["id"], credentialId);
    assert.equal(wallet.body["issuer"], ISSUER_DID);
    assert.equal((wallet.body["credentialSubject"] as Record<string, unknown>)["id"], holderSubject);
    assert.ok(wallet.body["proof"] !== undefined);

    const otherHolder = await harness.token([ROLE_SEAFARER], "principal-02");
    assert.equal((await get(harness.baseUrl, "/v1/wallet/credentials/current", otherHolder)).status, 404);
  });

  await t.test("revoked credentials disappear from the wallet surface", async () => {
    const approver = await harness.token([ROLE_NIMASA_APPROVER]);
    const revoked = await post(harness.baseUrl, "/v1/revoke", {
      credentialId,
      holderId: holderSubject,
      reason: "certificate withdrawn",
    }, approver);
    assert.equal(revoked.status, 200);
    const seafarer = await harness.token([ROLE_SEAFARER], holderSubject);
    assert.equal((await get(harness.baseUrl, "/v1/wallet/credentials/current", seafarer)).status, 404);
  });

  await t.test("issuer key endpoint is public and serves the Ed25519 key", async () => {
    const key = await get(harness.baseUrl, `/v1/issuers/${encodeURIComponent(ISSUER_DID)}/key`);
    assert.equal(key.status, 200);
    assert.equal(key.body["issuer"], ISSUER_DID);
    assert.equal(key.body["kid"], `${ISSUER_DID}#ed25519-key-1`);
    assert.match(String(key.body["public_key_hex"]), /^[0-9a-f]{64}$/);
    const unknown = await get(harness.baseUrl, `/v1/issuers/${encodeURIComponent("did:web:unknown.example")}/key`);
    assert.equal(unknown.status, 404);
  });
});

test("authorizeRequest enforces the role matrix fail-closed", () => {
  assert.throws(() => authorizeRequest("GET", new Set(), [ROLE_AUDITOR]), AuthorizationError);
  assert.throws(() => authorizeRequest("POST", new Set([ROLE_AUDITOR]), [ROLE_AUDITOR]), AuthorizationError);
  authorizeRequest("GET", new Set([ROLE_AUDITOR]), [ROLE_AUDITOR]);
  assert.throws(() => authorizeRequest("POST", new Set([ROLE_EMPLOYER]), [ROLE_NIMASA_APPROVER]), AuthorizationError);
  authorizeRequest("POST", new Set([ROLE_NIMASA_APPROVER]), [ROLE_NIMASA_APPROVER]);
  authorizeRequest("POST", new Set([ROLE_PSC_INSPECTOR]), [ROLE_EMPLOYER, ROLE_PSC_INSPECTOR]);
});

test("PBAC middleware denies routes without a matching allow-rule", async (t) => {
  // Policy document identical to the baseline but WITHOUT the wallet and
  // status-list rules: the static role table still admits these callers, so
  // any denial is attributable to the policy engine (deny-by-default).
  const restrictive = {
    version: "1.0",
    policies: [
      { name: "nimasa-approver-issues-credentials", roles: ["nimasa-approver"], tenant: "*", resource: "credential", action: "issue", classification: ["CONFIDENTIAL"] },
      { name: "nimasa-approver-revokes-credentials", roles: ["nimasa-approver"], tenant: "*", resource: "credential", action: "revoke", classification: ["CONFIDENTIAL"] },
      { name: "verifiers-verify-credentials", roles: ["employer", "psc-inspector"], tenant: "*", resource: "credential", action: "verify", classification: ["CONFIDENTIAL"] },
    ],
  };
  const harness = await startHarness({ policyDocument: restrictive });
  t.after(() => harness.close());

  const seafarer = await harness.token([ROLE_SEAFARER]);
  const wallet = await get(harness.baseUrl, "/v1/wallet/credentials/current", seafarer);
  assert.equal(wallet.status, 403, "policy engine must deny the wallet route without an allow-rule");
  assert.match(String(wallet.body["error"]), /denied by policy/);

  const auditor = await harness.token([ROLE_AUDITOR]);
  const statusList = await get(harness.baseUrl, "/v1/status-list/main", auditor);
  assert.equal(statusList.status, 403, "policy engine must deny the status-list route without an allow-rule");

  // Routes whose rules remain continue to work (allow rules still apply).
  const approver = await harness.token([ROLE_NIMASA_APPROVER]);
  const blocked = await post(harness.baseUrl, "/v1/credentials", { ...ISSUE_BODY, workflowId: "wf-not-eligible" }, approver);
  assert.equal(blocked.status, 409, "an allowed route still reaches the service layer");
});
