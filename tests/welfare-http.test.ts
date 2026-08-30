import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, writeFile, mkdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { AddressInfo } from "node:net";
import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from "jose";

import { KeycloakAuthenticator, type PrincipalRole } from "../src/auth/keycloak.js";
import { PolicyEngine } from "../src/auth/pbac.js";
import { createHttpService } from "../src/http/server.js";
import { CredentialService } from "../src/service/credential-service.js";
import { createJsonlTestStatusStore } from "../src/status/jsonl-test-store.js";
import { generateEphemeralIssuerKeyPair } from "../src/vc/issuer.js";
import type { EligibilityGate } from "../src/temporal/eligibility-gate.js";
import type { IssuanceLedger } from "../src/ledger/issuance-ledger.js";
import { NarrativeKey } from "../src/welfare/confidentiality.js";
import { InMemoryComplaintLifecycle } from "../src/welfare/lifecycle.js";
import { welfareRoutes } from "../src/welfare/routes.js";
import { WelfareService } from "../src/welfare/service.js";
import type { WelfarePolicy } from "../src/welfare/policy.js";
import { InMemoryWelfareStore } from "./welfare-fakes.js";

/**
 * HTTP surface tests for the 15 crew-welfare routes: real HTTP server, real
 * Keycloak JWT authentication (local JWKS), real PBAC policy engine loaded
 * from the shipped policy document. The welfare store is the shared in-memory
 * double; PostgreSQL enforcement is covered by tests/welfare-postgres.test.ts.
 */

const ISSUER_DID = "did:web:credentials.nimasa.gov.ng";
const OIDC_ISSUER = "https://keycloak.blueeconomy.example/realms/blueeconomy";
const OIDC_AUDIENCE = "credential-verification";

const POLICY: WelfarePolicy = {
  claims: {
    schema_version: "blueeconomy.welfare.policy.v1",
    policy_version: "ng-mlc-2026.1",
    regime: "min_rest",
    complaint_sla_seconds: { ack: 3_600, onboard_process: 86_400, escalation: 172_800, resolution: 604_800 },
    issued_by: "nimasa-welfare-desk",
    effective_at: "2026-08-01T00:00:00.000Z",
  },
  keyId: "blueeconomy-credential-verification-1",
};

interface Harness {
  baseUrl: string;
  store: InMemoryWelfareStore;
  close(): Promise<void>;
  token(roles: PrincipalRole[], subject?: string): Promise<string>;
  call(method: string, path: string, options?: { roles?: PrincipalRole[]; subject?: string; body?: unknown; idempotencyKey?: string; token?: string }): Promise<{ status: number; body: any }>;
}

async function startHarness(options: { stripWelfarePolicies?: boolean } = {}): Promise<Harness> {
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

  const directory = await mkdtemp(join(tmpdir(), "blueeconomy-welfare-http-"));
  const policyDirectory = join(directory, "policies");
  await mkdir(policyDirectory);
  // Load the shipped policy document; optionally strip welfare policies to
  // prove PBAC denial is real and not vacuous.
  const shippedPath = fileURLToPath(new URL("../policies/credential-verification.policy.json", import.meta.url));
  const shipped = JSON.parse(await readFile(shippedPath, "utf8")) as { policies: Array<{ resource: string }> };
  const policies = options.stripWelfarePolicies
    ? shipped.policies.filter((policy) => !["welfare-directory", "complaint", "referral", "rest-hours"].includes(policy.resource))
    : shipped.policies;
  await writeFile(join(policyDirectory, "test.policy.json"), JSON.stringify({ version: "1.0", policies }));
  const policyEngine = await PolicyEngine.load(policyDirectory);

  const statusStore = createJsonlTestStatusStore(join(directory, "status.jsonl"), {
    BLUEECONOMY_STATUS_JSONL_TEST_PATH: join(directory, "status.jsonl"),
    BLUEECONOMY_STATUS_ISSUER: ISSUER_DID,
  });
  const { privateKey: issuerKey } = generateEphemeralIssuerKeyPair();
  const ledger: IssuanceLedger = {
    async record() {
      return { transferIdHex: "ab".repeat(16), commitHash: "c".repeat(64), idempotentReplay: false };
    },
    async healthCheck() {},
    async close() {},
  };
  const eligibilityGate: EligibilityGate = {
    async check(_workflowId, seafarerId) {
      return { eligible: false, observation: { seafarerId, correlationId: "corr", stage: "AWAITING_EXAM_RESULT", slaBreachedStages: [] } };
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
    approvals: statusStore,
    ledger,
    eligibilityGate,
    producer: "blueeconomy-credential-verification",
    statusListId: "https://credentials.nimasa.gov.ng/v1/status-list/main",
    allocateStatusListIndex: async () => nextIndex++,
  });

  const store = new InMemoryWelfareStore();
  const lifecycle = new InMemoryComplaintLifecycle();
  const welfareService = new WelfareService({
    store,
    policy: POLICY,
    narrativeKey: NarrativeKey.fromHex("d".repeat(64)),
    signing: { privateKey: generateEphemeralIssuerKeyPair().privateKey, keyId: "blueeconomy-credential-verification-1" },
    producer: "blueeconomy-credential-verification",
    identity: { referenceFor: async (subject) => (subject === "seafarer-01" ? "NG-SRN-0001" : undefined) },
    lifecycle,
    curationContact: "welfare-desk@example.test",
  });

  const { server } = createHttpService({
    authenticator,
    policyEngine,
    service,
    statusStore,
    additionalRoutes: (metrics) => welfareRoutes(welfareService, metrics),
  });
  await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  const address = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${address.port}`;

  async function mint(roles: PrincipalRole[], subject: string): Promise<string> {
    return new SignJWT({ realm_access: { roles } })
      .setProtectedHeader({ alg: "RS256", kid: "keycloak-test-key" })
      .setIssuer(OIDC_ISSUER)
      .setAudience(OIDC_AUDIENCE)
      .setSubject(subject)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(oidcKey);
  }

  return {
    baseUrl,
    store,
    async close() {
      await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
      await statusStore.close();
    },
    token: (roles, subject = "principal-01") => mint(roles, subject),
    async call(method, path, callOptions = {}) {
      const headers: Record<string, string> = { "content-type": "application/json" };
      const token = callOptions.token ?? (callOptions.roles !== undefined ? await mint(callOptions.roles, callOptions.subject ?? "principal-01") : undefined);
      if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
      if (callOptions.idempotencyKey !== undefined) headers["idempotency-key"] = callOptions.idempotencyKey;
      const response = await fetch(`${baseUrl}${path}`, {
        method,
        headers,
        ...(callOptions.body !== undefined ? { body: JSON.stringify(callOptions.body) } : {}),
      });
      return { status: response.status, body: await response.json().catch(() => null) };
    },
  };
}

const SEAFARER: PrincipalRole[] = ["seafarer"];
const OFFICER: PrincipalRole[] = ["nimasa-labour-officer"];
const OPERATOR: PrincipalRole[] = ["operator"];
const INSPECTOR: PrincipalRole[] = ["nimasa-inspector"];

function complaintBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    channel: "onboard_r515",
    vesselRef: "NG-LKJ-0001",
    category: "wages",
    narrative: "Wages unpaid for three months.",
    attachments: [],
    rightToRedressNoticeAck: true,
    ...overrides,
  };
}

async function submitComplaint(h: Harness, key = "idem-http-c1") {
  return h.call("POST", "/v1/welfare/complaints", { roles: SEAFARER, subject: "seafarer-01", body: complaintBody(), idempotencyKey: key });
}

test("welfare routes require authentication", async () => {
  const h = await startHarness();
  try {
    const response = await h.call("GET", "/v1/welfare/providers");
    assert.equal(response.status, 401);
  } finally {
    await h.close();
  }
});

test("directory: honest empty state, curation is officer-only, reads are role-gated", async () => {
  const h = await startHarness();
  try {
    const empty = await h.call("GET", "/v1/welfare/providers", { roles: SEAFARER, subject: "seafarer-01" });
    assert.equal(empty.status, 200);
    assert.equal(empty.body.providers.length, 0);
    assert.equal(empty.body.empty.curationContact, "welfare-desk@example.test");

    const badPort = await h.call("GET", "/v1/welfare/providers?port_code=lagos", { roles: SEAFARER, subject: "seafarer-01" });
    assert.equal(badPort.status, 400, "port_code must be UN/LOCODE-style");

    const denied = await h.call("POST", "/v1/welfare/providers", { roles: SEAFARER, subject: "seafarer-01", body: {} });
    assert.equal(denied.status, 403, "directory curation is officer-only");

    const curated = await h.call("POST", "/v1/welfare/providers", {
      roles: OFFICER,
      body: {
        name: "Lagos Seafarer Centre", kind: "seafarer_centre", portCode: "NGLOS",
        address: "Apapa", contact: {}, hours: "24/7", sourceReference: "https://example.test/los",
        services: [{ description: "Shelter", eligibility: "all", languages: ["en"] }],
      },
    });
    assert.equal(curated.status, 201);
    const providerId = curated.body.providerId as string;
    const fetched = await h.call("GET", `/v1/welfare/providers/${providerId}`, { roles: INSPECTOR });
    assert.equal(fetched.status, 200);
    assert.equal(fetched.body.name, "Lagos Seafarer Centre");
    const missing = await h.call("GET", "/v1/welfare/providers/urn:uuid:missing", { roles: INSPECTOR });
    assert.equal(missing.status, 404);
  } finally {
    await h.close();
  }
});

test("complaints: Idempotency-Key is required, intake is seafarer-only, replay is honest", async () => {
  const h = await startHarness();
  try {
    const noKey = await h.call("POST", "/v1/welfare/complaints", { roles: SEAFARER, subject: "seafarer-01", body: complaintBody() });
    assert.equal(noKey.status, 400);
    assert.match(noKey.body.error, /Idempotency-Key/);

    const officerSubmit = await h.call("POST", "/v1/welfare/complaints", { roles: OFFICER, body: complaintBody(), idempotencyKey: "k1" });
    assert.equal(officerSubmit.status, 403, "complaint intake binds to the seafarer's own verified identity");

    const badCategory = await h.call("POST", "/v1/welfare/complaints", { roles: SEAFARER, subject: "seafarer-01", body: complaintBody({ category: "piracy" }), idempotencyKey: "k2" });
    assert.equal(badCategory.status, 400);

    const noAck = await h.call("POST", "/v1/welfare/complaints", { roles: SEAFARER, subject: "seafarer-01", body: complaintBody({ rightToRedressNoticeAck: false }), idempotencyKey: "k3" });
    assert.equal(noAck.status, 400);
    assert.match(noAck.body.error, /5\.1\.5/);

    const created = await submitComplaint(h);
    assert.equal(created.status, 201);
    assert.equal(created.body.status, "RECEIVED");
    const replay = await submitComplaint(h);
    assert.equal(replay.status, 200, "idempotent replay returns 200 with the retained complaint");
    assert.equal(replay.body.complaintId, created.body.complaintId);
  } finally {
    await h.close();
  }
});

test("complaints: complainant view vs identity-withheld officer caseload", async () => {
  const h = await startHarness();
  try {
    await submitComplaint(h);
    const mine = await h.call("GET", "/v1/welfare/complaints/mine", { roles: SEAFARER, subject: "seafarer-01" });
    assert.equal(mine.status, 200);
    assert.equal(mine.body.complaints[0].narrative, "Wages unpaid for three months.");

    const mineDenied = await h.call("GET", "/v1/welfare/complaints/mine", { roles: OFFICER });
    assert.equal(mineDenied.status, 403);

    const caseloadDenied = await h.call("GET", "/v1/welfare/complaints", { roles: SEAFARER, subject: "seafarer-01" });
    assert.equal(caseloadDenied.status, 403, "caseload is officer-only");
    const auditorDenied = await h.call("GET", "/v1/welfare/complaints", { roles: ["auditor"] });
    assert.equal(auditorDenied.status, 403, "auditors do not hold the complaint caseload");

    const caseload = await h.call("GET", "/v1/welfare/complaints", { roles: OFFICER });
    assert.equal(caseload.status, 200);
    const view = caseload.body.complaints[0];
    assert.equal(view.disclosureScope, "withheld");
    assert.ok(!("seafarerRef" in view), "Reg 5.1.5(2): complainant identity withheld until governed disclosure");
    assert.ok(!("createdBySubject" in view));
    assert.equal(view.narrative, "Wages unpaid for three months.", "officers inside the boundary read the narrative");

    const badStatus = await h.call("GET", "/v1/welfare/complaints?status=BOGUS", { roles: OFFICER });
    assert.equal(badStatus.status, 400);
  } finally {
    await h.close();
  }
});

test("complaint transitions and disclosures run maker/checker over HTTP", async () => {
  const h = await startHarness();
  try {
    const created = await submitComplaint(h);
    const complaintId = created.body.complaintId as string;

    const illegal = await h.call("POST", `/v1/welfare/complaints/${complaintId}/transition`, { roles: OFFICER, subject: "officer-a", body: { to: "CLOSED", reasonCode: "skip" } });
    assert.equal(illegal.status, 409);

    const badTo = await h.call("POST", `/v1/welfare/complaints/${complaintId}/transition`, { roles: OFFICER, subject: "officer-a", body: { to: "PENDING", reasonCode: "x" } });
    assert.equal(badTo.status, 400);

    const seafarerTransition = await h.call("POST", `/v1/welfare/complaints/${complaintId}/transition`, { roles: SEAFARER, subject: "seafarer-01", body: { to: "ACKED", reasonCode: "x" } });
    assert.equal(seafarerTransition.status, 403);

    const request = await h.call("POST", `/v1/welfare/complaints/${complaintId}/transition`, { roles: OFFICER, subject: "officer-a", body: { to: "ACKED", reasonCode: "ack-received" } });
    assert.equal(request.status, 202);
    assert.equal(request.body.status, "PENDING");

    const selfApprove = await h.call("POST", `/v1/welfare/complaint-transitions/${request.body.requestId}/approve`, { roles: OFFICER, subject: "officer-a", body: {} });
    assert.equal(selfApprove.status, 409, "maker cannot check their own request");

    const approved = await h.call("POST", `/v1/welfare/complaint-transitions/${request.body.requestId}/approve`, { roles: OFFICER, subject: "officer-b", body: {} });
    assert.equal(approved.status, 200);
    assert.equal(approved.body.status, "ACKED");

    // Governed disclosure by two distinct officers reveals the identity.
    const disclosure = await h.call("POST", `/v1/welfare/complaints/${complaintId}/disclose`, { roles: OFFICER, subject: "officer-a", body: { reasonCode: "flag-state-investigation" } });
    assert.equal(disclosure.status, 202);
    const discloseApproved = await h.call("POST", `/v1/welfare/complaint-transitions/${disclosure.body.requestId}/approve`, { roles: OFFICER, subject: "officer-b", body: {} });
    assert.equal(discloseApproved.status, 200);
    assert.equal(discloseApproved.body.disclosureEvent, true);

    const caseload = await h.call("GET", "/v1/welfare/complaints", { roles: OFFICER });
    assert.equal(caseload.body.complaints[0].seafarerRef, "NG-SRN-0001", "identity visible after governed disclosure");

    const unknownApprove = await h.call("POST", "/v1/welfare/complaint-transitions/urn:uuid:missing/approve", { roles: OFFICER, subject: "officer-b", body: {} });
    assert.equal(unknownApprove.status, 404);
  } finally {
    await h.close();
  }
});

test("referrals: consent mandatory at the edge, seafarer self-service, officer transitions", async () => {
  const h = await startHarness();
  try {
    const curated = await h.call("POST", "/v1/welfare/providers", {
      roles: OFFICER,
      body: { name: "Apapa Medical", kind: "medical", portCode: "NGLOS", address: "", contact: {}, hours: "", sourceReference: "https://example.test/med" },
    });
    const serviceId = curated.body.services?.[0]?.serviceId as string | undefined;
    // Provider curated without explicit services has none; curate with services.
    let targetServiceId = serviceId;
    if (targetServiceId === undefined) {
      const withServices = await h.call("POST", "/v1/welfare/providers", {
        roles: OFFICER,
        body: { name: "Apapa Medical 2", kind: "medical", portCode: "NGLOS", address: "", contact: {}, hours: "", sourceReference: "https://example.test/med2", services: [{ description: "Clinic", eligibility: "", languages: [] }] },
      });
      targetServiceId = withServices.body.services[0].serviceId as string;
    }

    const noKey = await h.call("POST", "/v1/welfare/referrals", { roles: SEAFARER, subject: "seafarer-01", body: { serviceId: targetServiceId, consentAt: new Date().toISOString() } });
    assert.equal(noKey.status, 400);

    const noConsent = await h.call("POST", "/v1/welfare/referrals", { roles: SEAFARER, subject: "seafarer-01", idempotencyKey: "r1", body: { serviceId: targetServiceId } });
    assert.equal(noConsent.status, 400, "consent is mandatory (fail-closed)");

    const created = await h.call("POST", "/v1/welfare/referrals", { roles: SEAFARER, subject: "seafarer-01", idempotencyKey: "r2", body: { serviceId: targetServiceId, consentAt: new Date().toISOString() } });
    assert.equal(created.status, 201);
    assert.equal(created.body.status, "OFFERED");

    const mine = await h.call("GET", "/v1/welfare/referrals/mine", { roles: SEAFARER, subject: "seafarer-01" });
    assert.equal(mine.status, 200);
    assert.equal(mine.body.referrals.length, 1);
    const mineDenied = await h.call("GET", "/v1/welfare/referrals/mine", { roles: OFFICER });
    assert.equal(mineDenied.status, 403);

    const transitionDenied = await h.call("POST", `/v1/welfare/referrals/${created.body.referralId}/transition`, { roles: SEAFARER, subject: "seafarer-01", body: { to: "ACCEPTED" } });
    assert.equal(transitionDenied.status, 403, "referral transitions are officer-driven");

    const accepted = await h.call("POST", `/v1/welfare/referrals/${created.body.referralId}/transition`, { roles: OFFICER, body: { to: "ACCEPTED" } });
    assert.equal(accepted.status, 200);
    const closeNoNote = await h.call("POST", `/v1/welfare/referrals/${created.body.referralId}/transition`, { roles: OFFICER, body: { to: "CLOSED" } });
    assert.equal(closeNoNote.status, 400, "closing requires an outcome note");
    const closed = await h.call("POST", `/v1/welfare/referrals/${created.body.referralId}/transition`, { roles: OFFICER, body: { to: "CLOSED", outcomeNote: "Treated and discharged." } });
    assert.equal(closed.status, 200);
  } finally {
    await h.close();
  }
});

test("rest hours: operator/master submit, seafarer reads own, inspector reads flags", async () => {
  const h = await startHarness();
  try {
    const periods = [
      { start: "2026-08-10T00:00:00.000Z", end: "2026-08-10T06:00:00.000Z", kind: "rest" },
      { start: "2026-08-10T06:00:00.000Z", end: "2026-08-11T00:00:00.000Z", kind: "work" },
    ];
    const body = { seafarerRef: "NG-SRN-0001", vesselRef: "NG-LKJ-0001", recordDate: "2026-08-10", periods };

    const noKey = await h.call("POST", "/v1/rest-hours/records", { roles: OPERATOR, body });
    assert.equal(noKey.status, 400);
    const seafarerSubmit = await h.call("POST", "/v1/rest-hours/records", { roles: SEAFARER, subject: "seafarer-01", body, idempotencyKey: "rh0" });
    assert.equal(seafarerSubmit.status, 403, "seafarers never originate rest records");

    const created = await h.call("POST", "/v1/rest-hours/records", { roles: OPERATOR, body, idempotencyKey: "rh1" });
    assert.equal(created.status, 201);
    assert.ok(created.body.flags.some((flag: { rule: string }) => flag.rule === "min_rest_10h_24"), "6h rest day must flag");
    assert.equal(created.body.policyVersion, "ng-mlc-2026.1");

    const replay = await h.call("POST", "/v1/rest-hours/records", { roles: OPERATOR, body, idempotencyKey: "rh1" });
    assert.equal(replay.status, 200);
    assert.equal(replay.body.recordId, created.body.recordId);

    const master = await h.call("POST", "/v1/rest-hours/records", { roles: ["master"], body, idempotencyKey: "rh2" });
    assert.equal(master.status === 201 || master.status === 200, true, "masters may originate records");

    const mine = await h.call("GET", "/v1/rest-hours/records/mine?from=2026-08-09&to=2026-08-12&vessel_ref=NG-LKJ-0001", { roles: SEAFARER, subject: "seafarer-01" });
    assert.equal(mine.status, 200);
    assert.ok(mine.body.missingCount >= 1, "unrecorded days surface as NOT_SUBMITTED");
    const mineDenied = await h.call("GET", "/v1/rest-hours/records/mine", { roles: OPERATOR });
    assert.equal(mineDenied.status, 403);

    const flags = await h.call("GET", "/v1/rest-hours/flags", { roles: INSPECTOR });
    assert.equal(flags.status, 200);
    assert.ok(flags.body.flags.length >= 1);
    const flagsDenied = await h.call("GET", "/v1/rest-hours/flags", { roles: SEAFARER, subject: "seafarer-01" });
    assert.equal(flagsDenied.status, 403);
  } finally {
    await h.close();
  }
});

test("PBAC: stripping welfare policies denies even role-correct callers", async () => {
  const h = await startHarness({ stripWelfarePolicies: true });
  try {
    const response = await h.call("POST", "/v1/welfare/complaints", { roles: SEAFARER, subject: "seafarer-01", body: complaintBody(), idempotencyKey: "pbac-1" });
    assert.equal(response.status, 403, "without a PBAC grant the route fails closed");
    const read = await h.call("GET", "/v1/welfare/providers", { roles: SEAFARER, subject: "seafarer-01" });
    assert.equal(read.status, 403);
  } finally {
    await h.close();
  }
});
