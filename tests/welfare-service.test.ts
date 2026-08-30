import assert from "node:assert/strict";
import test from "node:test";

import { ServiceError } from "../src/service/credential-service.js";
import { InMemoryComplaintLifecycle } from "../src/welfare/lifecycle.js";
import { NarrativeKey } from "../src/welfare/confidentiality.js";
import { WelfareService, type ComplaintSubmitInput, type Principal } from "../src/welfare/service.js";
import type { WelfarePolicy } from "../src/welfare/policy.js";
import { WelfareStateError } from "../src/welfare/store.js";
import { generateEphemeralIssuerKeyPair } from "../src/vc/issuer.js";
import { verifyEnvelopeSignature, type KeyDirectory } from "../src/events/envelope-verification.js";
import { importJWK, exportJWK } from "jose";
import { InMemoryWelfareStore } from "./welfare-fakes.js";

/**
 * Service-level welfare tests over the shared in-memory store double
 * (tests/welfare-fakes.ts honors the PgWelfareStore invariants; the real
 * PostgreSQL enforcement is exercised by tests/welfare-postgres.test.ts).
 */

const NARRATIVE_KEY = NarrativeKey.fromHex("b".repeat(64));

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

const SEAFARER: Principal = { subject: "seafarer-subject-01", role: "seafarer" };
const OFFICER_A: Principal = { subject: "officer-a", role: "nimasa-labour-officer" };
const OFFICER_B: Principal = { subject: "officer-b", role: "nimasa-labour-officer" };
const OPERATOR: Principal = { subject: "operator-01", role: "operator" };

function complaintInput(overrides: Partial<ComplaintSubmitInput> = {}): ComplaintSubmitInput {
  return {
    channel: "onboard_r515",
    vesselRef: "NG-LKJ-0001",
    category: "wages",
    narrative: "Wages unpaid for three months.",
    attachments: [{ name: "payslip.pdf", sha256: "c".repeat(64) }],
    rightToRedressNoticeAck: true,
    ...overrides,
  };
}

interface Rig {
  service: WelfareService;
  store: InMemoryWelfareStore;
  lifecycle: InMemoryComplaintLifecycle;
  directory: KeyDirectory;
  keyId: string;
}

async function rig(options: { policy?: WelfarePolicy | undefined; narrativeKey?: NarrativeKey | undefined; failLifecycle?: boolean; seafarerRef?: string } = {}): Promise<Rig> {
  const { privateKey, publicKey } = generateEphemeralIssuerKeyPair();
  const keyId = "blueeconomy-credential-verification-1";
  const jwk = await exportJWK(publicKey);
  const resolved = await importJWK({ kty: "OKP", crv: "Ed25519", x: jwk.x! }, "EdDSA");
  const directory: KeyDirectory = { size: 1, resolve: (kid) => (kid === keyId ? resolved : undefined) };
  const store = new InMemoryWelfareStore();
  const lifecycle = new InMemoryComplaintLifecycle(options.failLifecycle ?? false);
  const seafarerRef = options.seafarerRef === undefined ? "NG-SRN-0001" : options.seafarerRef;
  const service = new WelfareService({
    store,
    policy: "policy" in options ? options.policy : POLICY,
    policyUnavailableReason: "policy not deployed in test",
    narrativeKey: "narrativeKey" in options ? options.narrativeKey : NARRATIVE_KEY,
    signing: { privateKey, keyId },
    producer: "blueeconomy-credential-verification",
    identity: { referenceFor: async (subject) => (subject === SEAFARER.subject && seafarerRef !== "" ? seafarerRef : undefined) },
    lifecycle,
    curationContact: "welfare-desk@example.test",
  });
  return { service, store, lifecycle, directory, keyId };
}

async function submitOne(r: Rig, idempotencyKey = "idem-complaint-1") {
  return r.service.submitComplaint(complaintInput(), idempotencyKey, SEAFARER);
}

// ---------------------------------------------------------------- complaints

test("complaint intake: persists encrypted narrative, emits signed envelope, starts the SLA tracker", async () => {
  const r = await rig();
  const result = await submitOne(r);
  assert.equal(result.created, true);
  assert.equal(result.status, "RECEIVED");
  const record = await r.store.getComplaint(result.complaintId);
  assert.ok(record !== undefined);
  assert.notEqual(record.narrativeEnc, "Wages unpaid for three months.");
  assert.equal(NARRATIVE_KEY.decrypt(record.narrativeEnc), "Wages unpaid for three months.", "narrative round-trips through AES-256-GCM");
  assert.equal(record.disclosureScope, "withheld");
  assert.equal(record.rightToRedressNoticeAck, true);
  assert.equal(r.lifecycle.started.length, 1, "SLA tracker starts with the complaint");
  assert.equal(r.store.outbox.length, 1);
  const outbox = r.store.outbox[0]!;
  assert.equal(outbox.topic, "seafarers.welfare.v1");
  assert.equal(outbox.eventId, result.eventId);
  const envelope = outbox.payload as never as Record<string, unknown>;
  assert.equal(envelope["eventType"], "seafarer.welfare.complaint.v1");
  // The emitted envelope verifies independently against the producer key.
  assert.equal(await verifyEnvelopeSignature(envelope, r.directory), r.keyId);
  // Tokenized references only: no raw seafarer/vessel identifiers on the wire.
  const resource = ((envelope["fhir"] as { entry: Array<{ resource: Record<string, unknown> }> }).entry[0]!).resource;
  assert.match(String(resource["seafarerReference"]), /^sfr-[0-9a-f]{12}$/);
  assert.ok(!JSON.stringify(envelope).includes("NG-SRN-0001"), "raw seafarer reference never enters the event");
  assert.ok(!JSON.stringify(envelope).includes("Wages unpaid"), "the narrative never enters the event");
});

test("complaint intake: idempotent replay returns the existing complaint and emits nothing twice", async () => {
  const r = await rig();
  const first = await submitOne(r);
  const replay = await submitOne(r);
  assert.equal(replay.created, false);
  assert.equal(replay.complaintId, first.complaintId);
  assert.equal(r.store.outbox.length, 1, "a replay must not enqueue a second event");
  // Key reuse with a different payload fails closed.
  await assert.rejects(
    r.service.submitComplaint(complaintInput({ narrative: "A different story" }), "idem-complaint-1", SEAFARER),
    WelfareStateError,
  );
});

test("complaint intake: fail-closed gates (policy, narrative key, redress ack, identity)", async () => {
  const noPolicy = await rig({ policy: undefined });
  await assert.rejects(submitOne(noPolicy), (error: unknown) => error instanceof ServiceError && error.statusCode === 503);

  const noKey = await rig({ narrativeKey: undefined });
  await assert.rejects(submitOne(noKey), (error: unknown) => error instanceof ServiceError && error.statusCode === 503);

  const r = await rig();
  await assert.rejects(
    r.service.submitComplaint(complaintInput({ rightToRedressNoticeAck: false }), "idem-x1", SEAFARER),
    (error: unknown) => error instanceof ServiceError && error.statusCode === 400 && /5\.1\.5/.test(error.message),
  );
  await assert.rejects(
    r.service.submitComplaint(complaintInput(), "idem-x2", { subject: "unknown-subject", role: "seafarer" }),
    (error: unknown) => error instanceof ServiceError && error.statusCode === 409 && /no current CoC credential/.test(error.message),
  );
  await assert.rejects(
    r.service.submitComplaint(complaintInput({ narrative: "" }), "idem-x3", SEAFARER),
    (error: unknown) => error instanceof ServiceError && error.statusCode === 400,
  );
});

test("complaint intake: lifecycle start failure refuses intake honestly and records nothing", async () => {
  const r = await rig({ failLifecycle: true });
  await assert.rejects(submitOne(r), (error: unknown) => error instanceof ServiceError && error.statusCode === 503 && /NOT recorded/.test(error.message));
  assert.equal(r.store.complaints.size, 0, "no orphan complaint without its SLA tracker");
  assert.equal(r.store.outbox.length, 0);
});

test("complaint transitions: maker/checker dual control over the governed lifecycle", async () => {
  const r = await rig();
  const { complaintId } = await submitOne(r);

  // Illegal transition refused before any request is created.
  await assert.rejects(
    r.service.requestTransition(complaintId, { to: "RESOLVED", reasonCode: "skip" }, OFFICER_A),
    (error: unknown) => error instanceof ServiceError && error.statusCode === 409,
  );

  const request = await r.service.requestTransition(complaintId, { to: "ACKED", reasonCode: "ack-received" }, OFFICER_A);
  assert.equal(request.status, "PENDING");

  // The maker cannot check their own request.
  await assert.rejects(
    r.service.approveTransitionRequest(request.requestId, OFFICER_A),
    (error: unknown) => error instanceof ServiceError && error.statusCode === 409,
  );

  const approved = await r.service.approveTransitionRequest(request.requestId, OFFICER_B);
  assert.equal(approved.status, "ACKED");
  assert.equal(approved.lifecycleSignalled, true);
  assert.equal(r.lifecycle.signalled.length, 1);
  const record = await r.store.getComplaint(complaintId);
  assert.equal(record?.status, "ACKED");
  assert.equal(r.store.outbox.length, 2, "intake + transition events");
  const transitionEnvelope = r.store.outbox[1]!.payload as Record<string, unknown>;
  assert.equal(transitionEnvelope["eventType"], "seafarer.welfare.complaint_status.v1");
  assert.equal(await verifyEnvelopeSignature(transitionEnvelope, r.directory), r.keyId);

  // Double approval is refused; an unknown request 404s.
  await assert.rejects(
    r.service.approveTransitionRequest(request.requestId, OFFICER_B),
    (error: unknown) => error instanceof ServiceError && error.statusCode === 409,
  );
  await assert.rejects(
    r.service.approveTransitionRequest("urn:uuid:unknown", OFFICER_B),
    (error: unknown) => error instanceof ServiceError && error.statusCode === 404,
  );

  // Replaying an already-executed identical request fails closed (the complaint
  // has already moved on, so the stale transition no longer applies).
  await assert.rejects(
    r.service.requestTransition(complaintId, { to: "ACKED", reasonCode: "ack-received" }, OFFICER_A),
    (error: unknown) => error instanceof ServiceError && error.statusCode === 409,
  );
});

test("complaint disclosure: officer view withholds identity until governed disclosure", async () => {
  const r = await rig();
  const { complaintId } = await submitOne(r);

  const before = await r.service.caseload({});
  const officerView = before.complaints[0] as Record<string, unknown>;
  assert.equal(officerView["disclosureScope"], "withheld");
  assert.ok(!("seafarerRef" in officerView), "complainant identity withheld from officer views (Reg 5.1.5(2))");
  assert.ok(!("createdBySubject" in officerView));

  const request = await r.service.requestDisclosure(complaintId, { reasonCode: "flag-state-investigation" }, OFFICER_A);
  await r.service.approveTransitionRequest(request.requestId, OFFICER_B);

  const after = await r.service.caseload({});
  const disclosed = after.complaints[0] as Record<string, unknown>;
  assert.equal(disclosed["disclosureScope"], "disclosed");
  assert.equal(disclosed["seafarerRef"], "NG-SRN-0001");
  assert.equal(disclosed["disclosedReasonCode"], "flag-state-investigation");
  const disclosureEnvelope = r.store.outbox.at(-1)!.payload as Record<string, unknown>;
  assert.equal(await verifyEnvelopeSignature(disclosureEnvelope, r.directory), r.keyId);
  const resource = ((disclosureEnvelope["fhir"] as { entry: Array<{ resource: Record<string, unknown> }> }).entry[0]!).resource;
  assert.equal(resource["disclosureEvent"], true);

  // Disclosure is one-time.
  await assert.rejects(
    r.service.requestDisclosure(complaintId, { reasonCode: "again" }, OFFICER_A),
    (error: unknown) => error instanceof ServiceError && error.statusCode === 409,
  );
});

test("complainant view returns the own timeline with the decrypted narrative", async () => {
  const r = await rig();
  const { complaintId } = await submitOne(r);
  const request = await r.service.requestTransition(complaintId, { to: "ACKED", reasonCode: "ack" }, OFFICER_A);
  await r.service.approveTransitionRequest(request.requestId, OFFICER_B);
  const mine = await r.service.myComplaints(SEAFARER.subject);
  assert.equal(mine.seafarerReference, "NG-SRN-0001");
  const view = mine.complaints[0] as Record<string, unknown>;
  assert.equal(view["narrative"], "Wages unpaid for three months.");
  assert.equal(view["status"], "ACKED");
  assert.equal((view["timeline"] as unknown[]).length, 2, "intake + ack events");
  // A subject without a credential sees an honest empty wallet.
  const stranger = await r.service.myComplaints("unknown-subject");
  assert.equal(stranger.seafarerReference, null);
  assert.deepEqual(stranger.complaints, []);
});

// ----------------------------------------------------------------- referrals

async function rigWithService(r: Rig): Promise<{ serviceId: string }> {
  const provider = await r.service.curateProvider({
    name: "Lagos Seafarer Centre",
    kind: "seafarer_centre",
    portCode: "NGLOS",
    address: "Apapa",
    contact: { phone: "+234-000" },
    hours: "24/7",
    sourceReference: "https://example.test/directory/los",
  }, [{ description: "Shelter and counselling", eligibility: "all seafarers", languages: ["en"] }], OFFICER_A);
  return { serviceId: provider.services[0]!.serviceId };
}

test("referrals: consent is mandatory, recent and never in the future", async () => {
  const r = await rig();
  const { serviceId } = await rigWithService(r);
  await assert.rejects(
    r.service.createReferral({ serviceId, consentAt: "not-a-date" }, "idem-r1", OFFICER_A),
    (error: unknown) => error instanceof ServiceError && error.statusCode === 400 && /consent_at is mandatory/.test(error.message),
  );
  await assert.rejects(
    r.service.createReferral({ serviceId, consentAt: new Date(Date.now() + 3_600_000).toISOString(), seafarerRef: "NG-SRN-0001" }, "idem-r2", OFFICER_A),
    (error: unknown) => error instanceof ServiceError && error.statusCode === 400 && /future/.test(error.message),
  );
  // Officer-created referrals must name the seafarer; seafarers act for themselves only.
  await assert.rejects(
    r.service.createReferral({ serviceId, consentAt: new Date().toISOString() }, "idem-r3", OFFICER_A),
    (error: unknown) => error instanceof ServiceError && error.statusCode === 400 && /seafarerRef is required/.test(error.message),
  );
  await assert.rejects(
    r.service.createReferral({ serviceId, consentAt: new Date().toISOString(), seafarerRef: "NG-SRN-9999" }, "idem-r4", SEAFARER),
    (error: unknown) => error instanceof ServiceError && error.statusCode === 403,
  );
  await assert.rejects(
    r.service.createReferral({ serviceId: "urn:uuid:unknown", consentAt: new Date().toISOString() }, "idem-r5", SEAFARER),
    (error: unknown) => error instanceof ServiceError && error.statusCode === 404,
  );
});

test("referrals: create, idempotent replay, governed transition chain with outcome note", async () => {
  const r = await rig();
  const { serviceId } = await rigWithService(r);
  const consentAt = new Date().toISOString();
  const created = await r.service.createReferral({ serviceId, consentAt }, "idem-ref-1", SEAFARER);
  assert.equal(created.created, true);
  assert.equal(created.status, "OFFERED");
  const replay = await r.service.createReferral({ serviceId, consentAt }, "idem-ref-1", SEAFARER);
  assert.equal(replay.created, false);
  assert.equal(replay.referralId, created.referralId);
  assert.equal(r.store.outbox.length, 1, "referral replay must not duplicate the event");

  // Closing requires an outcome note; engagement requires acceptance first.
  await assert.rejects(
    r.service.transitionReferral(created.referralId, { to: "CLOSED" }, OFFICER_A),
    (error: unknown) => error instanceof ServiceError && error.statusCode === 400 && /outcome note/.test(error.message),
  );
  await assert.rejects(
    r.service.transitionReferral(created.referralId, { to: "ENGAGED" }, OFFICER_A),
    (error: unknown) => error instanceof ServiceError && error.statusCode === 409,
  );
  await r.service.transitionReferral(created.referralId, { to: "ACCEPTED" }, OFFICER_A);
  await r.service.transitionReferral(created.referralId, { to: "ENGAGED" }, OFFICER_A);
  const closed = await r.service.transitionReferral(created.referralId, { to: "CLOSED", outcomeNote: "Seafarer repatriated." }, OFFICER_A);
  assert.equal(closed.status, "CLOSED");
  assert.equal(r.store.outbox.length, 4, "create + 3 transitions");
  for (const message of r.store.outbox) {
    assert.equal(await verifyEnvelopeSignature(message.payload as Record<string, unknown>, r.directory), r.keyId);
    assert.equal(message.topic, "seafarers.welfare.v1");
  }
  const mine = await r.service.myReferrals(SEAFARER.subject);
  assert.equal((mine.referrals[0] as Record<string, unknown>)["status"], "CLOSED");
});

// ---------------------------------------------------------------- rest hours

const REST_PERIODS = [
  { start: "2026-08-10T00:00:00.000Z", end: "2026-08-10T10:00:00.000Z", kind: "rest" as const },
  { start: "2026-08-10T10:00:00.000Z", end: "2026-08-11T00:00:00.000Z", kind: "work" as const },
];
const BREACHING_PERIODS = [
  { start: "2026-08-10T00:00:00.000Z", end: "2026-08-10T06:00:00.000Z", kind: "rest" as const },
  { start: "2026-08-10T06:00:00.000Z", end: "2026-08-11T00:00:00.000Z", kind: "work" as const },
];

function restInput(periods = REST_PERIODS) {
  return { seafarerRef: "NG-SRN-0001", vesselRef: "NG-LKJ-0001", recordDate: "2026-08-10", periods };
}

test("rest records: only operator/master originate; policy gates the endpoint", async () => {
  const r = await rig();
  await assert.rejects(
    r.service.submitRestRecord(restInput(), "idem-rest-x", SEAFARER),
    (error: unknown) => error instanceof ServiceError && error.statusCode === 403,
  );
  const noPolicy = await rig({ policy: undefined });
  await assert.rejects(
    noPolicy.service.submitRestRecord(restInput(), "idem-rest-x", OPERATOR),
    (error: unknown) => error instanceof ServiceError && error.statusCode === 503,
  );
});

test("rest records: breaching record persists policy-versioned flags and emits one event per flag", async () => {
  const r = await rig();
  const result = await r.service.submitRestRecord(restInput(BREACHING_PERIODS), "idem-rest-1", OPERATOR);
  assert.equal(result.created, true);
  const rules = new Set(result.flags.map((flag) => flag.rule));
  assert.ok(rules.has("min_rest_10h_24"), "6h rest in 24h must flag");
  assert.ok(rules.has("min_rest_77h_7d"));
  for (const flag of result.flags) assert.equal(flag.policyVersion, "ng-mlc-2026.1");
  assert.equal(result.eventIds.length, result.flags.length);
  assert.equal(r.store.outbox.length, result.flags.length);
  for (const message of r.store.outbox) {
    const envelope = message.payload as Record<string, unknown>;
    assert.equal(envelope["eventType"], "seafarer.rest_hours.flagged.v1");
    assert.equal(await verifyEnvelopeSignature(envelope, r.directory), r.keyId);
  }
});

test("rest records: idempotent replay returns retained flags without recomputation or duplicate events", async () => {
  const r = await rig();
  const first = await r.service.submitRestRecord(restInput(BREACHING_PERIODS), "idem-rest-1", OPERATOR);
  const replay = await r.service.submitRestRecord(restInput(BREACHING_PERIODS), "idem-rest-1", OPERATOR);
  assert.equal(replay.created, false);
  assert.equal(replay.recordId, first.recordId);
  assert.deepEqual(replay.eventIds, []);
  assert.equal(replay.flags.length, first.flags.length);
  assert.equal(r.store.outbox.length, first.flags.length, "no duplicated flag events");
  // Same key, different periods fails closed.
  await assert.rejects(
    r.service.submitRestRecord(restInput(), "idem-rest-1", OPERATOR),
    WelfareStateError,
  );
});

test("rest records: honest NOT_SUBMITTED days in the seafarer range view", async () => {
  const r = await rig();
  await r.service.submitRestRecord(restInput(), "idem-rest-ok", OPERATOR);
  const view = await r.service.myRestRecords(SEAFARER.subject, { from: "2026-08-09", to: "2026-08-12", vesselRef: "NG-LKJ-0001" });
  assert.equal(view.missingCount, 3, "2026-08-09/11/12 carry no operator record");
  const days = view.days as Array<Record<string, unknown>>;
  assert.deepEqual(days.find((day) => day["date"] === "2026-08-10")?.["status"], "RECORDED");
  assert.deepEqual(days.find((day) => day["date"] === "2026-08-11"), { date: "2026-08-11", status: "NOT_SUBMITTED" });
  // Range misuse fails closed.
  await assert.rejects(r.service.myRestRecords(SEAFARER.subject, { from: "2026-08-01" }), /from and to must both/);
  await assert.rejects(r.service.myRestRecords(SEAFARER.subject, { from: "2026-08-12", to: "2026-08-01", vesselRef: "V" }), /must not be after/);
  await assert.rejects(r.service.myRestRecords(SEAFARER.subject, { from: "2026-08-01", to: "2026-09-15", vesselRef: "V" }), /31 days/);
  await assert.rejects(r.service.myRestRecords(SEAFARER.subject, { from: "2026-08-01", to: "2026-08-05" }), /vessel_ref is required/);
});

test("rest records: record-date and period-shape validation fails closed", async () => {
  const r = await rig();
  await assert.rejects(
    r.service.submitRestRecord({ ...restInput(), recordDate: "10/08/2026" }, "i1", OPERATOR),
    (error: unknown) => error instanceof ServiceError && error.statusCode === 400 && /YYYY-MM-DD/.test(error.message),
  );
  await assert.rejects(
    r.service.submitRestRecord(restInput([{ start: "2026-08-08T00:00:00.000Z", end: "2026-08-08T01:00:00.000Z", kind: "rest" }]), "i2", OPERATOR),
    (error: unknown) => error instanceof ServiceError && error.statusCode === 400 && /record date/.test(error.message),
  );
  await assert.rejects(
    r.service.submitRestRecord(restInput([
      { start: "2026-08-10T00:00:00.000Z", end: "2026-08-10T06:00:00.000Z", kind: "rest" },
      { start: "2026-08-10T05:00:00.000Z", end: "2026-08-10T07:00:00.000Z", kind: "work" },
    ]), "i3", OPERATOR),
    (error: unknown) => error instanceof ServiceError && error.statusCode === 400 && /overlap/.test(error.message),
  );
});

// ----------------------------------------------------------------- directory

test("directory: honest empty state, curation requires provenance, suspended providers refuse referrals", async () => {
  const r = await rig();
  const empty = await r.service.listProviders();
  assert.equal(empty.providers.length, 0);
  assert.equal(empty.empty?.curationContact, "welfare-desk@example.test");

  await assert.rejects(
    r.service.curateProvider({
      name: "Unsourced Centre", kind: "medical", portCode: "NGLOS", address: "", contact: {}, hours: "", sourceReference: "  ",
    }, [], OFFICER_A),
    (error: unknown) => error instanceof ServiceError && error.statusCode === 400 && /source_reference/.test(error.message),
  );

  const { serviceId } = await rigWithService(r);
  const provider = (await r.service.listProviders("NGLOS")).providers[0]!;
  assert.equal(provider.services[0]!.serviceId, serviceId);
  assert.equal(await r.service.getProvider(provider.providerId).then((p) => p.name), "Lagos Seafarer Centre");
  await assert.rejects(r.service.getProvider("urn:uuid:missing"), (error: unknown) => error instanceof ServiceError && error.statusCode === 404);

  // Suspend the provider at the store level: new referrals are refused.
  const stored = r.store.providers.get(provider.providerId)!;
  r.store.providers.set(provider.providerId, { ...stored, status: "SUSPENDED" });
  await assert.rejects(
    r.service.createReferral({ serviceId, consentAt: new Date().toISOString() }, "idem-susp", SEAFARER),
    (error: unknown) => error instanceof ServiceError && error.statusCode === 409 && /not active/.test(error.message),
  );
});

test("caseload: SLA breaches are observed and recorded exactly once per stage", async () => {
  const r = await rig();
  const { complaintId } = await submitOne(r);
  r.lifecycle.setBreaches(complaintId, ["AWAITING_ACK"]);
  const first = await r.service.caseload({});
  assert.deepEqual(first.newlyObservedBreaches, [{ complaintId, stage: "AWAITING_ACK" }]);
  const second = await r.service.caseload({});
  assert.deepEqual(second.newlyObservedBreaches, [], "a breach already recorded is not counted again");
  const view = first.complaints[0] as Record<string, unknown>;
  assert.deepEqual((view["sla"] as Record<string, unknown>)["slaBreachedStages"], ["AWAITING_ACK"]);
});
