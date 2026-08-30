import assert from "node:assert/strict";
import test from "node:test";
import { existsSync } from "node:fs";
import { mkdtemp, writeFile, symlink, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { exportJWK } from "jose";

import { evaluateRestHours, parsePeriods, RestRecordValidationError, type RestHourPeriod, type RuleBreach } from "../src/welfare/rest-rules.js";
import {
  COMPLAINT_TRANSITIONS,
  REFERRAL_TRANSITIONS,
  isLegalComplaintTransition,
  isLegalReferralTransition,
  tokenizeReference,
  deterministicUuid,
} from "../src/welfare/types.js";
import {
  WELFARE_POLICY_PATH_ENV,
  loadWelfarePolicyFromEnv,
  signWelfarePolicy,
  verifyWelfarePolicy,
  type WelfarePolicyClaims,
} from "../src/welfare/policy.js";
import { KEY_DIRECTORY_PATH_ENV, loadKeyDirectory, verifyEnvelopeSignature, EnvelopeVerificationError } from "../src/events/envelope-verification.js";
import { NarrativeKey, narrativeKeyFromEnv, NARRATIVE_KEY_ENV } from "../src/welfare/confidentiality.js";
import { buildWelfareEnvelope, WELFARE_TOPIC } from "../src/welfare/envelope.js";
import { generateEphemeralIssuerKeyPair } from "../src/vc/issuer.js";

// ---------------------------------------------------------------------------
// MLC Reg 2.3 rest-rule engine: exact-window boundaries.
// ---------------------------------------------------------------------------

const DAY = "2026-08-10";
function at(dayOffset: number, hhmm: string): string {
  // "24:00" is the next day's midnight (not valid ISO as-is).
  const extra = hhmm === "24:00" ? 1 : 0;
  const clock = extra === 1 ? "00:00" : hhmm;
  const base = Date.parse(`${DAY}T00:00:00.000Z`) + (dayOffset + extra) * 86_400_000;
  return `${new Date(base).toISOString().slice(0, 10)}T${clock}:00.000Z`;
}
function work(dayOffset: number, from: string, to: string): RestHourPeriod {
  return { start: at(dayOffset, from), end: at(dayOffset, to), kind: "work" };
}
function rest(dayOffset: number, from: string, to: string): RestHourPeriod {
  return { start: at(dayOffset, from), end: at(dayOffset, to), kind: "rest" };
}
function rulesOf(breaches: RuleBreach[]): Set<string> {
  return new Set(breaches.map((breach) => breach.rule));
}

/** 12h rest / 12h work per day for 7 days: 84h rest per 7 d, 12h per 24 h, single 12h blocks, 12h gaps. */
function compliantMinRestWeek(): RestHourPeriod[] {
  const periods: RestHourPeriod[] = [];
  for (let day = 0; day < 7; day += 1) {
    periods.push(rest(day, "00:00", "12:00"), work(day, "12:00", "24:00"));
  }
  return periods;
}

test("rest rules: a compliant 7-day min-rest schedule flags nothing", () => {
  assert.deepEqual(evaluateRestHours(compliantMinRestWeek(), "min_rest"), []);
});

test("rest rules: exactly 10h rest in 24h is the compliant boundary; 9h59m flags min_rest_10h_24", () => {
  const boundary = [rest(0, "00:00", "10:00"), work(0, "10:00", "24:00")];
  const boundaryRules = rulesOf(evaluateRestHours(boundary, "min_rest"));
  assert.ok(!boundaryRules.has("min_rest_10h_24"), "exactly 10h rest must not flag");
  assert.ok(boundaryRules.has("min_rest_77h_7d"), "a single day can never satisfy 77h/7d");

  const below = [rest(0, "00:00", "09:59"), work(0, "09:59", "24:00")];
  assert.ok(rulesOf(evaluateRestHours(below, "min_rest")).has("min_rest_10h_24"));
});

test("rest rules: exactly 77h rest in 7d is the compliant boundary; 76h59m flags min_rest_77h_7d", () => {
  // compliantMinRestWeek carries exactly 77h; shave one minute off day 0.
  const below: RestHourPeriod[] = [rest(0, "00:01", "11:00"), work(0, "11:00", "24:00")];
  for (let day = 1; day < 7; day += 1) {
    below.push(rest(day, "00:00", "11:00"), work(day, "11:00", "24:00"));
  }
  const rules = rulesOf(evaluateRestHours(below, "min_rest"));
  assert.ok(rules.has("min_rest_77h_7d"), "76h59m in 7d must flag");
  assert.ok(!rules.has("min_rest_10h_24"), "each day still carries >= 10h rest");
});

test("rest rules: a 14h gap between rest periods is compliant; 14h01m flags max_gap_14h", () => {
  const boundary = [rest(0, "00:00", "06:01"), work(0, "06:01", "20:01"), rest(0, "20:01", "24:00")];
  const boundaryRules = rulesOf(evaluateRestHours(boundary, "min_rest"));
  assert.ok(!boundaryRules.has("max_gap_14h"), "exactly 14h between rest periods must not flag");
  assert.ok(!boundaryRules.has("min_rest_10h_24"));

  const over = [rest(0, "00:00", "06:00"), work(0, "06:00", "20:02"), rest(0, "20:02", "24:00")];
  assert.ok(rulesOf(evaluateRestHours(over, "min_rest")).has("max_gap_14h"));
});

test("rest rules: rest in three periods within 24h flags max_two_periods; two periods do not", () => {
  const three = [
    rest(0, "00:00", "06:00"), work(0, "06:00", "08:00"),
    rest(0, "08:00", "12:00"), work(0, "12:00", "14:00"),
    rest(0, "14:00", "24:00"),
  ];
  const rules = rulesOf(evaluateRestHours(three, "min_rest"));
  assert.ok(rules.has("max_two_periods"));
  assert.ok(!rules.has("min_one_period_6h"), "the 10h block satisfies the 6h single-period rule");

  const two = [rest(0, "00:00", "06:00"), work(0, "06:00", "14:00"), rest(0, "14:00", "24:00")];
  assert.ok(!rulesOf(evaluateRestHours(two, "min_rest")).has("max_two_periods"));
});

test("rest rules: exactly 6h longest rest period is compliant; 5h59m flags min_one_period_6h", () => {
  const boundary = [rest(0, "00:00", "06:00"), work(0, "06:00", "18:00"), rest(0, "18:00", "24:00")];
  assert.ok(!rulesOf(evaluateRestHours(boundary, "min_rest")).has("min_one_period_6h"));

  const below = [rest(0, "00:00", "05:59"), work(0, "05:59", "18:01"), rest(0, "18:01", "24:00")];
  assert.ok(rulesOf(evaluateRestHours(below, "min_rest")).has("min_one_period_6h"));
});

test("rest rules: exactly 14h work in 24h is the compliant boundary; 14h01m flags max_work_14h_24", () => {
  const boundary = [rest(0, "00:00", "10:00"), work(0, "10:00", "24:00")];
  assert.deepEqual(evaluateRestHours(boundary, "max_work"), [], "14h work / 10h rest single day is fully compliant under max_work");

  const over = [rest(0, "00:00", "09:59"), work(0, "09:59", "24:00")];
  const rules = rulesOf(evaluateRestHours(over, "max_work"));
  assert.ok(rules.has("max_work_14h_24"));
});

test("rest rules: exactly 72h work in 7d is compliant; 77h flags max_work_72h_7d", () => {
  const boundary: RestHourPeriod[] = [];
  for (let day = 0; day < 7; day += 1) {
    // 10h17m work/day = 71h59m per week, under the 72h ceiling.
    boundary.push(rest(day, "00:00", "13:43"), work(day, "13:43", "24:00"));
  }
  assert.ok(!rulesOf(evaluateRestHours(boundary, "max_work")).has("max_work_72h_7d"));

  const over: RestHourPeriod[] = [];
  for (let day = 0; day < 7; day += 1) {
    over.push(rest(day, "00:00", "13:00"), work(day, "13:00", "24:00")); // 77h work/week
  }
  const rules = rulesOf(evaluateRestHours(over, "max_work"));
  assert.ok(rules.has("max_work_72h_7d"));
  assert.ok(!rules.has("max_work_14h_24"), "11h workdays stay under the daily ceiling");
});

test("rest rules: the regime selects the rule set — min_rest never evaluates max_work and vice versa", () => {
  const heavyWork = [rest(0, "00:00", "08:00"), work(0, "08:00", "24:00")]; // 8h rest, 16h work
  const minRest = rulesOf(evaluateRestHours(heavyWork, "min_rest"));
  assert.ok(minRest.has("min_rest_10h_24"));
  assert.ok(!minRest.has("max_work_14h_24"), "max_work rules are not part of the min_rest regime");
  const maxWork = rulesOf(evaluateRestHours(heavyWork, "max_work"));
  assert.ok(maxWork.has("max_work_14h_24"));
  assert.ok(!maxWork.has("min_rest_10h_24"), "min_rest rules are not part of the max_work regime");
});

test("rest rules: breach details carry durations and windows, never PII", () => {
  const breaches = evaluateRestHours([rest(0, "00:00", "09:59"), work(0, "09:59", "24:00")], "min_rest");
  const breach = breaches.find((candidate) => candidate.rule === "min_rest_10h_24");
  assert.ok(breach !== undefined);
  assert.match(breach.detail, /9h 59m/);
  assert.match(breach.detail, /24 h window/);
});

test("rest rules: record validation fails closed", () => {
  assert.throws(() => parsePeriods([]), RestRecordValidationError);
  assert.throws(() => parsePeriods([{ start: at(0, "00:00"), end: at(0, "00:00"), kind: "rest" }]), /end must be after start/);
  assert.throws(() => parsePeriods([rest(0, "00:00", "06:00"), work(0, "05:00", "12:00")]), /must not overlap/);
  assert.throws(() => parsePeriods([{ start: "not-a-date", end: at(0, "01:00"), kind: "rest" }]), /valid ISO/);
  assert.throws(() => parsePeriods([{ start: at(0, "00:00"), end: at(0, "01:00"), kind: "sleep" as never }]), /work or rest/);
  const tooMany: RestHourPeriod[] = Array.from({ length: 65 }, (_, index) =>
    rest(Math.floor(index / 8), `${String(index % 8).padStart(2, "0")}:00`, `${String(index % 8).padStart(2, "0")}:30`));
  assert.throws(() => parsePeriods(tooMany), /1-64 entries/);
  assert.throws(() => parsePeriods([rest(0, "00:00", "01:00"), rest(9, "00:00", "01:00")]), /at most 8 days/);
});

// ---------------------------------------------------------------------------
// Governed state machines (complaint lifecycle + referral lifecycle).
// ---------------------------------------------------------------------------

test("complaint state machine matches the governed proto lifecycle", () => {
  assert.ok(isLegalComplaintTransition("RECEIVED", "ACKED"));
  assert.ok(isLegalComplaintTransition("ACKED", "ONBOARD_PROCESS"));
  assert.ok(isLegalComplaintTransition("ACKED", "ESCALATED_FLAGSTATE"));
  assert.ok(isLegalComplaintTransition("ONBOARD_PROCESS", "REFERRED"));
  assert.ok(isLegalComplaintTransition("ESCALATED_FLAGSTATE", "RESOLVED"));
  assert.ok(isLegalComplaintTransition("REFERRED", "RESOLVED"));
  assert.ok(isLegalComplaintTransition("RESOLVED", "CLOSED"));
  // Illegal: skips, reversals and transitions out of the terminal state.
  assert.ok(!isLegalComplaintTransition("RECEIVED", "RESOLVED"), "no skipping intake stages");
  assert.ok(!isLegalComplaintTransition("RECEIVED", "CLOSED"));
  assert.ok(!isLegalComplaintTransition("ACKED", "RECEIVED"), "no reversals");
  assert.ok(!isLegalComplaintTransition("CLOSED", "RECEIVED"), "CLOSED is terminal");
  assert.ok(!isLegalComplaintTransition("RESOLVED", "ONBOARD_PROCESS"));
  assert.deepEqual(COMPLAINT_TRANSITIONS["CLOSED"], []);
  // Every declared transition is self-consistent.
  for (const [from, targets] of Object.entries(COMPLAINT_TRANSITIONS)) {
    for (const to of targets) {
      assert.ok(isLegalComplaintTransition(from as never, to as never));
    }
  }
});

test("referral state machine: OFFERED -> ACCEPTED -> ENGAGED -> CLOSED with decline branch", () => {
  assert.ok(isLegalReferralTransition("OFFERED", "ACCEPTED"));
  assert.ok(isLegalReferralTransition("OFFERED", "CLOSED"), "decline is OFFERED -> CLOSED");
  assert.ok(isLegalReferralTransition("ACCEPTED", "ENGAGED"));
  assert.ok(isLegalReferralTransition("ENGAGED", "CLOSED"));
  assert.ok(!isLegalReferralTransition("OFFERED", "ENGAGED"), "engagement requires acceptance");
  assert.ok(!isLegalReferralTransition("CLOSED", "OFFERED"), "CLOSED is terminal");
  assert.deepEqual(REFERRAL_TRANSITIONS["CLOSED"], []);
});

test("tokenized references are deterministic, scoped and non-reversible", () => {
  assert.equal(tokenizeReference("sfr", "NG-SRN-0001"), tokenizeReference("sfr", "NG-SRN-0001"));
  assert.notEqual(tokenizeReference("sfr", "NG-SRN-0001"), tokenizeReference("vsl", "NG-SRN-0001"));
  assert.notEqual(tokenizeReference("sfr", "NG-SRN-0001"), tokenizeReference("sfr", "NG-SRN-0002"));
  assert.match(tokenizeReference("sfr", "NG-SRN-0001"), /^sfr-[0-9a-f]{12}$/);
  assert.equal(deterministicUuid("complaint", "key-1"), deterministicUuid("complaint", "key-1"));
  assert.notEqual(deterministicUuid("complaint", "key-1"), deterministicUuid("referral", "key-1"));
});

// ---------------------------------------------------------------------------
// Narrative confidentiality (AES-256-GCM, env-only key).
// ---------------------------------------------------------------------------

const NARRATIVE_HEX = "a".repeat(64);

test("narrative key: encrypt/decrypt round-trip, random nonces, tamper-evident", () => {
  const key = NarrativeKey.fromHex(NARRATIVE_HEX);
  const plaintext = "Wages unpaid for three months; master refuses repatriation.";
  const first = key.encrypt(plaintext);
  const second = key.encrypt(plaintext);
  assert.notEqual(first, second, "nonces must be random per encryption");
  assert.ok(!first.includes(Buffer.from(plaintext).toString("base64")), "ciphertext never carries plaintext");
  assert.equal(key.decrypt(first), plaintext);
  // Tampering with any byte fails the GCM tag check.
  const raw = Buffer.from(first, "base64");
  raw[raw.length - 1] = raw[raw.length - 1]! ^ 0x01;
  assert.throws(() => key.decrypt(raw.toString("base64")));
  assert.throws(() => key.decrypt(Buffer.from("short").toString("base64")), /truncated/);
});

test("narrative key: fail-closed construction and env factory", () => {
  assert.throws(() => NarrativeKey.fromHex("zz".repeat(32)), /64 lowercase hex/);
  assert.throws(() => NarrativeKey.fromHex("A".repeat(64)), /lowercase/);
  assert.throws(() => NarrativeKey.fromHex("a".repeat(63)), /64 lowercase hex/);
  assert.equal(narrativeKeyFromEnv({}), undefined, "unset env means intake 503s honestly");
  assert.equal(narrativeKeyFromEnv({ [NARRATIVE_KEY_ENV]: "  " }), undefined);
  assert.ok(narrativeKeyFromEnv({ [NARRATIVE_KEY_ENV]: NARRATIVE_HEX }) !== undefined);
});

// ---------------------------------------------------------------------------
// Signed welfare policy: fail-closed loader.
// ---------------------------------------------------------------------------

const POLICY_CLAIMS: WelfarePolicyClaims = {
  schema_version: "blueeconomy.welfare.policy.v1",
  policy_version: "ng-mlc-2026.1",
  regime: "min_rest",
  complaint_sla_seconds: { ack: 3_600, onboard_process: 86_400, escalation: 172_800, resolution: 604_800 },
  issued_by: "nimasa-welfare-desk",
  effective_at: "2026-08-01T00:00:00.000Z",
};

async function policyFixture(): Promise<{ directory: string; policyPath: string; keyDirectoryPath: string; keyId: string }> {
  const directory = await mkdtemp(join(tmpdir(), "blueeconomy-welfare-policy-"));
  const { privateKey, publicKey } = generateEphemeralIssuerKeyPair();
  const keyId = "blueeconomy-credential-verification-1";
  const jwk = await exportJWK(publicKey);
  const keyDirectoryPath = join(directory, "keys.json");
  await writeFile(keyDirectoryPath, JSON.stringify({ [keyId]: jwk.x }));
  const policyPath = join(directory, "welfare-policy.jws");
  await writeFile(policyPath, await signWelfarePolicy(POLICY_CLAIMS, privateKey, keyId));
  return { directory, policyPath, keyDirectoryPath, keyId };
}

test("welfare policy: unset env degrades honestly; a valid signed policy loads", async () => {
  const unset = await loadWelfarePolicyFromEnv({});
  assert.equal(unset.configured, false);
  if (!unset.configured) assert.match(unset.reason, /not set/);

  const fixture = await policyFixture();
  const loaded = await loadWelfarePolicyFromEnv({
    [WELFARE_POLICY_PATH_ENV]: fixture.policyPath,
    [KEY_DIRECTORY_PATH_ENV]: fixture.keyDirectoryPath,
  });
  assert.equal(loaded.configured, true);
  if (loaded.configured) {
    assert.equal(loaded.policy.claims.policy_version, "ng-mlc-2026.1");
    assert.equal(loaded.policy.claims.regime, "min_rest");
    assert.equal(loaded.policy.keyId, fixture.keyId);
  }
});

test("welfare policy: missing file, symlink and oversized/empty documents abort boot", async () => {
  const fixture = await policyFixture();
  const env = { [KEY_DIRECTORY_PATH_ENV]: fixture.keyDirectoryPath };
  await assert.rejects(
    loadWelfarePolicyFromEnv({ ...env, [WELFARE_POLICY_PATH_ENV]: join(fixture.directory, "absent.jws") }),
    /not readable \(fail-closed\)/,
  );
  const symlinkPath = join(fixture.directory, "linked.jws");
  await symlink(fixture.policyPath, symlinkPath);
  await assert.rejects(
    loadWelfarePolicyFromEnv({ ...env, [WELFARE_POLICY_PATH_ENV]: symlinkPath }),
    /regular non-symlink file/,
  );
  const emptyPath = join(fixture.directory, "empty.jws");
  await writeFile(emptyPath, "");
  await assert.rejects(loadWelfarePolicyFromEnv({ ...env, [WELFARE_POLICY_PATH_ENV]: emptyPath }), /must contain 1 to/);
});

test("welfare policy: malformed JWS, unknown kid, tampered payload and bad claims all fail closed", async () => {
  const fixture = await policyFixture();
  const keyDirectory = await loadKeyDirectory(fixture.keyDirectoryPath);

  await assert.rejects(verifyWelfarePolicy("not-a-jws", keyDirectory), /not a JWS compact/);
  await assert.rejects(verifyWelfarePolicy("aaaa.bbbb.cccc", keyDirectory), /fail-closed/);

  // Tamper with the payload segment of an otherwise valid document.
  const valid = await readFile(fixture.policyPath, "utf8");
  const [header, payload, signature] = valid.trim().split(".");
  const tamperedPayload = Buffer.from(`{"tampered":true,"pad":"${"x".repeat(Math.max(0, (payload ?? "").length - 20))}"}`).toString("base64url");
  await assert.rejects(verifyWelfarePolicy([header, tamperedPayload, signature].join("."), keyDirectory), /fail-closed/);

  // Unknown kid: sign with the same claims but a kid absent from the directory.
  const { privateKey } = generateEphemeralIssuerKeyPair();
  const unknownKid = await signWelfarePolicy(POLICY_CLAIMS, privateKey, "no-such-kid");
  await assert.rejects(verifyWelfarePolicy(unknownKid, keyDirectory), /not in the key directory/);

  // Signature under a different key than the directory resolves.
  const wrongKey = await signWelfarePolicy(POLICY_CLAIMS, privateKey, fixture.keyId);
  await assert.rejects(verifyWelfarePolicy(wrongKey, keyDirectory), /signature does not verify/);

  // Schema violations (bad regime) signed by the right key still fail closed.
  const badClaims = { ...POLICY_CLAIMS, regime: "whatever" } as never;
  await assert.rejects(signWelfarePolicy(badClaims, privateKey, fixture.keyId), /claims are invalid/);
});

test("welfare policy: KEY_DIRECTORY_PATH is required to verify a configured policy", async () => {
  const fixture = await policyFixture();
  await assert.rejects(
    loadWelfarePolicyFromEnv({ [WELFARE_POLICY_PATH_ENV]: fixture.policyPath }),
    /KEY_DIRECTORY_PATH is required/,
  );
});

// ---------------------------------------------------------------------------
// Welfare envelope: JWS/JCS sign + independent verify; contracts fixtures.
// ---------------------------------------------------------------------------

async function keyDirectoryFor(publicKey: ReturnType<typeof generateEphemeralIssuerKeyPair>["publicKey"], keyId: string) {
  const jwk = await exportJWK(publicKey);
  const directory = await mkdtemp(join(tmpdir(), "blueeconomy-welfare-keys-"));
  const path = join(directory, "keys.json");
  await writeFile(path, JSON.stringify({ [keyId]: jwk.x }));
  return loadKeyDirectory(path);
}

test("welfare envelope: build -> independent verify round-trip, deterministic id, fail-closed construction", async () => {
  const { privateKey, publicKey } = generateEphemeralIssuerKeyPair();
  const keyId = "blueeconomy-credential-verification-1";
  const directory = await keyDirectoryFor(publicKey, keyId);
  const input = {
    eventType: "seafarer.welfare.complaint.v1" as const,
    producer: "blueeconomy-credential-verification",
    correlationId: "corr-welfare-1",
    principal: { principalId: "officer-01", principalRole: "nimasa-labour-officer" },
    resource: {
      "@type": "type.googleapis.com/blueeconomy.contracts.v1.WelfareComplaintSubmitted",
      complaintId: "wfc-1",
    },
    signingKey: privateKey,
    keyId,
    deduplicationKey: "complaint|wfc-1",
    occurredAt: new Date("2026-08-30T12:00:00.000Z"),
  };
  const first = await buildWelfareEnvelope(input);
  const second = await buildWelfareEnvelope(input);
  assert.equal(first.eventId, second.eventId, "eventId must be deterministic for idempotent retries");
  assert.equal(first.envelopeVersion, "1.0");
  assert.equal(first.classification, "CONFIDENTIAL");
  assert.equal(first.recordClassification, "CONFIDENTIAL");
  assert.equal(first.provenance.ledgerCommitHash, "", "welfare envelopes bind durability to the outbox, not the issuance ledger (documented deviation)");
  assert.equal(WELFARE_TOPIC, "seafarers.welfare.v1");

  const verifiedKid = await verifyEnvelopeSignature(JSON.parse(JSON.stringify(first)), directory);
  assert.equal(verifiedKid, keyId);

  const tampered = JSON.parse(JSON.stringify(first)) as Record<string, unknown>;
  tampered["correlationId"] = "corr-attacker";
  await assert.rejects(verifyEnvelopeSignature(tampered, directory), EnvelopeVerificationError);

  // Fail-closed construction: non-Ed25519 key, unknown event type, missing @type.
  await assert.rejects(buildWelfareEnvelope({ ...input, eventType: "seafarer.credential.v1" as never }), /not in the welfare contracts enum/);
  await assert.rejects(buildWelfareEnvelope({ ...input, resource: { complaintId: "wfc-1" } }), /proto @type/);
  const { generateKeyPairSync } = await import("node:crypto");
  const { privateKey: rsaKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  await assert.rejects(buildWelfareEnvelope({ ...input, signingKey: rsaKey as never }), /Ed25519/);
});

function contractsFixtureDirectory(): string {
  const root = resolve(fileURLToPath(new URL(".", import.meta.url)), "..");
  const candidates = [
    process.env["BLUEECONOMY_CONTRACTS_FIXTURES_DIR"],
    join(root, "..", "blueeconomy-contracts", "fixtures", "welfare"),
    join(root, "..", "..", "repos", "blueeconomy-contracts", "fixtures", "welfare"),
    "/mnt/agents/output/blueeconomy-review/repos/blueeconomy-contracts/fixtures/welfare",
  ].filter((candidate): candidate is string => candidate !== undefined);
  for (const candidate of candidates) {
    if (existsSync(join(candidate, "seafarer.welfare.complaint.v1.json"))) return candidate;
  }
  throw new Error(`blueeconomy-contracts welfare fixtures not found; set BLUEECONOMY_CONTRACTS_FIXTURES_DIR (tried: ${candidates.join(", ")})`);
}

test("welfare envelope: committed contracts fixtures verify byte-for-byte with their published key", async () => {
  // kid/public key published in blueeconomy-contracts fixtures/welfare/README.md
  // (throwaway synthetic fixture key; never a production producer key).
  const directory = await mkdtemp(join(tmpdir(), "blueeconomy-fixture-keys-"));
  const keyDirectoryPath = join(directory, "keys.json");
  await writeFile(keyDirectoryPath, JSON.stringify({
    "blueeconomy-credential-verification-0": "r_2PSmU6m2LJ7aXLYoOjXzXY8S0IE6TiQmldezOs00M",
  }));
  const keyDirectory = await loadKeyDirectory(keyDirectoryPath);

  const fixtureDir = contractsFixtureDirectory();
  const fixtures = [
    "seafarer.welfare.complaint.v1.json",
    "seafarer.welfare.complaint_status.v1.json",
    "seafarer.welfare.referral.v1.json",
    "seafarer.rest_hours.flagged.v1.json",
  ];
  for (const fixture of fixtures) {
    const envelope = JSON.parse(await readFile(join(fixtureDir, fixture), "utf8")) as Record<string, unknown>;
    const kid = await verifyEnvelopeSignature(envelope, keyDirectory);
    assert.equal(kid, "blueeconomy-credential-verification-0", `${fixture} must verify under the fixture key`);
    assert.equal(envelope["envelopeVersion"], "1.0");
    assert.equal(envelope["classification"], "CONFIDENTIAL");
    const provenance = envelope["provenance"] as Record<string, unknown>;
    assert.equal(provenance["ledgerCommitHash"], "", "fixtures carry the documented empty ledgerCommitHash");
    assert.equal(envelope["eventType"], fixture.replace(/\.json$/, ""));
  }
  // A tampered fixture must be rejected, proving the check is not vacuous.
  const tampered = JSON.parse(await readFile(join(fixtureDir, fixtures[0]!), "utf8")) as Record<string, unknown>;
  tampered["producer"] = "attacker-producer";
  await assert.rejects(verifyEnvelopeSignature(tampered, keyDirectory), EnvelopeVerificationError);
});
