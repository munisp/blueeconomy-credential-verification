import assert from "node:assert/strict";
import test from "node:test";
import { createPublicKey, type KeyObject } from "node:crypto";

import { addDataIntegrityProof } from "../src/vc/data-integrity.js";
import { generateEphemeralIssuerKeyPair, issueCoCCredential, type IssuerConfiguration } from "../src/vc/issuer.js";
import type { JsonValue } from "../src/vc/jcs.js";
import {
  buildStatusListCredential,
  createBitstring,
  setStatusBit,
  statusListCredentialToJson,
  type BitstringStatusListCredential,
} from "../src/vc/status-list.js";
import { verifyCoCCredential } from "../src/vc/verifier.js";
import type { SeafarerCoCCredential } from "../src/vc/types.js";

const NOW = new Date("2026-06-01T00:00:00.000Z");
const STATUS_LIST_URL = "https://credentials.nimasa.gov.ng/v1/status-list/main";
const HOLDER = "did:web:wallet.seafarer.example:ng-0001";

interface Fixture {
  issuer: IssuerConfiguration;
  publicKey: KeyObject;
  credential: SeafarerCoCCredential;
  statusList: BitstringStatusListCredential;
}

function makeFixture(overrides: Partial<Parameters<typeof issueCoCCredential>[1]> = {}): Fixture {
  const { privateKey, publicKey } = generateEphemeralIssuerKeyPair();
  const issuer: IssuerConfiguration = {
    issuerDid: "did:web:credentials.nimasa.gov.ng",
    verificationMethod: "did:web:credentials.nimasa.gov.ng#ed25519-key-1",
    privateKey,
    statusListCredentialUrl: STATUS_LIST_URL,
  };
  const credential = issueCoCCredential(issuer, {
    credentialId: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    holderId: HOLDER,
    seafarerReferenceNumber: "NG-SRN-0001",
    capacity: "Officer in charge of a navigational watch",
    stcwRegulation: "STCW regulation II/1",
    limitations: [],
    statusListIndex: 7,
    validFrom: new Date("2026-01-01T00:00:00.000Z"),
    validUntil: new Date("2031-01-01T00:00:00.000Z"),
    ...overrides,
  }, NOW);
  return { issuer, publicKey, credential, statusList: signStatusList(issuer, createBitstring()) };
}

function signStatusList(issuer: IssuerConfiguration, bits: Uint8Array): BitstringStatusListCredential {
  const unsigned = buildStatusListCredential(STATUS_LIST_URL, issuer.issuerDid, bits, NOW);
  const proof = addDataIntegrityProof(statusListCredentialToJson(unsigned), {
    created: NOW.toISOString(),
    verificationMethod: issuer.verificationMethod,
    proofPurpose: "assertionMethod",
  }, issuer.privateKey);
  return { ...unsigned, proof: proof as unknown as Record<string, JsonValue> };
}

function verify(fixture: Fixture, credential: unknown = fixture.credential, now = NOW) {
  return verifyCoCCredential({
    credential,
    issuerPublicKey: fixture.publicKey,
    expectedIssuer: fixture.issuer.issuerDid,
    expectedHolderId: HOLDER,
    statusListCredential: fixture.statusList,
    now,
  });
}

test("VC issue to verify round-trip succeeds", () => {
  const fixture = makeFixture();
  const result = verify(fixture);
  assert.equal(result.credentialId, fixture.credential.id);
  assert.equal(result.holderId, HOLDER);
  assert.equal(result.stcwRegulation, "STCW regulation II/1");
  assert.equal(result.checkedStatusListIndex, 7);
});

test("tampered credential is rejected", () => {
  const fixture = makeFixture();
  const tampered = JSON.parse(JSON.stringify(fixture.credential)) as SeafarerCoCCredential;
  tampered.credentialSubject.capacity = "Master on ships of 3000 GT or more";
  assert.throws(() => verify(fixture, tampered), /proof verification failed/);
});

test("revoked credential is rejected via the status list", () => {
  const fixture = makeFixture();
  const bits = createBitstring();
  setStatusBit(bits, 7, true);
  const revokedList = signStatusList(fixture.issuer, bits);
  assert.throws(
    () => verifyCoCCredential({
      credential: fixture.credential,
      issuerPublicKey: fixture.publicKey,
      expectedIssuer: fixture.issuer.issuerDid,
      expectedHolderId: HOLDER,
      statusListCredential: revokedList,
      now: NOW,
    }),
    /has been revoked/,
  );
});

test("expired credential is rejected", () => {
  const fixture = makeFixture();
  assert.throws(() => verify(fixture, fixture.credential, new Date("2031-06-01T00:00:00.000Z")), /expired/);
});

test("credential bound to a different holder is rejected", () => {
  const fixture = makeFixture();
  assert.throws(
    () => verifyCoCCredential({
      credential: fixture.credential,
      issuerPublicKey: fixture.publicKey,
      expectedIssuer: fixture.issuer.issuerDid,
      expectedHolderId: "did:web:wallet.seafarer.example:ng-9999",
      statusListCredential: fixture.statusList,
      now: NOW,
    }),
    /not bound to the presented holder/,
  );
});

test("verification is offline-capable (no network access)", async () => {
  const fixture = makeFixture();
  const originalFetch = globalThis.fetch;
  const failingFetch = (() => {
    throw new Error("network access attempted during verification");
  }) as typeof fetch;
  globalThis.fetch = failingFetch;
  try {
    const result = verify(fixture);
    assert.equal(result.issuer, fixture.issuer.issuerDid);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("unsigned status list snapshot is rejected (fail-closed)", () => {
  const fixture = makeFixture();
  const unsigned = { ...fixture.statusList } as Record<string, unknown>;
  delete unsigned["proof"];
  assert.throws(
    () => verifyCoCCredential({
      credential: fixture.credential,
      issuerPublicKey: fixture.publicKey,
      expectedIssuer: fixture.issuer.issuerDid,
      expectedHolderId: HOLDER,
      statusListCredential: unsigned,
      now: NOW,
    }),
    /unsigned/,
  );
});

test("verification latency stays within the 5s p99 budget", () => {
  const fixture = makeFixture();
  const durations: number[] = [];
  for (let iteration = 0; iteration < 50; iteration += 1) {
    const started = performance.now();
    verify(fixture);
    durations.push(performance.now() - started);
  }
  durations.sort((left, right) => left - right);
  const p99 = durations[Math.min(durations.length - 1, Math.floor(durations.length * 0.99))] ?? 0;
  assert.ok(p99 <= 5_000, `p99 verification latency ${p99.toFixed(1)}ms exceeded the 5000ms budget`);
});

test("issuer refuses to mint an already-expired credential", () => {
  assert.throws(
    () => makeFixture({ validUntil: new Date("2020-01-01T00:00:00.000Z") }),
    /already-expired/,
  );
});

test("credential JSON round-trips through serialization deterministically", () => {
  const fixture = makeFixture();
  const canonical = JSON.stringify(JSON.parse(JSON.stringify(fixture.credential)));
  assert.doesNotThrow(() => verify(fixture, JSON.parse(canonical)));
});
