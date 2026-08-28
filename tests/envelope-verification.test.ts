import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync } from "node:crypto";
import { CompactSign, exportJWK } from "jose";

import {
  EnvelopeVerificationError,
  loadKeyDirectory,
  loadKeyDirectoryFromEnv,
  verifyEnvelopeSignature,
  type KeyDirectory,
  type SignatureVerificationMetrics,
} from "../src/events/envelope-verification.js";
import { canonicalizeJson, asJsonValue, type JsonValue } from "../src/vc/jcs.js";

const TEST_KID = "blueeconomy-credential-verification-0";

function testKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { privateKey, publicKey };
}

async function publicKeyBase64Url(publicKey: ReturnType<typeof testKeyPair>["publicKey"]): Promise<string> {
  const jwk = await exportJWK(publicKey);
  const x = (jwk as { x?: string }).x;
  assert.ok(typeof x === "string");
  return x;
}

async function writeDirectory(entries: Record<string, string>): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "blueeconomy-keydir-"));
  const path = join(directory, "keys.json");
  await writeFile(path, JSON.stringify(entries));
  return path;
}

function sampleEnvelope(signature = "placeholder"): Record<string, unknown> {
  return {
    envelopeVersion: "1.0",
    eventId: "2b3c4d5e-6f70-4819-8a2b-3c4d5e6f7081",
    eventType: "seafarer.credential.v1",
    occurredAt: "2026-08-12T12:00:00.000Z",
    producer: "blueeconomy-credential-verification",
    correlationId: "correlation-001",
    fhir: {
      resourceType: "Bundle",
      type: "message",
      entry: [{ resource: { note: "cross-language véctor 😀", sequence: 7 } }],
    },
    provenance: {
      principalId: "svc-credential-verification",
      principalRole: "nimasa-approver",
      signature,
      ledgerCommitHash: "c".repeat(64),
    },
    classification: "CONFIDENTIAL",
  };
}

function signedPayload(envelope: Record<string, unknown>): Uint8Array {
  const { provenance, ...rest } = envelope as { provenance: Record<string, unknown> } & Record<string, unknown>;
  const { signature: _signature, ...provenanceWithoutSignature } = provenance;
  return new TextEncoder().encode(
    canonicalizeJson(asJsonValue({ ...rest, provenance: provenanceWithoutSignature } as Record<string, JsonValue>)),
  );
}

async function signEnvelope(
  envelope: Record<string, unknown>,
  privateKey: ReturnType<typeof testKeyPair>["privateKey"],
  kid: string,
): Promise<string> {
  return new CompactSign(signedPayload(envelope)).setProtectedHeader({ alg: "EdDSA", kid }).sign(privateKey);
}

class RecordingMetrics implements SignatureVerificationMetrics {
  public verified = 0;
  public readonly rejected: Record<string, number> = {};
  recordVerified(): void {
    this.verified += 1;
  }
  recordRejected(reason: string): void {
    this.rejected[reason] = (this.rejected[reason] ?? 0) + 1;
  }
}

async function directoryFor(kid: string, publicKeyBase64: string): Promise<KeyDirectory> {
  return loadKeyDirectory(await writeDirectory({ [kid]: publicKeyBase64 }));
}

test("key directory loads a valid Ed25519 key and resolves it", async () => {
  const { publicKey } = testKeyPair();
  const directory = await directoryFor(TEST_KID, await publicKeyBase64Url(publicKey));
  assert.equal(directory.size, 1);
  assert.ok(directory.resolve(TEST_KID) !== undefined);
  assert.equal(directory.resolve("unknown-0"), undefined);
});

test("key directory fails closed on missing, empty and malformed inputs", async () => {
  await assert.rejects(() => loadKeyDirectory(join(tmpdir(), "definitely-absent-keys.json")), /not readable|fail-closed/);
  const directory = await mkdtemp(join(tmpdir(), "blueeconomy-keydir-bad-"));
  const empty = join(directory, "empty.json");
  await writeFile(empty, "");
  await assert.rejects(() => loadKeyDirectory(empty), /1 to/);
  const notJson = join(directory, "not-json.json");
  await writeFile(notJson, "{nope");
  await assert.rejects(() => loadKeyDirectory(notJson), /not valid JSON/);
  const emptyObject = join(directory, "empty-object.json");
  await writeFile(emptyObject, "{}");
  await assert.rejects(() => loadKeyDirectory(emptyObject), /at least one key/);
  const badKey = join(directory, "bad-key.json");
  await writeFile(badKey, JSON.stringify({ "k-0": "AAAA" }));
  await assert.rejects(() => loadKeyDirectory(badKey), /32-byte Ed25519/);
  const badKid = join(directory, "bad-kid.json");
  await writeFile(badKid, JSON.stringify({ "bad kid!": "AAAA" }));
  await assert.rejects(() => loadKeyDirectory(badKid), /malformed kid/);
});

test("key directory env loader requires KEY_DIRECTORY_PATH", async () => {
  await assert.rejects(() => loadKeyDirectoryFromEnv({}), /KEY_DIRECTORY_PATH is required/);
  const { publicKey } = testKeyPair();
  const path = await writeDirectory({ [TEST_KID]: await publicKeyBase64Url(publicKey) });
  const directory = await loadKeyDirectoryFromEnv({ KEY_DIRECTORY_PATH: path });
  assert.ok(directory.resolve(TEST_KID) !== undefined);
});

test("valid fleet signature verifies and returns the kid", async () => {
  const { privateKey, publicKey } = testKeyPair();
  const envelope = sampleEnvelope();
  (envelope["provenance"] as Record<string, unknown>)["signature"] = await signEnvelope(envelope, privateKey, TEST_KID);
  const directory = await directoryFor(TEST_KID, await publicKeyBase64Url(publicKey));
  const metrics = new RecordingMetrics();
  const kid = await verifyEnvelopeSignature(envelope, directory, metrics);
  assert.equal(kid, TEST_KID);
  assert.equal(metrics.verified, 1);
  assert.deepEqual(metrics.rejected, {});
});

test("python data-platform signature verifies (cross-language interop vector)", async () => {
  // Vector produced by blueeconomy-data-platform signature_verification.py
  // (RFC 8785 canonicalizer + JWS compact EdDSA), proving byte-level agreement.
  const vector = {
    kid: "interop-producer-7",
    publicKeyBase64Url: "SBfGjv_9Lz6e9iSFpkZlQS3UQi19qfMkM4gO8nVsfHw",
    signature:
      "eyJhbGciOiJFZERTQSIsImtpZCI6ImludGVyb3AtcHJvZHVjZXItNyJ9.eyJjbGFzc2lmaWNhdGlvbiI6IkNPTkZJREVOVElBTCIsImNvcnJlbGF0aW9uSWQiOiJpbnRlcm9wLWNvcnItMDAwMSIsImVudmVsb3BlVmVyc2lvbiI6IjEuMCIsImV2ZW50SWQiOiI5ZjhlN2Q2Yy01YjRhLTQzMTktODI3My0xNDA1MDYwNzA4MDkiLCJldmVudFR5cGUiOiJpbnRlcm9wLnNpZ25hdHVyZS52MSIsImZoaXIiOnsiZW50cnkiOlt7InJlc291cmNlIjp7Im5vdGUiOiJjcm9zcy1sYW5ndWFnZSB2w6ljdG9yIPCfmIAiLCJzZXEiOjMsIndlaWdodCI6MC4xfX1dLCJyZXNvdXJjZVR5cGUiOiJCdW5kbGUiLCJ0eXBlIjoibWVzc2FnZSJ9LCJvY2N1cnJlZEF0IjoiMjAyNi0wOC0yOFQwMDowMDowMFoiLCJwcm9kdWNlciI6ImludGVyb3AtcHJvZHVjZXIiLCJwcm92ZW5hbmNlIjp7ImxlZGdlckNvbW1pdEhhc2giOiJkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkIiwicHJpbmNpcGFsSWQiOiJzdmMtaW50ZXJvcCIsInByaW5jaXBhbFJvbGUiOiJpbnRlcm9wLXRlc3RlciJ9fQ.8A2RdOILa_elkF26RcoYIHKmtuViSJFAl9qQCsMdaKgTiGhkLDk8r15PzJnx7XPWbjdtsG50vd3xlUOhEurSBA",
  };
  const envelope = sampleEnvelope();
  envelope["eventId"] = "9f8e7d6c-5b4a-4319-8273-140506070809";
  envelope["eventType"] = "interop.signature.v1";
  envelope["occurredAt"] = "2026-08-28T00:00:00Z";
  envelope["producer"] = "interop-producer";
  envelope["correlationId"] = "interop-corr-0001";
  envelope["fhir"] = {
    resourceType: "Bundle",
    type: "message",
    entry: [{ resource: { note: "cross-language véctor 😀", seq: 3, weight: 0.1 } }],
  };
  envelope["provenance"] = {
    principalId: "svc-interop",
    principalRole: "interop-tester",
    signature: vector.signature,
    ledgerCommitHash: "d".repeat(64),
  };
  const directory = await directoryFor(vector.kid, vector.publicKeyBase64Url);
  assert.equal(await verifyEnvelopeSignature(envelope, directory), vector.kid);
});

test("unknown kid is rejected and counted", async () => {
  const { privateKey, publicKey } = testKeyPair();
  const envelope = sampleEnvelope();
  (envelope["provenance"] as Record<string, unknown>)["signature"] = await signEnvelope(envelope, privateKey, "attacker-9");
  const directory = await directoryFor(TEST_KID, await publicKeyBase64Url(publicKey));
  const metrics = new RecordingMetrics();
  await assert.rejects(
    () => verifyEnvelopeSignature(envelope, directory, metrics),
    (error: unknown) => error instanceof EnvelopeVerificationError && error.reason === "unknown-kid",
  );
  assert.deepEqual(metrics.rejected, { "unknown-kid": 1 });
});

test("post-signing envelope mutation is a payload mismatch", async () => {
  const { privateKey, publicKey } = testKeyPair();
  const envelope = sampleEnvelope();
  (envelope["provenance"] as Record<string, unknown>)["signature"] = await signEnvelope(envelope, privateKey, TEST_KID);
  envelope["correlationId"] = "attacker-override";
  const directory = await directoryFor(TEST_KID, await publicKeyBase64Url(publicKey));
  await assert.rejects(
    () => verifyEnvelopeSignature(envelope, directory),
    (error: unknown) => error instanceof EnvelopeVerificationError && error.reason === "payload-mismatch",
  );
});

test("tampered signature is rejected", async () => {
  const { privateKey, publicKey } = testKeyPair();
  const envelope = sampleEnvelope();
  const jws = await signEnvelope(envelope, privateKey, TEST_KID);
  const segments = jws.split(".");
  segments[2] = (segments[2]!.startsWith("A") ? "B" : "A") + segments[2]!.slice(1);
  (envelope["provenance"] as Record<string, unknown>)["signature"] = segments.join(".");
  const directory = await directoryFor(TEST_KID, await publicKeyBase64Url(publicKey));
  await assert.rejects(
    () => verifyEnvelopeSignature(envelope, directory),
    (error: unknown) => error instanceof EnvelopeVerificationError && error.reason === "invalid-signature",
  );
});

test("unsupported algorithm header is rejected", async () => {
  const { privateKey, publicKey } = testKeyPair();
  const envelope = sampleEnvelope();
  const payload = Buffer.from(signedPayload(envelope)).toString("base64url");
  const header = Buffer.from(JSON.stringify({ alg: "none", kid: TEST_KID })).toString("base64url");
  void privateKey;
  (envelope["provenance"] as Record<string, unknown>)["signature"] = `${header}.${payload}.AAAA`;
  const directory = await directoryFor(TEST_KID, await publicKeyBase64Url(publicKey));
  await assert.rejects(
    () => verifyEnvelopeSignature(envelope, directory),
    (error: unknown) => error instanceof EnvelopeVerificationError && error.reason === "unsupported-alg",
  );
});

test("malformed compact serializations are rejected", async () => {
  const { publicKey } = testKeyPair();
  const directory = await directoryFor(TEST_KID, await publicKeyBase64Url(publicKey));
  for (const signature of ["not-a-jws", "two.segments", "a.b.c.d", "", "aa==.bb.cc"]) {
    const envelope = sampleEnvelope(signature);
    await assert.rejects(
      () => verifyEnvelopeSignature(envelope, directory),
      (error: unknown) => error instanceof EnvelopeVerificationError && error.reason === "malformed-jws",
      `expected malformed-jws for ${JSON.stringify(signature)}`,
    );
  }
});

test("missing provenance or non-string signature is rejected", async () => {
  const { publicKey } = testKeyPair();
  const directory = await directoryFor(TEST_KID, await publicKeyBase64Url(publicKey));
  const envelope = sampleEnvelope();
  delete envelope["provenance"];
  await assert.rejects(() => verifyEnvelopeSignature(envelope, directory), /no provenance object/);
  const second = sampleEnvelope(42 as unknown as string);
  await assert.rejects(() => verifyEnvelopeSignature(second, directory), /not text/);
});
