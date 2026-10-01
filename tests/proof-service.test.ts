import { randomBytes } from "node:crypto";
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  createProofServiceHandler,
  canonicalJson,
  PROOF_SIGNING_KEY_ENV,
  PROOF_KEY_ID_ENV,
} from "../src/proof-service.js";

// Test-only key material generated per run; never committed, never reused in production.
const testKey = randomBytes(32).toString("hex");
const handler = createProofServiceHandler({
  signingKey: testKey,
  keyId: "proof-key-2026-01",
  domains: ["ferry-ticket-proof", "credential-proof"],
});

const claims = {
  ticketId: "tkt-001",
  tripId: "trip-001",
  operatorId: "op-001",
  state: "ISSUED",
  fareNgnMinor: 250000,
  passengerDigestSha256: randomBytes(32).toString("hex"),
  version: 1,
};

test("artifact issuance and verify round-trip with domain separation", async () => {
  const keys = await handler(new Request("https://proof.test/v1/proof/verification-keys"));
  assert.equal(keys.status, 200);
  const keysBody = await keys.json();
  assert.equal(keysBody.keys[0].keyId, "proof-key-2026-01");
  assert.equal(keysBody.keys[0].algorithm, "HMAC-SHA256");
  assert.equal(keysBody.keys[0].distribution, "out-of-band");

  const issued = await handler(
    new Request("https://proof.test/v1/proof/artifact", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ domain: "ferry-ticket-proof", claims }),
    }),
  );
  assert.equal(issued.status, 200);
  const artifact = await issued.json();
  assert.equal(artifact.keyId, "proof-key-2026-01");
  assert.equal(artifact.algorithm, "HMAC-SHA256");
  assert.match(artifact.signature, /^[0-9a-f]{64}$/);

  const verified = await handler(
    new Request("https://proof.test/v1/proof/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ domain: "ferry-ticket-proof", claims: artifact.claims, keyId: artifact.keyId, signature: artifact.signature }),
    }),
  );
  assert.equal(verified.status, 200);
  const result = await verified.json();
  assert.equal(result.valid, true);
});

test("verify rejects tampered claims and wrong-domain signatures", async () => {
  const issued = await handler(
    new Request("https://proof.test/v1/proof/artifact", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ domain: "ferry-ticket-proof", claims }),
    }),
  );
  const artifact = await issued.json();

  const tampered = await handler(
    new Request("https://proof.test/v1/proof/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        domain: "ferry-ticket-proof",
        claims: { ...artifact.claims, state: "BOARDED" },
        keyId: artifact.keyId,
        signature: artifact.signature,
      }),
    }),
  );
  assert.equal((await tampered.json()).valid, false);

  const wrongDomain = await handler(
    new Request("https://proof.test/v1/proof/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        domain: "credential-proof",
        claims: artifact.claims,
        keyId: artifact.keyId,
        signature: artifact.signature,
      }),
    }),
  );
  assert.equal((await wrongDomain.json()).valid, false);

  const unapproved = await handler(
    new Request("https://proof.test/v1/proof/artifact", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ domain: "unapproved-domain", claims }),
    }),
  );
  assert.equal(unapproved.status, 403);
});

test("unconfigured signing key fails closed with 503 on every endpoint", async () => {
  const unconfigured = createProofServiceHandler({ env: {}, domains: ["ferry-ticket-proof"] });
  const keys = await unconfigured(new Request("https://proof.test/v1/proof/verification-keys"));
  assert.equal(keys.status, 503);
  const issue = await unconfigured(
    new Request("https://proof.test/v1/proof/artifact", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ domain: "ferry-ticket-proof", claims }),
    }),
  );
  assert.equal(issue.status, 503);
  const verify = await unconfigured(
    new Request("https://proof.test/v1/proof/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ domain: "ferry-ticket-proof", claims, keyId: "proof-key-2026-01", signature: "0".repeat(64) }),
    }),
  );
  assert.equal(verify.status, 503);
  const shortKey = createProofServiceHandler({ signingKey: "too-short", domains: ["ferry-ticket-proof"] });
  assert.equal((await shortKey(new Request("https://proof.test/v1/proof/verification-keys"))).status, 503);
});

test("env-only key configuration is honoured and canonical json is stable", async () => {
  const envHandler = createProofServiceHandler({
    env: { [PROOF_SIGNING_KEY_ENV]: testKey, [PROOF_KEY_ID_ENV]: "env-key-1" },
    domains: ["credential-proof"],
  });
  const keys = await envHandler(new Request("https://proof.test/v1/proof/verification-keys"));
  assert.equal((await keys.json()).keys[0].keyId, "env-key-1");
  assert.equal(canonicalJson({ b: 1, a: { d: 2, c: 3 } }), canonicalJson({ a: { c: 3, d: 2 }, b: 1 }));
});
