import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { SignJWT, generateKeyPair } from "jose";

import { assertApprovedIssuerKeyId, loadApprovedIssuerPolicy } from "../src/issuer-policy.js";
import { assertCredentialProtectedHeader } from "../src/verify.js";

const expected = {
  issuer: "https://issuer.example.test/",
  audience: "fmmbe",
  jwksUrl: new URL("https://issuer.example.test/.well-known/jwks.json"),
  algorithm: "RS256",
};

async function policyFile(overrides: Record<string, unknown> = {}) {
  const directory = await mkdtemp(join(tmpdir(), "blueeconomy-issuer-policy-"));
  const path = join(directory, "policy.json");
  await writeFile(path, JSON.stringify({
    schema_version: "blueeconomy.credential.issuer-policy.v1",
    issuer: expected.issuer,
    audience: expected.audience,
    jwks_url: expected.jwksUrl.toString(),
    algorithms: ["RS256"],
    active: true,
    ...overrides,
  }));
  return path;
}

async function signedCredential(kid?: string): Promise<string> {
  const { privateKey } = await generateKeyPair("RS256");
  const header: { alg: "RS256"; kid?: string } = { alg: "RS256" };
  if (kid !== undefined) header.kid = kid;
  return new SignJWT({ scope: "credential-status" })
    .setProtectedHeader(header)
    .setIssuer(expected.issuer)
    .setAudience(expected.audience)
    .setSubject("holder-001")
    .setJti("credential-001")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);
}

test("accepts an active approved issuer policy", async () => {
  const policy = await loadApprovedIssuerPolicy(await policyFile(), expected);
  assert.equal(policy.issuer, expected.issuer);
});

test("rejects a policy with a different issuer or JWKS URL", async () => {
  const path = await policyFile({ issuer: "https://other.example.test/" });
  await assert.rejects(() => loadApprovedIssuerPolicy(path, expected), /does not match/);
});

test("rejects a policy that does not approve the selected algorithm", async () => {
  const path = await policyFile({ algorithms: ["RS384"] });
  await assert.rejects(() => loadApprovedIssuerPolicy(path, expected), /algorithms must be a unique nonempty allowlist/);
});

test("requires unique canonical KIDs when an issuer policy pins keys", async () => {
  const whitespace = await policyFile({ key_ids: ["issuer key"] });
  await assert.rejects(() => loadApprovedIssuerPolicy(whitespace, expected), /key_ids must be a unique nonempty canonical allowlist/);
  const duplicate = await policyFile({ key_ids: ["issuer-key-2026-a", "issuer-key-2026-a"] });
  await assert.rejects(() => loadApprovedIssuerPolicy(duplicate, expected), /key_ids must be a unique nonempty canonical allowlist/);
});

test("pins a real signed JWT protected-header KID to the approved issuer policy", async () => {
  const policy = await loadApprovedIssuerPolicy(
    await policyFile({ key_ids: ["issuer-key-2026-a"] }),
    expected,
  );
  const credential = await signedCredential("issuer-key-2026-a");
  assert.equal(assertCredentialProtectedHeader(credential, "RS256", policy), "issuer-key-2026-a");
  assert.doesNotThrow(() => assertApprovedIssuerKeyId(policy, "issuer-key-2026-a"));
});

test("rejects a missing or unapproved KID before JWKS resolution", async () => {
  const policy = await loadApprovedIssuerPolicy(
    await policyFile({ key_ids: ["issuer-key-2026-a"] }),
    expected,
  );
  const missing = await signedCredential();
  assert.throws(
    () => assertCredentialProtectedHeader(missing, "RS256", policy),
    /kid is required/,
  );
  const unapproved = await signedCredential("issuer-key-2026-b");
  assert.throws(
    () => assertCredentialProtectedHeader(unapproved, "RS256", policy),
    /kid is not approved/,
  );
});
