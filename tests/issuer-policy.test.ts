import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { loadApprovedIssuerPolicy } from "../src/issuer-policy.js";

const expected = { issuer: "https://issuer.example.test/", audience: "fmmbe", jwksUrl: new URL("https://issuer.example.test/.well-known/jwks.json"), algorithm: "RS256" };

async function policyFile(overrides: Record<string, unknown> = {}) {
  const directory = await mkdtemp(join(tmpdir(), "blueeconomy-issuer-policy-"));
  const path = join(directory, "policy.json");
  await writeFile(path, JSON.stringify({ schema_version: "blueeconomy.credential.issuer-policy.v1", issuer: expected.issuer, audience: expected.audience, jwks_url: expected.jwksUrl.toString(), algorithms: ["RS256"], active: true, ...overrides }));
  return path;
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
  await assert.rejects(() => loadApprovedIssuerPolicy(path, expected), /algorithm is not approved/);
});
