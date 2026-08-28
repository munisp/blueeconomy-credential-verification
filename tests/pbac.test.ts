import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { PolicyEngine, type PolicyRequest } from "../src/auth/pbac.js";

const SHIPPED_POLICY_DIRECTORY = new URL("../policies", import.meta.url).pathname;

function request(overrides: Partial<PolicyRequest> = {}): PolicyRequest {
  return {
    roles: new Set(["seafarer"]),
    resource: "wallet",
    action: "read",
    ...overrides,
  };
}

async function writePolicyDirectory(files: Record<string, unknown>): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "blueeconomy-pbac-"));
  for (const [name, document] of Object.entries(files)) {
    await writeFile(join(directory, name), typeof document === "string" ? document : JSON.stringify(document));
  }
  return directory;
}

test("shipped policy directory loads and encodes the route matrix", async () => {
  const engine = await PolicyEngine.load(SHIPPED_POLICY_DIRECTORY);
  // Allow cases: one per shipped rule.
  assert.equal(engine.evaluate(request({ roles: new Set(["nimasa-approver"]), resource: "credential", action: "issue", classification: "CONFIDENTIAL" })).allowed, true);
  assert.equal(engine.evaluate(request({ roles: new Set(["nimasa-approver"]), resource: "credential", action: "revoke", classification: "CONFIDENTIAL" })).allowed, true);
  assert.equal(engine.evaluate(request({ roles: new Set(["employer"]), resource: "credential", action: "verify", classification: "CONFIDENTIAL" })).allowed, true);
  assert.equal(engine.evaluate(request({ roles: new Set(["psc-inspector"]), resource: "credential", action: "verify", classification: "CONFIDENTIAL" })).allowed, true);
  assert.equal(engine.evaluate(request({ roles: new Set(["seafarer"]), resource: "wallet", action: "read", classification: "CONFIDENTIAL" })).allowed, true);
  assert.equal(engine.evaluate(request({ roles: new Set(["auditor"]), resource: "status-list", action: "read", classification: "CONFIDENTIAL" })).allowed, true);
});

test("deny-by-default: unmatched roles, resources, actions and classifications", async () => {
  const engine = await PolicyEngine.load(SHIPPED_POLICY_DIRECTORY);
  // Role not listed for the action.
  assert.equal(engine.evaluate(request({ roles: new Set(["seafarer"]), resource: "credential", action: "issue", classification: "CONFIDENTIAL" })).allowed, false);
  assert.equal(engine.evaluate(request({ roles: new Set(["employer"]), resource: "credential", action: "revoke", classification: "CONFIDENTIAL" })).allowed, false);
  // Auditor (read-only oversight) can never issue/revoke/verify.
  assert.equal(engine.evaluate(request({ roles: new Set(["auditor"]), resource: "credential", action: "issue", classification: "CONFIDENTIAL" })).allowed, false);
  assert.equal(engine.evaluate(request({ roles: new Set(["auditor"]), resource: "credential", action: "verify", classification: "CONFIDENTIAL" })).allowed, false);
  // Unknown resource/action combinations.
  assert.equal(engine.evaluate(request({ roles: new Set(["nimasa-approver"]), resource: "ledger", action: "write" })).allowed, false);
  assert.equal(engine.evaluate(request({ roles: new Set(["nimasa-approver"]), resource: "credential", action: "read" })).allowed, false);
  // Classification outside the rule's list.
  assert.equal(engine.evaluate(request({ roles: new Set(["nimasa-approver"]), resource: "credential", action: "issue", classification: "FIDUCIARY_SEGREGATED" })).allowed, false);
  // No roles at all.
  assert.equal(engine.evaluate(request({ roles: new Set(), resource: "wallet", action: "read", classification: "CONFIDENTIAL" })).allowed, false);
});

test("tenant and clearance dimensions narrow the match", async () => {
  const directory = await writePolicyDirectory({
    "scoped.policy.json": {
      version: "1.0",
      policies: [
        { name: "tenant-a-reads", roles: ["seafarer"], tenant: "tenant-a", resource: "wallet", action: "read", clearance: ["CONFIDENTIAL"] },
      ],
    },
  });
  const engine = await PolicyEngine.load(directory);
  const base = request({ resource: "wallet", action: "read" });
  assert.equal(engine.evaluate({ ...base, tenant: "tenant-a", clearance: "CONFIDENTIAL" }).allowed, true);
  assert.equal(engine.evaluate({ ...base, tenant: "tenant-b", clearance: "CONFIDENTIAL" }).allowed, false);
  assert.equal(engine.evaluate({ ...base, tenant: "tenant-a", clearance: "SECRET" }).allowed, false);
  assert.equal(engine.evaluate({ ...base, tenant: "tenant-a" }).allowed, false, "missing clearance claim cannot satisfy a clearance rule");
  assert.equal(engine.evaluate({ ...base, clearance: "CONFIDENTIAL" }).allowed, false, "missing tenant cannot satisfy a tenant rule");
});

test("wildcard dimensions match anything", async () => {
  const directory = await writePolicyDirectory({
    "wild.policy.json": {
      version: "1.0",
      policies: [
        { name: "wild", roles: ["*"], tenant: "*", resource: "status-list", action: "*", classification: ["*"] },
      ],
    },
  });
  const engine = await PolicyEngine.load(directory);
  assert.equal(engine.evaluate(request({ roles: new Set(["anything"]), resource: "status-list", action: "read" })).allowed, true);
  assert.equal(engine.evaluate(request({ roles: new Set(["anything"]), resource: "status-list", action: "purge" })).allowed, true);
  assert.equal(engine.evaluate(request({ roles: new Set(["anything"]), resource: "wallet", action: "read" })).allowed, false);
});

test("boot fails closed without a directory or policy files", async () => {
  await assert.rejects(() => PolicyEngine.load(join(tmpdir(), "definitely-absent-policy-dir")), /not readable/);
  const empty = await mkdtemp(join(tmpdir(), "blueeconomy-pbac-empty-"));
  await assert.rejects(() => PolicyEngine.load(empty), /no \*\.policy\.json files/);
  const noRules = await writePolicyDirectory({ "empty.policy.json": { version: "1.0", policies: [] } });
  await assert.rejects(() => PolicyEngine.load(noRules), /no allow rules/);
  await assert.rejects(() => PolicyEngine.fromEnv({}), /POLICY_DIR is required/);
});

test("boot fails closed on malformed policy documents", async () => {
  const cases: Record<string, unknown> = {
    "not-json.policy.json": "{invalid",
    "wrong-version.policy.json": { version: "2.0", policies: [] },
    "no-roles.policy.json": { version: "1.0", policies: [{ name: "x", roles: [], resource: "a", action: "b" }] },
    "bad-classification.policy.json": { version: "1.0", policies: [{ name: "x", roles: ["a"], resource: "b", action: "c", classification: ["TOP-SECRET"] }] },
    "unknown-field.policy.json": { version: "1.0", policies: [{ name: "x", roles: ["a"], resource: "b", action: "c", effect: "allow" }] },
    "bad-name.policy.json": { version: "1.0", policies: [{ name: "bad name!", roles: ["a"], resource: "b", action: "c" }] },
  };
  for (const [name, document] of Object.entries(cases)) {
    const directory = await writePolicyDirectory({ [name]: document });
    await assert.rejects(() => PolicyEngine.load(directory), /fail-closed|invalid/, `expected ${name} to be rejected`);
  }
});

test("duplicate rule names across files fail closed", async () => {
  const directory = await mkdtemp(join(tmpdir(), "blueeconomy-pbac-dupe-"));
  const rule = { name: "same", roles: ["a"], resource: "b", action: "c" };
  await writeFile(join(directory, "one.policy.json"), JSON.stringify({ version: "1.0", policies: [rule] }));
  await writeFile(join(directory, "two.policy.json"), JSON.stringify({ version: "1.0", policies: [rule] }));
  await assert.rejects(() => PolicyEngine.load(directory), /duplicated/);
});

test("fromEnv loads the configured directory", async () => {
  const engine = await PolicyEngine.fromEnv({ POLICY_DIR: SHIPPED_POLICY_DIRECTORY });
  assert.equal(engine.evaluate(request({ roles: new Set(["seafarer"]), resource: "wallet", action: "read", classification: "CONFIDENTIAL" })).allowed, true);
});

test("mkdir-prefixed nested policy directories are not required", async () => {
  const directory = await mkdtemp(join(tmpdir(), "blueeconomy-pbac-flat-"));
  await mkdir(join(directory, "nested"));
  await writeFile(join(directory, "flat.policy.json"), JSON.stringify({ version: "1.0", policies: [{ name: "r", roles: ["a"], resource: "b", action: "c" }] }));
  const engine = await PolicyEngine.load(directory);
  assert.equal(engine.evaluate({ roles: new Set(["a"]), resource: "b", action: "c" }).allowed, true);
});
