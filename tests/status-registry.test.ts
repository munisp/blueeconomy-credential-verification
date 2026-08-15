import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair } from "jose";
import { test } from "node:test";
import assert from "node:assert/strict";
import { StatusRegistry, verifyStatusRecord } from "../src/status-registry.js";

test("status registry persists signed lifecycle and returns latest status", async () => {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const directory = await mkdtemp(join(tmpdir(), "blueeconomy-status-"));
  const registry = new StatusRegistry({ path: join(directory, "status.jsonl"), issuer: "https://issuer.example.test", key: privateKey, algorithm: "RS256", keyId: "key-2026-01" });

  assert.equal((await registry.lookup("jti-unknown", publicKey)).status, "UNKNOWN");
  const active = await registry.setStatus("jti-001", "ACTIVE", "issued", "issuer-operator");
  const revoked = await registry.setStatus("jti-001", "REVOKED", "credential compromised", "revocation-officer");
  assert.equal(active.claims.sequence, 1);
  assert.equal(revoked.claims.sequence, 2);
  assert.equal((await registry.lookup("jti-001", publicKey)).status, "REVOKED");
  assert.equal((await verifyStatusRecord(revoked, publicKey, "RS256")).status, "REVOKED");
});

test("status registry rejects modified signed records and non-contiguous sequences", async () => {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const directory = await mkdtemp(join(tmpdir(), "blueeconomy-status-tamper-"));
  const path = join(directory, "status.jsonl");
  const registry = new StatusRegistry({ path, issuer: "https://issuer.example.test", key: privateKey, algorithm: "RS256", keyId: "key-2026-01" });
  const record = await registry.setStatus("jti-002", "SUSPENDED", "investigation", "issuer-operator");
  await assert.rejects(() => verifyStatusRecord({ ...record, claims: { ...record.claims, status: "ACTIVE" } }, publicKey, "RS256"));
  const content = await readFile(path, "utf8");
  await writeFile(path, `${content}${JSON.stringify({ ...record, claims: { ...record.claims, sequence: 3 } })}\n`);
  await assert.rejects(() => registry.lookup("jti-002", publicKey), /sequence is not contiguous/);
});
