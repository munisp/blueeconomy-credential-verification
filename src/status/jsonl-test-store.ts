import { readFile } from "node:fs/promises";
import { generateKeyPairSync } from "node:crypto";
import { StatusRegistry } from "../status-registry.js";
import {
  assertStatusEntry,
  credentialIdReference,
  type CredentialStatus,
  type HolderCredentialRecord,
  type StatusEntry,
  type StatusListBitRow,
  type StatusRecord,
  type StatusStore,
} from "./store.js";

interface JsonlLine {
  protected_jws: string;
  claims: {
    schema_version: string;
    sequence: number;
    credential_id_reference_sha256: string;
    status: CredentialStatus;
    reason: string;
    effective_at: string;
    updated_by: string;
    issuer: string;
  };
}

/**
 * TEST-ONLY single-process JSONL status store. Enabled exclusively via the
 * BLUEECONOMY_STATUS_JSONL_TEST_PATH flag; createStatusStoreFromEnv refuses
 * to select it when a production database URL is present. Exists so unit
 * tests and local tooling can run without a PostgreSQL instance.
 */
export function createJsonlTestStatusStore(path: string, env: NodeJS.ProcessEnv): StatusStore {
  if (env["BLUEECONOMY_STATUS_JSONL_TEST_PATH"] === undefined) {
    throw new Error("JSONL status store requires the explicit BLUEECONOMY_STATUS_JSONL_TEST_PATH test flag");
  }
  const issuer = env["BLUEECONOMY_STATUS_ISSUER"] ?? "did:web:credentials.nimasa.gov.ng";
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const registry = new StatusRegistry({ path, issuer, key: privateKey as never, algorithm: "RS256", keyId: "jsonl-test-key" });
  const placementByCredential = new Map<string, { statusListId: string; statusListIndex: number }>();
  const holderCredentials = new Map<string, { holderId: string; document: Record<string, unknown>; validUntil: Date }>();

  async function readLines(): Promise<JsonlLine[]> {
    let content: string;
    try {
      content = await readFile(path, "utf8");
    } catch (error) {
      if (typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT") return [];
      throw error;
    }
    return content.split("\n").filter((line) => line.length > 0).map((line) => JSON.parse(line) as JsonlLine);
  }

  return {
    async setStatus(entry: StatusEntry): Promise<StatusRecord> {
      assertStatusEntry(entry);
      const effectiveAt = entry.effectiveAt ?? new Date();
      const record = await registry.setStatus(entry.credentialId, entry.status, entry.reason, entry.updatedBy, effectiveAt);
      placementByCredential.set(entry.credentialId, { statusListId: entry.statusListId, statusListIndex: entry.statusListIndex });
      if (entry.issuance !== undefined) {
        holderCredentials.set(entry.credentialId, {
          holderId: entry.issuance.holderId,
          document: entry.issuance.document,
          validUntil: entry.issuance.validUntil,
        });
      }
      return {
        credentialIdReferenceSha256: record.claims.credential_id_reference_sha256,
        issuer: record.claims.issuer,
        status: record.claims.status,
        reason: record.claims.reason,
        statusListId: entry.statusListId,
        statusListIndex: entry.statusListIndex,
        updatedBy: record.claims.updated_by,
        effectiveAt: record.claims.effective_at,
        updatedAt: record.claims.effective_at,
        sequence: record.claims.sequence,
      };
    },
    async getStatus(credentialId: string, requestedIssuer: string): Promise<StatusRecord | undefined> {
      if (requestedIssuer !== issuer) return undefined;
      const lines = await readLines();
      const reference = credentialIdReference(credentialId);
      const matches = lines.filter((line) => line.claims.credential_id_reference_sha256 === reference);
      const latest = matches[matches.length - 1];
      if (latest === undefined) return undefined;
      const placement = placementByCredential.get(credentialId) ?? { statusListId: "unknown", statusListIndex: 0 };
      return {
        credentialIdReferenceSha256: latest.claims.credential_id_reference_sha256,
        issuer: latest.claims.issuer,
        status: latest.claims.status,
        reason: latest.claims.reason,
        statusListId: placement.statusListId,
        statusListIndex: placement.statusListIndex,
        updatedBy: latest.claims.updated_by,
        effectiveAt: latest.claims.effective_at,
        updatedAt: latest.claims.effective_at,
        sequence: latest.claims.sequence,
      };
    },
    async listStatusBits(requestedIssuer: string, statusListId: string): Promise<StatusListBitRow[]> {
      if (requestedIssuer !== issuer) return [];
      const latestByReference = new Map<string, CredentialStatus>();
      for (const line of await readLines()) {
        latestByReference.set(line.claims.credential_id_reference_sha256, line.claims.status);
      }
      const rows: StatusListBitRow[] = [];
      for (const [credentialId, placement] of placementByCredential) {
        if (placement.statusListId !== statusListId) continue;
        const status = latestByReference.get(credentialIdReference(credentialId));
        if (status !== undefined) {
          rows.push({ statusListIndex: placement.statusListIndex, revoked: status === "REVOKED" });
        }
      }
      return rows.sort((left, right) => left.statusListIndex - right.statusListIndex);
    },
    async listCurrentHolderCredentials(holderId: string, requestedIssuer: string): Promise<HolderCredentialRecord[]> {
      if (requestedIssuer !== issuer) return [];
      const latestByReference = new Map<string, CredentialStatus>();
      for (const line of await readLines()) {
        latestByReference.set(line.claims.credential_id_reference_sha256, line.claims.status);
      }
      const now = Date.now();
      const records: HolderCredentialRecord[] = [];
      for (const [credentialId, held] of [...holderCredentials.entries()].reverse()) {
        if (held.holderId !== holderId) continue;
        if (held.validUntil.getTime() <= now) continue;
        if (latestByReference.get(credentialIdReference(credentialId)) !== "ACTIVE") continue;
        records.push({ document: held.document, validUntil: held.validUntil.toISOString() });
      }
      return records;
    },
    async healthCheck(): Promise<void> {
      // File-backed test store has no liveness dependency.
    },
    async close(): Promise<void> {
      // Nothing to release.
    },
  };
}
