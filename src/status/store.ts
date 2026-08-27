import { createHash } from "node:crypto";
import type { CredentialStatus } from "../status-registry.js";

export { type CredentialStatus };

export interface StatusEntry {
  credentialId: string;
  status: CredentialStatus;
  reason: string;
  updatedBy: string;
  issuer: string;
  statusListId: string;
  statusListIndex: number;
  effectiveAt?: Date;
}

export interface StatusRecord {
  credentialIdReferenceSha256: string;
  issuer: string;
  status: CredentialStatus;
  reason: string;
  statusListId: string;
  statusListIndex: number;
  updatedBy: string;
  effectiveAt: string;
  updatedAt: string;
  sequence: number;
}

export interface StatusListBitRow {
  statusListIndex: number;
  revoked: boolean;
}

export interface OutboxMessage {
  topic: string;
  eventId: string;
  payload: Record<string, unknown>;
}

/**
 * Durable credential status/revocation store. Production deployments use the
 * PostgreSQL implementation; the JSONL file store exists only behind the
 * explicit BLUEECONOMY_STATUS_JSONL_TEST_PATH test flag.
 */
export interface StatusStore {
  setStatus(entry: StatusEntry, outbox?: OutboxMessage): Promise<StatusRecord>;
  getStatus(credentialId: string, issuer: string): Promise<StatusRecord | undefined>;
  listStatusBits(issuer: string, statusListId: string): Promise<StatusListBitRow[]>;
  healthCheck(): Promise<void>;
  close(): Promise<void>;
}

export function credentialIdReference(credentialId: string): string {
  if (credentialId.trim() !== credentialId || credentialId.length === 0 || credentialId.length > 256) {
    throw new Error("credential id must be canonical non-empty text of at most 256 characters");
  }
  return createHash("sha256").update(credentialId, "utf8").digest("hex");
}

export function assertStatusEntry(entry: StatusEntry): void {
  credentialIdReference(entry.credentialId);
  if (entry.status !== "ACTIVE" && entry.status !== "SUSPENDED" && entry.status !== "REVOKED") {
    throw new Error("status must be ACTIVE, SUSPENDED or REVOKED");
  }
  if (entry.reason.trim() !== entry.reason || entry.reason.length === 0 || entry.reason.length > 512) {
    throw new Error("reason must be canonical text of 1-512 characters");
  }
  if (entry.updatedBy.trim() !== entry.updatedBy || entry.updatedBy.length === 0 || entry.updatedBy.length > 256) {
    throw new Error("updatedBy must be canonical text of 1-256 characters");
  }
  if (entry.issuer.trim() !== entry.issuer || entry.issuer.length === 0 || entry.issuer.length > 512) {
    throw new Error("issuer must be canonical text of 1-512 characters");
  }
  if (!/^[A-Za-z0-9._:/-]{1,512}$/.test(entry.statusListId)) {
    throw new Error("status list id must be a canonical identifier or URL");
  }
  if (!Number.isInteger(entry.statusListIndex) || entry.statusListIndex < 0 || entry.statusListIndex >= 1_048_576) {
    throw new Error("status list index must be an integer within the bitstring range");
  }
  if (entry.effectiveAt !== undefined && !Number.isFinite(entry.effectiveAt.getTime())) {
    throw new Error("effectiveAt must be a valid date");
  }
}
