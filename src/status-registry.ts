import { createHash } from "node:crypto";
import { appendFile, mkdir, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { CompactSign, compactVerify } from "jose";

type SigningKey = Parameters<CompactSign["sign"]>[0];
type VerificationKey = Parameters<typeof compactVerify>[1];

export type CredentialStatus = "ACTIVE" | "SUSPENDED" | "REVOKED";

export interface StatusRegistryClaims {
  schema_version: "blueeconomy.credential.status.v1";
  sequence: number;
  credential_id_reference_sha256: string;
  status: CredentialStatus;
  reason: string;
  effective_at: string;
  updated_by: string;
  issuer: string;
}

export interface SignedStatusRecord {
  protected_jws: string;
  claims: StatusRegistryClaims;
}

export interface StatusLookup {
  status: CredentialStatus | "UNKNOWN";
  claims?: StatusRegistryClaims;
  protected_jws?: string;
}

export interface StatusRegistryConfiguration {
  path: string;
  issuer: string;
  key: SigningKey;
  algorithm: "RS256" | "RS384" | "RS512";
  keyId: string;
}

export interface VerifiedStatusRegistryConfiguration {
  path: string;
  issuer: string;
  key: VerificationKey;
  algorithm: "RS256" | "RS384" | "RS512";
  keyId?: string;
}

export class StatusRegistry {
  private writeChain: Promise<void> = Promise.resolve();
  private readonly path: string;

  public constructor(private readonly configuration: StatusRegistryConfiguration) {
    this.path = resolve(configuration.path);
    if (configuration.issuer.trim() !== configuration.issuer || configuration.issuer.length === 0) {
      throw new Error("registry issuer must be canonical non-empty text");
    }
    if (!isCanonicalKeyId(configuration.keyId)) {
      throw new Error("registry key id must be canonical non-empty text");
    }
  }

  public async setStatus(
    credentialId: string,
    status: CredentialStatus,
    reason: string,
    updatedBy: string,
    effectiveAt = new Date(),
  ): Promise<SignedStatusRecord> {
    if (credentialId.trim() !== credentialId || credentialId.length === 0) throw new Error("credential id must be canonical non-empty text");
    if (reason.trim() !== reason || reason.length === 0 || reason.length > 512) throw new Error("reason must be canonical text of 1-512 characters");
    if (updatedBy.trim() !== updatedBy || updatedBy.length === 0 || updatedBy.length > 256) throw new Error("updated_by must be canonical text of 1-256 characters");
    if (!Number.isFinite(effectiveAt.getTime())) throw new Error("effective_at must be a valid date");

    let result!: SignedStatusRecord;
    await this.enqueue(async () => {
      const previous = await readStatusRecords(this.path);
      const claims: StatusRegistryClaims = {
        schema_version: "blueeconomy.credential.status.v1",
        sequence: previous.length + 1,
        credential_id_reference_sha256: digest(credentialId),
        status,
        reason,
        effective_at: effectiveAt.toISOString(),
        updated_by: updatedBy,
        issuer: this.configuration.issuer,
      };
      const protectedJws = await new CompactSign(Buffer.from(JSON.stringify(claims), "utf8"))
        .setProtectedHeader({ alg: this.configuration.algorithm, kid: this.configuration.keyId, typ: "status+jws" })
        .sign(this.configuration.key);
      result = { protected_jws: protectedJws, claims };
      await mkdir(dirname(this.path), { recursive: true, mode: 0o750 });
      await appendFile(this.path, `${JSON.stringify(result)}\n`, { encoding: "utf8", mode: 0o640 });
    });
    return result;
  }

  public async lookup(credentialId: string, verificationKey?: VerificationKey): Promise<StatusLookup> {
    const reference = digest(credentialId);
    const records = await readStatusRecords(this.path);
    const matches = records.filter((record) => record.claims.credential_id_reference_sha256 === reference);
    if (matches.length === 0) return { status: "UNKNOWN" };
    const latest = matches[matches.length - 1];
    if (latest === undefined) throw new Error("status registry match disappeared");
    if (verificationKey !== undefined) await verifyStatusRecord(latest, verificationKey, this.configuration.algorithm, this.configuration.keyId);
    return { status: latest.claims.status, claims: latest.claims, protected_jws: latest.protected_jws };
  }

  private async enqueue(operation: () => Promise<void>): Promise<void> {
    const next = this.writeChain.then(operation, operation);
    this.writeChain = next.then(() => undefined, () => undefined);
    await next;
  }
}

/**
 * Reads a registry without signing capability. Every record is verified before
 * lookup, including unrelated records, to fail closed on chain corruption.
 */
export async function lookupVerifiedStatus(
  credentialId: string,
  configuration: VerifiedStatusRegistryConfiguration,
  now = new Date(),
): Promise<StatusLookup> {
  if (credentialId.trim() !== credentialId || credentialId.length === 0) throw new Error("credential id must be canonical non-empty text");
  if (configuration.issuer.trim() !== configuration.issuer || configuration.issuer.length === 0) throw new Error("registry issuer must be canonical non-empty text");
  if (configuration.keyId !== undefined && !isCanonicalKeyId(configuration.keyId)) throw new Error("registry verification key id must be canonical non-empty text");
  if (!Number.isFinite(now.getTime())) throw new Error("status evaluation time must be valid");

  const records = await readStatusRecords(resolve(configuration.path));
  const reference = digest(credentialId);
  let latest: SignedStatusRecord | undefined;
  for (const record of records) {
    const claims = await verifyStatusRecord(record, configuration.key, configuration.algorithm, configuration.keyId);
    if (claims.issuer !== configuration.issuer) throw new Error("status registry record issuer does not match configured issuer");
    const effectiveAt = new Date(claims.effective_at);
    if (!Number.isFinite(effectiveAt.getTime())) throw new Error("status registry effective_at is invalid");
    if (claims.credential_id_reference_sha256 === reference && effectiveAt <= now) latest = record;
  }
  if (latest === undefined) return { status: "UNKNOWN" };
  return { status: latest.claims.status, claims: latest.claims, protected_jws: latest.protected_jws };
}

export async function verifyStatusRecord(
  record: SignedStatusRecord,
  key: VerificationKey,
  algorithm: StatusRegistryConfiguration["algorithm"],
  expectedKeyId?: string,
): Promise<StatusRegistryClaims> {
  const verified = await compactVerify(record.protected_jws, key, { algorithms: [algorithm] });
  if (expectedKeyId !== undefined && verified.protectedHeader.kid !== expectedKeyId) {
    throw new Error("status record protected-header kid does not match approved verification key");
  }
  const claims = JSON.parse(new TextDecoder().decode(verified.payload)) as StatusRegistryClaims;
  if (JSON.stringify(claims) !== JSON.stringify(record.claims)) throw new Error("status record claims do not match signed payload");
  if (claims.schema_version !== "blueeconomy.credential.status.v1") throw new Error("unsupported status record schema");
  if (!isCredentialStatus(claims.status)) throw new Error("unsupported credential status");
  return claims;
}

async function readStatusRecords(path: string): Promise<SignedStatusRecord[]> {
  try {
    const content = await readFile(path, "utf8");
    const lines = content.split("\n").filter((line) => line.length > 0);
    const records = lines.map((line) => JSON.parse(line) as SignedStatusRecord);
    validateSequence(records);
    return records;
  } catch (error) {
    if (isMissingFile(error)) return [];
    throw error;
  }
}

function validateSequence(records: readonly SignedStatusRecord[]): void {
  records.forEach((record, index) => {
    if (record.claims.sequence !== index + 1) throw new Error("status registry sequence is not contiguous");
  });
}

function isCredentialStatus(value: unknown): value is CredentialStatus {
  return value === "ACTIVE" || value === "SUSPENDED" || value === "REVOKED";
}

function isCanonicalKeyId(value: string): boolean {
  return /^[A-Za-z0-9._:-]{1,128}$/.test(value);
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function isMissingFile(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}
