import { lstat, readFile } from "node:fs/promises";
import { compactVerify, decodeProtectedHeader, importJWK } from "jose";
import { canonicalizeBytes, asJsonValue, type JsonValue } from "../vc/jcs.js";

/**
 * Consumer-side verification of the fleet envelope provenance signature,
 * implementing blueeconomy-contracts docs/envelope-signature.md exactly:
 *
 * - provenance.signature is a JWS compact serialization (EdDSA/Ed25519) over
 *   the JCS-canonicalized (RFC 8785) JSON of the full envelope excluding the
 *   signature field, with protected header {"alg":"EdDSA","kid":"<producer>-<epoch>"};
 * - producer public keys resolve from a mounted key directory shaped
 *   {kid: base64url-ed25519-pubkey}, path from KEY_DIRECTORY_PATH;
 * - the directory loads once at startup, fail-closed; unknown kid, malformed
 *   compact serializations, payload mismatches and invalid signatures are
 *   rejected, and rejected envelopes must never be persisted.
 */

export const KEY_DIRECTORY_PATH_ENV = "KEY_DIRECTORY_PATH";
export const MAX_KEY_DIRECTORY_BYTES = 1 << 20;
export const ED25519_PUBLIC_KEY_BYTES = 32;

export const REASON_MALFORMED_JWS = "malformed-jws";
export const REASON_UNSUPPORTED_ALG = "unsupported-alg";
export const REASON_UNKNOWN_KID = "unknown-kid";
export const REASON_PAYLOAD_MISMATCH = "payload-mismatch";
export const REASON_INVALID_SIGNATURE = "invalid-signature";

export type EnvelopeVerificationReason =
  | typeof REASON_MALFORMED_JWS
  | typeof REASON_UNSUPPORTED_ALG
  | typeof REASON_UNKNOWN_KID
  | typeof REASON_PAYLOAD_MISMATCH
  | typeof REASON_INVALID_SIGNATURE;

export class EnvelopeVerificationError extends Error {
  public constructor(
    public readonly reason: EnvelopeVerificationReason,
    detail: string,
  ) {
    super(`envelope signature rejected (${reason}): ${detail}`);
  }
}

const KID_PATTERN = /^[A-Za-z0-9._-]{1,256}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

export interface KeyDirectory {
  readonly size: number;
  resolve(kid: string): Awaited<ReturnType<typeof importJWK>> | undefined;
}

class LoadedKeyDirectory implements KeyDirectory {
  public constructor(private readonly keys: ReadonlyMap<string, Awaited<ReturnType<typeof importJWK>>>) {}

  public get size(): number {
    return this.keys.size;
  }

  public resolve(kid: string): Awaited<ReturnType<typeof importJWK>> | undefined {
    return this.keys.get(kid);
  }
}

/** Loads the mounted producer public-key directory, failing closed on any deviation. */
export async function loadKeyDirectory(path: string): Promise<KeyDirectory> {
  const stats = await lstat(path).catch(() => {
    throw new Error(`key directory ${path} is not readable (fail-closed)`);
  });
  if (!stats.isFile() || stats.isSymbolicLink()) {
    throw new Error(`key directory ${path} must be a regular non-symlink file (fail-closed)`);
  }
  if (stats.size === 0 || stats.size > MAX_KEY_DIRECTORY_BYTES) {
    throw new Error(`key directory ${path} must contain 1 to ${MAX_KEY_DIRECTORY_BYTES} bytes`);
  }
  let document: unknown;
  try {
    document = JSON.parse(await readFile(path, "utf8")) as unknown;
  } catch {
    throw new Error(`key directory ${path} is not valid JSON (fail-closed)`);
  }
  if (typeof document !== "object" || document === null || Array.isArray(document)) {
    throw new Error(`key directory ${path} must be a JSON object of kid to key (fail-closed)`);
  }
  const entries = Object.entries(document as Record<string, unknown>);
  if (entries.length === 0) {
    throw new Error(`key directory ${path} must contain at least one key (fail-closed)`);
  }
  const keys = new Map<string, Awaited<ReturnType<typeof importJWK>>>();
  for (const [kid, encoded] of entries) {
    if (!KID_PATTERN.test(kid)) {
      throw new Error(`key directory ${path} carries a malformed kid (fail-closed)`);
    }
    if (typeof encoded !== "string" || !BASE64URL_PATTERN.test(encoded)) {
      throw new Error(`key directory ${path} key for ${kid} is not unpadded base64url (fail-closed)`);
    }
    const raw = Buffer.from(encoded, "base64url");
    if (raw.length !== ED25519_PUBLIC_KEY_BYTES) {
      throw new Error(`key directory ${path} key for ${kid} is not a 32-byte Ed25519 public key (fail-closed)`);
    }
    keys.set(kid, await importJWK({ kty: "OKP", crv: "Ed25519", x: encoded }, "EdDSA"));
  }
  return new LoadedKeyDirectory(keys);
}

/** Fail-closed startup loader bound to the KEY_DIRECTORY_PATH environment variable. */
export async function loadKeyDirectoryFromEnv(env: NodeJS.ProcessEnv = process.env): Promise<KeyDirectory> {
  const path = env[KEY_DIRECTORY_PATH_ENV];
  if (path === undefined || path.trim().length === 0) {
    throw new Error(`${KEY_DIRECTORY_PATH_ENV} is required (fail-closed)`);
  }
  return loadKeyDirectory(path);
}

export interface SignatureVerificationMetrics {
  recordVerified(): void;
  recordRejected(reason: EnvelopeVerificationReason): void;
}

/**
 * Verifies the provenance signature of a parsed envelope and returns the
 * authenticated kid. Throws EnvelopeVerificationError on any violation.
 */
export async function verifyEnvelopeSignature(
  envelope: Record<string, unknown>,
  directory: KeyDirectory,
  metrics?: SignatureVerificationMetrics,
): Promise<string> {
  try {
    const kid = await verify(envelope, directory);
    metrics?.recordVerified();
    return kid;
  } catch (error) {
    if (error instanceof EnvelopeVerificationError) {
      metrics?.recordRejected(error.reason);
    }
    throw error;
  }
}

async function verify(envelope: Record<string, unknown>, directory: KeyDirectory): Promise<string> {
  const provenance = envelope["provenance"];
  if (typeof provenance !== "object" || provenance === null || Array.isArray(provenance)) {
    throw new EnvelopeVerificationError(REASON_MALFORMED_JWS, "envelope carries no provenance object");
  }
  const signature = (provenance as Record<string, unknown>)["signature"];
  if (typeof signature !== "string") {
    throw new EnvelopeVerificationError(REASON_MALFORMED_JWS, "provenance.signature is not text");
  }
  const segments = signature.split(".");
  if (segments.length !== 3 || segments.some((segment) => segment.length === 0)) {
    throw new EnvelopeVerificationError(REASON_MALFORMED_JWS, "JWS compact form must have three non-empty segments");
  }
  const [encodedHeader, encodedPayload] = segments as [string, string, string];
  if (!BASE64URL_PATTERN.test(encodedHeader) || !BASE64URL_PATTERN.test(encodedPayload)) {
    throw new EnvelopeVerificationError(REASON_MALFORMED_JWS, "JWS segments must be unpadded base64url");
  }
  let header: { alg?: unknown; kid?: unknown };
  try {
    header = decodeProtectedHeader(signature) as { alg?: unknown; kid?: unknown };
  } catch {
    throw new EnvelopeVerificationError(REASON_MALFORMED_JWS, "protected header is not valid JSON");
  }
  if (header.alg !== "EdDSA") {
    throw new EnvelopeVerificationError(REASON_UNSUPPORTED_ALG, "protected header alg must be EdDSA");
  }
  if (typeof header.kid !== "string" || !KID_PATTERN.test(header.kid)) {
    throw new EnvelopeVerificationError(REASON_MALFORMED_JWS, "protected header kid is malformed");
  }
  const publicKey = directory.resolve(header.kid);
  if (publicKey === undefined) {
    throw new EnvelopeVerificationError(REASON_UNKNOWN_KID, `kid ${header.kid} is not in the key directory`);
  }

  const signedDocument: Record<string, JsonValue> = {};
  for (const [key, value] of Object.entries(envelope)) {
    if (key === "provenance") continue;
    signedDocument[key] = asJsonValue(value);
  }
  const provenanceWithoutSignature: Record<string, JsonValue> = {};
  for (const [key, value] of Object.entries(provenance as Record<string, unknown>)) {
    if (key === "signature") continue;
    provenanceWithoutSignature[key] = asJsonValue(value);
  }
  signedDocument["provenance"] = asJsonValue(provenanceWithoutSignature);
  let expectedPayload: Uint8Array;
  try {
    expectedPayload = canonicalizeBytes(asJsonValue(signedDocument));
  } catch (error) {
    throw new EnvelopeVerificationError(
      REASON_PAYLOAD_MISMATCH,
      `envelope cannot be canonicalized: ${error instanceof Error ? error.message : "unknown"}`,
    );
  }
  // The payload segment must carry exactly the canonical envelope bytes: the
  // compact serialization is self-verifying by specification.
  const payload = Buffer.from(encodedPayload, "base64url");
  if (payload.length !== expectedPayload.length || !payload.equals(Buffer.from(expectedPayload))) {
    throw new EnvelopeVerificationError(REASON_PAYLOAD_MISMATCH, "JWS payload does not match the canonical envelope");
  }
  try {
    await compactVerify(signature, publicKey);
  } catch {
    throw new EnvelopeVerificationError(REASON_INVALID_SIGNATURE, "Ed25519 signature does not verify");
  }
  return header.kid;
}
