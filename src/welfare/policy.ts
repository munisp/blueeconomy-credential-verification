import { lstat, readFile } from "node:fs/promises";
import { CompactSign, compactVerify, decodeProtectedHeader, importJWK, type KeyObject } from "jose";
import { canonicalizeBytes, asJsonValue, type JsonValue } from "../vc/jcs.js";
import { loadKeyDirectory, type KeyDirectory } from "../events/envelope-verification.js";
import { REST_HOUR_REGIMES, isMember, type RestHourRegime } from "./types.js";

/**
 * Signed welfare-policy document (spec §5.6, Wave A). The MLC Reg 2.3
 * compliance regime (min-rest 10/77 vs max-work 14/72 — Nigeria's adopted
 * regime to be confirmed by NIMASA) is configuration, never hard-coded, and
 * the complaint SLA budgets travel with it. The document is a JWS compact
 * serialization (EdDSA/Ed25519) over the JCS-canonical claims, verified
 * against the platform producer key directory (KEY_DIRECTORY_PATH, the same
 * trust root as docs/envelope-signature.md), so the policy cannot be selected
 * by an unsigned or tampered file.
 *
 * Fail-closed contract:
 *   - BLUEECONOMY_WELFARE_POLICY_PATH unset  -> policy NOT configured; the
 *     complaint/rest mutation endpoints answer 503-honest until NIMASA's
 *     signed selection is deployed. Directory and referral reads still serve.
 *   - set but unreadable / not a regular non-symlink file / malformed JWS /
 *     unknown kid / payload mismatch / invalid signature / schema violation
 *     -> startup aborts (a configured-but-invalid policy is a
 *     misconfiguration, never a silent degrade).
 */

export const WELFARE_POLICY_PATH_ENV = "BLUEECONOMY_WELFARE_POLICY_PATH";
export const WELFARE_POLICY_SCHEMA_VERSION = "blueeconomy.welfare.policy.v1";
export const MAX_WELFARE_POLICY_BYTES = 1 << 16;

export interface WelfarePolicyClaims {
  schema_version: typeof WELFARE_POLICY_SCHEMA_VERSION;
  /** Version carried onto every derived rest-hour flag (policy-versioned). */
  policy_version: string;
  regime: RestHourRegime;
  /** Complaint lifecycle SLA budgets in seconds, keyed by workflow stage. */
  complaint_sla_seconds: {
    ack: number;
    onboard_process: number;
    escalation: number;
    resolution: number;
  };
  issued_by: string;
  effective_at: string;
}

export interface WelfarePolicy {
  claims: WelfarePolicyClaims;
  /** kid of the signing key that vouches for this policy. */
  keyId: string;
}

export type WelfarePolicyLoadResult =
  | { configured: true; policy: WelfarePolicy }
  | { configured: false; reason: string };

const KID_PATTERN = /^[A-Za-z0-9._-]{1,256}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

/** Signs a welfare-policy document (governance tooling and tests). */
export async function signWelfarePolicy(claims: WelfarePolicyClaims, signingKey: KeyObject, keyId: string): Promise<string> {
  assertWelfarePolicyClaims(claims);
  if (!KID_PATTERN.test(keyId)) throw new Error("policy signing kid is malformed");
  const payload = canonicalizeBytes(asJsonValue(claims as unknown as Record<string, JsonValue>));
  return new CompactSign(payload).setProtectedHeader({ alg: "EdDSA", kid: keyId }).sign(signingKey);
}

/** Verifies and parses a signed welfare-policy document, failing closed. */
export async function verifyWelfarePolicy(document: string, directory: KeyDirectory): Promise<WelfarePolicy> {
  const trimmed = document.trim();
  const segments = trimmed.split(".");
  if (segments.length !== 3 || segments.some((segment) => !BASE64URL_PATTERN.test(segment) || segment.length === 0)) {
    throw new Error("welfare policy is not a JWS compact serialization (fail-closed)");
  }
  let header: { alg?: unknown; kid?: unknown };
  try {
    header = decodeProtectedHeader(trimmed) as { alg?: unknown; kid?: unknown };
  } catch {
    throw new Error("welfare policy protected header is not valid JSON (fail-closed)");
  }
  if (header.alg !== "EdDSA") throw new Error("welfare policy alg must be EdDSA (fail-closed)");
  if (typeof header.kid !== "string" || !KID_PATTERN.test(header.kid)) {
    throw new Error("welfare policy kid is malformed (fail-closed)");
  }
  const publicKey = directory.resolve(header.kid);
  if (publicKey === undefined) {
    throw new Error(`welfare policy kid ${header.kid} is not in the key directory (fail-closed)`);
  }
  let verified: { payload: Uint8Array };
  try {
    verified = await compactVerify(trimmed, publicKey);
  } catch {
    throw new Error("welfare policy signature does not verify (fail-closed)");
  }
  let claims: unknown;
  try {
    claims = JSON.parse(Buffer.from(verified.payload).toString("utf8")) as unknown;
  } catch {
    throw new Error("welfare policy payload is not valid JSON (fail-closed)");
  }
  // The payload must byte-equal the JCS canonicalization of the parsed claims
  // (self-verifying compact serialization, mirroring envelope-signature.md).
  const parsed = asJsonValue(claims);
  const expected = canonicalizeBytes(parsed);
  const actual = Buffer.from(verified.payload);
  if (actual.length !== expected.length || !actual.equals(Buffer.from(expected))) {
    throw new Error("welfare policy payload is not the canonical claims document (fail-closed)");
  }
  assertWelfarePolicyClaims(claims);
  return { claims, keyId: header.kid };
}

export function assertWelfarePolicyClaims(claims: unknown): asserts claims is WelfarePolicyClaims {
  const fail = (detail: string): never => {
    throw new Error(`welfare policy claims are invalid: ${detail} (fail-closed)`);
  };
  if (typeof claims !== "object" || claims === null || Array.isArray(claims)) fail("document must be a JSON object");
  const record = claims as Record<string, unknown>;
  const allowedKeys = new Set(["schema_version", "policy_version", "regime", "complaint_sla_seconds", "issued_by", "effective_at"]);
  for (const key of Object.keys(record)) {
    if (!allowedKeys.has(key)) fail(`unknown field ${key}`);
  }
  if (record["schema_version"] !== WELFARE_POLICY_SCHEMA_VERSION) fail(`schema_version must be "${WELFARE_POLICY_SCHEMA_VERSION}"`);
  const policyVersion = record["policy_version"];
  if (typeof policyVersion !== "string" || policyVersion.trim() !== policyVersion || policyVersion.length === 0 || policyVersion.length > 128) {
    fail("policy_version must be canonical text of 1-128 characters");
  }
  if (!isMember(REST_HOUR_REGIMES, record["regime"])) fail("regime must be min_rest or max_work");
  const sla = record["complaint_sla_seconds"];
  if (typeof sla !== "object" || sla === null || Array.isArray(sla)) fail("complaint_sla_seconds must be an object");
  const slaRecord = sla as Record<string, unknown>;
  const stages = ["ack", "onboard_process", "escalation", "resolution"];
  for (const stage of stages) {
    const value = slaRecord[stage];
    if (!Number.isInteger(value) || (value as number) <= 0 || (value as number) > 31_536_000) {
      fail(`complaint_sla_seconds.${stage} must be an integer in 1-31536000`);
    }
  }
  if (Object.keys(slaRecord).some((key) => !stages.includes(key))) {
    fail("complaint_sla_seconds carries an unknown stage");
  }
  const issuedBy = record["issued_by"];
  if (typeof issuedBy !== "string" || issuedBy.trim() !== issuedBy || issuedBy.length === 0 || issuedBy.length > 128) {
    fail("issued_by must be canonical text");
  }
  if (typeof record["effective_at"] !== "string" || !Number.isFinite(Date.parse(record["effective_at"] as string))) {
    fail("effective_at must be a valid date-time");
  }
}

/**
 * Loads the signed welfare policy from BLUEECONOMY_WELFARE_POLICY_PATH. Unset
 * returns "not configured" (endpoints degrade honestly to 503); a set but
 * invalid path/document throws (boot aborts, fail-closed).
 */
export async function loadWelfarePolicyFromEnv(env: NodeJS.ProcessEnv = process.env): Promise<WelfarePolicyLoadResult> {
  const path = env[WELFARE_POLICY_PATH_ENV];
  if (path === undefined || path.trim().length === 0) {
    return { configured: false, reason: `${WELFARE_POLICY_PATH_ENV} is not set; complaint and rest-hour mutation endpoints are closed until NIMASA's signed welfare policy is deployed` };
  }
  const stats = await lstat(path).catch(() => {
    throw new Error(`welfare policy ${path} is not readable (fail-closed)`);
  });
  if (!stats.isFile() || stats.isSymbolicLink()) {
    throw new Error(`welfare policy ${path} must be a regular non-symlink file (fail-closed)`);
  }
  if (stats.size === 0 || stats.size > MAX_WELFARE_POLICY_BYTES) {
    throw new Error(`welfare policy ${path} must contain 1 to ${MAX_WELFARE_POLICY_BYTES} bytes`);
  }
  const document = await readFile(path, "utf8");
  const directory = await loadKeyDirectory(requiredEnv(env, "KEY_DIRECTORY_PATH"));
  const policy = await verifyWelfarePolicy(document, directory);
  return { configured: true, policy };
}

function requiredEnv(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (value === undefined || value.trim().length === 0) {
    throw new Error(`${name} is required to verify the signed welfare policy (fail-closed)`);
  }
  return value;
}
