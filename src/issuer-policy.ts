import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

export type ApprovedIssuerAlgorithm = "RS256" | "ES256" | "EdDSA";

export interface ApprovedIssuerPolicy {
  schema_version: "blueeconomy.credential.issuer-policy.v1";
  issuer: string;
  audience: string;
  jwks_url: string;
  algorithms: ApprovedIssuerAlgorithm[];
  key_ids?: string[];
  active: boolean;
}

export interface IssuerPolicyExpectation {
  issuer: string;
  audience: string;
  jwksUrl: URL;
  algorithm: string;
  keyId?: string;
}

export async function loadApprovedIssuerPolicy(path: string, expected: IssuerPolicyExpectation): Promise<ApprovedIssuerPolicy> {
  const content = await readFile(resolve(path), "utf8");
  const policy = JSON.parse(content) as Partial<ApprovedIssuerPolicy>;
  if (policy.schema_version !== "blueeconomy.credential.issuer-policy.v1" || policy.active !== true) {
    throw new Error("approved issuer policy is inactive or unsupported");
  }
  if (policy.issuer !== expected.issuer || policy.audience !== expected.audience || policy.jwks_url !== expected.jwksUrl.toString()) {
    throw new Error("credential configuration does not match approved issuer policy");
  }
  if (!Array.isArray(policy.algorithms) || policy.algorithms.length === 0 || !policy.algorithms.every(isApprovedAlgorithm) || new Set(policy.algorithms).size !== policy.algorithms.length) {
    throw new Error("approved issuer policy algorithms must be a unique nonempty allowlist");
  }
  if (!policy.algorithms.includes(expected.algorithm as ApprovedIssuerAlgorithm)) {
    throw new Error("credential algorithm is not approved for this issuer");
  }
  const jwks = new URL(policy.jwks_url);
  if (jwks.protocol !== "https:" || jwks.username || jwks.password || jwks.search || jwks.hash) {
    throw new Error("approved issuer policy jwks_url must be an HTTPS URL without credentials or query data");
  }
  if (policy.key_ids !== undefined) {
    if (!Array.isArray(policy.key_ids) || policy.key_ids.length === 0 || !policy.key_ids.every(isCanonicalKeyId) || new Set(policy.key_ids).size !== policy.key_ids.length) {
      throw new Error("approved issuer policy key_ids must be a unique nonempty canonical allowlist");
    }
  }
  if (expected.keyId !== undefined) {
    assertApprovedIssuerKeyId(policy as ApprovedIssuerPolicy, expected.keyId);
  }
  return policy as ApprovedIssuerPolicy;
}

/**
 * Enforces the manifest-pinned JWK KID allowlist before a verifier resolves a
 * remote JWKS. If a policy carries key_ids, absence of kid is also rejected:
 * key selection must be explicit and auditable during issuer key rotation.
 */
export function assertApprovedIssuerKeyId(policy: ApprovedIssuerPolicy, keyId: string | undefined): void {
  if (policy.key_ids === undefined) return;
  if (keyId === undefined || !isCanonicalKeyId(keyId)) {
    throw new Error("credential protected-header kid is required and must be canonical for this issuer policy");
  }
  if (!policy.key_ids.includes(keyId)) {
    throw new Error("credential protected-header kid is not approved for this issuer policy");
  }
}

function isApprovedAlgorithm(value: unknown): value is ApprovedIssuerAlgorithm {
  return value === "RS256" || value === "ES256" || value === "EdDSA";
}

function isCanonicalKeyId(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(value);
}
