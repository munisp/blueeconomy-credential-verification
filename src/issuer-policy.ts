import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

export interface ApprovedIssuerPolicy {
  schema_version: "blueeconomy.credential.issuer-policy.v1";
  issuer: string;
  audience: string;
  jwks_url: string;
  algorithms: string[];
  key_ids?: string[];
  active: boolean;
}

export async function loadApprovedIssuerPolicy(path: string, expected: { issuer: string; audience: string; jwksUrl: URL; algorithm: string; keyId?: string }): Promise<ApprovedIssuerPolicy> {
  const content = await readFile(resolve(path), "utf8");
  const policy = JSON.parse(content) as Partial<ApprovedIssuerPolicy>;
  if (policy.schema_version !== "blueeconomy.credential.issuer-policy.v1" || policy.active !== true) throw new Error("approved issuer policy is inactive or unsupported");
  if (policy.issuer !== expected.issuer || policy.audience !== expected.audience || policy.jwks_url !== expected.jwksUrl.toString()) throw new Error("credential configuration does not match approved issuer policy");
  if (!Array.isArray(policy.algorithms) || !policy.algorithms.includes(expected.algorithm)) throw new Error("credential algorithm is not approved for this issuer");
  if (expected.keyId !== undefined && Array.isArray(policy.key_ids) && !policy.key_ids.includes(expected.keyId)) throw new Error("credential key id is not approved for this issuer");
  const jwks = new URL(policy.jwks_url);
  if (jwks.protocol !== "https:" || jwks.username || jwks.password || jwks.search || jwks.hash) throw new Error("approved issuer policy jwks_url must be an HTTPS URL without credentials or query data");
  return policy as ApprovedIssuerPolicy;
}
