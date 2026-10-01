import { createHmac, createHash, timingSafeEqual } from "node:crypto";

/**
 * Shared credential-proof verification service. Generalizes the ferry-ticketing
 * ticket-proof contract (internal/httpapi/ticket_proof.go, Phase 22) into a
 * domain-separated HMAC-SHA256 proof service usable by any Blue Economy
 * artifact type (ferry tickets, credentials, wallet proofs).
 *
 * Doctrine: fail-closed. When no signing key is configured every endpoint
 * answers 503 with an honest error. Key material comes only from the
 * PROOF_SIGNING_KEY environment variable (or an explicitly injected key for
 * approved non-production use); it is never served by the API and never
 * committed to the repository.
 */

export const PROOF_ALGORITHM = "HMAC-SHA256";
export const PROOF_SIGNING_KEY_ENV = "PROOF_SIGNING_KEY";
export const PROOF_KEY_ID_ENV = "PROOF_KEY_ID";
export const MIN_SIGNING_KEY_BYTES = 32;

/** Domain separator strings, per artifact type. Mirrors the Go `\x00` framing. */
const KEY_ID_DOMAIN = "blueeconomy-proof-key-id\x00";
const SIGNATURE_SEPARATOR = "\x00";

export interface ProofServiceConfiguration {
  /** Signing key. Defaults to process.env.PROOF_SIGNING_KEY. */
  signingKey?: string;
  /** Public key identifier. Defaults to process.env.PROOF_KEY_ID or a derived id. */
  keyId?: string;
  /** Approved artifact-type domains. When omitted, issuance is refused fail-closed. */
  domains?: readonly string[];
  /** Environment override, primarily for tests. */
  env?: NodeJS.ProcessEnv;
}

export interface ProofArtifact {
  claims: Record<string, unknown>;
  domain: string;
  keyId: string;
  algorithm: typeof PROOF_ALGORITHM;
  signature: string;
}

interface ResolvedKey {
  key: Buffer;
  keyId: string;
}

function resolveKey(configuration: ProofServiceConfiguration): ResolvedKey | undefined {
  const env = configuration.env ?? process.env;
  const material = configuration.signingKey ?? env[PROOF_SIGNING_KEY_ENV];
  if (material === undefined || material.trim() !== material || material.length === 0) return undefined;
  const key = Buffer.from(material, "utf8");
  if (key.length < MIN_SIGNING_KEY_BYTES) return undefined;
  const configured = configuration.keyId ?? env[PROOF_KEY_ID_ENV];
  const keyId = configured !== undefined && configured.length > 0 ? configured : deriveKeyId(key);
  if (!isCanonicalKeyId(keyId)) return undefined;
  return { key, keyId };
}

function deriveKeyId(key: Buffer): string {
  const digest = createHash("sha256").update(KEY_ID_DOMAIN).update(key).digest("hex");
  return digest.slice(0, 16);
}

function isCanonicalKeyId(value: string): boolean {
  return /^[A-Za-z0-9._:-]{1,128}$/.test(value);
}

function isDomainAllowed(domain: string, configuration: ProofServiceConfiguration): boolean {
  return configuration.domains !== undefined && configuration.domains.includes(domain);
}

/** Deterministic canonical JSON: object keys sorted recursively, no whitespace. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  const entries = Object.keys(record)
    .sort()
    .filter((key) => record[key] !== undefined)
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`);
  return `{${entries.join(",")}}`;
}

export function signClaims(
  domain: string,
  claims: Record<string, unknown>,
  key: Buffer,
  keyId: string,
): ProofArtifact {
  const mac = createHmac("sha256", key);
  mac.update(domain);
  mac.update(SIGNATURE_SEPARATOR);
  mac.update(canonicalJson(claims), "utf8");
  return {
    claims,
    domain,
    keyId,
    algorithm: PROOF_ALGORITHM,
    signature: mac.digest("hex"),
  };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function unavailable(message: string): Response {
  return jsonResponse(503, { error: message });
}

async function readBody(request: Request): Promise<Record<string, unknown> | undefined> {
  try {
    const parsed: unknown = await request.json();
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return undefined;
    return parsed as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

function isClaimsObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validSignature(presented: string, expected: string): boolean {
  const presentedBytes = Buffer.from(presented, "hex");
  const expectedBytes = Buffer.from(expected, "hex");
  return presentedBytes.length === expectedBytes.length && timingSafeEqual(presentedBytes, expectedBytes);
}

/**
 * Creates a Fetch-API request handler exposing the shared proof contract:
 *   GET  /v1/proof/verification-keys — public key descriptors (material never served)
 *   POST /v1/proof/artifact          — issue a domain-separated signed artifact
 *   POST /v1/proof/verify            — verify an artifact, constant-time, fail-closed
 */
export function createProofServiceHandler(
  configuration: ProofServiceConfiguration,
): (request: Request) => Promise<Response> {
  return async (request: Request): Promise<Response> => {
    const path = new URL(request.url).pathname;
    if (request.method === "GET" && path === "/v1/proof/verification-keys") {
      const resolved = resolveKey(configuration);
      if (resolved === undefined) return unavailable("proof verification keys are not configured");
      return jsonResponse(200, {
        keys: [
          {
            keyId: resolved.keyId,
            algorithm: PROOF_ALGORITHM,
            use: "credential-proof",
            // HMAC verification requires the shared secret; it is distributed
            // to authorized verifiers out of band, never via this API.
            distribution: "out-of-band",
          },
        ],
      });
    }
    if (request.method === "POST" && path === "/v1/proof/artifact") {
      const resolved = resolveKey(configuration);
      if (resolved === undefined) return unavailable("proof signing is not configured");
      const body = await readBody(request);
      if (body === undefined) return jsonResponse(400, { error: "request body must be a JSON object" });
      const { domain, claims } = body;
      if (typeof domain !== "string" || domain.length === 0 || !isClaimsObject(claims)) {
        return jsonResponse(400, { error: "domain and claims are required" });
      }
      if (!isDomainAllowed(domain, configuration)) {
        return jsonResponse(403, { error: "artifact domain is not approved" });
      }
      return jsonResponse(200, signClaims(domain, claims, resolved.key, resolved.keyId));
    }
    if (request.method === "POST" && path === "/v1/proof/verify") {
      const resolved = resolveKey(configuration);
      if (resolved === undefined) return unavailable("proof verification is not configured");
      const body = await readBody(request);
      if (body === undefined) return jsonResponse(400, { error: "request body must be a JSON object" });
      const { domain, claims, keyId, signature } = body;
      if (
        typeof domain !== "string" ||
        !isClaimsObject(claims) ||
        typeof keyId !== "string" ||
        typeof signature !== "string" ||
        !/^[0-9a-f]{64}$/.test(signature)
      ) {
        return jsonResponse(400, { error: "domain, claims, keyId and a hex HMAC-SHA256 signature are required" });
      }
      const expected = signClaims(domain, claims, resolved.key, resolved.keyId);
      const valid = keyId === resolved.keyId && validSignature(signature, expected.signature);
      if (!valid) {
        return jsonResponse(200, { valid: false, reason: "signature does not match the domain-separated claims" });
      }
      return jsonResponse(200, { valid: true, keyId: resolved.keyId, domain });
    }
    return jsonResponse(404, { error: "not found" });
  };
}
