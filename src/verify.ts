import { readFile, rename, writeFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import process from "node:process";
import { createRemoteJWKSet, decodeProtectedHeader, importSPKI, jwtVerify, type JWTPayload } from "jose";
import { createHash } from "node:crypto";
import { assertApprovedIssuerKeyId, type ApprovedIssuerPolicy, loadApprovedIssuerPolicy } from "./issuer-policy.js";
import { lookupVerifiedStatus, type CredentialStatus } from "./status-registry.js";

export type VerificationAlgorithm = "RS256" | "ES256" | "EdDSA";

export interface StatusVerificationConfiguration {
  registryPath: string;
  verificationKeyPath: string;
  algorithm: "RS256" | "RS384" | "RS512";
  keyId: string;
}

export interface VerificationConfiguration {
  credentialPath: string;
  issuer: string;
  audience: string;
  jwksUrl: URL;
  algorithm: VerificationAlgorithm;
  evidencePath: string;
  requireJti: boolean;
  issuerPolicyPath?: string;
  statusVerification?: StatusVerificationConfiguration;
}

export interface VerificationEvidence {
  schema_version: "blueeconomy.credential.verification.v1";
  verified_at: string;
  credential_reference_sha256: string;
  issuer: string;
  audience: string;
  algorithm: VerificationAlgorithm;
  subject_reference_sha256?: string;
  issued_at?: string;
  expires_at?: string;
  key_id?: string;
  credential_id_reference_sha256?: string;
  credential_status?: CredentialStatus;
}

export function parseConfiguration(args: readonly string[]): VerificationConfiguration {
  const values = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (name === undefined || value === undefined || !name.startsWith("--")) {
      throw new Error("usage: credential-verifier --credential <path> --issuer <https-url> --audience <value> --jwks-url <https-url> --algorithm <name> --evidence <path> [--require-jti <true|false>] [--issuer-policy <path>] [--status-registry <path> --status-verification-key <pem-path> --status-algorithm <name> --status-kid <id>]");
    }
    if (values.has(name)) {
      throw new Error(`duplicate argument: ${name}`);
    }
    values.set(name, value);
  }

  const credentialPath = resolve(required(values, "--credential"));
  const issuer = parseHttpsUrl(required(values, "--issuer"), "issuer").toString();
  const audience = required(values, "--audience");
  const jwksUrl = parseHttpsUrl(required(values, "--jwks-url"), "jwks-url");
  const algorithm = parseAlgorithm(required(values, "--algorithm"));
  const evidencePath = resolve(required(values, "--evidence"));
  const requireJti = values.has("--require-jti") ? parseBoolean(required(values, "--require-jti"), "--require-jti") : false;
  const issuerPolicyPath = values.has("--issuer-policy") ? resolve(required(values, "--issuer-policy")) : undefined;
  const statusNames = ["--status-registry", "--status-verification-key", "--status-algorithm", "--status-kid"] as const;
  const configuredStatusCount = statusNames.filter((name) => values.has(name)).length;
  if (configuredStatusCount !== 0 && configuredStatusCount !== statusNames.length) {
    throw new Error("status verification requires --status-registry, --status-verification-key, --status-algorithm and --status-kid together");
  }
  const statusVerification = configuredStatusCount === 0 ? undefined : {
    registryPath: resolve(required(values, "--status-registry")),
    verificationKeyPath: resolve(required(values, "--status-verification-key")),
    algorithm: parseStatusAlgorithm(required(values, "--status-algorithm")),
    keyId: parseCanonicalKeyId(required(values, "--status-kid"), "--status-kid"),
  };
  const expectedSize = 6 + (values.has("--require-jti") ? 1 : 0) + (values.has("--issuer-policy") ? 1 : 0) + configuredStatusCount;
  if (values.size !== expectedSize) {
    throw new Error("unexpected argument supplied");
  }
  if (credentialPath === evidencePath || credentialPath === `${evidencePath}.tmp`) {
    throw new Error("evidence path or staging path must not overwrite the credential input");
  }
  const configuration: VerificationConfiguration = { credentialPath, issuer, audience, jwksUrl, algorithm, evidencePath, requireJti };
  if (issuerPolicyPath !== undefined) configuration.issuerPolicyPath = issuerPolicyPath;
  if (statusVerification !== undefined) configuration.statusVerification = statusVerification;
  return configuration;
}

export async function verifyCredential(configuration: VerificationConfiguration): Promise<VerificationEvidence> {
  const compactJwt = (await readFile(configuration.credentialPath, "utf8")).trim();
  if (compactJwt.length === 0) {
    throw new Error("credential input is empty");
  }
  if (compactJwt.split(".").length !== 3) {
    throw new Error("credential must be a compact signed JWT with three segments");
  }

  const issuerPolicy = configuration.issuerPolicyPath === undefined
    ? undefined
    : await loadApprovedIssuerPolicy(configuration.issuerPolicyPath, {
      issuer: configuration.issuer,
      audience: configuration.audience,
      jwksUrl: configuration.jwksUrl,
      algorithm: configuration.algorithm,
    });
  assertCredentialProtectedHeader(compactJwt, configuration.algorithm, issuerPolicy);
  const jwks = createRemoteJWKSet(configuration.jwksUrl, {
    timeoutDuration: 10_000,
    cooldownDuration: 5_000,
  });
  const verified = await jwtVerify(compactJwt, jwks, {
    issuer: configuration.issuer,
    audience: configuration.audience,
    algorithms: [configuration.algorithm],
    clockTolerance: 5,
  });
  const credentialStatus = await verifyCredentialStatus(configuration, verified.payload);
  return createEvidence(configuration, compactJwt, verified.protectedHeader.kid, verified.payload, credentialStatus);
}

/**
 * Verifies the signed-JWT protected header against the configured algorithm
 * and the issuer manifest's pinned KID allowlist before remote JWKS selection.
 */
export function assertCredentialProtectedHeader(
  compactJwt: string,
  algorithm: VerificationAlgorithm,
  issuerPolicy?: ApprovedIssuerPolicy,
): string | undefined {
  const protectedHeader = decodeProtectedHeader(compactJwt);
  if (protectedHeader.alg !== algorithm) {
    throw new Error("credential protected-header algorithm does not match configured algorithm");
  }
  const keyId = typeof protectedHeader.kid === "string" ? protectedHeader.kid : undefined;
  if (issuerPolicy !== undefined) {
    assertApprovedIssuerKeyId(issuerPolicy, keyId);
  }
  return keyId;
}

export async function writeEvidence(path: string, evidence: VerificationEvidence): Promise<void> {
  const finalPath = resolve(path);
  const temporaryPath = `${finalPath}.tmp`;
  await mkdir(dirname(finalPath), { recursive: true, mode: 0o750 });
  await writeFile(temporaryPath, `${JSON.stringify(evidence, null, 2)}\n`, { encoding: "utf8", mode: 0o640 });
  await rename(temporaryPath, finalPath);
}

function createEvidence(
  configuration: VerificationConfiguration,
  compactJwt: string,
  keyId: string | undefined,
  payload: JWTPayload,
  credentialStatus?: CredentialStatus,
): VerificationEvidence {
  const evidence: VerificationEvidence = {
    schema_version: "blueeconomy.credential.verification.v1",
    verified_at: new Date().toISOString(),
    credential_reference_sha256: digest(compactJwt),
    issuer: configuration.issuer,
    audience: configuration.audience,
    algorithm: configuration.algorithm,
  };
  if (typeof payload.sub === "string" && payload.sub.length > 0) {
    evidence.subject_reference_sha256 = digest(payload.sub);
  }
  if (configuration.requireJti) {
    if (typeof payload.jti !== "string" || payload.jti.length === 0) {
      throw new Error("credential jti is required for status and revocation evidence");
    }
    evidence.credential_id_reference_sha256 = digest(payload.jti);
  } else if (typeof payload.jti === "string" && payload.jti.length > 0) {
    evidence.credential_id_reference_sha256 = digest(payload.jti);
  }
  if (typeof payload.iat === "number") {
    evidence.issued_at = new Date(payload.iat * 1_000).toISOString();
  }
  if (typeof payload.exp === "number") {
    evidence.expires_at = new Date(payload.exp * 1_000).toISOString();
  }
  if (keyId !== undefined && keyId.length > 0) {
    evidence.key_id = keyId;
  }
  if (credentialStatus !== undefined) {
    evidence.credential_status = credentialStatus;
  }
  return evidence;
}

function required(values: ReadonlyMap<string, string>, name: string): string {
  const value = values.get(name)?.trim();
  if (value === undefined || value.length === 0) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function parseBoolean(value: string, field: string): boolean {
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`${field} must be true or false`);
}

async function verifyCredentialStatus(
  configuration: VerificationConfiguration,
  payload: JWTPayload,
): Promise<CredentialStatus | undefined> {
  if (configuration.statusVerification === undefined) return undefined;
  if (typeof payload.jti !== "string" || payload.jti.length === 0) {
    throw new Error("credential jti is required for signed status verification");
  }
  const status = configuration.statusVerification;
  const pem = await readFile(status.verificationKeyPath, "utf8");
  const verificationKey = await importSPKI(pem, status.algorithm);
  let result: Awaited<ReturnType<typeof lookupVerifiedStatus>>;
  try {
    result = await lookupVerifiedStatus(payload.jti, {
      path: status.registryPath,
      issuer: configuration.issuer,
      key: verificationKey,
      algorithm: status.algorithm,
      keyId: status.keyId,
    });
  } catch (error) {
    // Status enforcement is fail-closed: unavailable, unreadable or
    // cryptographically invalid status evidence may never imply ACTIVE.
    const detail = error instanceof Error ? error.message : "unknown failure";
    throw new Error(`credential status evidence unavailable: ${detail}`);
  }
  if (result.status !== "ACTIVE") {
    throw new Error(`credential status must be ACTIVE, got ${result.status}`);
  }
  return result.status;
}

function parseAlgorithm(value: string): VerificationAlgorithm {
  if (value === "RS256" || value === "ES256" || value === "EdDSA") {
    return value;
  }
  throw new Error("algorithm must be one of RS256, ES256 or EdDSA");
}

function parseStatusAlgorithm(value: string): "RS256" | "RS384" | "RS512" {
  if (value === "RS256" || value === "RS384" || value === "RS512") return value;
  throw new Error("--status-algorithm must be one of RS256, RS384 or RS512");
}

function parseCanonicalKeyId(value: string, field: string): string {
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(value)) {
    throw new Error(`${field} must be a canonical key identifier`);
  }
  return value;
}

function parseHttpsUrl(value: string, field: string): URL {
  const parsed = new URL(value);
  if (parsed.protocol !== "https:" || parsed.username.length > 0 || parsed.password.length > 0 || parsed.search.length > 0 || parsed.hash.length > 0) {
    throw new Error(`${field} must be an HTTPS URL without credentials, query parameters or fragments`);
  }
  return parsed;
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

async function main(): Promise<void> {
  try {
    const configuration = parseConfiguration(process.argv.slice(2));
    const evidence = await verifyCredential(configuration);
    await writeEvidence(configuration.evidencePath, evidence);
    process.stdout.write(`${JSON.stringify(evidence)}\n`);
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown credential verification failure";
    process.stderr.write(`credential-verifier: ${message}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] !== undefined && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  await main();
}
