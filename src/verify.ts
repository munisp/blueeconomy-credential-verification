import { createHash } from "node:crypto";
import { readFile, rename, writeFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import process from "node:process";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

export interface VerificationConfiguration {
  credentialPath: string;
  issuer: string;
  audience: string;
  jwksUrl: URL;
  evidencePath: string;
}

export interface VerificationEvidence {
  schema_version: "blueeconomy.credential.verification.v1";
  verified_at: string;
  credential_reference_sha256: string;
  issuer: string;
  audience: string;
  subject_reference_sha256?: string;
  issued_at?: string;
  expires_at?: string;
  key_id?: string;
}

export function parseConfiguration(args: readonly string[]): VerificationConfiguration {
  const values = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (name === undefined || value === undefined || !name.startsWith("--")) {
      throw new Error("usage: credential-verifier --credential <path> --issuer <https-url> --audience <value> --jwks-url <https-url> --evidence <path>");
    }
    if (values.has(name)) {
      throw new Error(`duplicate argument: ${name}`);
    }
    values.set(name, value);
  }

  const credentialPath = required(values, "--credential");
  const issuer = parseHttpsUrl(required(values, "--issuer"), "issuer").toString();
  const audience = required(values, "--audience");
  const jwksUrl = parseHttpsUrl(required(values, "--jwks-url"), "jwks-url");
  const evidencePath = required(values, "--evidence");
  if (values.size !== 5) {
    throw new Error("unexpected argument supplied");
  }
  return { credentialPath, issuer, audience, jwksUrl, evidencePath };
}

export async function verifyCredential(configuration: VerificationConfiguration): Promise<VerificationEvidence> {
  const compactJwt = (await readFile(configuration.credentialPath, "utf8")).trim();
  if (compactJwt.length === 0) {
    throw new Error("credential input is empty");
  }
  if (compactJwt.split(".").length !== 3) {
    throw new Error("credential must be a compact signed JWT with three segments");
  }

  const jwks = createRemoteJWKSet(configuration.jwksUrl, {
    timeoutDuration: 10_000,
    cooldownDuration: 5_000,
  });
  const verified = await jwtVerify(compactJwt, jwks, {
    issuer: configuration.issuer,
    audience: configuration.audience,
    clockTolerance: 5,
  });
  return createEvidence(configuration, compactJwt, verified.protectedHeader.kid, verified.payload);
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
): VerificationEvidence {
  const evidence: VerificationEvidence = {
    schema_version: "blueeconomy.credential.verification.v1",
    verified_at: new Date().toISOString(),
    credential_reference_sha256: digest(compactJwt),
    issuer: configuration.issuer,
    audience: configuration.audience,
  };
  if (typeof payload.sub === "string" && payload.sub.length > 0) {
    evidence.subject_reference_sha256 = digest(payload.sub);
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
  return evidence;
}

function required(values: ReadonlyMap<string, string>, name: string): string {
  const value = values.get(name)?.trim();
  if (value === undefined || value.length === 0) {
    throw new Error(`${name} is required`);
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
