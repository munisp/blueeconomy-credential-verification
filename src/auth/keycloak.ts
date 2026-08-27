import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey, type JWTPayload } from "jose";

/**
 * Keycloak RS256/JWKS authentication, ported from
 * blueeconomy-administration-service/internal/admin. Roles are read from the
 * token's realm_access.roles claim and, when role client IDs are configured,
 * from resource_access[client].roles. Verification is fail-closed: no role
 * claim means no access.
 */

export type PrincipalRole = "nimasa-approver" | "employer" | "psc-inspector" | "auditor";

export const ROLE_NIMASA_APPROVER: PrincipalRole = "nimasa-approver";
export const ROLE_EMPLOYER: PrincipalRole = "employer";
export const ROLE_PSC_INSPECTOR: PrincipalRole = "psc-inspector";
export const ROLE_AUDITOR: PrincipalRole = "auditor";

export const APPROVED_ROLES: readonly PrincipalRole[] = [
  ROLE_NIMASA_APPROVER, ROLE_EMPLOYER, ROLE_PSC_INSPECTOR, ROLE_AUDITOR,
];

/** Read-only oversight role: denied every mutating route generically. */
export const READ_ONLY_ROLES: ReadonlySet<PrincipalRole> = new Set([ROLE_AUDITOR]);

export interface AuthenticatedPrincipal {
  subject: string;
  roles: ReadonlySet<PrincipalRole>;
}

export interface KeycloakAuthConfiguration {
  issuer: string;
  audience: string;
  /** Roles client IDs whose resource_access roles are honoured. */
  roleClientIds: string[];
  getKey: JWTVerifyGetKey;
}

export class KeycloakAuthenticator {
  public constructor(private readonly configuration: KeycloakAuthConfiguration) {}

  public async authenticate(authorizationHeader: string | undefined): Promise<AuthenticatedPrincipal> {
    if (authorizationHeader === undefined || !authorizationHeader.startsWith("Bearer ")) {
      throw new AuthenticationError("bearer token is required");
    }
    const token = authorizationHeader.slice("Bearer ".length).trim();
    if (token.length === 0) throw new AuthenticationError("bearer token is required");
    let verified: { payload: JWTPayload };
    try {
      verified = await jwtVerify(token, this.configuration.getKey, {
        issuer: this.configuration.issuer,
        audience: this.configuration.audience,
        algorithms: ["RS256"],
        clockTolerance: 5,
      });
    } catch (error) {
      throw new AuthenticationError(error instanceof Error ? error.message : "token verification failed");
    }
    const subject = verified.payload.sub;
    if (typeof subject !== "string" || subject.trim().length === 0 || subject.length > 512) {
      throw new AuthenticationError("authenticated subject is required");
    }
    return { subject, roles: extractApprovedRoles(verified.payload, this.configuration.roleClientIds) };
  }
}

export class AuthenticationError extends Error {}

export function extractApprovedRoles(payload: JWTPayload, roleClientIds: readonly string[]): Set<PrincipalRole> {
  const roles = new Set<PrincipalRole>();
  const realmAccess = payload["realm_access"];
  if (typeof realmAccess === "object" && realmAccess !== null) {
    const realmRoles = (realmAccess as Record<string, unknown>)["roles"];
    if (Array.isArray(realmRoles)) collectApproved(realmRoles, roles);
  }
  const resourceAccess = payload["resource_access"];
  if (typeof resourceAccess === "object" && resourceAccess !== null) {
    for (const clientId of roleClientIds) {
      const entry = (resourceAccess as Record<string, unknown>)[clientId];
      if (typeof entry === "object" && entry !== null) {
        const clientRoles = (entry as Record<string, unknown>)["roles"];
        if (Array.isArray(clientRoles)) collectApproved(clientRoles, roles);
      }
    }
  }
  return roles;
}

export class AuthorizationError extends Error {}

/**
 * Fail-closed route authorization, ported from the Go authorizer: a
 * roleless identity is denied, read-only roles are denied every mutating
 * method, and at least one held role must appear in the route's allowlist.
 */
export function authorizeRequest(method: string, heldRoles: ReadonlySet<PrincipalRole>, allowedRoles: readonly PrincipalRole[]): void {
  if (heldRoles.size === 0) {
    throw new AuthorizationError("authenticated token carries no approved role claim");
  }
  const mutating = method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
  for (const role of heldRoles) {
    if (mutating && READ_ONLY_ROLES.has(role)) continue;
    if (allowedRoles.includes(role)) return;
  }
  throw new AuthorizationError("authenticated subject lacks an approved role for this route");
}

/** Fail-closed authenticator factory; JWKS resolved from Keycloak over HTTPS. */
export function createAuthenticatorFromEnv(env: NodeJS.ProcessEnv = process.env): KeycloakAuthenticator {
  const jwksUrl = env["BLUEECONOMY_OIDC_JWKS_URL"];
  const issuer = env["BLUEECONOMY_OIDC_ISSUER"];
  const audience = env["BLUEECONOMY_OIDC_AUDIENCE"];
  if (jwksUrl === undefined || issuer === undefined || audience === undefined) {
    throw new Error("OIDC is not configured: set BLUEECONOMY_OIDC_JWKS_URL, BLUEECONOMY_OIDC_ISSUER and BLUEECONOMY_OIDC_AUDIENCE (fail-closed)");
  }
  const parsed = new URL(jwksUrl);
  if (parsed.protocol !== "https:" || parsed.username || parsed.password) {
    throw new Error("BLUEECONOMY_OIDC_JWKS_URL must be an HTTPS URL without credentials");
  }
  const roleClientIds = (env["BLUEECONOMY_OIDC_ROLES_CLIENT_IDS"] ?? "")
    .split(",").map((entry) => entry.trim()).filter((entry) => entry.length > 0);
  return new KeycloakAuthenticator({
    issuer,
    audience,
    roleClientIds,
    getKey: createRemoteJWKSet(parsed, { timeoutDuration: 10_000, cooldownDuration: 5_000 }),
  });
}

function collectApproved(values: unknown[], into: Set<PrincipalRole>): void {
  for (const value of values) {
    if (typeof value === "string" && (APPROVED_ROLES as readonly string[]).includes(value)) {
      into.add(value as PrincipalRole);
    }
  }
}
