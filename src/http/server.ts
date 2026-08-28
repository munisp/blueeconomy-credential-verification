import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { AuthenticationError, AuthorizationError, authorizeRequest, type AuthenticatedPrincipal, type KeycloakAuthenticator, type PrincipalRole, ROLE_AUDITOR, ROLE_EMPLOYER, ROLE_NIMASA_APPROVER, ROLE_PSC_INSPECTOR, ROLE_SEAFARER } from "../auth/keycloak.js";
import { CredentialService, ServiceError } from "../service/credential-service.js";
import type { StatusStore } from "../status/store.js";

/**
 * Issuer/verifier HTTP surface. The route table is the single source of
 * truth; any route not present here is denied by default (fail-closed),
 * mirroring the Go administration-service authorizer.
 */

export interface HttpServiceDependencies {
  authenticator: KeycloakAuthenticator;
  service: CredentialService;
  statusStore: StatusStore;
}

const MAX_BODY_BYTES = 1 << 20;

interface Route {
  pattern: RegExp;
  paramNames: string[];
  roles: readonly PrincipalRole[] | null;
  handler: (request: RouteRequest) => Promise<{ status: number; body: unknown }>;
}

interface RouteRequest {
  method: string;
  params: Record<string, string>;
  body: unknown;
  principal: AuthenticatedPrincipal | undefined;
}

export class MetricsRegistry {
  private readonly counters = new Map<string, number>();

  public increment(name: string, labels: Record<string, string> = {}): void {
    const key = `${name}{${Object.entries(labels).map(([k, v]) => `${k}="${v}"`).join(",")}}`;
    this.counters.set(key, (this.counters.get(key) ?? 0) + 1);
  }

  public render(): string {
    const lines: string[] = [];
    for (const [key, value] of [...this.counters.entries()].sort()) {
      lines.push(`${key} ${value}`);
    }
    return `${lines.join("\n")}\n`;
  }
}

export function createHttpService(deps: HttpServiceDependencies): { server: Server; metrics: MetricsRegistry } {
  const metrics = new MetricsRegistry();
  const primaryRole = (principal: AuthenticatedPrincipal): string => {
    for (const role of [ROLE_NIMASA_APPROVER, ROLE_EMPLOYER, ROLE_PSC_INSPECTOR, ROLE_AUDITOR] as const) {
      if (principal.roles.has(role)) return role;
    }
    return "none";
  };

  const routes: Record<string, Route> = {
    "GET /healthz": route(/^\/healthz$/, [], null, async () => ({ status: 200, body: { status: "ok" } })),
    "GET /readyz": route(/^\/readyz$/, [], null, async () => {
      await deps.statusStore.healthCheck();
      return { status: 200, body: { status: "ready" } };
    }),
    "GET /metrics": route(/^\/metrics$/, [], null, async () => ({ status: 200, body: metrics.render(), })),
    "POST /v1/credentials": route(/^\/v1\/credentials$/, [], [ROLE_NIMASA_APPROVER], async (request) => {
      const body = assertObject(request.body);
      const principal = assertPrincipal(request.principal);
      const result = await deps.service.issueCredential({
        workflowId: assertString(body, "workflowId"),
        seafarerId: assertString(body, "seafarerId"),
        holderId: assertString(body, "holderId"),
        seafarerReferenceNumber: assertString(body, "seafarerReferenceNumber"),
        capacity: assertString(body, "capacity"),
        stcwRegulation: assertString(body, "stcwRegulation"),
        limitations: assertStringArray(body, "limitations"),
        validUntil: assertString(body, "validUntil"),
        ...(typeof body["name"] === "string" ? { name: body["name"] } : {}),
        ...(typeof body["nationality"] === "string" ? { nationality: body["nationality"] } : {}),
      }, { subject: principal.subject, role: primaryRole(principal) });
      metrics.increment("blueeconomy_vc_issued_total");
      return { status: 201, body: result };
    }),
    "POST /v1/verify": route(/^\/v1\/verify$/, [], [ROLE_EMPLOYER, ROLE_PSC_INSPECTOR], async (request) => {
      const body = assertObject(request.body);
      const result = await deps.service.verifyCredential(body["credential"], assertString(body, "holderId"));
      metrics.increment("blueeconomy_vc_verified_total");
      return { status: 200, body: result };
    }),
    "GET /v1/status-list/{id}": route(/^\/v1\/status-list\/([A-Za-z0-9._:-]{1,128})$/, ["id"], [ROLE_NIMASA_APPROVER, ROLE_EMPLOYER, ROLE_PSC_INSPECTOR, ROLE_AUDITOR, ROLE_SEAFARER], async (request) => {
      const credential = await deps.service.statusListCredential(request.params["id"] ?? "");
      return { status: 200, body: credential };
    }),
    "GET /v1/wallet/credentials/current": route(/^\/v1\/wallet\/credentials\/current$/, [], [ROLE_SEAFARER], async (request) => {
      const principal = assertPrincipal(request.principal);
      const credential = await deps.service.currentHolderCredential(principal.subject);
      if (credential === undefined) throw new ServiceError(404, "the authenticated holder has no current credential");
      metrics.increment("blueeconomy_vc_wallet_served_total");
      return { status: 200, body: credential };
    }),
    "GET /v1/issuers/{issuer}/key": route(/^\/v1\/issuers\/([A-Za-z0-9._:%-]{1,384})\/key$/, ["issuer"], null, async (request) => {
      const key = deps.service.issuerKeyMaterial();
      if (request.params["issuer"] !== key.issuer) throw new ServiceError(404, "issuer is unknown to this service");
      return { status: 200, body: { issuer: key.issuer, kid: key.kid, public_key_hex: key.publicKeyHex } };
    }),
    "POST /v1/revoke": route(/^\/v1\/revoke$/, [], [ROLE_NIMASA_APPROVER], async (request) => {
      const body = assertObject(request.body);
      const principal = assertPrincipal(request.principal);
      const result = await deps.service.revokeCredential({
        credentialId: assertString(body, "credentialId"),
        holderId: assertString(body, "holderId"),
        reason: assertString(body, "reason"),
      }, { subject: principal.subject, role: primaryRole(principal) });
      metrics.increment("blueeconomy_vc_revoked_total");
      return { status: 200, body: result };
    }),
  };

  const server = createServer(async (request, response) => {
    try {
      await dispatch(request, response, routes, deps.authenticator, metrics);
    } catch (error) {
      writeError(response, error);
    }
  });
  return { server, metrics };
}

function route(
  pattern: RegExp,
  paramNames: string[],
  roles: readonly PrincipalRole[] | null,
  handler: Route["handler"],
): Route {
  return { pattern, paramNames, roles, handler };
}

async function dispatch(
  request: IncomingMessage,
  response: ServerResponse,
  routes: Record<string, Route>,
  authenticator: KeycloakAuthenticator,
  metrics: MetricsRegistry,
): Promise<void> {
  const method = request.method ?? "GET";
  const url = new URL(request.url ?? "/", "http://localhost");
  const path = url.pathname;
  const key = Object.keys(routes).find((candidate) => candidate.startsWith(`${method} `) && routes[candidate]?.pattern.test(path));
  const selected = key === undefined ? undefined : routes[key];
  if (key === undefined || selected === undefined) {
    writeJson(response, 404, { error: "route not found or denied by default" });
    return;
  }
  let principal: AuthenticatedPrincipal | undefined;
  if (selected.roles !== null) {
    try {
      principal = await authenticator.authenticate(request.headers["authorization"]);
      authorizeRequest(method, principal.roles, selected.roles);
    } catch (error) {
      if (error instanceof AuthenticationError) {
        writeJson(response, 401, { error: error.message });
        return;
      }
      if (error instanceof AuthorizationError) {
        writeJson(response, 403, { error: error.message });
        return;
      }
      throw error;
    }
  }
  const match = selected.pattern.exec(path);
  const params: Record<string, string> = {};
  selected.paramNames.forEach((name, index) => {
    params[name] = decodeURIComponent(match?.[index + 1] ?? "");
  });
  const body = method === "POST" || method === "PUT" ? await readJsonBody(request) : undefined;
  const result = await selected.handler({ method, params, body, principal });
  metrics.increment("blueeconomy_http_requests_total", { route: key, status: String(result.status) });
  if (key === "GET /metrics") {
    response.writeHead(result.status, { "content-type": "text/plain; version=0.0.4" });
    response.end(String(result.body));
    return;
  }
  writeJson(response, result.status, result.body);
}

async function readJsonBody(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const buffer = chunk as Buffer;
    total += buffer.length;
    if (total > MAX_BODY_BYTES) throw new ServiceError(413, "request body exceeds the 1 MiB limit");
    chunks.push(buffer);
  }
  if (chunks.length === 0) throw new ServiceError(400, "request body is required");
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    throw new ServiceError(400, "request body must be valid JSON");
  }
}

function writeError(response: ServerResponse, error: unknown): void {
  if (response.headersSent) {
    response.end();
    return;
  }
  if (error instanceof ServiceError) {
    writeJson(response, error.statusCode, { error: error.message });
    return;
  }
  writeJson(response, 500, { error: "internal credential service failure" });
}

function writeJson(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

function assertPrincipal(principal: AuthenticatedPrincipal | undefined): AuthenticatedPrincipal {
  if (principal === undefined) throw new ServiceError(401, "authentication is required");
  return principal;
}

function assertObject(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ServiceError(400, "request body must be a JSON object");
  }
  return value as Record<string, unknown>;
}

function assertString(body: Record<string, unknown>, field: string): string {
  const value = body[field];
  if (typeof value !== "string" || value.trim() !== value || value.length === 0) {
    throw new ServiceError(400, `${field} must be canonical non-empty text`);
  }
  return value;
}

function assertStringArray(body: Record<string, unknown>, field: string): string[] {
  const value = body[field];
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new ServiceError(400, `${field} must be an array of text`);
  }
  return value as string[];
}
