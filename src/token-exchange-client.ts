export interface TokenExchangeRequest {
  subjectToken: string;
  requestedTenant: string;
  resource: URL;
  scope?: string;
  actorToken?: string;
}

export interface TokenExchangeResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  scope: string;
  tenant_id: string;
  issued_token_type?: "urn:ietf:params:oauth:token-type:access_token";
}

export async function exchangeCrossMinistryToken(
  endpoint: URL,
  request: TokenExchangeRequest,
  fetcher: typeof fetch = fetch,
): Promise<TokenExchangeResponse> {
  if (endpoint.protocol !== "https:" && endpoint.hostname !== "127.0.0.1" && endpoint.hostname !== "localhost") throw new Error("token exchange endpoint must use HTTPS");
  if (!/^tenant-[A-Za-z0-9._:-]{3,128}$/.test(request.requestedTenant)) throw new Error("requested tenant is invalid");
  if (!/^https:$/.test(request.resource.protocol)) throw new Error("resource must use HTTPS");
  if (request.subjectToken.trim() === "") throw new Error("subject token is required");
  const body = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    subject_token: request.subjectToken,
    subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
    requested_tenant: request.requestedTenant,
    resource: request.resource.toString(),
  });
  if (request.scope !== undefined) body.set("scope", request.scope);
  if (request.actorToken !== undefined) { body.set("actor_token", request.actorToken); body.set("actor_token_type", "urn:ietf:params:oauth:token-type:access_token"); }
  const response = await fetcher(endpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" }, body });
  if (!response.ok) throw new Error(`token exchange rejected: HTTP ${response.status}`);
  const result = await response.json() as Partial<TokenExchangeResponse>;
  if (result.token_type !== "Bearer" || typeof result.access_token !== "string" || result.access_token.length === 0 || typeof result.expires_in !== "number" || result.expires_in < 1 || result.expires_in > 900 || typeof result.scope !== "string" || result.tenant_id !== request.requestedTenant) throw new Error("token exchange response violates tenant-bound contract");
  return result as TokenExchangeResponse;
}
