import assert from "node:assert/strict";
import { createServer } from "node:http";
import { exchangeCrossMinistryToken } from "../src/token-exchange-client.js";

let calls = 0;
const server = createServer(async (request, response) => {
  const chunks: Buffer[] = []; for await (const chunk of request) chunks.push(Buffer.from(chunk));
  const form = new URLSearchParams(Buffer.concat(chunks).toString());
  assert.equal(request.method, "POST");
  assert.equal(form.get("grant_type"), "urn:ietf:params:oauth:grant-type:token-exchange");
  assert.equal(form.get("subject_token_type"), "urn:ietf:params:oauth:token-type:access_token");
  assert.equal(form.get("requested_tenant"), "tenant-ministry-a");
  const tenant = calls++ === 0 ? "tenant-ministry-a" : "tenant-ministry-b";
  response.writeHead(200, { "content-type": "application/json" });
  response.end(JSON.stringify({ access_token: "local-contract-token", token_type: "Bearer", expires_in: 300, scope: "s1.read", tenant_id: tenant }));
});
await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
const address = server.address(); if (!address || typeof address === "string") throw new Error("bind failed");
const endpoint = new URL(`http://127.0.0.1:${address.port}/v1/oauth/token-exchange`);
const request = { subjectToken: "authority-subject-token", requestedTenant: "tenant-ministry-a", resource: new URL("https://s1.nonprod.example"), scope: "s1.read" };
try {
  const accepted = await exchangeCrossMinistryToken(endpoint, request); assert.equal(accepted.tenant_id, request.requestedTenant);
  await assert.rejects(() => exchangeCrossMinistryToken(endpoint, request), /tenant-bound contract/);
  console.log("TOKEN_EXCHANGE_CONTRACT_HARNESS_PASSED");
} finally { await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); }
