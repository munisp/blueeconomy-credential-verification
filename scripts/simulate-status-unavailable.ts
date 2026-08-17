import { createServer } from "node:http";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair, exportJWK, exportSPKI, SignJWT } from "jose";
import { verifyCredential } from "../src/verify.js";

const directory = await mkdtemp(join(tmpdir(), "s4-status-unavailable-"));
const { privateKey, publicKey } = await generateKeyPair("RS256");
const jwk = await exportJWK(publicKey);
jwk.kid = "local-status-sim-kid";
jwk.alg = "RS256";
jwk.use = "sig";
const server = createServer((_request, response) => {
  response.writeHead(200, { "content-type": "application/json" });
  response.end(JSON.stringify({ keys: [jwk] }));
});
await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
const address = server.address();
if (!address || typeof address === "string") throw new Error("local JWKS server failed to bind");
const issuer = "https://local-status-sim.example";
const credential = await new SignJWT({ sub: "local-subject", jti: "local-status-sim-jti" })
  .setProtectedHeader({ alg: "RS256", kid: jwk.kid })
  .setIssuer(issuer).setAudience("local-audience").setIssuedAt().setExpirationTime("5m").sign(privateKey);
const credentialPath = join(directory, "credential.jwt");
const keyPath = join(directory, "status-public.pem");
const statusPath = join(directory, "corrupt-status.jsonl");
await writeFile(credentialPath, credential);
await writeFile(keyPath, await exportSPKI(publicKey));
await writeFile(statusPath, "not-a-signed-status-record\\n");
try {
  await verifyCredential({
    credentialPath, issuer, audience: "local-audience", jwksUrl: new URL(`http://127.0.0.1:${address.port}/jwks`),
    algorithm: "RS256", evidencePath: join(directory, "evidence.json"), requireJti: true,
    statusVerification: { registryPath: statusPath, verificationKeyPath: keyPath, algorithm: "RS256", keyId: jwk.kid },
  });
  throw new Error("unexpected verification success without status evidence");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  if (!message.startsWith("credential status evidence unavailable:")) throw error;
  console.log(message);
} finally {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  await rm(directory, { recursive: true, force: true });
}
