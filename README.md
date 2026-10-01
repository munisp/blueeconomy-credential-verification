# Blue Economy Credential Verification

This repository contains a TypeScript command that validates an **actual compact signed JWT credential** against an explicitly supplied HTTPS issuer, audience and JWKS endpoint. It uses the `jose` library to retrieve the issuer’s public keys and verify the credential signature and registered issuer/audience/time claims.

## Shared credential-proof verification service

`src/proof-service.ts` exposes a shared proof-verification contract (generalized from the ferry-ticketing ticket-proof in Phase 22) that ferry-ticketing and, later, wallet components converge on. The handler is a Fetch-API `(request: Request) => Promise<Response>` module with no runtime dependencies beyond `node:crypto`:

- `GET /v1/proof/verification-keys` — public key descriptors (`keyId`, `algorithm: HMAC-SHA256`, `use: credential-proof`, `distribution: out-of-band`). Key material is never served.
- `POST /v1/proof/artifact` — body `{ "domain", "claims" }`; issues a signed artifact `{ claims, domain, keyId, algorithm, signature }`. Only configured domains are signed; others get 403.
- `POST /v1/proof/verify` — body `{ "domain", "claims", "keyId", "signature" }`; recomputes the signature and compares in constant time, answering `{ "valid": true|false, "reason"? }`.

Signatures are HMAC-SHA256 over `domain \x00 canonical-json(claims)` (domain-separated per artifact type, canonical JSON with recursively sorted keys). Signing/verification keys are **environment-only secrets**: `PROOF_SIGNING_KEY` (>= 32 bytes) and optional `PROOF_KEY_ID` (otherwise derived as a truncated SHA-256 of the key). When no key is configured, every endpoint **fails closed with 503** and an honest error — the service never fabricates key material. HMAC verification secrets are distributed to authorized verifiers out of band, never via this API.

## Required execution inputs

The verifier has no default issuer, JWKS URL, audience, credential, user, credential type or sample token. It requires an approved real credential file and the real issuer configuration:

```bash
node --import tsx src/verify.ts \
  --credential /approved/input/credential.jwt \
  --issuer https://approved-issuer.example \
  --audience approved-audience \
  --jwks-url https://approved-issuer.example/.well-known/jwks.json \
  --algorithm RS256 \
  --require-jti true \
  --evidence /approved/evidence/credential-verification.json
```

The evidence file stores a SHA-256 reference for the credential, a hashed subject reference when available, issuer/audience, key ID and issued/expiry times. For a status/revocation-capable profile, `--require-jti true` requires a non-empty JWT `jti` and records only a SHA-256 reference to that identifier. It does not store the compact JWT, the raw subject, private keys, password material or credential claims. The JTI control does not replace an issuer-approved status-list or revocation endpoint.

## Integration gate

This is an issuer-backed verification control, not a credential issuance platform. A genuine Ministry credential capability requires an approved credential profile and schema, issuer/DID or Keycloak/federation model, key-management process, holder binding, revocation/status approach, relying-party policy, STCW-F/other relevant domain requirements, privacy impact assessment, credential lifecycle workflow and authorised non-production issuer/holder/relying-party environment. Those dependencies must be supplied before any issuer or credential integration is represented as live.
