# Blue Economy Credential Verification

This repository contains a TypeScript command that validates an **actual compact signed JWT credential** against an explicitly supplied HTTPS issuer, audience and JWKS endpoint. It uses the `jose` library to retrieve the issuer’s public keys and verify the credential signature and registered issuer/audience/time claims.

## Required execution inputs

The verifier has no default issuer, JWKS URL, audience, credential, user, credential type or sample token. It requires an approved real credential file and the real issuer configuration:

```bash
node --import tsx src/verify.ts \
  --credential /approved/input/credential.jwt \
  --issuer https://approved-issuer.example \
  --audience approved-audience \
  --jwks-url https://approved-issuer.example/.well-known/jwks.json \
  --evidence /approved/evidence/credential-verification.json
```

The evidence file stores a SHA-256 reference for the credential, a hashed subject reference when available, issuer/audience, key ID and issued/expiry times. It does not store the compact JWT, the raw subject, private keys, password material or credential claims.

## Integration gate

This is an issuer-backed verification control, not a credential issuance platform. A genuine Ministry credential capability requires an approved credential profile and schema, issuer/DID or Keycloak/federation model, key-management process, holder binding, revocation/status approach, relying-party policy, STCW-F/other relevant domain requirements, privacy impact assessment, credential lifecycle workflow and authorised non-production issuer/holder/relying-party environment. Those dependencies must be supplied before any issuer or credential integration is represented as live.
