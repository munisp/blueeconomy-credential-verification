-- Holder-subject -> credential index backing the seafarer wallet read surface
-- (GET /v1/wallet/credentials/current). The signed credential document is
-- persisted at issuance, atomically with the credential_status upsert, so the
-- holder can retrieve it later with nothing but their Keycloak identity.
BEGIN;

CREATE TABLE holder_credentials (
  credential_id_reference_sha256 text PRIMARY KEY
    REFERENCES credential_status (credential_id_reference_sha256),
  holder_id text NOT NULL CHECK (char_length(holder_id) BETWEEN 1 AND 256),
  issuer text NOT NULL,
  credential_document jsonb NOT NULL,
  valid_until timestamptz NOT NULL,
  issued_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX holder_credentials_holder_idx
  ON holder_credentials (holder_id, issuer);

INSERT INTO schema_migrations (migration) VALUES ('0002_holder_credentials');

COMMIT;
