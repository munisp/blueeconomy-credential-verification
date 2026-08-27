-- Durable credential status/revocation registry and transactional outbox for
-- the seafarer CoC wallet credentialing service.
BEGIN;

CREATE TABLE credential_status (
  credential_id_reference_sha256 text PRIMARY KEY,
  issuer text NOT NULL,
  status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED')),
  reason text NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 512),
  status_list_id text NOT NULL,
  status_list_index integer NOT NULL CHECK (status_list_index >= 0 AND status_list_index < 1048576),
  updated_by text NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 256),
  effective_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  sequence bigint GENERATED ALWAYS AS IDENTITY
);

CREATE INDEX credential_status_list_idx
  ON credential_status (issuer, status_list_id, status_list_index);

CREATE TABLE credential_outbox (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  topic text NOT NULL CHECK (topic IN ('seafarer.credential.v1', 'seafarer.revocation.v1')),
  event_id text NOT NULL UNIQUE,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz
);

CREATE INDEX credential_outbox_unpublished_idx
  ON credential_outbox (id)
  WHERE published_at IS NULL;

CREATE TABLE schema_migrations (
  migration text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO schema_migrations (migration) VALUES ('0001_credential_status');

COMMIT;
