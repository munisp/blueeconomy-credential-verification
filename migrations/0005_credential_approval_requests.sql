-- Maker/checker dual control for seafarer credential issuance and
-- revocation. A NIMASA-approver-tier officer (maker) submits a mutation into
-- this pending-approval ledger; it only executes when a second, distinct
-- officer of the same tier (checker) approves it. The CHECK constraint makes
-- the separation of duties a database-layer invariant, backstopping the
-- service-layer comparison, and the row itself is the audit trail binding
-- request payload, requester, approver and both timestamps.
BEGIN;

CREATE TABLE credential_approval_requests (
  request_id text PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('issuance', 'revocation')),
  payload jsonb NOT NULL,
  requester_subject text NOT NULL CHECK (char_length(requester_subject) BETWEEN 1 AND 256),
  requester_role text NOT NULL CHECK (char_length(requester_role) BETWEEN 1 AND 256),
  status text NOT NULL CHECK (status IN ('PENDING', 'APPROVED')),
  requested_at timestamptz NOT NULL DEFAULT now(),
  approver_subject text,
  decided_at timestamptz,
  CHECK (approver_subject IS NULL OR approver_subject <> requester_subject),
  CHECK ((status = 'PENDING') = (approver_subject IS NULL AND decided_at IS NULL))
);

CREATE INDEX credential_approval_requests_status_idx
  ON credential_approval_requests (status, kind);

INSERT INTO schema_migrations (migration) VALUES ('0005_credential_approval_requests');

COMMIT;
