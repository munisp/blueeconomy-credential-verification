-- Revocation is one-way. Before 0004 the credential_status upsert could move
-- a REVOKED row back to ACTIVE on re-issuance, silently reversing a published
-- revocation. This trigger makes REVOKED terminal at the database layer: any
-- UPDATE that attempts to leave REVOKED raises, regardless of which code path
-- issues it. (The application additionally guards its upsert with
-- WHERE credential_status.status <> 'REVOKED' so it can return a truthful
-- error instead of a raw constraint violation.)
BEGIN;

CREATE OR REPLACE FUNCTION credential_status_revoked_is_terminal()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.status = 'REVOKED' AND NEW.status <> 'REVOKED' THEN
    RAISE EXCEPTION 'credential status REVOKED is terminal; transition to % refused', NEW.status;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER credential_status_revoked_terminal
  BEFORE UPDATE ON credential_status
  FOR EACH ROW
  EXECUTE FUNCTION credential_status_revoked_is_terminal();

INSERT INTO schema_migrations (migration) VALUES ('0004_revocation_terminal');

COMMIT;
