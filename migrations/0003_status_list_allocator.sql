-- Durable status-list index allocator. The pre-0003 in-process counter
-- (seeded from BLUEECONOMY_STATUS_LIST_INDEX_START) could hand out duplicate
-- bitstring indices after a restart or across replicas, so revoking one
-- credential could silently flip the bit of another. Allocation now serializes
-- on a per-list counter row, and a UNIQUE index backstops the invariant at
-- the database layer: any duplicate placement fails the transaction.
BEGIN;

CREATE TABLE status_list_allocator (
  status_list_id text PRIMARY KEY,
  next_index integer NOT NULL CHECK (next_index >= 0 AND next_index <= 1048576)
);

CREATE UNIQUE INDEX credential_status_unique_list_position
  ON credential_status (issuer, status_list_id, status_list_index);

DROP INDEX credential_status_list_idx;

INSERT INTO schema_migrations (migration) VALUES ('0003_status_list_allocator');

COMMIT;
