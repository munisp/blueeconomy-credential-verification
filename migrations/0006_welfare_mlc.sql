-- Crew Welfare / MLC 2006 module (phase 8, spec_crew_welfare_mlc.md).
-- Bounded to welfare_* / rest_hour_* tables; credential issuance/verification
-- tables are untouched. Anchors: MLC Reg 5.1.5 (on-board complaints,
-- anti-victimization), Reg 5.2.2 (flag-state onshore channel), Reg 2.3
-- (work/rest records surfaced digest-bound, never originated here), Reg 4.4
-- (shore-welfare directory).
--
-- Hard rules encoded at the database layer:
--   * directory entries exist only with provenance (source_reference,
--     curated_by) — no fabricated fixtures can be inserted by code paths;
--   * complaints carry the narrative only AES-256-GCM-encrypted plus its
--     SHA-256 digest, and the right-to-redress acknowledgement is a CHECK
--     (Reg 5.1.5(3) fail-closed);
--   * complaint audit events and operator rest-hour records are append-only
--     (trigger-enforced), so the anti-victimization trail and the
--     operator-originated record cannot be rewritten;
--   * complaint transitions and identity disclosures execute under
--     maker/checker dual control (mirrors 0005: requester <> approver is a
--     database CHECK);
--   * rest-hour breach flags are derived computations keyed by
--     (record, rule, policy_version) — recomputable and policy-versioned.
BEGIN;

-- The shared transactional outbox (0001) predates the welfare topic; widen
-- its topic CHECK so welfare envelopes commit with their state transitions.
ALTER TABLE credential_outbox DROP CONSTRAINT credential_outbox_topic_check;
ALTER TABLE credential_outbox ADD CONSTRAINT credential_outbox_topic_check
  CHECK (topic IN ('seafarer.credential.v1', 'seafarer.revocation.v1', 'seafarers.welfare.v1'));

-- ---------------------------------------------------------------------------
-- W1: welfare services directory (Reg 4.4). Empty is an honest state; rows
-- enter only through the curation API with provenance.
-- ---------------------------------------------------------------------------
CREATE TABLE welfare_provider (
  provider_id text PRIMARY KEY,
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 256),
  kind text NOT NULL CHECK (kind IN ('seafarer_centre','medical','transport','comms','faith','helpline','legal')),
  port_code text NOT NULL CHECK (port_code ~ '^[A-Z0-9]{2,8}$'),
  address text NOT NULL DEFAULT '' CHECK (char_length(address) <= 512),
  contact jsonb NOT NULL DEFAULT '{}'::jsonb,
  hours text NOT NULL DEFAULT '' CHECK (char_length(hours) <= 256),
  -- Provenance is mandatory: the documented public source this entry was
  -- curated from (for example an ISWAN SeafarerHelp directory URL).
  source_reference text NOT NULL CHECK (char_length(source_reference) BETWEEN 1 AND 512),
  status text NOT NULL CHECK (status IN ('ACTIVE','SUSPENDED')),
  curated_by text NOT NULL CHECK (char_length(curated_by) BETWEEN 1 AND 256),
  curated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX welfare_provider_port_idx ON welfare_provider (port_code, status);

CREATE TABLE welfare_service (
  service_id text PRIMARY KEY,
  provider_id text NOT NULL REFERENCES welfare_provider(provider_id),
  description text NOT NULL CHECK (char_length(description) BETWEEN 1 AND 1024),
  eligibility text NOT NULL DEFAULT '' CHECK (char_length(eligibility) <= 512),
  languages jsonb NOT NULL DEFAULT '[]'::jsonb
);

CREATE INDEX welfare_service_provider_idx ON welfare_service (provider_id);

-- ---------------------------------------------------------------------------
-- W2: complaint/grievance channel (Reg 5.1.5 on-board, Reg 5.2.2 flag-state).
-- narrative_enc is AES-256-GCM output (base64 nonce|ciphertext|tag); the
-- plaintext narrative is never stored. seafarer_ref binds the complaint to the
-- complainant's verified VC seafarerReferenceNumber; it is withheld from every
-- respondent-facing view until a governed disclosure sets disclosure_scope.
-- ---------------------------------------------------------------------------
CREATE TABLE welfare_complaint (
  complaint_id text PRIMARY KEY,
  channel text NOT NULL CHECK (channel IN ('onboard_r515','flagstate_r522')),
  seafarer_ref text NOT NULL CHECK (char_length(seafarer_ref) BETWEEN 1 AND 128),
  vessel_ref text NOT NULL CHECK (char_length(vessel_ref) BETWEEN 1 AND 128),
  operator_ref text CHECK (operator_ref IS NULL OR char_length(operator_ref) BETWEEN 1 AND 128),
  category text NOT NULL CHECK (category IN ('wages','rest_hours','accommodation','food','medical','harassment_bullying','repatriation','abandonment','other_mlc')),
  narrative_enc text NOT NULL CHECK (char_length(narrative_enc) BETWEEN 1 AND 65536),
  narrative_digest_sha256 text NOT NULL CHECK (narrative_digest_sha256 ~ '^[0-9a-f]{64}$'),
  attachments jsonb NOT NULL DEFAULT '[]'::jsonb,
  idempotency_key text NOT NULL UNIQUE CHECK (char_length(idempotency_key) BETWEEN 1 AND 256),
  status text NOT NULL CHECK (status IN ('RECEIVED','ACKED','ONBOARD_PROCESS','ESCALATED_FLAGSTATE','REFERRED','RESOLVED','CLOSED')),
  -- Reg 5.1.5(3): the right-to-external-redress notice must have been
  -- displayed and acknowledged at intake; the CHECK fails closed otherwise.
  right_to_redress_notice_ack boolean NOT NULL CHECK (right_to_redress_notice_ack),
  disclosure_scope text NOT NULL DEFAULT 'withheld' CHECK (disclosure_scope IN ('withheld','disclosed')),
  disclosed_at timestamptz,
  disclosed_reason_code text,
  -- Internal audit binding only; never exposed on respondent-facing views.
  created_by_subject text NOT NULL CHECK (char_length(created_by_subject) BETWEEN 1 AND 256),
  submitted_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((disclosure_scope = 'disclosed') = (disclosed_at IS NOT NULL AND disclosed_reason_code IS NOT NULL))
);

CREATE INDEX welfare_complaint_seafarer_idx ON welfare_complaint (seafarer_ref, submitted_at);
CREATE INDEX welfare_complaint_caseload_idx ON welfare_complaint (status, vessel_ref);

-- Immutable anti-victimization audit trail. actor_role records the acting
-- role class only — never the complainant identity on respondent views.
CREATE TABLE welfare_complaint_event (
  id bigserial PRIMARY KEY,
  complaint_id text NOT NULL REFERENCES welfare_complaint(complaint_id),
  at timestamptz NOT NULL DEFAULT now(),
  actor_role text NOT NULL CHECK (char_length(actor_role) BETWEEN 1 AND 64),
  transition text NOT NULL CHECK (char_length(transition) BETWEEN 1 AND 128),
  note_digest_sha256 text CHECK (note_digest_sha256 IS NULL OR note_digest_sha256 ~ '^[0-9a-f]{64}$'),
  disclosure_event boolean NOT NULL DEFAULT false
);

CREATE INDEX welfare_complaint_event_complaint_idx ON welfare_complaint_event (complaint_id, id);

CREATE OR REPLACE FUNCTION welfare_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'welfare % rows are append-only; the audit trail cannot be rewritten', TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER welfare_complaint_event_append_only
  BEFORE UPDATE OR DELETE ON welfare_complaint_event
  FOR EACH ROW
  EXECUTE FUNCTION welfare_append_only();

-- Maker/checker dual control for complaint status transitions and identity
-- disclosures, mirroring migration 0005 (credential_approval_requests): the
-- CHECK makes requester <> approver a database-layer invariant.
CREATE TABLE welfare_transition_requests (
  request_id text PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('transition','disclosure')),
  complaint_id text NOT NULL REFERENCES welfare_complaint(complaint_id),
  payload jsonb NOT NULL,
  requester_subject text NOT NULL CHECK (char_length(requester_subject) BETWEEN 1 AND 256),
  requester_role text NOT NULL CHECK (char_length(requester_role) BETWEEN 1 AND 256),
  status text NOT NULL CHECK (status IN ('PENDING','APPROVED')),
  requested_at timestamptz NOT NULL DEFAULT now(),
  approver_subject text,
  decided_at timestamptz,
  CHECK (approver_subject IS NULL OR approver_subject <> requester_subject),
  CHECK ((status = 'PENDING') = (approver_subject IS NULL AND decided_at IS NULL))
);

CREATE INDEX welfare_transition_requests_status_idx ON welfare_transition_requests (status, kind);

-- ---------------------------------------------------------------------------
-- W4: welfare-provider referrals. Consent is mandatory and timestamped.
-- ---------------------------------------------------------------------------
CREATE TABLE welfare_referral (
  referral_id text PRIMARY KEY,
  complaint_id text REFERENCES welfare_complaint(complaint_id),
  seafarer_ref text NOT NULL CHECK (char_length(seafarer_ref) BETWEEN 1 AND 128),
  service_id text NOT NULL REFERENCES welfare_service(service_id),
  consent_at timestamptz NOT NULL,
  status text NOT NULL CHECK (status IN ('OFFERED','ACCEPTED','ENGAGED','CLOSED')),
  outcome_note_digest_sha256 text CHECK (outcome_note_digest_sha256 IS NULL OR outcome_note_digest_sha256 ~ '^[0-9a-f]{64}$'),
  idempotency_key text NOT NULL UNIQUE CHECK (char_length(idempotency_key) BETWEEN 1 AND 256),
  created_by_subject text NOT NULL CHECK (char_length(created_by_subject) BETWEEN 1 AND 256),
  recorded_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX welfare_referral_seafarer_idx ON welfare_referral (seafarer_ref, recorded_at);

-- ---------------------------------------------------------------------------
-- W3: work/rest-hour record surface (Reg 2.3). Records are originated by the
-- operator/master, digest-bound and immutable (append-only trigger); the
-- module never originates or alters them. Absent records surface as
-- NOT_SUBMITTED at the read layer — never as compliant.
-- ---------------------------------------------------------------------------
CREATE TABLE rest_hour_record (
  record_id text PRIMARY KEY,
  seafarer_ref text NOT NULL CHECK (char_length(seafarer_ref) BETWEEN 1 AND 128),
  vessel_ref text NOT NULL CHECK (char_length(vessel_ref) BETWEEN 1 AND 128),
  record_date date NOT NULL,
  periods jsonb NOT NULL,
  regime text NOT NULL CHECK (regime IN ('min_rest','max_work')),
  submitted_by text NOT NULL CHECK (char_length(submitted_by) BETWEEN 1 AND 256),
  submitted_by_role text NOT NULL CHECK (submitted_by_role IN ('operator','master')),
  source_digest_sha256 text NOT NULL CHECK (source_digest_sha256 ~ '^[0-9a-f]{64}$'),
  policy_version text NOT NULL CHECK (char_length(policy_version) BETWEEN 1 AND 128),
  idempotency_key text NOT NULL UNIQUE CHECK (char_length(idempotency_key) BETWEEN 1 AND 256),
  submitted_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX rest_hour_record_seafarer_idx ON rest_hour_record (seafarer_ref, record_date);
CREATE INDEX rest_hour_record_vessel_idx ON rest_hour_record (vessel_ref, record_date);

CREATE TRIGGER rest_hour_record_append_only
  BEFORE UPDATE OR DELETE ON rest_hour_record
  FOR EACH ROW
  EXECUTE FUNCTION welfare_append_only();

-- Derived breach flags: recomputable for the same (record, policy_version);
-- the UNIQUE key makes recomputation idempotent.
CREATE TABLE rest_hour_flag (
  flag_id text PRIMARY KEY,
  record_id text NOT NULL REFERENCES rest_hour_record(record_id),
  rule text NOT NULL CHECK (rule IN ('min_rest_10h_24','min_rest_77h_7d','max_two_periods','min_one_period_6h','max_gap_14h','max_work_14h_24','max_work_72h_7d')),
  detail text NOT NULL CHECK (char_length(detail) BETWEEN 1 AND 512),
  policy_version text NOT NULL CHECK (char_length(policy_version) BETWEEN 1 AND 128),
  computed_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (record_id, rule, policy_version)
);

CREATE INDEX rest_hour_flag_record_idx ON rest_hour_flag (record_id);

-- SLA-breach observation markers: the service counts
-- welfare_complaint_sla_breaches_total exactly once per (complaint, stage)
-- even when the lifecycle observation is read repeatedly.
CREATE TABLE welfare_sla_breach_observed (
  complaint_id text NOT NULL REFERENCES welfare_complaint(complaint_id),
  stage text NOT NULL CHECK (char_length(stage) BETWEEN 1 AND 64),
  observed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (complaint_id, stage)
);

INSERT INTO schema_migrations (migration) VALUES ('0006_welfare_mlc');

COMMIT;
