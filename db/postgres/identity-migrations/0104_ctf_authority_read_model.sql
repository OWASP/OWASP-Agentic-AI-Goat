-- Inert authority read model. No runtime writer/worker or route activation.
CREATE TABLE identity.ctf_authority (
  scope_key TEXT PRIMARY KEY CHECK (scope_key = 'global' OR scope_key ~ '^(stage|owner):[1-9][0-9]*$'),
  revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0),
  owner_generation BIGINT CHECK (owner_generation >= 0),
  lifecycle_state TEXT NOT NULL DEFAULT 'uninitialized'
    CHECK (lifecycle_state IN ('uninitialized','ready','pending','blocked')),
  pending_operation_id UUID,
  next_sequence BIGINT NOT NULL DEFAULT 0 CHECK (next_sequence >= 0),
  applied_sequence BIGINT NOT NULL DEFAULT 0 CHECK (applied_sequence >= 0 AND applied_sequence <= next_sequence),
  CHECK (scope_key = 'global' OR (next_sequence = 0 AND applied_sequence = 0)),
  CHECK ((scope_key LIKE 'owner:%') = (owner_generation IS NOT NULL)),
  CHECK ((lifecycle_state = 'pending') = (pending_operation_id IS NOT NULL))
);
INSERT INTO identity.ctf_authority(scope_key) VALUES ('global');

CREATE TABLE identity.ctf_decisions (
  decision_id UUID PRIMARY KEY,
  run_id UUID NOT NULL UNIQUE,
  owner_id BIGINT NOT NULL CHECK (owner_id > 0),
  session_id BIGINT NOT NULL CHECK (session_id > 0),
  owner_key TEXT NOT NULL CHECK (octet_length(owner_key) BETWEEN 1 AND 128),
  owner_generation BIGINT NOT NULL CHECK (owner_generation >= 0),
  global_revision BIGINT NOT NULL CHECK (global_revision >= 0),
  stage_revision BIGINT NOT NULL CHECK (stage_revision >= 0),
  participant_id BIGINT NOT NULL CHECK (participant_id > 0),
  progress_id BIGINT NOT NULL CHECK (progress_id > 0),
  stage_id BIGINT NOT NULL CHECK (stage_id > 0),
  stage_digest TEXT NOT NULL CHECK (stage_digest ~ '^[a-f0-9]{64}$'),
  evidence_hash TEXT NOT NULL CHECK (evidence_hash ~ '^[a-f0-9]{64}$'),
  evidence JSONB NOT NULL CHECK (jsonb_typeof(evidence) = 'object' AND octet_length(evidence::text) <= 65536),
  verdict TEXT NOT NULL CHECK (verdict IN ('pass','fail','unavailable','blocked')),
  accepted BOOLEAN NOT NULL DEFAULT FALSE CHECK (NOT accepted OR verdict = 'pass'),
  sequence BIGINT NOT NULL UNIQUE CHECK (sequence > 0),
  UNIQUE (decision_id, sequence),
  authorized_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
  -- Historical identifiers deliberately have no cascading user/session FK.
);
CREATE UNIQUE INDEX ctf_decisions_accepted_incarnation ON identity.ctf_decisions
  (owner_id, owner_generation, participant_id, progress_id, stage_id) WHERE accepted;
CREATE FUNCTION identity.reject_ctf_decision_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN RAISE EXCEPTION 'CTF decisions are immutable'; END;
$$;
REVOKE ALL ON FUNCTION identity.reject_ctf_decision_mutation() FROM PUBLIC;
CREATE TRIGGER ctf_decisions_immutable BEFORE UPDATE OR DELETE ON identity.ctf_decisions
FOR EACH ROW EXECUTE FUNCTION identity.reject_ctf_decision_mutation();

CREATE TABLE identity.ctf_outbox (
  sequence BIGINT PRIMARY KEY CHECK (sequence > 0),
  operation_id UUID NOT NULL UNIQUE,
  decision_id UUID UNIQUE,
  kind TEXT NOT NULL CHECK (kind IN ('decision','catalog_mutation','owner_reset','owner_remove',
    'global_reset','ban','unban','blocklist_clear','admit_attempt','record_blocked_attempt',
    'register','start','hint')),
  command JSONB NOT NULL CHECK (jsonb_typeof(command) = 'object' AND octet_length(command::text) <= 65536),
  command_hash TEXT NOT NULL CHECK (command_hash ~ '^[a-f0-9]{64}$'),
  state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','applied','blocked')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 1000000),
  next_attempt_at TIMESTAMPTZ,
  error_class TEXT CHECK (octet_length(error_class) <= 128),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CHECK ((kind = 'decision') = (decision_id IS NOT NULL)),
  FOREIGN KEY (decision_id, sequence) REFERENCES identity.ctf_decisions(decision_id, sequence)
);
CREATE TABLE identity.ctf_adaptive_memory (
  memory_id UUID PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('technique','payload')),
  stage_id BIGINT NOT NULL CHECK (stage_id > 0),
  stage_revision BIGINT NOT NULL CHECK (stage_revision >= 0),
  clear_revision BIGINT NOT NULL DEFAULT 0 CHECK (clear_revision >= 0),
  owner_id BIGINT CHECK (owner_id > 0),
  owner_generation BIGINT CHECK (owner_generation >= 0),
  technique_tag TEXT CHECK (octet_length(technique_tag) BETWEEN 1 AND 128),
  payload_hash TEXT CHECK (payload_hash ~ '^[a-f0-9]{64}$'),
  normalized_payload TEXT CHECK (octet_length(normalized_payload) <= 16384),
  decision_id UUID REFERENCES identity.ctf_decisions(decision_id),
  legacy_source TEXT CHECK (octet_length(legacy_source) BETWEEN 1 AND 256),
  CHECK ((decision_id IS NULL) <> (legacy_source IS NULL)),
  CHECK ((kind = 'technique' AND owner_id IS NOT NULL AND owner_generation IS NOT NULL
    AND technique_tag IS NOT NULL AND payload_hash IS NULL AND normalized_payload IS NULL)
    OR (kind = 'payload' AND owner_id IS NULL AND owner_generation IS NULL
    AND technique_tag IS NULL AND payload_hash IS NOT NULL AND normalized_payload IS NOT NULL))
);
CREATE UNIQUE INDEX ctf_adaptive_technique_identity ON identity.ctf_adaptive_memory
  (stage_id,stage_revision,clear_revision,owner_id,owner_generation,technique_tag) WHERE kind='technique';
CREATE UNIQUE INDEX ctf_adaptive_payload_identity ON identity.ctf_adaptive_memory
  (stage_id,stage_revision,clear_revision,payload_hash) WHERE kind='payload';
REVOKE ALL ON identity.ctf_authority, identity.ctf_decisions, identity.ctf_outbox,
  identity.ctf_adaptive_memory FROM PUBLIC, dvaia_identity_runtime;
GRANT SELECT ON identity.ctf_authority, identity.ctf_decisions, identity.ctf_outbox,
  identity.ctf_adaptive_memory TO dvaia_identity_runtime;
