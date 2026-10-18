-- UNREGISTERED PRODUCTION CANDIDATE. Native fresh/upgrade/replay qualification
-- is required before migration registration. The historical protected-storage
-- draft remains unchanged. This candidate performs no legacy source import.

CREATE SCHEMA legacy_ai_private;
REVOKE ALL ON SCHEMA legacy_ai_private FROM PUBLIC;

CREATE TABLE legacy_ai_private.owners (
  owner_id integer PRIMARY KEY REFERENCES identity.users(id) ON DELETE CASCADE,
  generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE legacy_ai_private.history (
  request_id uuid PRIMARY KEY,
  owner_id integer NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
  generation bigint NOT NULL CHECK (generation >= 0),
  source_route text NOT NULL CHECK (source_route IN (
    'prompt_injection', 'chain_of_thought', 'context_stuffing', 'multi_turn_jailbreak'
  )),
  prompt text NOT NULL CHECK (octet_length(prompt) BETWEEN 1 AND 65536),
  response text NOT NULL CHECK (octet_length(response) BETWEEN 1 AND 262144),
  model_used text NOT NULL CHECK (octet_length(model_used) BETWEEN 1 AND 256),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX legacy_ai_history_owner_generation
  ON legacy_ai_private.history(owner_id, generation, created_at DESC, request_id DESC);
-- Administrator history is globally ordered, without an owner predicate.
CREATE INDEX legacy_ai_history_admin_created
  ON legacy_ai_private.history(created_at DESC, request_id DESC);

CREATE TABLE legacy_ai_private.reset_receipts (
  reset_request_id uuid PRIMARY KEY,
  owner_id integer NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
  from_generation bigint NOT NULL CHECK (from_generation >= 0),
  to_generation bigint NOT NULL CHECK (to_generation = from_generation + 1),
  removed_count integer NOT NULL CHECK (removed_count >= 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX legacy_ai_reset_owner
  ON legacy_ai_private.reset_receipts(owner_id, created_at, reset_request_id);

-- A retry before the adapter acknowledges its still-pending/failed step must
-- return the durable cleanup result rather than infer ownership from an archive
-- record or repeat a partial deletion. The receipt remains after acknowledgement.
CREATE TABLE legacy_ai_private.deletion_receipts (
  job_id uuid PRIMARY KEY REFERENCES identity.student_deletion_jobs(job_id) ON DELETE RESTRICT,
  owner_id integer NOT NULL CHECK (owner_id > 0),
  history_removed integer NOT NULL CHECK (history_removed >= 0),
  reset_receipts_removed integer NOT NULL CHECK (reset_receipts_removed >= 0),
  owner_state_removed integer NOT NULL CHECK (owner_state_removed >= 0),
  archive_removed integer NOT NULL CHECK (archive_removed >= 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Migration-only, lossless quarantine and resume journal. Runtime roles receive
-- no table or function access to these records. A future reviewed importer must
-- write the complete source-row JSON and its authoritative digest before source
-- removal; it may never infer a platform owner from the legacy local user_id.
CREATE TABLE legacy_ai_private.import_batches (
  batch_id uuid PRIMARY KEY,
  source_store_identity text NOT NULL CHECK (octet_length(source_store_identity) BETWEEN 1 AND 512),
  state text NOT NULL CHECK (state IN ('copying', 'verified', 'source_removed', 'blocked')),
  expected_count integer NOT NULL CHECK (expected_count >= 0),
  copied_count integer NOT NULL DEFAULT 0 CHECK (copied_count >= 0),
  aggregate_digest text NOT NULL CHECK (aggregate_digest ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  verified_at timestamptz,
  source_removed_at timestamptz,
  CHECK (copied_count <= expected_count),
  CHECK (state NOT IN ('verified', 'source_removed') OR copied_count = expected_count),
  CHECK ((state IN ('verified', 'source_removed')) = (verified_at IS NOT NULL)),
  CHECK ((state = 'source_removed') = (source_removed_at IS NOT NULL))
);

CREATE TABLE legacy_ai_private.import_archive (
  batch_id uuid NOT NULL REFERENCES legacy_ai_private.import_batches(batch_id) ON DELETE RESTRICT,
  source_row_id bigint NOT NULL CHECK (source_row_id BETWEEN -2147483648 AND 2147483647),
  -- Legacy SQLite TEXT is unbounded. Do not impose an application-history
  -- limit here: an oversized owned row may block promotion, but its complete
  -- source bytes must remain quarantined rather than being truncated.
  source_record jsonb NOT NULL CHECK (jsonb_typeof(source_record) = 'object'),
  source_digest text NOT NULL CHECK (source_digest ~ '^[0-9a-f]{64}$'),
  classification text NOT NULL DEFAULT 'unknown'
    CHECK (classification IN ('unknown', 'conflict', 'owned', 'synthetic')),
  classified_owner_id integer REFERENCES identity.users(id) ON DELETE RESTRICT,
  archived_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (batch_id, source_row_id),
  CHECK ((classification = 'owned') = (classified_owner_id IS NOT NULL))
);

-- These target-only records are an append-only import proof. They are never
-- callable by either runtime role. `source_record` is archived before an owned
-- row can be promoted into application-limited history, and a source-removal
-- capability is deliberately absent from this draft.
CREATE TABLE legacy_ai_private.import_history_receipts (
  batch_id uuid NOT NULL,
  source_row_id bigint NOT NULL,
  source_digest text NOT NULL CHECK (source_digest ~ '^[0-9a-f]{64}$'),
  owner_id integer NOT NULL REFERENCES identity.users(id) ON DELETE RESTRICT,
  request_id uuid NOT NULL,
  source_route text NOT NULL CHECK (source_route IN ('prompt_injection', 'chain_of_thought', 'context_stuffing', 'multi_turn_jailbreak')),
  history_digest text NOT NULL CHECK (history_digest ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL,
  promoted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (batch_id, source_row_id),
  UNIQUE (request_id),
  FOREIGN KEY (batch_id, source_row_id)
    REFERENCES legacy_ai_private.import_archive(batch_id, source_row_id) ON DELETE RESTRICT
);

CREATE TABLE legacy_ai_private.import_batch_events (
  batch_id uuid NOT NULL REFERENCES legacy_ai_private.import_batches(batch_id) ON DELETE RESTRICT,
  event_ordinal bigint GENERATED ALWAYS AS IDENTITY,
  event_kind text NOT NULL CHECK (event_kind IN ('started', 'archived', 'promoted', 'verified', 'invalidated_by_deletion', 'source_cleanup_committed')),
  event_digest text NOT NULL CHECK (event_digest ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (batch_id, event_ordinal)
);

-- One immutable cross-store acknowledgement, independent of archive deletion.
CREATE UNIQUE INDEX legacy_ai_source_cleanup_ack_once
  ON legacy_ai_private.import_batch_events(batch_id,event_kind)
  WHERE event_kind='source_cleanup_committed';

REVOKE ALL ON legacy_ai_private.owners,
  legacy_ai_private.history,
  legacy_ai_private.reset_receipts,
  legacy_ai_private.deletion_receipts,
  legacy_ai_private.import_batches,
  legacy_ai_private.import_archive,
  legacy_ai_private.import_history_receipts,
  legacy_ai_private.import_batch_events
FROM PUBLIC, dvaia_identity_runtime;

CREATE FUNCTION legacy_ai_private.assert_live_session(requested_owner integer, requested_session bigint)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE account identity.users%ROWTYPE; active_session identity.user_sessions%ROWTYPE;
BEGIN
  IF requested_owner IS NULL OR requested_session IS NULL THEN
    RAISE EXCEPTION 'Complete legacy AI history authority required' USING ERRCODE = '55000';
  END IF;
  -- The locked owner row is the deletion fence. Student-deletion admission
  -- locks its subject account FOR UPDATE before it checks/inserts a job, so a
  -- history operation sees either the pre-admission account with no job or the
  -- completed admission with the account disabled and its job present. Do not
  -- take a table lock here: it reverses that order and couples other students.
  SELECT * INTO account FROM identity.users WHERE id = requested_owner FOR SHARE;
  SELECT * INTO active_session FROM identity.user_sessions
    WHERE id = requested_session AND user_id = requested_owner FOR SHARE;
  IF account.id IS NULL OR account.is_active <> 1
    OR account.role NOT IN ('student', 'admin', 'super_admin')
    OR (account.account_locked_until IS NOT NULL AND account.account_locked_until > clock_timestamp())
    OR active_session.id IS NULL OR active_session.is_active <> 1
    OR active_session.expires_at <= clock_timestamp()
    OR EXISTS (SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id = requested_owner)
  THEN
    RAISE EXCEPTION 'Legacy AI history authority unavailable' USING ERRCODE = '55000';
  END IF;
END
$$;

CREATE FUNCTION legacy_ai_private.assert_admin_reader(requested_admin integer, requested_session bigint)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE account identity.users%ROWTYPE;
BEGIN
  PERFORM legacy_ai_private.assert_live_session(requested_admin, requested_session);
  SELECT * INTO account FROM identity.users WHERE id = requested_admin FOR SHARE;
  IF account.role NOT IN ('admin', 'super_admin') OR account.admin_level < 1 THEN
    RAISE EXCEPTION 'Legacy AI history administrator permission unavailable' USING ERRCODE = '42501';
  END IF;
  -- Hold the exact grant row through the protected SELECT. A revocation or
  -- expiry update waits instead of racing the authorization check.
  PERFORM 1 FROM identity.admin_permissions permission
    WHERE permission.admin_id = requested_admin
      AND permission.permission_name = 'view_analytics'
      AND permission.is_active = 1
      AND (permission.expires_at IS NULL OR permission.expires_at > clock_timestamp())
    FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Legacy AI history administrator permission unavailable' USING ERRCODE = '42501';
  END IF;
END
$$;

-- Admission is a short transaction; inference must run after it commits.
-- Append rechecks the live session and generation, so this is not a durable
-- authorization token and cannot allow a stale response across reset/deletion.
CREATE FUNCTION legacy_ai_private.admit_history(requested_owner integer, requested_session bigint)
RETURNS TABLE (owner_id integer, session_id bigint, generation bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  PERFORM legacy_ai_private.assert_live_session(requested_owner, requested_session);
  INSERT INTO legacy_ai_private.owners(owner_id) VALUES(requested_owner) ON CONFLICT DO NOTHING;
  RETURN QUERY SELECT owned.owner_id, requested_session, owned.generation
    FROM legacy_ai_private.owners owned
    WHERE owned.owner_id = requested_owner FOR SHARE;
END
$$;

CREATE FUNCTION legacy_ai_private.append_history(
  requested_owner integer,
  requested_session bigint,
  expected_generation bigint,
  requested_id uuid,
  requested_route text,
  requested_prompt text,
  requested_response text,
  requested_model text
)
RETURNS TABLE (
  request_id uuid,
  owner_id integer,
  generation bigint,
  source_route text,
  prompt text,
  response text,
  model_used text,
  created_at timestamptz,
  cursor_token text,
  replayed boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE current_generation bigint; prior legacy_ai_private.history%ROWTYPE; inserted_at timestamptz;
BEGIN
  PERFORM legacy_ai_private.assert_live_session(requested_owner, requested_session);
  IF expected_generation IS NULL OR expected_generation < 0 OR requested_id IS NULL
    OR requested_route NOT IN ('prompt_injection', 'chain_of_thought', 'context_stuffing', 'multi_turn_jailbreak')
    OR requested_prompt IS NULL OR octet_length(requested_prompt) NOT BETWEEN 1 AND 65536
    OR requested_response IS NULL OR octet_length(requested_response) NOT BETWEEN 1 AND 262144
    OR requested_model IS NULL OR octet_length(requested_model) NOT BETWEEN 1 AND 256
  THEN
    RAISE EXCEPTION 'Invalid legacy AI history append' USING ERRCODE = '22023';
  END IF;

  INSERT INTO legacy_ai_private.owners(owner_id) VALUES(requested_owner) ON CONFLICT DO NOTHING;
  SELECT owned.generation INTO current_generation FROM legacy_ai_private.owners owned
    WHERE owned.owner_id = requested_owner FOR UPDATE;
  IF current_generation <> expected_generation THEN
    RAISE EXCEPTION 'Legacy AI history generation is stale' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO prior FROM legacy_ai_private.history item WHERE item.request_id = requested_id;
  IF prior.request_id IS NOT NULL THEN
    IF prior.owner_id <> requested_owner OR prior.generation <> expected_generation
      OR prior.source_route <> requested_route OR prior.prompt <> requested_prompt
      OR prior.response <> requested_response OR prior.model_used <> requested_model
    THEN
      RAISE EXCEPTION 'Legacy AI history request differs' USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT prior.request_id, prior.owner_id, prior.generation, prior.source_route,
      prior.prompt, prior.response, prior.model_used, prior.created_at,
      to_char(prior.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
        || '|' || prior.request_id::text, true;
    RETURN;
  END IF;

  INSERT INTO legacy_ai_private.history(
    request_id, owner_id, generation, source_route, prompt, response, model_used
  ) VALUES (
    requested_id, requested_owner, expected_generation, requested_route,
    requested_prompt, requested_response, requested_model
  ) RETURNING legacy_ai_private.history.created_at INTO inserted_at;
  RETURN QUERY SELECT requested_id, requested_owner, expected_generation, requested_route,
    requested_prompt, requested_response, requested_model, inserted_at,
    to_char(inserted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
      || '|' || requested_id::text, false;
END
$$;

CREATE FUNCTION legacy_ai_private.list_own_history(
  requested_owner integer,
  requested_session bigint,
  requested_limit integer,
  requested_cursor text
)
RETURNS TABLE (
  request_id uuid,
  owner_id integer,
  generation bigint,
  source_route text,
  prompt text,
  response text,
  model_used text,
  created_at timestamptz,
  cursor_token text,
  replayed boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE current_generation bigint; before_created_at timestamptz; before_request_id uuid;
BEGIN
  PERFORM legacy_ai_private.assert_live_session(requested_owner, requested_session);
  IF requested_limit IS NULL OR requested_limit NOT BETWEEN 1 AND 200
    OR (requested_cursor IS NOT NULL AND requested_cursor !~
      '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z\|[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
  THEN
    RAISE EXCEPTION 'Invalid legacy AI history page' USING ERRCODE = '22023';
  END IF;
  IF requested_cursor IS NOT NULL THEN
    before_created_at := split_part(requested_cursor, '|', 1)::timestamptz;
    before_request_id := split_part(requested_cursor, '|', 2)::uuid;
  END IF;
  SELECT owned.generation INTO current_generation FROM legacy_ai_private.owners owned
    WHERE owned.owner_id = requested_owner FOR SHARE;
  IF current_generation IS NULL THEN RETURN; END IF;
  RETURN QUERY SELECT item.request_id, item.owner_id, item.generation, item.source_route,
    item.prompt, item.response, item.model_used, item.created_at,
    to_char(item.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
      || '|' || item.request_id::text, false
  FROM legacy_ai_private.history item
  WHERE item.owner_id = requested_owner AND item.generation = current_generation
    AND (requested_cursor IS NULL OR (item.created_at, item.request_id) < (before_created_at, before_request_id))
  ORDER BY item.created_at DESC, item.request_id DESC
  LIMIT requested_limit;
END
$$;

CREATE FUNCTION legacy_ai_private.list_admin_history(
  requested_admin integer,
  requested_session bigint,
  requested_limit integer,
  requested_cursor text
)
RETURNS TABLE (
  request_id uuid,
  owner_id integer,
  generation bigint,
  source_route text,
  prompt text,
  response text,
  model_used text,
  created_at timestamptz,
  cursor_token text,
  replayed boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE before_created_at timestamptz; before_request_id uuid;
BEGIN
  PERFORM legacy_ai_private.assert_admin_reader(requested_admin, requested_session);
  IF requested_limit IS NULL OR requested_limit NOT BETWEEN 1 AND 200
    OR (requested_cursor IS NOT NULL AND requested_cursor !~
      '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z\|[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
  THEN
    RAISE EXCEPTION 'Invalid legacy AI history administrator page' USING ERRCODE = '22023';
  END IF;
  IF requested_cursor IS NOT NULL THEN
    before_created_at := split_part(requested_cursor, '|', 1)::timestamptz;
    before_request_id := split_part(requested_cursor, '|', 2)::uuid;
  END IF;
  RETURN QUERY SELECT item.request_id, item.owner_id, item.generation, item.source_route,
    item.prompt, item.response, item.model_used, item.created_at,
    to_char(item.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
      || '|' || item.request_id::text, false
  FROM legacy_ai_private.history item
  JOIN legacy_ai_private.owners owned
    ON owned.owner_id = item.owner_id AND owned.generation = item.generation
  WHERE requested_cursor IS NULL OR (item.created_at, item.request_id) < (before_created_at, before_request_id)
  ORDER BY item.created_at DESC, item.request_id DESC
  LIMIT requested_limit;
END
$$;

CREATE FUNCTION legacy_ai_private.reset_history(
  requested_owner integer,
  requested_session bigint,
  expected_generation bigint,
  requested_reset uuid
)
RETURNS TABLE (
  reset_request_id uuid,
  owner_id integer,
  from_generation bigint,
  to_generation bigint,
  removed_count integer,
  created_at timestamptz,
  replayed boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE current_generation bigint; prior legacy_ai_private.reset_receipts%ROWTYPE;
  removed integer; next_generation bigint; recorded_at timestamptz;
BEGIN
  PERFORM legacy_ai_private.assert_live_session(requested_owner, requested_session);
  IF expected_generation IS NULL OR expected_generation < 0 OR requested_reset IS NULL THEN
    RAISE EXCEPTION 'Invalid legacy AI history reset' USING ERRCODE = '22023';
  END IF;
  INSERT INTO legacy_ai_private.owners(owner_id) VALUES(requested_owner) ON CONFLICT DO NOTHING;
  SELECT owned.generation INTO current_generation FROM legacy_ai_private.owners owned
    WHERE owned.owner_id = requested_owner FOR UPDATE;

  SELECT * INTO prior FROM legacy_ai_private.reset_receipts receipt
    WHERE receipt.reset_request_id = requested_reset;
  IF prior.reset_request_id IS NOT NULL THEN
    IF prior.owner_id <> requested_owner OR prior.from_generation <> expected_generation THEN
      RAISE EXCEPTION 'Legacy AI history reset request differs' USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT prior.reset_request_id, prior.owner_id, prior.from_generation,
      prior.to_generation, prior.removed_count, prior.created_at, true;
    RETURN;
  END IF;

  IF current_generation <> expected_generation OR current_generation = 9223372036854775807 THEN
    RAISE EXCEPTION 'Legacy AI history reset generation is stale' USING ERRCODE = '55000';
  END IF;
  next_generation := current_generation + 1;
  DELETE FROM legacy_ai_private.history item WHERE item.owner_id = requested_owner;
  GET DIAGNOSTICS removed = ROW_COUNT;
  UPDATE legacy_ai_private.owners
    SET generation = next_generation, updated_at = clock_timestamp()
    WHERE legacy_ai_private.owners.owner_id = requested_owner;
  INSERT INTO legacy_ai_private.reset_receipts(
    reset_request_id, owner_id, from_generation, to_generation, removed_count
  ) VALUES (requested_reset, requested_owner, current_generation, next_generation, removed)
  RETURNING legacy_ai_private.reset_receipts.created_at INTO recorded_at;
  RETURN QUERY SELECT requested_reset, requested_owner, current_generation,
    next_generation, removed, recorded_at, false;
END
$$;

-- Migration/operator-only import primitives. Their callers must be separately
-- constructed capabilities; no application or challenge runtime grant follows.
CREATE FUNCTION legacy_ai_private.begin_history_import(
  requested_batch uuid, requested_source_store text, requested_expected_count integer, requested_aggregate_digest text
)
RETURNS TABLE(batch_id uuid, state text, expected_count integer, aggregate_digest text, replayed boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE located legacy_ai_private.import_batches%ROWTYPE;
BEGIN
  IF requested_batch IS NULL OR requested_source_store IS NULL OR octet_length(requested_source_store) NOT BETWEEN 1 AND 512
    OR requested_expected_count IS NULL OR requested_expected_count < 0
    OR requested_aggregate_digest IS NULL OR requested_aggregate_digest !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'Complete immutable legacy AI import identity required' USING ERRCODE='22023';
  END IF;
  SELECT * INTO located FROM legacy_ai_private.import_batches existing WHERE existing.batch_id=requested_batch FOR UPDATE;
  IF located.batch_id IS NOT NULL THEN
    IF located.source_store_identity<>requested_source_store OR located.expected_count<>requested_expected_count
      OR located.aggregate_digest<>requested_aggregate_digest THEN
      RAISE EXCEPTION 'Legacy AI import batch conflicts with prior bytes' USING ERRCODE='23505';
    END IF;
    RETURN QUERY SELECT located.batch_id,located.state,located.expected_count,located.aggregate_digest,true; RETURN;
  END IF;
  INSERT INTO legacy_ai_private.import_batches(batch_id,source_store_identity,state,expected_count,aggregate_digest)
    VALUES(requested_batch,requested_source_store,'copying',requested_expected_count,requested_aggregate_digest);
  INSERT INTO legacy_ai_private.import_batch_events(batch_id,event_kind,event_digest)
    VALUES(requested_batch,'started',requested_aggregate_digest);
  RETURN QUERY SELECT requested_batch,'copying',requested_expected_count,requested_aggregate_digest,false;
END $$;

CREATE FUNCTION legacy_ai_private.archive_history_import_row(
  requested_batch uuid, requested_source_row bigint, requested_source_record jsonb,
  requested_source_digest text, requested_classification text, requested_owner integer
)
RETURNS TABLE(batch_id uuid, source_row_id bigint, source_digest text, replayed boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE batch legacy_ai_private.import_batches%ROWTYPE; prior legacy_ai_private.import_archive%ROWTYPE; copied integer;
BEGIN
  IF requested_source_record IS NULL OR jsonb_typeof(requested_source_record)<>'object' OR requested_source_row IS NULL OR requested_source_row NOT BETWEEN -2147483648 AND 2147483647
    OR requested_source_digest IS NULL OR requested_source_digest !~ '^[0-9a-f]{64}$'
    OR requested_classification NOT IN ('owned','unknown')
    OR (requested_classification='owned' AND requested_owner IS NULL) OR (requested_classification='unknown' AND requested_owner IS NOT NULL) THEN
    RAISE EXCEPTION 'Exact archived legacy AI source row required' USING ERRCODE='22023';
  END IF;
  -- Owned archive insertion has a foreign key to identity.users. Take the
  -- identity/deletion fence before the batch lock so it cannot invert cleanup's
  -- user → batch order. Unknown quarantine has no platform-owner lock.
  IF requested_classification='owned' THEN
    PERFORM 1 FROM identity.users attested_owner WHERE attested_owner.id=requested_owner
      AND attested_owner.is_active<>0 AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs deletion_job
        WHERE deletion_job.subject_user_id=requested_owner) FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Owned archive requires a live non-deleting identity owner' USING ERRCODE='55000'; END IF;
  END IF;
  SELECT * INTO batch FROM legacy_ai_private.import_batches located WHERE located.batch_id=requested_batch FOR UPDATE;
  IF batch.batch_id IS NULL OR batch.state<>'copying' THEN RAISE EXCEPTION 'Legacy AI import copy phase unavailable' USING ERRCODE='55000'; END IF;
  SELECT * INTO prior FROM legacy_ai_private.import_archive archived WHERE archived.batch_id=requested_batch AND archived.source_row_id=requested_source_row FOR UPDATE;
  IF prior.batch_id IS NOT NULL THEN
    IF prior.source_digest<>requested_source_digest OR prior.source_record IS DISTINCT FROM requested_source_record
      OR prior.classification<>requested_classification OR prior.classified_owner_id IS DISTINCT FROM requested_owner THEN
      RAISE EXCEPTION 'Legacy AI archived source row conflicts' USING ERRCODE='23505'; END IF;
    RETURN QUERY SELECT prior.batch_id,prior.source_row_id,prior.source_digest,true; RETURN;
  END IF;
  INSERT INTO legacy_ai_private.import_archive(batch_id,source_row_id,source_record,source_digest,classification,classified_owner_id)
    VALUES(requested_batch,requested_source_row,requested_source_record,requested_source_digest,requested_classification,requested_owner);
  SELECT count(*)::integer INTO copied FROM legacy_ai_private.import_archive copied_row
    WHERE copied_row.batch_id=requested_batch;
  IF copied>batch.expected_count THEN RAISE EXCEPTION 'Legacy AI import count conflicts' USING ERRCODE='23505'; END IF;
  UPDATE legacy_ai_private.import_batches updated_batch SET copied_count=copied
    WHERE updated_batch.batch_id=requested_batch;
  INSERT INTO legacy_ai_private.import_batch_events(batch_id,event_kind,event_digest) VALUES(requested_batch,'archived',requested_source_digest);
  RETURN QUERY SELECT requested_batch,requested_source_row,requested_source_digest,false;
END $$;

CREATE FUNCTION legacy_ai_private.promote_owned_history_import_row(
  requested_batch uuid, requested_source_row bigint, requested_owner integer, requested_request uuid,
  requested_route text, requested_prompt text, requested_response text, requested_model text,
  requested_created_at timestamptz, requested_history_digest text
)
RETURNS TABLE(request_id uuid, owner_id integer, source_row_id bigint, replayed boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE archived legacy_ai_private.import_archive%ROWTYPE; prior legacy_ai_private.import_history_receipts%ROWTYPE; stored legacy_ai_private.history%ROWTYPE; owner_state legacy_ai_private.owners%ROWTYPE; batch legacy_ai_private.import_batches%ROWTYPE;
BEGIN
  IF requested_batch IS NULL OR requested_source_row IS NULL OR requested_source_row NOT BETWEEN -2147483648 AND 2147483647 OR requested_owner IS NULL OR requested_owner<1
    OR requested_request IS NULL OR requested_route NOT IN ('prompt_injection','chain_of_thought','context_stuffing','multi_turn_jailbreak')
    OR requested_prompt IS NULL OR requested_response IS NULL OR requested_model IS NULL OR requested_created_at IS NULL
    OR requested_history_digest IS NULL OR requested_history_digest !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'Complete owned legacy AI import receipt required' USING ERRCODE='22023'; END IF;
  -- Global import/deletion order: identity user, owner generation, batch, then
  -- archive/receipt. Deletion admission already owns the user lock first.
  PERFORM 1 FROM identity.users import_owner WHERE import_owner.id=requested_owner
    AND import_owner.is_active<>0 AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs deletion_job
      WHERE deletion_job.subject_user_id=requested_owner) FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Owned legacy import requires a live quiescent owner' USING ERRCODE='55000'; END IF;
  INSERT INTO legacy_ai_private.owners(owner_id) VALUES(requested_owner) ON CONFLICT DO NOTHING;
  SELECT * INTO owner_state FROM legacy_ai_private.owners current_owner WHERE current_owner.owner_id=requested_owner FOR UPDATE;
  IF owner_state.generation<>0 THEN RAISE EXCEPTION 'Owned legacy import requires quiescent generation zero' USING ERRCODE='55000'; END IF;
  SELECT * INTO batch FROM legacy_ai_private.import_batches import_batch WHERE import_batch.batch_id=requested_batch FOR UPDATE;
  IF batch.batch_id IS NULL OR batch.state<>'copying' THEN RAISE EXCEPTION 'Legacy AI import promotion unavailable' USING ERRCODE='55000'; END IF;
  SELECT * INTO archived FROM legacy_ai_private.import_archive source_row
    WHERE source_row.batch_id=requested_batch AND source_row.source_row_id=requested_source_row FOR UPDATE;
  IF archived.batch_id IS NULL OR archived.classification<>'owned' OR archived.classified_owner_id<>requested_owner THEN
    RAISE EXCEPTION 'Explicit owned archive receipt required' USING ERRCODE='55000'; END IF;
  SELECT * INTO prior FROM legacy_ai_private.import_history_receipts receipt
    WHERE receipt.batch_id=requested_batch AND receipt.source_row_id=requested_source_row FOR UPDATE;
  IF prior.batch_id IS NOT NULL THEN
    IF prior.owner_id<>requested_owner OR prior.request_id<>requested_request OR prior.source_route<>requested_route
      OR prior.history_digest<>requested_history_digest OR prior.created_at<>requested_created_at OR prior.source_digest<>archived.source_digest THEN
      RAISE EXCEPTION 'Legacy AI history import receipt conflicts' USING ERRCODE='23505'; END IF;
    RETURN QUERY SELECT prior.request_id,prior.owner_id,requested_source_row,true; RETURN;
  END IF;
  IF octet_length(requested_prompt)>65536 OR octet_length(requested_response)>262144 OR octet_length(requested_model)>256 THEN
    RAISE EXCEPTION 'Owned history exceeds application limits after lossless archive' USING ERRCODE='22001'; END IF;
  SELECT * INTO stored FROM legacy_ai_private.history item WHERE item.request_id=requested_request FOR UPDATE;
  IF stored.request_id IS NOT NULL THEN
    RAISE EXCEPTION 'Legacy AI history request identifier conflicts' USING ERRCODE='23505'; END IF;
  INSERT INTO legacy_ai_private.history(request_id,owner_id,generation,source_route,prompt,response,model_used,created_at)
    VALUES(requested_request,requested_owner,owner_state.generation,requested_route,requested_prompt,requested_response,requested_model,requested_created_at);
  INSERT INTO legacy_ai_private.import_history_receipts(batch_id,source_row_id,source_digest,owner_id,request_id,source_route,history_digest,created_at)
    VALUES(requested_batch,requested_source_row,archived.source_digest,requested_owner,requested_request,requested_route,requested_history_digest,requested_created_at);
  INSERT INTO legacy_ai_private.import_batch_events(batch_id,event_kind,event_digest) VALUES(requested_batch,'promoted',requested_history_digest);
  RETURN QUERY SELECT requested_request,requested_owner,requested_source_row,false;
END $$;

CREATE FUNCTION legacy_ai_private.verify_history_import_quarantine(requested_batch uuid, requested_count integer, requested_aggregate_digest text)
RETURNS TABLE(batch_id uuid, verified_at timestamptz, source_removal_receipt text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE batch legacy_ai_private.import_batches%ROWTYPE; copied integer; missing_owned boolean; verified timestamptz;
BEGIN
  SELECT * INTO batch FROM legacy_ai_private.import_batches located WHERE located.batch_id=requested_batch FOR UPDATE;
  IF batch.batch_id IS NULL OR batch.expected_count<>requested_count OR batch.aggregate_digest<>requested_aggregate_digest THEN
    RAISE EXCEPTION 'Exact legacy AI import aggregate required' USING ERRCODE='23505'; END IF;
  IF batch.state='verified' THEN RETURN QUERY SELECT batch.batch_id,batch.verified_at,batch.aggregate_digest; RETURN; END IF;
  IF batch.state<>'copying' THEN RAISE EXCEPTION 'Legacy AI import verification unavailable' USING ERRCODE='55000'; END IF;
  SELECT count(*)::integer INTO copied FROM legacy_ai_private.import_archive archived WHERE archived.batch_id=requested_batch;
  SELECT EXISTS(SELECT 1 FROM legacy_ai_private.import_archive archived LEFT JOIN legacy_ai_private.import_history_receipts receipt
    ON receipt.batch_id=archived.batch_id AND receipt.source_row_id=archived.source_row_id
    WHERE archived.batch_id=requested_batch AND archived.classification='owned' AND receipt.batch_id IS NULL) INTO missing_owned;
  IF copied<>batch.expected_count OR missing_owned THEN RAISE EXCEPTION 'Legacy AI import quarantine is incomplete' USING ERRCODE='55000'; END IF;
  verified:=clock_timestamp();
  UPDATE legacy_ai_private.import_batches verified_batch SET state='verified',copied_count=copied,verified_at=verified
    WHERE verified_batch.batch_id=requested_batch;
  INSERT INTO legacy_ai_private.import_batch_events(batch_id,event_kind,event_digest) VALUES(requested_batch,'verified',requested_aggregate_digest);
  -- This is a target-origin receipt for a future separately provisioned source
  -- cleanup capability. It proves quarantine only; it does not authorize delete.
  RETURN QUERY SELECT requested_batch,verified,requested_aggregate_digest;
END $$;

-- PRODUCTION INTEGRATION: retain the existing Student Deletion manifest.
-- The identity finalizer below invokes this cleanup in its own transaction,
-- under the pending/failed identity step and a current job lease, after all
-- predecessors complete. This also covers resumed jobs whose legacy_challenge
-- step already completed. Production readiness must verify the function owner,
-- signature and grants. After identity acknowledgement, the receipt remains
-- evidence rather than a callable replay API. This candidate remains
-- unregistered until native migration and lifecycle qualification succeeds.
CREATE FUNCTION legacy_ai_private.cleanup_history_for_student_deletion(
  requested_job uuid,
  requested_lease uuid,
  requested_owner integer
)
RETURNS TABLE (
  job_id uuid,
  owner_id integer,
  history_removed integer,
  reset_receipts_removed integer,
  owner_state_removed integer,
  archive_removed integer,
  created_at timestamptz,
  replayed boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE job identity.student_deletion_jobs%ROWTYPE;
  cleanup_step identity.student_deletion_steps%ROWTYPE;
  subject identity.users%ROWTYPE;
  prior legacy_ai_private.deletion_receipts%ROWTYPE;
  history_count integer; reset_count integer; owner_count integer; archive_count integer; recorded_at timestamptz;
BEGIN
  SELECT * INTO job FROM identity.student_deletion_jobs deletion_job
    WHERE deletion_job.job_id = requested_job AND deletion_job.subject_user_id = requested_owner
      AND deletion_job.state = 'running' AND deletion_job.lease_token = requested_lease
      AND deletion_job.lease_expires_at > clock_timestamp()
    FOR UPDATE;
  IF job.job_id IS NULL THEN
    RAISE EXCEPTION 'Legacy AI history deletion authority unavailable' USING ERRCODE = '55000';
  END IF;
  SELECT * INTO cleanup_step FROM identity.student_deletion_steps deletion_step
    WHERE deletion_step.job_id = requested_job
      AND deletion_step.step_key = 'identity' FOR UPDATE;
  IF cleanup_step.job_id IS NULL
    OR cleanup_step.state NOT IN ('pending', 'failed')
    OR EXISTS (
      SELECT 1 FROM identity.student_deletion_steps previous
      WHERE previous.job_id = requested_job AND previous.ordinal < cleanup_step.ordinal
        AND previous.state <> 'completed'
    )
  THEN
    RAISE EXCEPTION 'Legacy AI history deletion step unavailable' USING ERRCODE = '55000';
  END IF;
  SELECT * INTO subject FROM identity.users WHERE id = requested_owner FOR UPDATE;
  IF subject.id IS NULL OR subject.is_active <> 0 OR subject.role <> 'student' OR subject.admin_level <> 0 THEN
    RAISE EXCEPTION 'Legacy AI history deletion subject unavailable' USING ERRCODE = '55000';
  END IF;
  SELECT * INTO prior FROM legacy_ai_private.deletion_receipts receipt WHERE receipt.job_id = requested_job;
  IF prior.job_id IS NOT NULL THEN
    IF prior.owner_id <> requested_owner THEN
      RAISE EXCEPTION 'Legacy AI history deletion receipt differs' USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT prior.job_id, prior.owner_id, prior.history_removed,
      prior.reset_receipts_removed, prior.owner_state_removed, prior.archive_removed, prior.created_at, true;
    RETURN;
  END IF;
  DELETE FROM legacy_ai_private.history item WHERE item.owner_id = requested_owner;
  GET DIAGNOSTICS history_count = ROW_COUNT;
  DELETE FROM legacy_ai_private.reset_receipts receipt WHERE receipt.owner_id = requested_owner;
  GET DIAGNOSTICS reset_count = ROW_COUNT;
  DELETE FROM legacy_ai_private.owners owned WHERE owned.owner_id = requested_owner;
  GET DIAGNOSTICS owner_count = ROW_COUNT;
  -- After the admitted identity user and owner-generation locks above, lock
  -- every affected batch in UUID order before touching archive/receipt rows.
  PERFORM 1 FROM legacy_ai_private.import_batches affected_batch
    WHERE EXISTS(SELECT 1 FROM legacy_ai_private.import_archive affected_archive
      WHERE affected_archive.batch_id=affected_batch.batch_id
        AND affected_archive.classification='owned' AND affected_archive.classified_owner_id=requested_owner)
    ORDER BY affected_batch.batch_id FOR UPDATE;
  -- Imported-history receipts reference their archived source rows. Remove only
  -- the private owned receipt edge before deleting those archive rows; unknown
  -- and sibling quarantine remains immutable evidence.
  DELETE FROM legacy_ai_private.import_history_receipts imported_receipt
    USING legacy_ai_private.import_archive imported_archive
    WHERE imported_receipt.batch_id=imported_archive.batch_id
      AND imported_receipt.source_row_id=imported_archive.source_row_id
      AND imported_archive.classification='owned' AND imported_archive.classified_owner_id=requested_owner;
  -- A verified aggregate that included rows about to be removed is no longer a
  -- source-removal receipt. Block it and append a reason before the archive
  -- deletion, while preserving all unknown/sibling archive evidence.
  INSERT INTO legacy_ai_private.import_batch_events(batch_id,event_kind,event_digest)
    SELECT DISTINCT archived.batch_id,'invalidated_by_deletion',batch.aggregate_digest
    FROM legacy_ai_private.import_archive archived JOIN legacy_ai_private.import_batches batch ON batch.batch_id=archived.batch_id
    WHERE archived.classification='owned' AND archived.classified_owner_id=requested_owner;
  UPDATE legacy_ai_private.import_batches batch SET state='blocked',verified_at=NULL,source_removed_at=NULL
    WHERE EXISTS(SELECT 1 FROM legacy_ai_private.import_archive archived
      WHERE archived.batch_id=batch.batch_id AND archived.classification='owned' AND archived.classified_owner_id=requested_owner);
  -- Unknown/conflicting archive rows are deliberately not reclassified from an
  -- owner number. They remain lossless and inaccessible until separate review.
  DELETE FROM legacy_ai_private.import_archive archived
    WHERE archived.classification = 'owned' AND archived.classified_owner_id = requested_owner;
  GET DIAGNOSTICS archive_count = ROW_COUNT;
  INSERT INTO legacy_ai_private.deletion_receipts(
    job_id, owner_id, history_removed, reset_receipts_removed, owner_state_removed, archive_removed
  ) VALUES (
    requested_job, requested_owner, history_count, reset_count, owner_count, archive_count
  ) RETURNING legacy_ai_private.deletion_receipts.created_at INTO recorded_at;
  RETURN QUERY SELECT requested_job, requested_owner, history_count, reset_count,
    owner_count, archive_count, recorded_at, false;
END
$$;

REVOKE ALL ON FUNCTION legacy_ai_private.assert_live_session(integer,bigint),
  legacy_ai_private.assert_admin_reader(integer,bigint),
  legacy_ai_private.admit_history(integer,bigint),
  legacy_ai_private.append_history(integer,bigint,bigint,uuid,text,text,text,text),
  legacy_ai_private.list_own_history(integer,bigint,integer,text),
  legacy_ai_private.list_admin_history(integer,bigint,integer,text),
  legacy_ai_private.reset_history(integer,bigint,bigint,uuid),
  legacy_ai_private.begin_history_import(uuid,text,integer,text),
  legacy_ai_private.archive_history_import_row(uuid,bigint,jsonb,text,text,integer),
  legacy_ai_private.promote_owned_history_import_row(uuid,bigint,integer,uuid,text,text,text,text,timestamptz,text),
  legacy_ai_private.verify_history_import_quarantine(uuid,integer,text),
  legacy_ai_private.cleanup_history_for_student_deletion(uuid,uuid,integer)
FROM PUBLIC, dvaia_identity_runtime;

GRANT USAGE ON SCHEMA legacy_ai_private TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION
  legacy_ai_private.admit_history(integer,bigint),
  legacy_ai_private.append_history(integer,bigint,bigint,uuid,text,text,text,text),
  legacy_ai_private.list_own_history(integer,bigint,integer,text),
  legacy_ai_private.list_admin_history(integer,bigint,integer,text),
  legacy_ai_private.reset_history(integer,bigint,bigint,uuid),
  legacy_ai_private.cleanup_history_for_student_deletion(uuid,uuid,integer)
TO dvaia_identity_runtime;


-- Preserve the established deletion protocol and require private cleanup even
-- for callers invoking the database finalizer directly. Both operations commit
-- together, including when a previously admitted job resumes its identity step.
CREATE OR REPLACE FUNCTION identity.finalize_student_deletion(
  requested_job_id uuid, requested_lease_token uuid, requested_subject_id integer
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity,workshop_platform AS $$
DECLARE job identity.student_deletion_jobs%ROWTYPE;
DECLARE subject identity.users%ROWTYPE;
BEGIN
  SELECT * INTO job FROM identity.student_deletion_jobs
    WHERE job_id=requested_job_id AND subject_user_id=requested_subject_id
      AND state='running' AND lease_token=requested_lease_token
      AND lease_expires_at>clock_timestamp() FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Deletion authority is unavailable' USING ERRCODE='55000'; END IF;
  IF EXISTS(SELECT 1 FROM identity.student_deletion_steps
      WHERE job_id=requested_job_id AND step_key<>'identity' AND state<>'completed')
     OR NOT EXISTS(SELECT 1 FROM identity.student_deletion_steps
      WHERE job_id=requested_job_id AND step_key='identity' AND state<>'completed') THEN
    RAISE EXCEPTION 'Deletion cleanup is incomplete' USING ERRCODE='55000';
  END IF;
  SELECT * INTO subject FROM identity.users WHERE id=requested_subject_id FOR UPDATE;
  IF NOT FOUND OR subject.role<>'student' OR subject.admin_level<>0 OR subject.is_active<>0 THEN
    RAISE EXCEPTION 'Deletion subject is unavailable' USING ERRCODE='55000';
  END IF;

  PERFORM legacy_ai_private.cleanup_history_for_student_deletion(
    requested_job_id, requested_lease_token, requested_subject_id);

  DELETE FROM workshop_platform.grade_packets WHERE user_id=requested_subject_id;
  DELETE FROM workshop_platform.objective_evidence WHERE user_id=requested_subject_id;
  INSERT INTO identity.xss_deletion_redaction_authority(
    backend_pid,transaction_id,job_id,lease_token,subject_user_id
  ) VALUES(pg_backend_pid(),txid_current(),requested_job_id,requested_lease_token,requested_subject_id);
  -- Pending attempts retain the NULL verdict/result invariant. Evaluated
  -- receipts retain the assessment coordinates while losing result content.
  UPDATE workshop_platform.objective_judgments SET
    result_json=CASE WHEN verdict IS NULL THEN NULL ELSE jsonb_build_object('deleted',true) END,
    result_digest=NULL
    WHERE user_id=requested_subject_id;
  DELETE FROM identity.xss_deletion_redaction_authority
    WHERE backend_pid=pg_backend_pid() AND transaction_id=txid_current()
      AND subject_user_id=requested_subject_id;
  DELETE FROM workshop_platform.completions WHERE user_id=requested_subject_id;
  DELETE FROM workshop_platform.time_tracking WHERE user_id=requested_subject_id;
  DELETE FROM workshop_platform.user_modes WHERE user_id=requested_subject_id;
  DELETE FROM workshop_platform.user_state WHERE user_id=requested_subject_id;
  DELETE FROM identity.email_agent_progress
    WHERE user_key IN (requested_subject_id::text,subject.username,subject.email);
  DELETE FROM identity.sent_emails_log
    WHERE user_key IN (requested_subject_id::text,subject.username,subject.email);
  DELETE FROM identity.email_verification_tokens WHERE user_id=requested_subject_id;
  DELETE FROM identity.activity_logs WHERE user_id=requested_subject_id;
  DELETE FROM identity.user_sessions WHERE user_id=requested_subject_id;
  UPDATE identity.admin_permissions SET granted_by=NULL WHERE granted_by=requested_subject_id;
  UPDATE workshop_platform.exercises SET updated_by=NULL WHERE updated_by=requested_subject_id;
  UPDATE workshop_platform.objectives SET updated_by=NULL WHERE updated_by=requested_subject_id;
  UPDATE workshop_platform.xss_legacy_solution_visibility SET enabled_by=NULL
    WHERE enabled_by=requested_subject_id;
  UPDATE identity.users SET
    username='deleted-'||requested_job_id::text,
    email='deleted-'||requested_job_id::text||'@invalid.local',
    password='$2b$12$000000000000000000000uG3W0Jp6IPhhD1TRqN8Yc2zJQG3vVnSA',
    full_name=NULL,phone=NULL,department=NULL,profile_image=NULL,
    email_verified=0,account_locked_until=NULL,login_attempts=0,last_login=NULL,
    password_reset_required=0,two_factor_enabled=0,two_factor_secret=NULL,
    created_by_ip=NULL,last_login_ip=NULL,updated_at=clock_timestamp()
    WHERE id=requested_subject_id;
  RETURN true;
END $$;

REVOKE ALL ON FUNCTION identity.finalize_student_deletion(uuid,uuid,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.finalize_student_deletion(uuid,uuid,integer) TO dvaia_identity_runtime;
