-- UNREGISTERED SOURCE CLEANUP CANDIDATE. No application route may invoke this.
-- Apply only with the legacy migration role in owned qualification stores until
-- native fresh/upgrade/replay and coordinated cross-store recovery are proved.
-- This function verifies source equality, NOT target quarantine. Its trusted
-- caller MUST verify exact target archive bytes and hold the target quarantine
-- batch lock through this source transaction's COMMIT. A digest supplied here
-- is a binding coordinate, never autonomous proof that an archive exists.
-- Both stores require a reviewed recovery coordinator; ordinary runtime roles
-- must never receive this capability or migration credentials.

CREATE SCHEMA legacy_ai_source_cleanup AUTHORIZATION dvaia_legacy_challenge_migration;
REVOKE ALL ON SCHEMA legacy_ai_source_cleanup FROM PUBLIC, dvaia_legacy_challenge_runtime;

CREATE TABLE legacy_ai_source_cleanup.receipts (
  batch_id uuid PRIMARY KEY,
  target_identity text NOT NULL CHECK (octet_length(target_identity) BETWEEN 1 AND 512),
  aggregate_digest text NOT NULL CHECK (aggregate_digest ~ '^[0-9a-f]{64}$'),
  payload_digest text NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
  source_ids integer[] NOT NULL,
  removed_count integer NOT NULL CHECK (removed_count BETWEEN 0 AND 100000),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON TABLE legacy_ai_source_cleanup.receipts FROM PUBLIC, dvaia_legacy_challenge_runtime;

CREATE FUNCTION legacy_ai_source_cleanup.cleanup_history_source(
  requested_batch uuid, requested_target_identity text,
  requested_aggregate_digest text, requested_source_records jsonb
)
RETURNS TABLE(batch_id uuid, removed_count integer, created_at timestamptz, replayed boolean)
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
DECLARE prior legacy_ai_source_cleanup.receipts%ROWTYPE;
  item jsonb; field_name text; ids integer[] := ARRAY[]::integer[];
  source_id integer; actual_record jsonb; removed integer; recorded_at timestamptz; payload_hash text;
BEGIN
  IF current_user <> 'dvaia_legacy_challenge_migration'
    OR session_user <> 'dvaia_legacy_challenge_migration' THEN
    RAISE EXCEPTION 'Exact source migration authority required' USING ERRCODE='42501';
  END IF;
  IF requested_batch IS NULL OR requested_target_identity IS NULL
    OR octet_length(requested_target_identity) NOT BETWEEN 1 AND 512
    OR requested_aggregate_digest IS NULL OR requested_aggregate_digest !~ '^[0-9a-f]{64}$'
    OR requested_source_records IS NULL OR jsonb_typeof(requested_source_records) <> 'array' THEN
    RAISE EXCEPTION 'Exact source cleanup request required' USING ERRCODE='22023';
  END IF;
  IF jsonb_array_length(requested_source_records) > 100000
    OR octet_length(requested_source_records::text) > 268435456 THEN
    RAISE EXCEPTION 'Bounded source cleanup request required' USING ERRCODE='22023';
  END IF;
  FOR item IN SELECT value FROM jsonb_array_elements(requested_source_records) LOOP
    IF jsonb_typeof(item) <> 'object' THEN
      RAISE EXCEPTION 'Exact source record required' USING ERRCODE='22023';
    END IF;
    IF (SELECT count(*) FROM jsonb_object_keys(item)) <> 7
      OR NOT item ?& ARRAY['id','userId','prompt','response','modelUsed','createdAt','platformOwnerId'] THEN
      RAISE EXCEPTION 'Exact seven source fields required' USING ERRCODE='22023';
    END IF;
    IF jsonb_typeof(item->'id') <> 'number' OR (item->>'id') !~ '^-?[0-9]+$'
      OR (item->>'id')::numeric NOT BETWEEN -2147483648 AND 2147483647
      OR jsonb_typeof(item->'prompt') <> 'string' THEN
      RAISE EXCEPTION 'Valid source ID and prompt required' USING ERRCODE='22023';
    END IF;
    FOREACH field_name IN ARRAY ARRAY['userId','platformOwnerId'] LOOP
      IF item->field_name <> 'null'::jsonb AND
        (jsonb_typeof(item->field_name) <> 'number' OR (item->>field_name) !~ '^-?[0-9]+$'
          OR (item->>field_name)::numeric NOT BETWEEN -2147483648 AND 2147483647) THEN
        RAISE EXCEPTION 'Nullable source integer required' USING ERRCODE='22023';
      END IF;
    END LOOP;
    FOREACH field_name IN ARRAY ARRAY['response','modelUsed','createdAt'] LOOP
      IF jsonb_typeof(item->field_name) NOT IN ('null','string') THEN
        RAISE EXCEPTION 'Nullable source text required' USING ERRCODE='22023';
      END IF;
    END LOOP;
    source_id := (item->>'id')::integer;
    ids := array_append(ids, source_id);
  END LOOP;
  IF cardinality(ids) <> (SELECT count(DISTINCT value) FROM unnest(ids) value) THEN
    RAISE EXCEPTION 'Unique source IDs required' USING ERRCODE='22023';
  END IF;

  payload_hash := encode(sha256(convert_to(requested_source_records::text,'UTF8')),'hex');

  -- Serialize every source writer, including raw intentional SQL sinks. Keep
  -- this lock until COMMIT: comparisons, deletion and receipt are one unit.
  LOCK TABLE legacy_challenge.ai_conversations IN SHARE ROW EXCLUSIVE MODE;
  SELECT * INTO prior FROM legacy_ai_source_cleanup.receipts receipt
    WHERE receipt.batch_id=requested_batch FOR UPDATE;
  IF prior.batch_id IS NOT NULL THEN
    IF prior.target_identity IS DISTINCT FROM requested_target_identity
      OR prior.aggregate_digest IS DISTINCT FROM requested_aggregate_digest
      OR prior.payload_digest IS DISTINCT FROM payload_hash
      OR prior.source_ids IS DISTINCT FROM ids THEN
      RAISE EXCEPTION 'Source cleanup replay conflicts' USING ERRCODE='23505';
    END IF;
    IF EXISTS(SELECT 1 FROM legacy_challenge.ai_conversations source WHERE source.id=ANY(ids)) THEN
      RAISE EXCEPTION 'Removed source IDs reappeared' USING ERRCODE='55000';
    END IF;
    RETURN QUERY SELECT prior.batch_id,prior.removed_count,prior.created_at,true;
    RETURN;
  END IF;

  -- Compare all rows before deleting any. Timestamp encoding matches the
  -- snapshot adapter exactly, including NULL, infinities and BC dates.
  FOR item IN SELECT value FROM jsonb_array_elements(requested_source_records) LOOP
    source_id := (item->>'id')::integer;
    SELECT jsonb_build_object(
      'id',source.id,'userId',source.user_id,'prompt',source.prompt,
      'response',source.response,'modelUsed',source.model_used,
      'createdAt',CASE
        WHEN source.created_at IS NULL THEN NULL
        WHEN source.created_at='infinity'::timestamptz THEN 'infinity'
        WHEN source.created_at='-infinity'::timestamptz THEN '-infinity'
        WHEN extract(year FROM source.created_at AT TIME ZONE 'UTC')>0
          THEN to_char(source.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
        ELSE to_char(source.created_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS.US BC')
      END,'platformOwnerId',source.platform_owner_id)
    INTO actual_record FROM legacy_challenge.ai_conversations source WHERE source.id=source_id;
    IF actual_record IS DISTINCT FROM item THEN
      RAISE EXCEPTION 'Source history changed or is missing' USING ERRCODE='55000';
    END IF;
  END LOOP;
  DELETE FROM legacy_challenge.ai_conversations source WHERE source.id=ANY(ids);
  GET DIAGNOSTICS removed = ROW_COUNT;
  IF removed <> cardinality(ids) THEN
    RAISE EXCEPTION 'Source removal count differs' USING ERRCODE='55000';
  END IF;
  INSERT INTO legacy_ai_source_cleanup.receipts(
    batch_id,target_identity,aggregate_digest,payload_digest,source_ids,removed_count
  ) VALUES(requested_batch,requested_target_identity,requested_aggregate_digest,payload_hash,ids,removed)
  RETURNING legacy_ai_source_cleanup.receipts.created_at INTO recorded_at;
  RETURN QUERY SELECT requested_batch,removed,recorded_at,false;
END
$$;
REVOKE ALL ON FUNCTION legacy_ai_source_cleanup.cleanup_history_source(uuid,text,text,jsonb)
  FROM PUBLIC, dvaia_legacy_challenge_runtime;
GRANT EXECUTE ON FUNCTION legacy_ai_source_cleanup.cleanup_history_source(uuid,text,text,jsonb)
  TO dvaia_legacy_challenge_migration;
