-- Durable, store-local retirement for a reset operation that must never be
-- allowed to start after parent reconciliation has retired it.  This is a
-- replay fence, not an identity-generation fence; the caller still owns the
-- parent/child lifecycle decision. Student cleanup intentionally leaves this
-- table intact: deleting a receipt must not reopen a late operation.
CREATE TABLE xss.scoped_profile_reset_retirements (
  operation_id uuid PRIMARY KEY,
  owner_id bigint NOT NULL CHECK(owner_id BETWEEN 1 AND 2147483647),
  graph_parent_generation bigint NOT NULL CHECK(graph_parent_generation >= 0),
  workshop_generation bigint NOT NULL CHECK(workshop_generation >= 0),
  stored_user_from bigint NOT NULL CHECK(stored_user_from >= 0 AND stored_user_from < 9223372036854775807),
  stored_user_to bigint NOT NULL,
  stored_llm_from bigint NOT NULL CHECK(stored_llm_from >= 0 AND stored_llm_from < 9223372036854775807),
  stored_llm_to bigint NOT NULL,
  retired_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK(stored_user_to=stored_user_from+1),
  CHECK(stored_llm_to=stored_llm_from+1)
);

CREATE FUNCTION xss.guard_scoped_profile_reset_retirement_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'XSS scoped profile reset retirements are immutable' USING ERRCODE='55000';
END $$;
CREATE TRIGGER scoped_profile_reset_retirement_immutable
  BEFORE UPDATE OR DELETE ON xss.scoped_profile_reset_retirements
  FOR EACH ROW EXECUTE FUNCTION xss.guard_scoped_profile_reset_retirement_update();

CREATE OR REPLACE FUNCTION xss.apply_scoped_profile_reset(
  requested_operation_id uuid,
  requested_owner_id bigint,
  requested_graph_parent_generation bigint,
  requested_workshop_generation bigint,
  requested_stored_user_from bigint,
  requested_stored_user_to bigint,
  requested_stored_llm_from bigint,
  requested_stored_llm_to bigint
) RETURNS TABLE(
  result_operation_id uuid,
  result_owner_id bigint,
  result_graph_parent_generation bigint,
  result_workshop_generation bigint,
  result_stored_user_from bigint,
  result_stored_user_to bigint,
  result_stored_llm_from bigint,
  result_stored_llm_to bigint,
  result_name_revision bigint,
  result_bio_revision bigint,
  result_website_revision bigint,
  result_origins_removed integer,
  result_applied_at timestamptz,
  result_replayed boolean
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,xss AS $$
DECLARE prior xss.scoped_profile_reset_receipts%ROWTYPE;
DECLARE reset_profile xss.profiles%ROWTYPE;
DECLARE removed integer;
BEGIN
  IF requested_operation_id IS NULL OR requested_owner_id IS NULL
     OR requested_owner_id<1 OR requested_owner_id>2147483647
     OR requested_graph_parent_generation IS NULL OR requested_graph_parent_generation<0
     OR requested_workshop_generation IS NULL OR requested_workshop_generation<0
     OR requested_stored_user_from IS NULL OR requested_stored_user_from<0
     OR requested_stored_user_from>=9223372036854775807
     OR requested_stored_user_to IS NULL
     OR requested_stored_llm_from IS NULL OR requested_stored_llm_from<0
     OR requested_stored_llm_from>=9223372036854775807
     OR requested_stored_llm_to IS NULL THEN
    RAISE EXCEPTION 'Invalid XSS scoped profile reset coordinates' USING ERRCODE='22023';
  END IF;
  IF requested_stored_user_to<>requested_stored_user_from+1
     OR requested_stored_llm_to<>requested_stored_llm_from+1 THEN
    RAISE EXCEPTION 'Invalid XSS scoped profile reset transition' USING ERRCODE='22023';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(requested_operation_id::text,8008));
  IF EXISTS (SELECT 1 FROM xss.scoped_profile_reset_retirements t
             WHERE t.operation_id=requested_operation_id) THEN
    RAISE EXCEPTION 'XSS scoped profile reset operation is retired' USING ERRCODE='55000';
  END IF;
  SELECT r.* INTO prior FROM xss.scoped_profile_reset_receipts r
    WHERE r.operation_id=requested_operation_id;
  IF FOUND THEN
    IF prior.owner_id IS DISTINCT FROM requested_owner_id
       OR prior.graph_parent_generation IS DISTINCT FROM requested_graph_parent_generation
       OR prior.workshop_generation IS DISTINCT FROM requested_workshop_generation
       OR prior.stored_user_from IS DISTINCT FROM requested_stored_user_from
       OR prior.stored_user_to IS DISTINCT FROM requested_stored_user_to
       OR prior.stored_llm_from IS DISTINCT FROM requested_stored_llm_from
       OR prior.stored_llm_to IS DISTINCT FROM requested_stored_llm_to THEN
      RAISE EXCEPTION 'XSS scoped profile reset operation mismatch' USING ERRCODE='22023';
    END IF;
    RETURN QUERY SELECT prior.operation_id,prior.owner_id,prior.graph_parent_generation,
      prior.workshop_generation,prior.stored_user_from,prior.stored_user_to,
      prior.stored_llm_from,prior.stored_llm_to,prior.name_revision,prior.bio_revision,
      prior.website_revision,prior.origins_removed,prior.applied_at,true;
    RETURN;
  END IF;

  INSERT INTO xss.profiles(
    user_key,name,bio,website,name_revision,bio_revision,website_revision
  ) VALUES(
    requested_owner_id::text,'Security Student','Learning about web security.',
    'https://example.com',1,1,1
  ) ON CONFLICT(user_key) DO UPDATE SET
    name=excluded.name,bio=excluded.bio,website=excluded.website,
    name_revision=xss.profiles.name_revision+1,
    bio_revision=xss.profiles.bio_revision+1,
    website_revision=xss.profiles.website_revision+1,
    updated_at=clock_timestamp()
  RETURNING * INTO reset_profile;
  DELETE FROM xss.profile_model_origins WHERE user_key=requested_owner_id::text;
  GET DIAGNOSTICS removed=ROW_COUNT;

  INSERT INTO xss.scoped_profile_reset_receipts(
    operation_id,owner_id,graph_parent_generation,workshop_generation,
    stored_user_from,stored_user_to,stored_llm_from,stored_llm_to,
    name_revision,bio_revision,website_revision,origins_removed
  ) VALUES(
    requested_operation_id,requested_owner_id,requested_graph_parent_generation,
    requested_workshop_generation,requested_stored_user_from,requested_stored_user_to,
    requested_stored_llm_from,requested_stored_llm_to,reset_profile.name_revision,
    reset_profile.bio_revision,reset_profile.website_revision,removed
  ) RETURNING * INTO prior;
  RETURN QUERY SELECT prior.operation_id,prior.owner_id,prior.graph_parent_generation,
    prior.workshop_generation,prior.stored_user_from,prior.stored_user_to,
    prior.stored_llm_from,prior.stored_llm_to,prior.name_revision,prior.bio_revision,
    prior.website_revision,prior.origins_removed,prior.applied_at,false;
END $$;

CREATE FUNCTION xss.retire_or_read_scoped_profile_reset(
  requested_operation_id uuid,
  requested_owner_id bigint,
  requested_graph_parent_generation bigint,
  requested_workshop_generation bigint,
  requested_stored_user_from bigint,
  requested_stored_user_to bigint,
  requested_stored_llm_from bigint,
  requested_stored_llm_to bigint
) RETURNS TABLE(
  result_operation_id uuid,
  result_owner_id bigint,
  result_graph_parent_generation bigint,
  result_workshop_generation bigint,
  result_stored_user_from bigint,
  result_stored_user_to bigint,
  result_stored_llm_from bigint,
  result_stored_llm_to bigint,
  result_name_revision bigint,
  result_bio_revision bigint,
  result_website_revision bigint,
  result_origins_removed integer,
  result_applied_at timestamptz,
  result_replayed boolean,
  result_retired boolean,
  result_retired_at timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,xss AS $$
DECLARE prior xss.scoped_profile_reset_receipts%ROWTYPE;
DECLARE retired xss.scoped_profile_reset_retirements%ROWTYPE;
BEGIN
  IF requested_operation_id IS NULL OR requested_owner_id IS NULL
     OR requested_owner_id<1 OR requested_owner_id>2147483647
     OR requested_graph_parent_generation IS NULL OR requested_graph_parent_generation<0
     OR requested_workshop_generation IS NULL OR requested_workshop_generation<0
     OR requested_stored_user_from IS NULL OR requested_stored_user_from<0
     OR requested_stored_user_from>=9223372036854775807
     OR requested_stored_user_to IS NULL
     OR requested_stored_llm_from IS NULL OR requested_stored_llm_from<0
     OR requested_stored_llm_from>=9223372036854775807
     OR requested_stored_llm_to IS NULL
     OR requested_stored_user_to<>requested_stored_user_from+1
     OR requested_stored_llm_to<>requested_stored_llm_from+1 THEN
    RAISE EXCEPTION 'Invalid XSS scoped profile reset coordinates' USING ERRCODE='22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(requested_operation_id::text,8008));
  SELECT r.* INTO prior FROM xss.scoped_profile_reset_receipts r WHERE r.operation_id=requested_operation_id;
  IF FOUND THEN
    IF prior.owner_id IS DISTINCT FROM requested_owner_id
       OR prior.graph_parent_generation IS DISTINCT FROM requested_graph_parent_generation
       OR prior.workshop_generation IS DISTINCT FROM requested_workshop_generation
       OR prior.stored_user_from IS DISTINCT FROM requested_stored_user_from
       OR prior.stored_user_to IS DISTINCT FROM requested_stored_user_to
       OR prior.stored_llm_from IS DISTINCT FROM requested_stored_llm_from
       OR prior.stored_llm_to IS DISTINCT FROM requested_stored_llm_to THEN
      RAISE EXCEPTION 'XSS scoped profile reset operation mismatch' USING ERRCODE='22023';
    END IF;
    RETURN QUERY SELECT prior.operation_id,prior.owner_id,prior.graph_parent_generation,
      prior.workshop_generation,prior.stored_user_from,prior.stored_user_to,
      prior.stored_llm_from,prior.stored_llm_to,prior.name_revision,prior.bio_revision,
      prior.website_revision,prior.origins_removed,prior.applied_at,false,false,NULL::timestamptz;
    RETURN;
  END IF;
  SELECT t.* INTO retired FROM xss.scoped_profile_reset_retirements t
    WHERE t.operation_id=requested_operation_id;
  IF FOUND THEN
    IF retired.owner_id IS DISTINCT FROM requested_owner_id
       OR retired.graph_parent_generation IS DISTINCT FROM requested_graph_parent_generation
       OR retired.workshop_generation IS DISTINCT FROM requested_workshop_generation
       OR retired.stored_user_from IS DISTINCT FROM requested_stored_user_from
       OR retired.stored_user_to IS DISTINCT FROM requested_stored_user_to
       OR retired.stored_llm_from IS DISTINCT FROM requested_stored_llm_from
       OR retired.stored_llm_to IS DISTINCT FROM requested_stored_llm_to THEN
      RAISE EXCEPTION 'XSS scoped profile reset operation mismatch' USING ERRCODE='22023';
    END IF;
    RETURN QUERY SELECT retired.operation_id,retired.owner_id,retired.graph_parent_generation,
      retired.workshop_generation,retired.stored_user_from,retired.stored_user_to,
      retired.stored_llm_from,retired.stored_llm_to,NULL::bigint,NULL::bigint,NULL::bigint,
      NULL::integer,NULL::timestamptz,false,true,retired.retired_at;
    RETURN;
  END IF;
  INSERT INTO xss.scoped_profile_reset_retirements(
    operation_id,owner_id,graph_parent_generation,workshop_generation,
    stored_user_from,stored_user_to,stored_llm_from,stored_llm_to
  ) VALUES(requested_operation_id,requested_owner_id,requested_graph_parent_generation,
    requested_workshop_generation,requested_stored_user_from,requested_stored_user_to,
    requested_stored_llm_from,requested_stored_llm_to)
  RETURNING * INTO retired;
  RETURN QUERY SELECT retired.operation_id,retired.owner_id,retired.graph_parent_generation,
    retired.workshop_generation,retired.stored_user_from,retired.stored_user_to,
    retired.stored_llm_from,retired.stored_llm_to,NULL::bigint,NULL::bigint,NULL::bigint,
    NULL::integer,NULL::timestamptz,false,true,retired.retired_at;
END $$;

REVOKE ALL ON xss.scoped_profile_reset_retirements FROM PUBLIC,dvaia_xss_runtime;
REVOKE ALL ON FUNCTION xss.guard_scoped_profile_reset_retirement_update() FROM PUBLIC,dvaia_xss_runtime;
REVOKE ALL ON FUNCTION xss.retire_or_read_scoped_profile_reset(
  uuid,bigint,bigint,bigint,bigint,bigint,bigint,bigint
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION xss.retire_or_read_scoped_profile_reset(
  uuid,bigint,bigint,bigint,bigint,bigint,bigint,bigint
) TO dvaia_xss_runtime;
