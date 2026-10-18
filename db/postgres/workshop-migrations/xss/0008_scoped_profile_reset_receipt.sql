-- Inactive XSS-store primitive. The caller must hold the owner lifecycle lock
-- and verify the current identity reset operation before invoking this
-- function. This receipt alone is not an identity/deletion/staleness fence.
CREATE TABLE xss.scoped_profile_reset_receipts (
  operation_id uuid PRIMARY KEY,
  owner_id bigint NOT NULL CHECK(owner_id BETWEEN 1 AND 2147483647),
  graph_parent_generation bigint NOT NULL CHECK(graph_parent_generation >= 0),
  workshop_generation bigint NOT NULL CHECK(workshop_generation >= 0),
  stored_user_from bigint NOT NULL CHECK(stored_user_from >= 0 AND stored_user_from < 9223372036854775807),
  stored_user_to bigint NOT NULL,
  stored_llm_from bigint NOT NULL CHECK(stored_llm_from >= 0 AND stored_llm_from < 9223372036854775807),
  stored_llm_to bigint NOT NULL,
  name_revision bigint NOT NULL CHECK(name_revision > 0),
  bio_revision bigint NOT NULL CHECK(bio_revision > 0),
  website_revision bigint NOT NULL CHECK(website_revision > 0),
  origins_removed integer NOT NULL CHECK(origins_removed >= 0),
  applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK(stored_user_to=stored_user_from+1),
  CHECK(stored_llm_to=stored_llm_from+1)
);

-- Receipt bytes are immutable while retained. They contain only operation and
-- generation coordinates plus counts/revisions, never profile/model payloads.
-- Runtime cannot delete them. Student-deletion retention must be explicitly
-- integrated before this inactive primitive is activated in production.
CREATE FUNCTION xss.guard_scoped_profile_reset_receipt_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'XSS scoped profile reset receipts are immutable' USING ERRCODE='55000';
END $$;
CREATE TRIGGER scoped_profile_reset_receipt_immutable
  BEFORE UPDATE ON xss.scoped_profile_reset_receipts
  FOR EACH ROW EXECUTE FUNCTION xss.guard_scoped_profile_reset_receipt_update();

CREATE FUNCTION xss.apply_scoped_profile_reset(
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

REVOKE ALL ON xss.scoped_profile_reset_receipts FROM PUBLIC,dvaia_xss_runtime;
REVOKE ALL ON FUNCTION xss.guard_scoped_profile_reset_receipt_update()
  FROM PUBLIC,dvaia_xss_runtime;
REVOKE ALL ON FUNCTION xss.apply_scoped_profile_reset(
  uuid,bigint,bigint,bigint,bigint,bigint,bigint,bigint
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION xss.apply_scoped_profile_reset(
  uuid,bigint,bigint,bigint,bigint,bigint,bigint,bigint
) TO dvaia_xss_runtime;
