-- Parent XSS reset primitive. This clears only store-local progress, profile
-- defaults/revisions, and model origins. It is fenced by the owner deletion
-- tombstone and retains an immutable operation receipt for idempotent replay.
CREATE TABLE xss.parent_profile_reset_receipts (
  operation_id uuid PRIMARY KEY,
  owner_id bigint NOT NULL CHECK(owner_id BETWEEN 1 AND 2147483647),
  name_revision bigint NOT NULL CHECK(name_revision > 0),
  bio_revision bigint NOT NULL CHECK(bio_revision > 0),
  website_revision bigint NOT NULL CHECK(website_revision > 0),
  progress_removed integer NOT NULL CHECK(progress_removed >= 0),
  origins_removed integer NOT NULL CHECK(origins_removed >= 0),
  applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION xss.guard_parent_profile_reset_receipt_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'XSS parent profile reset receipts are immutable' USING ERRCODE='55000';
END $$;
CREATE TRIGGER parent_profile_reset_receipt_immutable
  BEFORE UPDATE ON xss.parent_profile_reset_receipts
  FOR EACH ROW EXECUTE FUNCTION xss.guard_parent_profile_reset_receipt_update();

CREATE FUNCTION xss.clear_parent_profile_reset(
  requested_operation_id uuid,
  requested_owner_id bigint
) RETURNS TABLE(
  result_operation_id uuid,
  result_owner_id bigint,
  result_name_revision bigint,
  result_bio_revision bigint,
  result_website_revision bigint,
  result_progress_removed integer,
  result_origins_removed integer,
  result_applied_at timestamptz,
  result_replayed boolean
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,xss AS $$
DECLARE prior xss.parent_profile_reset_receipts%ROWTYPE;
DECLARE reset_profile xss.profiles%ROWTYPE;
DECLARE progress_removed integer;
DECLARE origins_removed integer;
BEGIN
  IF requested_operation_id IS NULL OR requested_owner_id IS NULL
     OR requested_owner_id<1 OR requested_owner_id>2147483647 THEN
    RAISE EXCEPTION 'Invalid XSS parent profile reset coordinates' USING ERRCODE='22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(requested_owner_id::text,8012));
  IF EXISTS (SELECT 1 FROM xss.scoped_profile_reset_owner_deletions d
             WHERE d.owner_id=requested_owner_id) THEN
    RAISE EXCEPTION 'XSS owner has been deleted' USING ERRCODE='55000';
  END IF;
  SELECT r.* INTO prior FROM xss.parent_profile_reset_receipts r
    WHERE r.operation_id=requested_operation_id;
  IF FOUND THEN
    IF prior.owner_id IS DISTINCT FROM requested_owner_id THEN
      RAISE EXCEPTION 'XSS parent profile reset operation mismatch' USING ERRCODE='22023';
    END IF;
    RETURN QUERY SELECT prior.operation_id,prior.owner_id,prior.name_revision,
      prior.bio_revision,prior.website_revision,prior.progress_removed,
      prior.origins_removed,prior.applied_at,true;
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
  DELETE FROM xss.progress WHERE user_key=requested_owner_id::text;
  GET DIAGNOSTICS progress_removed=ROW_COUNT;
  DELETE FROM xss.profile_model_origins WHERE user_key=requested_owner_id::text;
  GET DIAGNOSTICS origins_removed=ROW_COUNT;
  INSERT INTO xss.parent_profile_reset_receipts(
    operation_id,owner_id,name_revision,bio_revision,website_revision,
    progress_removed,origins_removed
  ) VALUES(requested_operation_id,requested_owner_id,reset_profile.name_revision,
    reset_profile.bio_revision,reset_profile.website_revision,progress_removed,origins_removed)
  RETURNING * INTO prior;
  RETURN QUERY SELECT prior.operation_id,prior.owner_id,prior.name_revision,
    prior.bio_revision,prior.website_revision,prior.progress_removed,
    prior.origins_removed,prior.applied_at,false;
END $$;

-- Parent cleanup removes retained receipts only after the owner deletion fence
-- has been written. The fence itself remains permanent against late workers.
CREATE OR REPLACE FUNCTION xss.destroy_student_owner(requested_user_id bigint)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,xss AS $$
DECLARE removed integer:=0; DECLARE n integer;
BEGIN
  IF requested_user_id IS NULL OR requested_user_id<1 OR requested_user_id>2147483647 THEN
    RAISE EXCEPTION 'Invalid deletion owner' USING ERRCODE='22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(requested_user_id::text,8012));
  INSERT INTO xss.scoped_profile_reset_owner_deletions(owner_id)
    VALUES(requested_user_id) ON CONFLICT (owner_id) DO NOTHING;
  DELETE FROM xss.template_previews WHERE user_id=requested_user_id; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
  DELETE FROM xss.email_templates WHERE user_id=requested_user_id; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
  DELETE FROM xss.email_profiles WHERE user_id=requested_user_id; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
  DELETE FROM xss.xss_challenge_progress WHERE user_id=requested_user_id; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
  DELETE FROM xss.xss_email_judge_receipts WHERE user_id=requested_user_id; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
  DELETE FROM xss.emails WHERE user_key=requested_user_id::text; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
  DELETE FROM xss.progress WHERE user_key=requested_user_id::text; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
  DELETE FROM xss.profiles WHERE user_key=requested_user_id::text; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
  DELETE FROM xss.scoped_profile_reset_receipts WHERE owner_id=requested_user_id; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
  DELETE FROM xss.parent_profile_reset_receipts WHERE owner_id=requested_user_id; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
  RETURN removed;
END $$;

REVOKE ALL ON xss.parent_profile_reset_receipts FROM PUBLIC,dvaia_xss_runtime;
REVOKE ALL ON FUNCTION xss.guard_parent_profile_reset_receipt_update() FROM PUBLIC,dvaia_xss_runtime;
REVOKE ALL ON FUNCTION xss.clear_parent_profile_reset(uuid,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION xss.clear_parent_profile_reset(uuid,bigint) TO dvaia_xss_runtime;
REVOKE ALL ON FUNCTION xss.destroy_student_owner(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION xss.destroy_student_owner(bigint) TO dvaia_xss_runtime;
