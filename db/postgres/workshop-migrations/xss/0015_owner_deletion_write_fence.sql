-- Fence direct runtime writes after student deletion.  The deletion function
-- retains the tombstone and deletes the rows, while this trigger prevents a
-- late worker from recreating numeric-owner state through ordinary DML.
CREATE OR REPLACE FUNCTION xss.reject_deleted_owner_write()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,xss AS $$
DECLARE
  old_owner text;
  new_owner text;
  locked_owner_id bigint;
BEGIN
  IF TG_TABLE_NAME IN (
    'email_profiles', 'email_templates', 'template_previews',
    'xss_challenge_progress', 'xss_email_judge_receipts'
  ) THEN
    IF TG_OP = 'UPDATE' THEN old_owner := OLD.user_id::text; END IF;
    new_owner := NEW.user_id::text;
  ELSE
    IF TG_OP = 'UPDATE' THEN old_owner := OLD.user_key; END IF;
    new_owner := NEW.user_key;
  END IF;

  -- Only canonical positive platform IDs are fenced.  In particular, do not
  -- normalize anonymous aliases or public NULL email rows into an owner ID.
  FOR locked_owner_id IN
    SELECT owner_id
    FROM (
      SELECT DISTINCT CASE
        WHEN value ~ '^[1-9][0-9]*$' AND length(value) <= 10
          THEN value::bigint
        ELSE NULL::bigint
      END AS owner_id
      FROM unnest(ARRAY[old_owner, new_owner]) AS owners(value)
    ) AS candidates
    WHERE owner_id BETWEEN 1 AND 2147483647
    ORDER BY owner_id
  LOOP
    -- Lock all affected owners before consulting the tombstone.  Sorting the
    -- IDs above makes two-owner updates deterministic and deadlock-resistant.
    PERFORM pg_advisory_xact_lock(hashtextextended(locked_owner_id::text, 8012));
    IF EXISTS (
      SELECT 1 FROM xss.scoped_profile_reset_owner_deletions
      WHERE scoped_profile_reset_owner_deletions.owner_id = locked_owner_id
    ) THEN
      RAISE EXCEPTION 'XSS owner has been deleted' USING ERRCODE='55000';
    END IF;
  END LOOP;

  RETURN NEW;
END $$;

REVOKE ALL ON FUNCTION xss.reject_deleted_owner_write() FROM PUBLIC, dvaia_xss_runtime;

DROP TRIGGER IF EXISTS xss_owner_deletion_write_fence ON xss.profiles;
CREATE TRIGGER xss_owner_deletion_write_fence
  BEFORE INSERT OR UPDATE ON xss.profiles
  FOR EACH ROW EXECUTE FUNCTION xss.reject_deleted_owner_write();

DROP TRIGGER IF EXISTS xss_owner_deletion_write_fence ON xss.progress;
CREATE TRIGGER xss_owner_deletion_write_fence
  BEFORE INSERT OR UPDATE ON xss.progress
  FOR EACH ROW EXECUTE FUNCTION xss.reject_deleted_owner_write();

DROP TRIGGER IF EXISTS xss_owner_deletion_write_fence ON xss.emails;
CREATE TRIGGER xss_owner_deletion_write_fence
  BEFORE INSERT OR UPDATE ON xss.emails
  FOR EACH ROW EXECUTE FUNCTION xss.reject_deleted_owner_write();

DROP TRIGGER IF EXISTS xss_owner_deletion_write_fence ON xss.profile_model_origins;
CREATE TRIGGER xss_owner_deletion_write_fence
  BEFORE INSERT OR UPDATE ON xss.profile_model_origins
  FOR EACH ROW EXECUTE FUNCTION xss.reject_deleted_owner_write();

DROP TRIGGER IF EXISTS xss_owner_deletion_write_fence ON xss.email_profiles;
CREATE TRIGGER xss_owner_deletion_write_fence
  BEFORE INSERT OR UPDATE ON xss.email_profiles
  FOR EACH ROW EXECUTE FUNCTION xss.reject_deleted_owner_write();

DROP TRIGGER IF EXISTS xss_owner_deletion_write_fence ON xss.email_templates;
CREATE TRIGGER xss_owner_deletion_write_fence
  BEFORE INSERT OR UPDATE ON xss.email_templates
  FOR EACH ROW EXECUTE FUNCTION xss.reject_deleted_owner_write();

DROP TRIGGER IF EXISTS xss_owner_deletion_write_fence ON xss.template_previews;
CREATE TRIGGER xss_owner_deletion_write_fence
  BEFORE INSERT OR UPDATE ON xss.template_previews
  FOR EACH ROW EXECUTE FUNCTION xss.reject_deleted_owner_write();

DROP TRIGGER IF EXISTS xss_owner_deletion_write_fence ON xss.xss_challenge_progress;
CREATE TRIGGER xss_owner_deletion_write_fence
  BEFORE INSERT OR UPDATE ON xss.xss_challenge_progress
  FOR EACH ROW EXECUTE FUNCTION xss.reject_deleted_owner_write();

DROP TRIGGER IF EXISTS xss_owner_deletion_write_fence ON xss.xss_email_judge_receipts;
CREATE TRIGGER xss_owner_deletion_write_fence
  BEFORE INSERT OR UPDATE ON xss.xss_email_judge_receipts
  FOR EACH ROW EXECUTE FUNCTION xss.reject_deleted_owner_write();
