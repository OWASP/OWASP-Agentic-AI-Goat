-- Separate builder scope; historical local level claims are never imported.
CREATE TABLE identity.xss_email_builder_resets (
 operation_id uuid PRIMARY KEY,
 owner_id integer NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
 from_generation bigint NOT NULL CHECK(from_generation>=0),
 to_generation bigint NOT NULL CHECK(to_generation=from_generation+1),
 status text NOT NULL CHECK(status IN ('pending','completed')),
 created_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz
);
CREATE UNIQUE INDEX xss_email_builder_one_pending ON identity.xss_email_builder_resets(owner_id) WHERE status='pending';
REVOKE ALL ON identity.xss_email_builder_resets FROM PUBLIC,dvaia_identity_runtime;
GRANT SELECT ON identity.xss_email_builder_resets TO dvaia_identity_runtime;
CREATE FUNCTION identity.begin_xss_email_builder_reset(p_owner integer,p_operation uuid)
RETURNS identity.xss_email_builder_resets LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE prior identity.xss_email_builder_resets%ROWTYPE; gen bigint;
BEGIN
 IF p_owner IS NULL OR p_owner<1 OR p_operation IS NULL THEN RAISE EXCEPTION 'Invalid builder reset'; END IF;
 PERFORM 1 FROM identity.users WHERE id=p_owner FOR UPDATE;
 IF NOT EXISTS(SELECT 1 FROM identity.users WHERE id=p_owner AND is_active=1)
 OR EXISTS(SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=p_owner) THEN RAISE EXCEPTION 'Builder owner unavailable'; END IF;
 SELECT * INTO prior FROM identity.xss_email_builder_resets WHERE operation_id=p_operation;
 IF FOUND THEN IF prior.owner_id<>p_owner THEN RAISE EXCEPTION 'Builder reset owner mismatch'; END IF; RETURN prior; END IF;
 SELECT * INTO prior FROM identity.xss_email_builder_resets WHERE owner_id=p_owner AND status='pending';
 IF FOUND THEN RAISE EXCEPTION 'Another builder reset is pending'; END IF;
 INSERT INTO workshop_platform.user_state(user_id,workshop_key) VALUES(p_owner,'xss_email_builder') ON CONFLICT DO NOTHING;
 SELECT generation INTO gen FROM workshop_platform.user_state WHERE user_id=p_owner AND workshop_key='xss_email_builder' FOR UPDATE;
 INSERT INTO identity.xss_email_builder_resets(operation_id,owner_id,from_generation,to_generation,status)
 VALUES(p_operation,p_owner,gen,gen+1,'pending') RETURNING * INTO prior;
 RETURN prior;
END $$;
CREATE FUNCTION identity.finish_xss_email_builder_reset(p_owner integer,p_operation uuid,p_from bigint,p_to bigint)
RETURNS identity.xss_email_builder_resets LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE prior identity.xss_email_builder_resets%ROWTYPE; gen bigint;
BEGIN
 PERFORM 1 FROM identity.users WHERE id=p_owner FOR UPDATE;
 SELECT * INTO prior FROM identity.xss_email_builder_resets WHERE operation_id=p_operation FOR UPDATE;
 IF prior.owner_id IS DISTINCT FROM p_owner OR prior.from_generation IS DISTINCT FROM p_from OR prior.to_generation IS DISTINCT FROM p_to THEN RAISE EXCEPTION 'Builder reset scope mismatch'; END IF;
 IF prior.status='completed' THEN RETURN prior; END IF;
 SELECT generation INTO gen FROM workshop_platform.user_state WHERE user_id=p_owner AND workshop_key='xss_email_builder' FOR UPDATE;
 IF gen IS DISTINCT FROM p_from THEN RAISE EXCEPTION 'Builder canonical generation changed'; END IF;
 DELETE FROM workshop_platform.completions WHERE user_id=p_owner AND workshop_key='xss_email_builder';
 DELETE FROM workshop_platform.activity_counters WHERE user_id=p_owner AND workshop_key='xss_email_builder';
 DELETE FROM workshop_platform.time_tracking WHERE user_id=p_owner AND workshop_key='xss_email_builder';
 UPDATE workshop_platform.user_state SET generation=p_to,started_at=NULL,updated_at=now() WHERE user_id=p_owner AND workshop_key='xss_email_builder';
 INSERT INTO workshop_platform.revisions(scope_type,scope_key,category,revision) VALUES('user',p_owner::text,'workshop_progress',1),('user',p_owner::text,'workshop_time',1) ON CONFLICT(scope_type,scope_key,category) DO UPDATE SET revision=workshop_platform.revisions.revision+1,updated_at=now();
 UPDATE identity.xss_email_builder_resets SET status='completed',completed_at=now() WHERE operation_id=p_operation RETURNING * INTO prior;
 RETURN prior;
END $$;
REVOKE ALL ON FUNCTION identity.begin_xss_email_builder_reset(integer,uuid),identity.finish_xss_email_builder_reset(integer,uuid,bigint,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.begin_xss_email_builder_reset(integer,uuid),identity.finish_xss_email_builder_reset(integer,uuid,bigint,bigint) TO dvaia_identity_runtime;
