-- Unmounted preparation only. No runtime bypass or automatic activation.
CREATE TABLE ctf.bootstrap_control (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 store_id uuid NOT NULL DEFAULT gen_random_uuid(), identity_store_id uuid,
 state text NOT NULL DEFAULT 'open' CHECK(state IN ('open','fenced','prepared')),
 operation_id uuid, revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0),
 manifest_sha256 text CHECK(manifest_sha256 ~ '^[a-f0-9]{64}$'),
 CHECK((state='open')=(operation_id IS NULL)),CHECK((state='prepared')=(manifest_sha256 IS NOT NULL))
);
INSERT INTO ctf.bootstrap_control(singleton) VALUES(true);
REVOKE ALL ON ctf.bootstrap_control FROM PUBLIC,dvaia_ctf_runtime;
GRANT SELECT ON ctf.bootstrap_control TO dvaia_ctf_runtime;
CREATE FUNCTION ctf.guard_bootstrap_source() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE s text;
BEGIN
 PERFORM pg_advisory_xact_lock(1886610804,44);
 SELECT state INTO s FROM ctf.bootstrap_control WHERE singleton FOR UPDATE;
 IF s IS DISTINCT FROM 'open' AND session_user<>'dvaia_ctf_migration' THEN RAISE EXCEPTION 'CTF bootstrap writer fence' USING ERRCODE='55000'; END IF;
 UPDATE ctf.bootstrap_control SET revision=revision+1,state=CASE WHEN state='prepared' THEN 'fenced' ELSE state END,manifest_sha256=NULL WHERE singleton;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION ctf.guard_bootstrap_source() FROM PUBLIC,dvaia_ctf_runtime;
DO $$ DECLARE tab text; BEGIN
 FOREACH tab IN ARRAY ARRAY['ctf_config','ctf_participants','ctf_stages','ctf_progress','ctf_attempts','ctf_leaderboard','ctf_events','ctf_sessions','ctf_technique_blocklist','ctf_payload_blocklist','ctf_bans','ctf_judgments','stage_default_fields','import_provenance'] LOOP
 EXECUTE format('CREATE TRIGGER ctf_bootstrap_source_fence BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON ctf.%I FOR EACH STATEMENT EXECUTE FUNCTION ctf.guard_bootstrap_source()',tab);
 END LOOP;
END $$;
