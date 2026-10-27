-- An authenticated owner requesting an old publication after an authority
-- generation change is stale, not a foreign principal. Preserve the original
-- 0133 authorizer and every other error class, including the final fence.
DO $migration$
DECLARE
 original text;
 old_branch text := $old$THEN RAISE EXCEPTION 'CTF publication scope stale' USING ERRCODE='42501'; END IF;$old$;
 new_branch text := $new$THEN
  IF o.scope_key IS NOT NULL AND o.owner_generation IS DISTINCT FROM d.owner_generation
  THEN RAISE EXCEPTION 'CTF publication scope stale' USING ERRCODE='PCT01'; END IF;
  RAISE EXCEPTION 'CTF publication scope stale' USING ERRCODE='42501'; END IF;$new$;
BEGIN
 SELECT p.prosrc INTO original FROM pg_catalog.pg_proc p
  JOIN pg_catalog.pg_language l ON l.oid=p.prolang
  WHERE p.oid='identity.authorize_ctf_current_publication(uuid,integer,integer,text)'::pg_catalog.regprocedure
   AND p.prosecdef AND l.lanname='plpgsql'
   AND p.proconfig=ARRAY['search_path=pg_catalog'];
 IF original IS NULL OR encode(sha256(convert_to(original,'UTF8')),'hex')
    <> '85171d42258878579726015bb091e1159a618acb13e76413dd95a2efc0506588'
    OR strpos(original,old_branch)=0
    OR strpos(substr(original,strpos(original,old_branch)+length(old_branch)),old_branch)>0 THEN
  RAISE EXCEPTION 'CTF publication authorizer predecessor unavailable' USING ERRCODE='55000';
 END IF;
 EXECUTE format('CREATE OR REPLACE FUNCTION identity.authorize_ctf_current_publication(
  p_decision uuid,p_actor integer,p_session integer,p_token_hash text)
  RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS %L',
  replace(original,old_branch,new_branch));
END $migration$;
REVOKE ALL ON FUNCTION identity.authorize_ctf_current_publication(uuid,integer,integer,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.authorize_ctf_current_publication(uuid,integer,integer,text) TO dvaia_identity_runtime;
